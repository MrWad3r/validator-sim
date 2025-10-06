use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio::time::{Duration, interval, sleep};
use tycho_types::cell::{Cell, CellBuilder, HashBytes};

type ValidatorAddress = HashBytes;

const FIXED_POINT_SHIFT: u32 = 16;
const FIXED_POINT_ONE: u32 = 1 << FIXED_POINT_SHIFT;

#[derive(Clone, Copy, Debug)]
struct ValidatorBehaviorConfig {
    malicious_signature_probability: u32,
    participation_rate: u32,
    malicious_reporter: bool,
}

impl ValidatorBehaviorConfig {
    fn new(
        malicious_signature_probability: u32,
        participation_rate: u32,
        malicious_reporter: bool,
    ) -> Self {
        Self {
            malicious_signature_probability,
            participation_rate,
            malicious_reporter,
        }
    }

    fn should_participate(&self) -> bool {
        let random_value = rand::random::<u32>() % FIXED_POINT_ONE;
        random_value < self.participation_rate
    }
}

#[derive(Clone, Copy, Debug)]
enum ValidatorProfile {
    Poor,
    Normal,
    Excellent,
    MaliciousReporter,
}

impl ValidatorProfile {
    fn to_behavior_config(&self) -> ValidatorBehaviorConfig {
        match self {
            Self::Poor => ValidatorBehaviorConfig::new(
                (FIXED_POINT_ONE * 30) / 100,
                (FIXED_POINT_ONE * 10) / 100,
                false,
            ),
            Self::Normal => ValidatorBehaviorConfig::new(
                (FIXED_POINT_ONE * 5) / 100,
                (FIXED_POINT_ONE * 20) / 100,
                false,
            ),
            Self::Excellent => ValidatorBehaviorConfig::new(0, FIXED_POINT_ONE * 100, false),
            Self::MaliciousReporter => {
                ValidatorBehaviorConfig::new(FIXED_POINT_ONE * 100, FIXED_POINT_ONE * 100, true)
            }
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Poor => "Poor",
            Self::Normal => "Normal",
            Self::Excellent => "Excellent",
            Self::MaliciousReporter => "🎭 Malicious",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockParticipation {
    ValidSignature,
    InvalidSignature,
    NotParticipated,
}

impl BlockParticipation {
    fn to_bits(self) -> (bool, bool, bool) {
        match self {
            Self::ValidSignature => (true, true, false),
            Self::InvalidSignature => (true, false, true),
            Self::NotParticipated => (false, false, true),
        }
    }

    fn from_bits(participated: bool, sig_valid: bool, sig_invalid_or_missing: bool) -> Self {
        match (participated, sig_valid, sig_invalid_or_missing) {
            (true, true, _) => Self::ValidSignature,
            (true, false, true) => Self::InvalidSignature,
            _ => Self::NotParticipated,
        }
    }
}

#[derive(Clone, Debug)]
struct Block {
    seqno: u64,
    hash: [u8; 32],
}

#[derive(Clone)]
struct BlockSignature {
    validator: ValidatorAddress,
    signature: Signature,
    is_valid: bool,
}

#[derive(Clone, Debug)]
struct ValidatorStats {
    blocks_count: usize,
    cell: Cell,
}

impl ValidatorStats {
    fn new(blocks_count: usize) -> Self {
        let total_bits = blocks_count * 3;
        let mut builder = CellBuilder::new();
        for _ in 0..total_bits {
            builder.store_bit(false).unwrap();
        }
        Self {
            blocks_count,
            cell: builder.build().unwrap(),
        }
    }

    fn update_block_stats(&mut self, block_idx: usize, participation: BlockParticipation) {
        if block_idx >= self.blocks_count {
            return;
        }

        let total_bits = self.blocks_count * 3;
        let mut current_bits = Vec::with_capacity(total_bits);
        let mut slice = self.cell.as_slice().unwrap();
        for _ in 0..total_bits {
            current_bits.push(slice.load_bit().unwrap_or(false));
        }

        let participation_bit_idx = block_idx;
        let valid_sig_bit_idx = self.blocks_count + block_idx * 2;
        let invalid_sig_bit_idx = self.blocks_count + block_idx * 2 + 1;
        let (participated, sig_valid, sig_invalid_or_missing) = participation.to_bits();

        current_bits[participation_bit_idx] = participated;
        current_bits[valid_sig_bit_idx] = sig_valid;
        current_bits[invalid_sig_bit_idx] = sig_invalid_or_missing;

        let mut builder = CellBuilder::new();
        for bit in current_bits {
            builder.store_bit(bit).unwrap();
        }
        self.cell = builder.build().unwrap();
    }

    fn get_block_stats(&self, block_idx: usize) -> BlockParticipation {
        if block_idx >= self.blocks_count {
            return BlockParticipation::NotParticipated;
        }

        let mut slice = self.cell.as_slice().unwrap();
        for _ in 0..block_idx {
            let _ = slice.load_bit();
        }
        let participated = slice.load_bit().unwrap_or(false);

        for _ in (block_idx + 1)..self.blocks_count {
            let _ = slice.load_bit();
        }
        for _ in 0..block_idx {
            let _ = slice.load_bit();
            let _ = slice.load_bit();
        }

        let sig_valid = slice.load_bit().unwrap_or(false);
        let sig_invalid_or_missing = slice.load_bit().unwrap_or(false);

        BlockParticipation::from_bits(participated, sig_valid, sig_invalid_or_missing)
    }

    fn visualize(&self, validator_name: &str) -> String {
        let mut result = String::new();
        result.push_str(&format!("Stats for {}: ", validator_name));
        for block_idx in 0..self.blocks_count {
            let symbol = match self.get_block_stats(block_idx) {
                BlockParticipation::ValidSignature => "✓",
                BlockParticipation::InvalidSignature => "✗",
                BlockParticipation::NotParticipated => "○",
            };
            result.push_str(symbol);
        }
        result
    }
}

#[derive(Clone, Copy, Debug)]
struct ScoringConfig {
    valid_signature_score: i32,
    invalid_signature_penalty: i32,
    missed_block_penalty: i32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            valid_signature_score: 5,
            invalid_signature_penalty: -5,
            missed_block_penalty: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatorMetrics {
    score: i32,
    total_blocks: usize,
    participated_blocks: usize,
    valid_signatures: usize,
    invalid_signatures: usize,
    missed_blocks: usize,
}

impl ValidatorMetrics {
    fn new() -> Self {
        Self {
            score: 0,
            total_blocks: 0,
            participated_blocks: 0,
            valid_signatures: 0,
            invalid_signatures: 0,
            missed_blocks: 0,
        }
    }

    fn calculate_from_stats(stats: &ValidatorStats, config: &ScoringConfig) -> Self {
        let mut metrics = Self::new();
        metrics.total_blocks = stats.blocks_count;

        for block_idx in 0..stats.blocks_count {
            match stats.get_block_stats(block_idx) {
                BlockParticipation::ValidSignature => {
                    metrics.participated_blocks += 1;
                    metrics.valid_signatures += 1;
                    metrics.score += config.valid_signature_score;
                }
                BlockParticipation::InvalidSignature => {
                    metrics.participated_blocks += 1;
                    metrics.invalid_signatures += 1;
                    metrics.score += config.invalid_signature_penalty;
                }
                BlockParticipation::NotParticipated => {
                    metrics.missed_blocks += 1;
                    metrics.score += config.missed_block_penalty;
                }
            }
        }
        metrics
    }

    fn get_participation_rate(&self) -> u32 {
        if self.total_blocks == 0 {
            return 0;
        }
        ((self.participated_blocks as u64 * FIXED_POINT_ONE as u64 * 100)
            / self.total_blocks as u64) as u32
    }

    fn get_validity_rate(&self) -> u32 {
        let total_sigs = self.valid_signatures + self.invalid_signatures;
        if total_sigs == 0 {
            return 0;
        }
        ((self.valid_signatures as u64 * FIXED_POINT_ONE as u64 * 100) / total_sigs as u64) as u32
    }

    fn get_rating(&self) -> &str {
        let participation_rate = self.get_participation_rate();
        let validity_rate = self.get_validity_rate();

        let ten_percent = (FIXED_POINT_ONE * 10) / 100;
        let fifty_percent = (FIXED_POINT_ONE * 50) / 100;
        let seventy_percent = (FIXED_POINT_ONE * 70) / 100;
        let eighty_percent = (FIXED_POINT_ONE * 80) / 100;
        let ninety_percent = (FIXED_POINT_ONE * 90) / 100;
        let ninety_five_percent = (FIXED_POINT_ONE * 95) / 100;
        let hundred_percent = FIXED_POINT_ONE;

        if self.participated_blocks == 0 || participation_rate < ten_percent {
            return "Critical";
        }

        if self.invalid_signatures > self.valid_signatures {
            return "Critical";
        }

        if validity_rate < fifty_percent {
            return "Critical";
        }

        if self.missed_blocks > 0 || self.invalid_signatures > 0 {
            if validity_rate < seventy_percent {
                return "Critical";
            }
            if validity_rate < eighty_percent || participation_rate < seventy_percent {
                return "Poor";
            }
            if validity_rate < ninety_percent || participation_rate < eighty_percent {
                return "Average";
            }
            if validity_rate < ninety_five_percent || participation_rate < ninety_percent {
                return "Good";
            }
            return "Good";
        }

        if participation_rate >= hundred_percent && validity_rate >= hundred_percent {
            return "Excellent";
        }

        "Good"
    }
}

struct BlockProducer {
    tx: broadcast::Sender<Block>,
    block_interval: Duration,
    total_blocks: usize,
}

impl BlockProducer {
    fn new(total_blocks: usize, block_interval: Duration) -> (Self, broadcast::Receiver<Block>) {
        let (tx, rx) = broadcast::channel(100);
        (
            Self {
                tx,
                block_interval,
                total_blocks,
            },
            rx,
        )
    }

    async fn start_producing(self) {
        let mut interval_timer = interval(self.block_interval);
        for block_idx in 0..self.total_blocks {
            interval_timer.tick().await;
            let block = Block {
                seqno: block_idx as u64,
                hash: {
                    let mut hash = [0u8; 32];
                    let mut rng = rand::rng();
                    rng.fill_bytes(&mut hash[..]);
                    hash
                },
            };
            println!("📦 Block producer: Broadcasting block #{}", block.seqno);
            let _ = self.tx.send(block);
        }
        println!(
            "✅ Block producer: Finished producing {} blocks",
            self.total_blocks
        );
    }
}

struct Validator {
    address: ValidatorAddress,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    local_stats: Arc<RwLock<HashMap<ValidatorAddress, ValidatorStats>>>,
    blocks_to_track: usize,
    validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
    stats_sender: Arc<
        Mutex<
            Option<
                tokio::sync::mpsc::Sender<(
                    ValidatorAddress,
                    HashMap<ValidatorAddress, ValidatorStats>,
                    bool,
                )>,
            >,
        >,
    >,
    behavior_config: ValidatorBehaviorConfig,
    profile: ValidatorProfile,
}

impl Validator {
    fn new(
        blocks_to_track: usize,
        validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
        profile: ValidatorProfile,
    ) -> Self {
        let mut rng = rand::rng();
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let mut address = HashBytes([0u8; 32]);
        address.0.copy_from_slice(verifying_key.as_bytes());

        let behavior_config = profile.to_behavior_config();

        Self {
            address,
            signing_key,
            verifying_key,
            local_stats: Arc::new(RwLock::new(HashMap::new())),
            blocks_to_track,
            validator_set,
            stats_sender: Arc::new(Mutex::new(None)),
            behavior_config,
            profile,
        }
    }

    async fn set_stats_sender(
        &self,
        sender: tokio::sync::mpsc::Sender<(
            ValidatorAddress,
            HashMap<ValidatorAddress, ValidatorStats>,
            bool,
        )>,
    ) {
        *self.stats_sender.lock().await = Some(sender);
    }

    async fn sign_block(&self, block: &Block) -> Signature {
        sleep(Duration::from_millis(1)).await;
        let message = [&block.seqno.to_le_bytes()[..], &block.hash[..]].concat();
        let signature = self.signing_key.sign(&message);

        let random_value = rand::random::<u32>() % FIXED_POINT_ONE;
        if random_value < self.behavior_config.malicious_signature_probability {
            let mut sig_bytes = signature.to_bytes();
            sig_bytes[0] ^= 0xFF;
            Signature::from_bytes(&sig_bytes)
        } else {
            signature
        }
    }

    async fn request_signature(
        &self,
        validator: &Arc<Validator>,
        block: &Block,
    ) -> Option<BlockSignature> {
        if !validator.behavior_config.should_participate() {
            return None;
        }

        let signature = validator.sign_block(block).await;
        Some(BlockSignature {
            validator: validator.address,
            signature,
            is_valid: false,
        })
    }

    fn verify_signature(
        &self,
        block: &Block,
        sig: &BlockSignature,
        verifying_key: &VerifyingKey,
    ) -> bool {
        let message = [&block.seqno.to_le_bytes()[..], &block.hash[..]].concat();
        verifying_key.verify(&message, &sig.signature).is_ok()
    }

    async fn collect_signatures(&self, block: &Block) -> Vec<BlockSignature> {
        let guard = self.validator_set.read().await;
        let all_validators: Vec<_> = guard.values().cloned().collect();
        drop(guard);

        let threshold = (all_validators.len() * 2 / 3) + 1;
        println!(
            "  🔍 Validator {:02x}{:02x}: Collecting signatures for block #{}",
            self.address[0], self.address[1], block.seqno
        );

        let mut validator_indices: Vec<usize> = (0..all_validators.len()).collect();
        use rand::seq::SliceRandom;
        validator_indices.shuffle(&mut rand::rng());

        let mut signatures = Vec::with_capacity(threshold);
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for idx in validator_indices {
            if signatures.len() >= threshold {
                break;
            }

            let validator = &all_validators[idx];

            if validator.address == self.address {
                if !self.behavior_config.should_participate() {
                    println!(
                        "    ⏭️  Validator {:02x} skipping participation in this block",
                        validator.address
                    );
                    continue;
                }

                let signature = self.sign_block(block).await;
                let is_valid = self.verify_signature(
                    block,
                    &BlockSignature {
                        validator: self.address,
                        signature: signature.clone(),
                        is_valid: false,
                    },
                    &self.verifying_key,
                );

                if is_valid {
                    valid_count += 1;
                } else {
                    invalid_count += 1;
                    println!("    ⚠️  Self-signed signature is INVALID!");
                }
                signatures.push(BlockSignature {
                    validator: self.address,
                    signature,
                    is_valid,
                });
            } else if let Some(mut sig) = self.request_signature(validator, block).await {
                sig.is_valid = self.verify_signature(block, &sig, &validator.verifying_key);
                if sig.is_valid {
                    valid_count += 1;
                } else {
                    invalid_count += 1;
                }
                signatures.push(sig);
            }
        }

        println!(
            "  ✓ Validator {:02x}: Collected {}/{} signatures (✓{} valid, ✗{} invalid)",
            self.address,
            signatures.len(),
            threshold,
            valid_count,
            invalid_count
        );
        signatures
    }

    async fn update_local_stats(&self, block_idx: usize, signatures: &[BlockSignature]) {
        let mut stats = self.local_stats.write().await;
        let registry = self.validator_set.read().await;
        let signature_map: HashMap<ValidatorAddress, &BlockSignature> =
            signatures.iter().map(|s| (s.validator, s)).collect();

        for (validator_addr, _validator) in registry.iter() {
            let validator_stats = stats
                .entry(*validator_addr)
                .or_insert_with(|| ValidatorStats::new(self.blocks_to_track));

            let actual_participation = if let Some(sig) = signature_map.get(validator_addr) {
                if sig.is_valid {
                    BlockParticipation::ValidSignature
                } else {
                    BlockParticipation::InvalidSignature
                }
            } else {
                BlockParticipation::NotParticipated
            };

            let reported_participation = if self.behavior_config.malicious_reporter {
                match actual_participation {
                    BlockParticipation::ValidSignature => {
                        println!(
                            "    🎭 MALICIOUS REPORT: {:02x} lies about {:02x}: VALID → INVALID",
                            self.address, validator_addr
                        );
                        BlockParticipation::InvalidSignature
                    }
                    BlockParticipation::InvalidSignature => {
                        println!(
                            "    🎭 MALICIOUS REPORT: {:02x} lies about {:02x}: INVALID → VALID",
                            self.address, validator_addr,
                        );
                        BlockParticipation::ValidSignature
                    }
                    BlockParticipation::NotParticipated => BlockParticipation::NotParticipated,
                }
            } else {
                actual_participation
            };

            validator_stats.update_block_stats(block_idx, reported_participation);
        }
    }

    async fn send_stats_to_slasher(&self, block_id: usize) {
        let stats = self.local_stats.read().await.clone();
        if let Some(sender) = self.stats_sender.lock().await.as_ref() {
            let is_malicious = self.behavior_config.malicious_reporter;
            let _ = sender.send((self.address, stats, is_malicious)).await;

            let reporter_type = if is_malicious {
                "🎭 MALICIOUS"
            } else {
                "✓ HONEST"
            };
            println!(
                "  📤 Validator {:02x} [{}]: Sent statistics to slasher for block {}",
                self.address, reporter_type, block_id
            );
        }
    }

    async fn run(self: Arc<Self>, mut block_rx: broadcast::Receiver<Block>) {
        loop {
            match block_rx.recv().await {
                Ok(block) => {
                    let block_idx = block.seqno as usize;
                    let signatures = self.collect_signatures(&block).await;
                    self.update_local_stats(block_idx, &signatures).await;

                    if block_idx == self.blocks_to_track - 1 {
                        self.send_stats_to_slasher(block_idx).await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    println!(
                        "  ⚠️  Validator {:02x}: Lagged by {} blocks",
                        self.address, n
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    println!(
                        "  🛑 Validator {:02x}: Block producer finished",
                        self.address,
                    );
                    break;
                }
            }
        }
        drop(self.stats_sender.lock().await.take());
    }
}

struct Slasher {
    validator_set: Vec<ValidatorAddress>,
    validator_map: HashMap<ValidatorAddress, Arc<Validator>>,
    aggregated_stats:
        Arc<Mutex<HashMap<ValidatorAddress, Vec<(ValidatorAddress, ValidatorStats, bool)>>>>,
    blocks_to_track: usize,
    stats_receiver: tokio::sync::mpsc::Receiver<(
        ValidatorAddress,
        HashMap<ValidatorAddress, ValidatorStats>,
        bool,
    )>,
    scoring_config: ScoringConfig,
}

impl Slasher {
    fn new(
        validator_set: Vec<ValidatorAddress>,
        validator_map: HashMap<ValidatorAddress, Arc<Validator>>,
        blocks_to_track: usize,
        stats_receiver: tokio::sync::mpsc::Receiver<(
            ValidatorAddress,
            HashMap<ValidatorAddress, ValidatorStats>,
            bool,
        )>,
        scoring_config: ScoringConfig,
    ) -> Self {
        Self {
            validator_set,
            validator_map,
            aggregated_stats: Arc::new(Mutex::new(HashMap::new())),
            blocks_to_track,
            stats_receiver,
            scoring_config,
        }
    }

    async fn receive_stats(
        &mut self,
        reporter: ValidatorAddress,
        stats: HashMap<ValidatorAddress, ValidatorStats>,
        is_malicious: bool,
    ) {
        let mut aggregated = self.aggregated_stats.lock().await;
        for (validator_addr, validator_stats) in stats {
            aggregated
                .entry(validator_addr)
                .or_insert_with(Vec::new)
                .push((reporter, validator_stats, is_malicious));
        }
    }

    async fn run(mut self) {
        println!("\n🎯 Slasher: Started listening for validator statistics...");
        while let Some((reporter, stats, is_malicious)) = self.stats_receiver.recv().await {
            let reporter_type = if is_malicious {
                "🎭 MALICIOUS"
            } else {
                "✓ honest"
            };
            println!(
                "  📥 Slasher: Received stats from validator {:02x} [{}]",
                reporter, reporter_type
            );
            self.receive_stats(reporter, stats, is_malicious).await;
        }
        println!("\n📊 Slasher: All statistics received, generating report...\n");
        self.print_aggregated_stats().await;
    }

    async fn aggregate_validator_stats(
        &self,
        validator: ValidatorAddress,
    ) -> Option<ValidatorStats> {
        let aggregated = self.aggregated_stats.lock().await;
        let reports = aggregated.get(&validator)?;
        if reports.is_empty() {
            return None;
        }

        let mut final_stats = ValidatorStats::new(self.blocks_to_track);

        // let honest_reporters: Vec<_> = reports.iter().filter(|(_, _, is_malicious)| !is_malicious).collect();
        // let malicious_reporters: Vec<_> = reports.iter().filter(|(_, _, is_malicious)| *is_malicious).collect();
        //
        // println!(
        //     "\n  🔬 Aggregating stats for validator {:02x}:",
        //     validator
        // );
        // println!(
        //     "     Total reports: {} (✓{} honest, 🎭{} malicious)",
        //     reports.len(),
        //     honest_reporters.len(),
        //     malicious_reporters.len()
        // );

        for block_idx in 0..self.blocks_to_track {
            let mut valid_sig_votes = 0;
            let mut invalid_sig_votes = 0;
            let mut not_participated_votes = 0;

            let mut honest_valid = 0;
            let mut honest_invalid = 0;
            let mut malicious_valid = 0;
            let mut malicious_invalid = 0;

            for (reporter, stats, is_malicious) in reports {
                match stats.get_block_stats(block_idx) {
                    BlockParticipation::ValidSignature => {
                        valid_sig_votes += 1;
                        if *is_malicious {
                            malicious_valid += 1;
                        } else {
                            honest_valid += 1;
                        }
                    }
                    BlockParticipation::InvalidSignature => {
                        invalid_sig_votes += 1;
                        if *is_malicious {
                            malicious_invalid += 1;
                            println!(
                                "      Block {}: 🎭 Malicious reporter {:02x} claims INVALID signature",
                                block_idx, reporter
                            );
                        } else {
                            honest_invalid += 1;
                            println!(
                                "      Block {}: ✓ Honest reporter {:02x} saw INVALID signature",
                                block_idx, reporter[0]
                            );
                        }
                    }
                    BlockParticipation::NotParticipated => {
                        not_participated_votes += 1;
                    }
                }
            }

            let participated_votes = valid_sig_votes + invalid_sig_votes;

            let participation = if participated_votes == 0 {
                BlockParticipation::NotParticipated
            } else {
                if honest_valid > honest_invalid {
                    BlockParticipation::ValidSignature
                } else if honest_invalid > honest_valid {
                    BlockParticipation::InvalidSignature
                } else {
                    if valid_sig_votes > invalid_sig_votes {
                        BlockParticipation::ValidSignature
                    } else {
                        BlockParticipation::InvalidSignature
                    }
                }
            };

            if block_idx < 3 || (invalid_sig_votes > 0) {
                println!(
                    "      Block {}: ✓Valid={} (✓h:{}, 🎭m:{}), ✗Invalid={} (✓h:{}, 🎭m:{}), NotPart={} → {:?}",
                    block_idx,
                    valid_sig_votes,
                    honest_valid,
                    malicious_valid,
                    invalid_sig_votes,
                    honest_invalid,
                    malicious_invalid,
                    not_participated_votes,
                    participation
                );
            }

            final_stats.update_block_stats(block_idx, participation);
        }
        Some(final_stats)
    }

    async fn calculate_all_metrics(&self) -> Vec<(ValidatorAddress, ValidatorMetrics, bool)> {
        let mut metrics_list = Vec::new();
        for validator_addr in &self.validator_set {
            if let Some(stats) = self.aggregate_validator_stats(*validator_addr).await {
                let metrics = ValidatorMetrics::calculate_from_stats(&stats, &self.scoring_config);
                let is_malicious = self
                    .validator_map
                    .get(validator_addr)
                    .map(|v| v.behavior_config.malicious_reporter)
                    .unwrap_or(false);
                metrics_list.push((*validator_addr, metrics, is_malicious));
            }
        }
        metrics_list.sort_by(|a, b| b.1.score.cmp(&a.1.score));
        metrics_list
    }

    async fn print_aggregated_stats(&self) {
        println!("╔══════════════════════════════════════════════════════════════════════╗");
        println!("║                      🎯 SLASHER PERFORMANCE REPORT                   ║");
        println!("╚══════════════════════════════════════════════════════════════════════╝");

        let metrics_list = self.calculate_all_metrics().await;

        println!("\n📊 VALIDATOR RANKINGS:");
        println!(
            "┌──────────────┬───────┬──────────┬────────┬─────────┬─────────┬──────────────┬──────────┐"
        );
        println!(
            "│  Validator   │ Score │ Rating   │ Part.% │ Valid % │ Invalid │   Missed     │  Type    │"
        );
        println!(
            "├──────────────┼───────┼──────────┼────────┼─────────┼─────────┼──────────────┼──────────┤"
        );

        for (rank, (validator, metrics, is_malicious)) in metrics_list.iter().enumerate() {
            let val_type = if *is_malicious {
                "🎭 Malicious"
            } else {
                "✓ Honest"
            };

            let validator_short = format!(
                "{:02x}{:02x}...{:02x}{:02x}",
                validator[0], validator[1], validator[30], validator[31]
            );

            let part_rate = (metrics.get_participation_rate() as u64 * 100) >> FIXED_POINT_SHIFT;
            let valid_rate = (metrics.get_validity_rate() as u64 * 100) >> FIXED_POINT_SHIFT;
            println!(
                "│ #{:2} {}│  {:4} │ {:8} │ {:5}.{}% │  {:5}.{}% │   {:3}   │     {:3}      │ {}│",
                rank + 1,
                validator_short,
                metrics.score,
                metrics.get_rating(),
                part_rate / 100,
                part_rate % 100,
                valid_rate / 100,
                valid_rate % 100,
                metrics.invalid_signatures,
                metrics.missed_blocks,
                val_type
            );
        }
        println!(
            "└──────────────┴───────┴──────────┴────────┴─────────┴─────────┴──────────────┴──────────┘"
        );

        let malicious_count = metrics_list.iter().filter(|(_, _, m)| *m).count();
        let byzantine_pct = if metrics_list.len() > 0 {
            ((malicious_count as u64 * 100) / metrics_list.len() as u64) as usize
        } else {
            0
        };

        let excellent_count = metrics_list
            .iter()
            .filter(|(_, m, _)| m.score >= 20)
            .count();
        let good_count = metrics_list
            .iter()
            .filter(|(_, m, _)| m.score >= 10 && m.score < 20)
            .count();
        let average_count = metrics_list
            .iter()
            .filter(|(_, m, _)| m.score >= 0 && m.score < 10)
            .count();
        let poor_count = metrics_list
            .iter()
            .filter(|(_, m, _)| m.score >= -10 && m.score < 0)
            .count();
        let critical_count = metrics_list
            .iter()
            .filter(|(_, m, _)| m.score < -10)
            .count();

        println!("\n📈 PERFORMANCE DISTRIBUTION:");
        println!("┌────────────────────────────────────────────┐");
        println!(
            "│ ⭐⭐⭐ Excellent (≥20):  {:2} validators      │",
            excellent_count
        );
        println!(
            "│ ⭐⭐  Good (10-19):     {:2} validators      │",
            good_count
        );
        println!(
            "│ ⭐   Average (0-9):    {:2} validators      │",
            average_count
        );
        println!(
            "│ ⚠️   Poor (-10 to -1): {:2} validators      │",
            poor_count
        );
        println!(
            "│ ❌   Critical (<-10):  {:2} validators      │",
            critical_count
        );
        println!("└────────────────────────────────────────────┘");

        let total_score: i32 = metrics_list.iter().map(|(_, m, _)| m.score).sum();
        let avg_score = if !metrics_list.is_empty() {
            (total_score << FIXED_POINT_SHIFT) / metrics_list.len() as i32
        } else {
            0
        };

        let total_participation: u32 = if !metrics_list.is_empty() {
            let sum: u64 = metrics_list
                .iter()
                .map(|(_, m, _)| m.get_participation_rate() as u64)
                .sum();
            (sum / metrics_list.len() as u64) as u32
        } else {
            0
        };

        let avg_score_display = ((avg_score as u64 * 10) >> FIXED_POINT_SHIFT) as i32;
        let total_part_display = ((total_participation as u64 * 100) >> FIXED_POINT_SHIFT) as u32;

        println!("\n🌐 NETWORK HEALTH:");
        println!("┌────────────────────────────────────────────┐");
        println!(
            "│ Average Score:         {:5}.{:01}              │",
            avg_score_display / 10,
            avg_score_display % 10
        );
        println!(
            "│ Network Participation: {:5}.{:01}%             │",
            total_part_display / 100,
            total_part_display % 100
        );
        println!(
            "│ Malicious Reporters:   {:2}/{:2} ({:2}%)        │",
            malicious_count,
            metrics_list.len(),
            byzantine_pct
        );

        let fifteen = ((FIXED_POINT_ONE * 15) >> FIXED_POINT_SHIFT) as i32;
        let five = ((FIXED_POINT_ONE * 5) >> FIXED_POINT_SHIFT) as i32;
        let avg_score_cmp = (avg_score >> FIXED_POINT_SHIFT) as i32;

        println!(
            "│ Network Status:        {}          │",
            if avg_score_cmp >= fifteen {
                "✅ Healthy    "
            } else if avg_score_cmp >= five {
                "⚠️  Degraded   "
            } else {
                "❌ Critical   "
            }
        );
        println!("└────────────────────────────────────────────┘");

        println!("\n💡 KEY INSIGHTS:");
        if byzantine_pct > 33 {
            println!("  ⚠️  WARNING: Byzantine fault tolerance exceeded!");
        } else {
            println!("  ✅ Byzantine fault tolerance maintained (malicious < 33%)");
        }

        let false_accusations = metrics_list
            .iter()
            .filter(|(_, m, is_mal)| !is_mal && m.invalid_signatures > 0)
            .count();
        if false_accusations > 0 {
            println!(
                "  🎭 {} honest validators received false accusations from malicious reporters",
                false_accusations
            );
        }

        println!("  ℹ️  Malicious validators cause triple harm:");
        let mal_profile = ValidatorProfile::MaliciousReporter.to_behavior_config();
        let mal_part = display_percentage(mal_profile.participation_rate);
        let mal_sigs = display_percentage(mal_profile.malicious_signature_probability);
        println!(
            "      1. Send bad signatures themselves ({}% invalid)",
            mal_sigs
        );
        println!("      2. Participate: {}%", mal_part);
        println!("      3. Invert ALL reports: good→bad, bad→good (100% lies)");
    }
}

fn create_validators(
    malicious: usize,
    poor: usize,
    normal: usize,
    excellent: usize,
) -> Vec<ValidatorProfile> {
    let mut profiles = Vec::new();

    for _ in 0..malicious {
        profiles.push(ValidatorProfile::MaliciousReporter);
    }
    for _ in 0..poor {
        profiles.push(ValidatorProfile::Poor);
    }
    for _ in 0..normal {
        profiles.push(ValidatorProfile::Normal);
    }
    for _ in 0..excellent {
        profiles.push(ValidatorProfile::Excellent);
    }

    profiles
}

fn display_percentage(value: u32) -> String {
    let whole = ((value as u64 * 100) >> FIXED_POINT_SHIFT) as u32;
    format!("{}.{}", whole / 100, whole % 100)
}

async fn simulate_slashing_system() {
    println!("🚀 Starting blockchain slashing simulation with Byzantine validators...\n");

    const NUM_BLOCKS: usize = 10;
    const BLOCK_INTERVAL_MS: u64 = 500;

    let validator_profiles = create_validators(5, 0, 0, 10);

    let num_validators = validator_profiles.len();

    let scoring_config = ScoringConfig {
        valid_signature_score: 5,
        invalid_signature_penalty: -5,
        missed_block_penalty: 0,
    };

    println!("⚙️  SYSTEM CONFIGURATION:");
    println!("  • Total validators: {}", num_validators);
    println!("  • Blocks to process: {}", NUM_BLOCKS);
    println!("  • Block interval: {}ms", BLOCK_INTERVAL_MS);
    println!("  • Byzantine fault tolerance: Up to 33% malicious");
    println!("\n💰 SCORING CONFIGURATION:");
    println!(
        "  • Valid signature: {:+} points",
        scoring_config.valid_signature_score
    );
    println!(
        "  • Invalid signature: {:+} points",
        scoring_config.invalid_signature_penalty
    );
    println!(
        "  • Missed block: {:+} points",
        scoring_config.missed_block_penalty
    );

    let validator_set = Arc::new(RwLock::new(HashMap::new()));
    let (stats_tx, stats_rx) = tokio::sync::mpsc::channel(100);

    let mut validators = Vec::new();
    let mut validator_addresses = Vec::new();

    for profile in validator_profiles {
        let validator = Arc::new(Validator::new(
            NUM_BLOCKS,
            Arc::clone(&validator_set),
            profile,
        ));
        validator.set_stats_sender(stats_tx.clone()).await;
        validator_addresses.push(validator.address);
        validators.push(validator);
    }
    drop(stats_tx);

    let mut validator_map = HashMap::new();
    {
        let mut registry = validator_set.write().await;
        for validator in &validators {
            registry.insert(validator.address, Arc::clone(validator));
            validator_map.insert(validator.address, Arc::clone(validator));
        }
    }

    let mut malicious_count = 0;
    let mut poor_count = 0;
    let mut normal_count = 0;
    let mut excellent_count = 0;

    println!("\n👥 VALIDATOR BEHAVIOR PROFILES:");
    println!("┌──────────────┬────────────┬──────────────┬─────────────────────┐");
    println!("│  Validator   │    Type    │  Particip %  │  Malicious Sig %    │");
    println!("├──────────────┼────────────┼──────────────┼─────────────────────┤");

    for validator in &validators {
        let validator_type = validator.profile.name();

        match validator.profile {
            ValidatorProfile::MaliciousReporter => malicious_count += 1,
            ValidatorProfile::Poor => poor_count += 1,
            ValidatorProfile::Normal => normal_count += 1,
            ValidatorProfile::Excellent => excellent_count += 1,
        }

        let validator_short = format!(
            "{:02x}{:02x}...{:02x}{:02x}",
            validator.address[0],
            validator.address[1],
            validator.address[30],
            validator.address[31]
        );
        let part_pct = display_percentage(validator.behavior_config.participation_rate);
        let mal_pct = display_percentage(validator.behavior_config.malicious_signature_probability);
        println!(
            "│ {} │ {:10} │   {:>6}%  │       {:>6}%      │",
            validator_short, validator_type, part_pct, mal_pct
        );
    }
    println!("└──────────────┴────────────┴──────────────┴─────────────────────┘");

    println!("\n📊 VALIDATOR DISTRIBUTION:");

    let mut profile_stats: HashMap<&str, (usize, u32, u32)> = HashMap::new();
    for validator in &validators {
        let entry = profile_stats
            .entry(validator.profile.name())
            .or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 = validator.behavior_config.participation_rate;
        entry.2 = validator.behavior_config.malicious_signature_probability;
    }

    for (profile_name, (count, part_rate, mal_rate)) in profile_stats.iter() {
        let part_pct = display_percentage(*part_rate);
        let mal_pct = display_percentage(*mal_rate);

        if *profile_name == "🎭 Malicious" {
            println!(
                "  • {} reporters: {} (~{}% of network)",
                profile_name,
                count,
                (count * 100) / num_validators
            );
            println!("      → Will ALWAYS invert truth about ALL other validators in reports");
            println!(
                "      → Participation: {}%, Bad signatures: {}%",
                part_pct, mal_pct
            );
        } else {
            println!(
                "  • {} performers: {} (participation {}%, bad sigs {}%)",
                profile_name, count, part_pct, mal_pct
            );
        }
    }

    let (producer, _) = BlockProducer::new(NUM_BLOCKS, Duration::from_millis(BLOCK_INTERVAL_MS));
    let slasher = Slasher::new(
        validator_addresses,
        validator_map,
        NUM_BLOCKS,
        stats_rx,
        scoring_config,
    );

    println!("\n⚡ STARTING SYSTEM COMPONENTS...\n");

    let mut validator_handles = Vec::new();
    for validator in validators {
        let rx = producer.tx.subscribe();
        let handle = tokio::spawn(validator.run(rx));
        validator_handles.push(handle);
    }

    let slasher_handle = tokio::spawn(slasher.run());
    let producer_handle = tokio::spawn(producer.start_producing());

    let _ = producer_handle.await;
    sleep(Duration::from_secs(3)).await;
    let _ = slasher_handle.await;

    println!("\n✅ Simulation completed!");
}

#[tokio::main]
async fn main() {
    simulate_slashing_system().await;
}
