use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio::time::{Duration, interval, sleep};
use tycho_types::cell::{Cell, CellBuilder, HashBytes};

type ValidatorAddress = HashBytes;

#[derive(Clone, Copy, Debug)]
struct ValidatorBehaviorConfig {
    response_probability: f32,
    malicious_signature_probability: f32,
    participation_rate: f32,
}

impl ValidatorBehaviorConfig {
    fn poor() -> Self {
        Self {
            response_probability: 0.3,
            malicious_signature_probability: 0.5,
            participation_rate: 0.3,
        }
    }

    fn normal() -> Self {
        Self {
            response_probability: 0.6,
            malicious_signature_probability: 0.1,
            participation_rate: 0.6,
        }
    }

    fn excellent() -> Self {
        Self {
            response_probability: 0.9,
            malicious_signature_probability: 0.01,
            participation_rate: 0.9,
        }
    }

    fn from_behavior_score(score: f32) -> Self {
        if score < 0.2 {
            Self::poor()
        } else if score < 0.8 {
            Self::normal()
        } else {
            Self::excellent()
        }
    }

    fn should_participate(&self) -> bool {
        rand::random::<f32>() < self.participation_rate
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
    height: u64,
    hash: [u8; 32],
    data: Vec<u8>,
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

    fn get_participation_rate(&self) -> f32 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        (self.participated_blocks as f32 / self.total_blocks as f32) * 100.0
    }

    fn get_validity_rate(&self) -> f32 {
        let total_sigs = self.valid_signatures + self.invalid_signatures;
        if total_sigs == 0 {
            return 0.0;
        }
        (self.valid_signatures as f32 / total_sigs as f32) * 100.0
    }

    fn get_rating(&self) -> &str {
        if self.participated_blocks == 0 || self.get_participation_rate() < 10.0 {
            return "Critical";
        }

        if self.invalid_signatures > self.valid_signatures {
            return "Critical";
        }

        let validity_rate = self.get_validity_rate();
        if validity_rate < 50.0 {
            return "Poor";
        }

        // Теперь оцениваем по комбинации участия и качества
        let participation_rate = self.get_participation_rate();

        if participation_rate >= 80.0 && validity_rate >= 95.0 {
            return "Excellent";
        }

        if participation_rate >= 60.0 && validity_rate >= 85.0 {
            return "Good";
        }

        if participation_rate >= 30.0 && validity_rate >= 70.0 {
            return "Average";
        }

        "Poor"
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
                height: block_idx as u64,
                hash: {
                    let mut hash = [0u8; 32];
                    let mut rng = rand::rng();
                    rng.fill_bytes(&mut hash[..]);
                    hash
                },
                data: vec![block_idx as u8; 100],
            };
            println!("Block producer: Broadcasting block #{}", block.height);
            let _ = self.tx.send(block);
        }
        println!(
            "Block producer: Finished producing {} blocks",
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
                )>,
            >,
        >,
    >,
    behavior_score: f32,
    behavior_config: ValidatorBehaviorConfig,
}

impl Validator {
    fn new(
        blocks_to_track: usize,
        validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
    ) -> Self {
        let mut rng = rand::rng();
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let mut address = HashBytes([0u8; 32]);
        address.0.copy_from_slice(verifying_key.as_bytes());

        let behavior_score = (address[0] as f32) / 255.0;
        let behavior_config = ValidatorBehaviorConfig::from_behavior_score(behavior_score);

        Self {
            address,
            signing_key,
            verifying_key,
            local_stats: Arc::new(RwLock::new(HashMap::new())),
            blocks_to_track,
            validator_set,
            stats_sender: Arc::new(Mutex::new(None)),
            behavior_score,
            behavior_config,
        }
    }

    async fn set_stats_sender(
        &self,
        sender: tokio::sync::mpsc::Sender<(
            ValidatorAddress,
            HashMap<ValidatorAddress, ValidatorStats>,
        )>,
    ) {
        *self.stats_sender.lock().await = Some(sender);
    }

    async fn sign_block(&self, block: &Block) -> Signature {
        sleep(Duration::from_millis(1)).await;
        let message = [&block.height.to_le_bytes()[..], &block.hash[..]].concat();
        let signature = self.signing_key.sign(&message);

        if rand::random::<f32>() < self.behavior_config.malicious_signature_probability {
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

        if rand::random::<f32>() >= validator.behavior_config.response_probability {
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
        let message = [&block.height.to_le_bytes()[..], &block.hash[..]].concat();
        verifying_key.verify(&message, &sig.signature).is_ok()
    }

    async fn collect_signatures(&self, block: &Block) -> Vec<BlockSignature> {
        let registry = self.validator_set.read().await;
        let all_validators: Vec<_> = registry.values().cloned().collect();
        drop(registry);

        let threshold = (all_validators.len() * 2 / 3) + 1;
        println!(
            "  Validator {:02x}{:02x}: Collecting signatures for block #{}",
            self.address[0], self.address[1], block.height
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
                    println!("    ⏭️  Skipping participation in this block");
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
                    println!(
                        "    ✗ Invalid signature from {:02x}{:02x}",
                        validator.address[0], validator.address[1]
                    );
                }
                signatures.push(sig);
            }
        }

        println!(
            "  Validator {:02x}{:02x}: Collected {}/{} signatures (✓{} valid, ✗{} invalid)",
            self.address[0],
            self.address[1],
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

        for validator_addr in registry.keys() {
            let validator_stats = stats
                .entry(*validator_addr)
                .or_insert_with(|| ValidatorStats::new(self.blocks_to_track));
            let participation = if let Some(sig) = signature_map.get(validator_addr) {
                if sig.is_valid {
                    BlockParticipation::ValidSignature
                } else {
                    BlockParticipation::InvalidSignature
                }
            } else {
                BlockParticipation::NotParticipated
            };
            validator_stats.update_block_stats(block_idx, participation);
        }
    }

    async fn send_stats_to_slasher(&self, block_id: usize) {
        let stats = self.local_stats.read().await.clone();
        if let Some(sender) = self.stats_sender.lock().await.as_ref() {
            let _ = sender.send((self.address, stats)).await;
            println!(
                "  Validator {:02x}{:02x}: Sent statistics to slasher for block {}",
                self.address[0], self.address[1], block_id
            );
        }
    }

    async fn run(self: Arc<Self>, mut block_rx: broadcast::Receiver<Block>) {
        let mut block_count = 0;
        loop {
            match block_rx.recv().await {
                Ok(block) => {
                    let block_idx = block.height as usize;
                    let signatures = self.collect_signatures(&block).await;
                    self.update_local_stats(block_idx, &signatures).await;
                    block_count += 1;
                    if block_count % 5 == 0 || block_idx == self.blocks_to_track - 1 {
                        self.send_stats_to_slasher(block_idx).await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    println!(
                        "  Validator {:02x}{:02x}: Lagged by {} blocks",
                        self.address[0], self.address[1], n
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    println!(
                        "  Validator {:02x}{:02x}: Block producer finished",
                        self.address[0], self.address[1]
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
    aggregated_stats:
        Arc<Mutex<HashMap<ValidatorAddress, Vec<(ValidatorAddress, ValidatorStats)>>>>,
    blocks_to_track: usize,
    stats_receiver:
        tokio::sync::mpsc::Receiver<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>,
    scoring_config: ScoringConfig,
}

impl Slasher {
    fn new(
        validator_set: Vec<ValidatorAddress>,
        blocks_to_track: usize,
        stats_receiver: tokio::sync::mpsc::Receiver<(
            ValidatorAddress,
            HashMap<ValidatorAddress, ValidatorStats>,
        )>,
        scoring_config: ScoringConfig,
    ) -> Self {
        Self {
            validator_set,
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
    ) {
        let mut aggregated = self.aggregated_stats.lock().await;
        for (validator_addr, validator_stats) in stats {
            aggregated
                .entry(validator_addr)
                .or_insert_with(Vec::new)
                .push((reporter, validator_stats));
        }
    }

    async fn run(mut self) {
        println!("\nSlasher: Started listening for validator statistics...");
        while let Some((reporter, stats)) = self.stats_receiver.recv().await {
            println!(
                "  Slasher: Received stats from validator {:02x}{:02x}",
                reporter[0], reporter[1]
            );
            self.receive_stats(reporter, stats).await;
        }
        println!("\nSlasher: All statistics received, generating report...");
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
        println!(
            "\n  Aggregating stats for validator {:02x}{:02x} from {} reports:",
            validator[0],
            validator[1],
            reports.len()
        );

        for block_idx in 0..self.blocks_to_track {
            let mut valid_sig_votes = 0;
            let mut invalid_sig_votes = 0;
            let mut not_participated_votes = 0;

            for (reporter, stats) in reports {
                match stats.get_block_stats(block_idx) {
                    BlockParticipation::ValidSignature => valid_sig_votes += 1,
                    BlockParticipation::InvalidSignature => {
                        invalid_sig_votes += 1;
                        println!(
                            "    Block {}: Reporter {:02x}{:02x} saw INVALID signature",
                            block_idx, reporter[0], reporter[1]
                        );
                    }
                    BlockParticipation::NotParticipated => not_participated_votes += 1,
                }
            }

            let participated_votes = valid_sig_votes + invalid_sig_votes;

            let participation = if participated_votes == 0 {
                BlockParticipation::NotParticipated
            } else {
                if invalid_sig_votes > participated_votes / 2 {
                    BlockParticipation::InvalidSignature
                } else if valid_sig_votes > participated_votes / 2 {
                    BlockParticipation::ValidSignature
                } else {
                    if invalid_sig_votes > 0 {
                        BlockParticipation::InvalidSignature
                    } else {
                        BlockParticipation::ValidSignature
                    }
                }
            };

            println!(
                "    Block {}: Valid={}, Invalid={}, NotPart={} | Participated={} → Decision: {:?}",
                block_idx,
                valid_sig_votes,
                invalid_sig_votes,
                not_participated_votes,
                participated_votes,
                participation
            );
            final_stats.update_block_stats(block_idx, participation);
        }
        Some(final_stats)
    }

    async fn calculate_all_metrics(&self) -> Vec<(ValidatorAddress, ValidatorMetrics)> {
        let mut metrics_list = Vec::new();
        for validator in &self.validator_set {
            if let Some(stats) = self.aggregate_validator_stats(*validator).await {
                let metrics = ValidatorMetrics::calculate_from_stats(&stats, &self.scoring_config);
                metrics_list.push((*validator, metrics));
            }
        }
        metrics_list.sort_by(|a, b| b.1.score.cmp(&a.1.score));
        metrics_list
    }

    async fn print_aggregated_stats(&self) {
        println!("\n╔════════════════════════════════════════════════════════════════════╗");
        println!("║                     SLASHER PERFORMANCE REPORT                     ║");
        println!("╚════════════════════════════════════════════════════════════════════╝");

        let metrics_list = self.calculate_all_metrics().await;

        println!("\n VALIDATOR RANKINGS:");
        println!("┌──────────────┬───────┬──────────┬────────┬─────────┬─────────┬──────────────┐");
        println!("│  Validator   │ Score │ Rating   │ Part.% │ Valid % │ Invalid │   Missed     │");
        println!("├──────────────┼───────┼──────────┼────────┼─────────┼─────────┼──────────────┤");

        for (rank, (validator, metrics)) in metrics_list.iter().enumerate() {
            let validator_short = format!(
                "{:02x}{:02x}...{:02x}{:02x}",
                validator[0], validator[1], validator[30], validator[31]
            );
            println!(
                "│ #{:2} {}│  {:4} │ {:8} │ {:5.1}% │  {:5.1}% │   {:3}   │     {:3}      │",
                rank + 1,
                validator_short,
                metrics.score,
                metrics.get_rating(),
                metrics.get_participation_rate(),
                metrics.get_validity_rate(),
                metrics.invalid_signatures,
                metrics.missed_blocks
            );
        }
        println!("└──────────────┴───────┴──────────┴────────┴─────────┴─────────┴──────────────┘");

        let excellent_count = metrics_list.iter().filter(|(_, m)| m.score >= 20).count();
        let good_count = metrics_list
            .iter()
            .filter(|(_, m)| m.score >= 10 && m.score < 20)
            .count();
        let average_count = metrics_list
            .iter()
            .filter(|(_, m)| m.score >= 0 && m.score < 10)
            .count();
        let poor_count = metrics_list
            .iter()
            .filter(|(_, m)| m.score >= -10 && m.score < 0)
            .count();
        let critical_count = metrics_list.iter().filter(|(_, m)| m.score < -10).count();

        println!("\n PERFORMANCE DISTRIBUTION:");
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

        let total_score: i32 = metrics_list.iter().map(|(_, m)| m.score).sum();
        let avg_score = if !metrics_list.is_empty() {
            total_score as f32 / metrics_list.len() as f32
        } else {
            0.0
        };
        let total_participation: f32 = if !metrics_list.is_empty() {
            metrics_list
                .iter()
                .map(|(_, m)| m.get_participation_rate())
                .sum::<f32>()
                / metrics_list.len() as f32
        } else {
            0.0
        };

        println!("\n🌐 NETWORK HEALTH:");
        println!("┌────────────────────────────────────────────┐");
        println!("│ Average Score:         {:6.1}              │", avg_score);
        println!(
            "│ Network Participation: {:6.1}%             │",
            total_participation
        );
        println!(
            "│ Network Status:        {}          │",
            if avg_score >= 15.0 {
                "✅ Healthy    "
            } else if avg_score >= 5.0 {
                "⚠️  Degraded   "
            } else {
                "❌ Critical   "
            }
        );
        println!("└────────────────────────────────────────────┘");
    }
}

async fn simulate_slashing_system() {
    println!("🚀 Starting blockchain slashing simulation...\n");

    const NUM_VALIDATORS: usize = 15;
    const NUM_BLOCKS: usize = 10;
    const BLOCK_INTERVAL_MS: u64 = 500;

    let scoring_config = ScoringConfig {
        valid_signature_score: 5,
        invalid_signature_penalty: -5,
        missed_block_penalty: 0,
    };

    println!("SYSTEM CONFIGURATION:");
    println!("  • Total validators: {}", NUM_VALIDATORS);
    println!("  • Blocks to process: {}", NUM_BLOCKS);
    println!("  • Block interval: {}ms", BLOCK_INTERVAL_MS);
    println!("\nSCORING CONFIGURATION:");
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

    for _ in 0..NUM_VALIDATORS {
        let validator = Arc::new(Validator::new(NUM_BLOCKS, Arc::clone(&validator_set)));
        validator.set_stats_sender(stats_tx.clone()).await;
        validator_addresses.push(validator.address);
        validators.push(validator);
    }
    drop(stats_tx);

    {
        let mut registry = validator_set.write().await;
        for validator in &validators {
            registry.insert(validator.address, Arc::clone(validator));
        }
    }

    let mut poor_count = 0;
    let mut normal_count = 0;
    let mut excellent_count = 0;

    println!("\nVALIDATOR BEHAVIOR PROFILES:");
    println!("┌──────────────┬──────────┬──────────────┬─────────────────────┬──────────────┐");
    println!("│  Validator   │  Type    │  Response %  │  Malicious Sig %    │  Particip %  │");
    println!("├──────────────┼──────────┼──────────────┼─────────────────────┼──────────────┤");

    for validator in &validators {
        let validator_type = if validator.behavior_score < 0.2 {
            poor_count += 1;
            "Poor"
        } else if validator.behavior_score < 0.8 {
            normal_count += 1;
            "Normal"
        } else {
            excellent_count += 1;
            "Excellent"
        };

        let validator_short = format!(
            "{:02x}{:02x}...{:02x}{:02x}",
            validator.address[0],
            validator.address[1],
            validator.address[30],
            validator.address[31]
        );
        println!(
            "│ {} │ {:8} │    {:5.1}%    │       {:5.1}%        │   {:5.1}%    │",
            validator_short,
            validator_type,
            validator.behavior_config.response_probability * 100.0,
            validator.behavior_config.malicious_signature_probability * 100.0,
            validator.behavior_config.participation_rate * 100.0
        );
    }
    println!("└──────────────┴──────────┴──────────────┴─────────────────────┴──────────────┘");

    println!("\nVALIDATOR DISTRIBUTION:");
    println!(
        "  • Poor performers: {} (response ~50%, malicious ~30%, participation ~60%)",
        poor_count
    );
    println!(
        "  • Normal performers: {} (response ~90%, malicious ~5%, participation ~95%)",
        normal_count
    );
    println!(
        "  • Excellent performers: {} (response ~98%, malicious ~1%, participation ~99%)",
        excellent_count
    );

    let (producer, _) = BlockProducer::new(NUM_BLOCKS, Duration::from_millis(BLOCK_INTERVAL_MS));
    let slasher = Slasher::new(validator_addresses, NUM_BLOCKS, stats_rx, scoring_config);

    println!("\n⚙️  STARTING SYSTEM COMPONENTS...\n");

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
