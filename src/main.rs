use std::collections::HashMap;
use std::ops::{Div, Mul};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32};
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{sleep, Duration, interval};
use tycho_types::cell::{Cell, CellBuilder, HashBytes, Store, Load, CellContext, CellSlice};
use tycho_types::prelude::{CellFamily, Dict};


type ValidatorAddress = HashBytes;

const FIXED_POINT_SHIFT: u32 = 16;
const FIXED_POINT_ONE: u32 = 1 << FIXED_POINT_SHIFT;

const BLOCK_WINDOW: u8 = 100;

#[derive(Clone, Copy, Debug)]
struct ValidatorBehaviorConfig {
    malicious_signature_probability: u32,
    participation_rate: u32,
    malicious_reporter: bool,
}

impl ValidatorBehaviorConfig {
    fn new(malicious_signature_probability: u32, participation_rate: u32, malicious_reporter: bool) -> Self {
        Self {
            malicious_signature_probability,
            participation_rate,
            malicious_reporter,
        }
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
                (FIXED_POINT_ONE * 30) / 100,
                false
            ),
            Self::Normal => ValidatorBehaviorConfig::new(
                (FIXED_POINT_ONE * 5) / 100,
                (FIXED_POINT_ONE * 70) / 100,
                false
            ),
            Self::Excellent => ValidatorBehaviorConfig::new(
                0,
                FIXED_POINT_ONE,
                false
            ),
            Self::MaliciousReporter => ValidatorBehaviorConfig::new(
                FIXED_POINT_ONE,
                FIXED_POINT_ONE,
                true
            ),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Poor => "Poor",
            Self::Normal => "Normal",
            Self::Excellent => "Excellent",
            Self::MaliciousReporter => "Malicious",
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
    fn to_bits(self) -> (bool, bool) {
        match self {
            Self::ValidSignature => (true, false),
            Self::InvalidSignature => (false, true),
            Self::NotParticipated => (false, false),
        }
    }

    fn from_bits(valid: bool, invalid: bool) -> Self {
        match (valid, invalid) {
            (true, false) => Self::ValidSignature,
            (false, true) => Self::InvalidSignature,
            (false, false) => Self::NotParticipated,
            _ => panic!()
        }
    }
}

#[derive(Clone, Debug)]
struct Block {
    seqno: u64,
    hash: HashBytes,
}

#[derive(Clone)]
struct BlockSignature {
    validator: ValidatorAddress,
    signature: Signature,
    is_valid: bool,
}


#[derive(Clone, Debug)]
struct ValidatorSignatureData {
    signatures: Vec<BlockParticipation>,
}

impl Store for ValidatorSignatureData {
    fn store_into(&self, builder: &mut CellBuilder, _context: &dyn CellContext) -> Result<(), tycho_types::error::Error> {
        let count = self.signatures.len().min(BLOCK_WINDOW as usize);

        for i in 0..count {
            let (valid, invalid) = self.signatures[i].to_bits();
            builder.store_bit(valid)?;
            builder.store_bit(invalid)?;
        }

        for _ in count..BLOCK_WINDOW as usize {
            builder.store_bit(false)?;
            builder.store_bit(false)?;
        }

        Ok(())
    }
}

impl<'a> Load<'a> for ValidatorSignatureData {
    fn load_from(slice: &mut CellSlice<'a>) -> Result<Self, tycho_types::error::Error> {
        let mut signatures = Vec::with_capacity(BLOCK_WINDOW as usize);

        for _ in 0..BLOCK_WINDOW {
            let valid = slice.load_bit()?;
            let invalid = slice.load_bit()?;
            signatures.push(BlockParticipation::from_bits(valid, invalid));
        }

        Ok(Self { signatures })
    }
}

#[derive(Clone, Debug)]
struct ValidatorStats {
    start_block_seqno: u32,
    blocks_count: usize,
    self_participation: Vec<bool>,
    validator_signatures: HashMap<u32, Vec<BlockParticipation>>,
}

impl ValidatorStats {
    fn new(start_block_seqno: u32, blocks_count: usize) -> Self {
        Self {
            start_block_seqno,
            blocks_count,
            self_participation: vec![false; blocks_count],
            validator_signatures: HashMap::new(),
        }
    }

    fn set_self_participation(&mut self, block_idx: usize, participated: bool) {
        if block_idx < self.blocks_count {
            self.self_participation[block_idx] = participated;
        }
    }

    fn update_validator_signature(&mut self, validator_id: u32, block_idx: usize, participation: BlockParticipation) {
        if block_idx >= self.blocks_count {
            return;
        }

        let signatures = self.validator_signatures
            .entry(validator_id)
            .or_insert_with(|| vec![BlockParticipation::InvalidSignature; self.blocks_count]);

        if block_idx < signatures.len() {
            signatures[block_idx] = participation;
        }
    }
}

impl Store for ValidatorStats {
    fn store_into(&self, builder: &mut CellBuilder, context: &dyn CellContext) -> Result<(), tycho_types::error::Error> {
        builder.store_u32(self.start_block_seqno)?;

        let participation_count = self.self_participation.len().min(BLOCK_WINDOW as usize);

        for i in 0..participation_count {
            builder.store_bit(self.self_participation[i])?;
        }

        for _ in participation_count..BLOCK_WINDOW as usize {
            builder.store_bit(false)?;
        }

        let mut signatures_dict = Dict::<u32, ValidatorSignatureData>::new();

        for (validator_id, signatures) in &self.validator_signatures {
            let sig_data = ValidatorSignatureData {
                signatures: signatures.clone(),
            };
            signatures_dict.set(*validator_id, sig_data)?;
        }

        signatures_dict.store_into(builder, context)?;

        Ok(())
    }
}

impl<'a> Load<'a> for ValidatorStats {
    fn load_from(slice: &mut CellSlice<'a>) -> Result<Self, tycho_types::error::Error> {
        let start_block_seqno = slice.load_u32()?;

        let mut self_participation = Vec::with_capacity(BLOCK_WINDOW as usize);
        for _ in 0..BLOCK_WINDOW {
            self_participation.push(slice.load_bit()?);
        }

        let signatures_dict = Dict::<u32, ValidatorSignatureData>::load_from(slice)?;

        let mut validator_signatures = HashMap::new();

        for entry in signatures_dict.iter() {
            let (validator_id, sig_data) = entry?;
            validator_signatures.insert(validator_id, sig_data.signatures);
        }

        Ok(Self {
            start_block_seqno,
            blocks_count: BLOCK_WINDOW as usize,
            self_participation,
            validator_signatures,
        })
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
        (Self { tx, block_interval, total_blocks }, rx)
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
                    HashBytes(hash)
                },
            };
            println!("Block producer: Broadcasting block #{}", block.seqno);
            let _ = self.tx.send(block);
        }
        println!("Block producer: Finished producing {} blocks", self.total_blocks);
    }
}

struct Validator {
    address: ValidatorAddress,
    validator_id: u32,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    local_stats: Arc<RwLock<ValidatorStats>>,
    block_participation: Arc<RwLock<HashMap<u64, bool>>>,
    blocks_to_track: usize,
    current_block: AtomicU32,
    validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
    validator_id_map: Arc<RwLock<HashMap<ValidatorAddress, u32>>>,
    stats_sender: Arc<Mutex<Option<tokio::sync::mpsc::Sender<(ValidatorAddress, Cell)>>>>,
    behavior_config: ValidatorBehaviorConfig,
    profile: ValidatorProfile,
}

impl Validator {
    fn new(
        validator_id: u32,
        blocks_to_track: usize,
        validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
        validator_id_map: Arc<RwLock<HashMap<ValidatorAddress, u32>>>,
        profile: ValidatorProfile,
    ) -> Self {
        let mut rng = rand::rng();
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let address = HashBytes::from_slice(verifying_key.as_bytes());

        let behavior_config = profile.to_behavior_config();
        let current_block = 0;
        let local_stats = ValidatorStats::new(current_block, blocks_to_track);

        Self {
            address,
            validator_id,
            signing_key,
            verifying_key,
            local_stats: Arc::new(RwLock::new(local_stats)),
            blocks_to_track,
            current_block: AtomicU32::new(current_block),
            validator_set,
            validator_id_map,
            stats_sender: Arc::new(Mutex::new(None)),
            behavior_config,
            profile,
            block_participation: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn decide_participation(&self, block_seqno: u64) -> bool {
        let mut participation = self.block_participation.write().await;
        *participation.entry(block_seqno).or_insert_with(|| {
            let random_value = rand::random::<u32>() % FIXED_POINT_ONE;
            random_value < self.behavior_config.participation_rate
        })
    }

    async fn set_stats_sender(&self, sender: tokio::sync::mpsc::Sender<(ValidatorAddress, Cell)>) {
        *self.stats_sender.lock().await = Some(sender);
    }

    async fn sign_block(&self, block: &Block) -> Signature {
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

    async fn request_signature(&self, validator: &Arc<Validator>, block: &Block) -> Option<BlockSignature> {
        if !validator.decide_participation(block.seqno).await {
            return None;
        }

        let signature = validator.sign_block(block).await;
        Some(BlockSignature {
            validator: validator.address,
            signature,
            is_valid: false,
        })
    }

    fn verify_signature(&self, block: &Block, sig: &BlockSignature, verifying_key: &VerifyingKey) -> bool {
        let message = [&block.seqno.to_le_bytes()[..], &block.hash[..]].concat();
        verifying_key.verify(&message, &sig.signature).is_ok()
    }

    async fn collect_signatures(&self, block: &Block) -> Vec<BlockSignature> {
        let registry = self.validator_set.read().await;
        let all_validators: Vec<_> = registry.values().cloned().collect();
        drop(registry);

        let threshold = (all_validators.len() * 2 / 3) + 1;

        let mut validator_indices: Vec<usize> = (0..all_validators.len()).collect();
        use rand::seq::SliceRandom;
        validator_indices.shuffle(&mut rand::rng());

        let mut signatures = Vec::with_capacity(threshold);

        for idx in validator_indices {
            if signatures.len() >= threshold {
                break;
            }

            let validator = &all_validators[idx];

            if validator.address == self.address {
                continue;
            }

            if let Some(mut sig) = self.request_signature(validator, block).await {
                sig.is_valid = self.verify_signature(block, &sig, &validator.verifying_key);
                signatures.push(sig);
            }
        }

        signatures
    }

    async fn update_local_stats(&self, block_idx: usize, signatures: &[BlockSignature], self_participated: bool) -> anyhow::Result<()> {
        let mut stats = self.local_stats.write().await;
        let registry = self.validator_set.read().await;
        let id_map = self.validator_id_map.read().await;

        // Обновляем участие самого валидатора
        stats.set_self_participation(block_idx, self_participated);

        let signature_map: HashMap<ValidatorAddress, &BlockSignature> =
            signatures.iter().map(|s| (s.validator, s)).collect();

        for (validator_addr, _validator) in registry.iter() {
            if *validator_addr == self.address {
                continue;
            }

            let validator_id = match id_map.get(validator_addr) {
                Some(id) => *id,
                None => continue,
            };

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
                    BlockParticipation::ValidSignature => BlockParticipation::InvalidSignature,
                    BlockParticipation::InvalidSignature => BlockParticipation::ValidSignature,
                    BlockParticipation::NotParticipated => BlockParticipation::NotParticipated,
                }
            } else {
                actual_participation
            };

            stats.update_validator_signature(validator_id, block_idx, reported_participation);
        }

        Ok(())
    }

    async fn send_stats_to_slasher(&self) -> anyhow::Result<()> {
        let stats = self.local_stats.read().await;
        let mut builder = CellBuilder::new();
        stats.store_into(&mut builder, Cell::empty_context())?;
        let cell = builder.build()?;

        if let Some(sender) = self.stats_sender.lock().await.as_ref() {
            let _ = sender.send((self.address, cell)).await;
        }
        Ok(())
    }

    async fn run(self: Arc<Self>, mut block_rx: broadcast::Receiver<Block>) -> Result<()> {
        loop {
            match block_rx.recv().await {
                Ok(block) => {
                    let block_idx = block.seqno as usize;
                    let self_participated = self.decide_participation(block.seqno).await;
                    let signatures = self.collect_signatures(&block).await;
                    self.update_local_stats(block_idx, &signatures, self_participated).await?;

                    if block_idx == self.blocks_to_track - 1 {
                        let _ = self.send_stats_to_slasher().await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        drop(self.stats_sender.lock().await.take());
        Ok(())
    }
}

struct PunishResult {
    decision: bool,
    weight: i32,
}

struct Slasher {
    validator_set: HashMap<u32, ValidatorAddress>,
    votes: Arc<Mutex<HashMap<ValidatorAddress, HashMap<ValidatorAddress, i32>>>>,
    blocks_to_track: usize,
    stats_receiver: tokio::sync::mpsc::Receiver<(ValidatorAddress, Cell)>,
}

impl Slasher {
    fn new(
        validator_addresses: Vec<ValidatorAddress>,
        blocks_to_track: usize,
        stats_receiver: tokio::sync::mpsc::Receiver<(ValidatorAddress, Cell)>,
    ) -> Self {
        let mut validator_set = HashMap::new();
        for (idx, addr) in validator_addresses.iter().enumerate() {
            validator_set.insert(idx as u32, *addr);
        }

        Self {
            validator_set,
            votes: Arc::new(Mutex::new(HashMap::new())),
            blocks_to_track,
            stats_receiver,
        }
    }

    async fn receive_stats(&self, reporter: ValidatorAddress, cell: Cell) -> Result<()> {
        let mut slice = cell.as_slice()?;
        let stats = ValidatorStats::load_from(&mut slice)?;

        let mut votes = self.votes.lock().await;

        for (validator_id, signatures) in &stats.validator_signatures {
            if let Some(validator_addr) = self.validator_set.get(validator_id) {
                if reporter == *validator_addr {
                    continue;
                }

                let weighted_vote = self.should_punish_validator(&stats.self_participation, signatures);

                *votes.entry(reporter)
                    .or_insert_with(HashMap::new)
                    .entry(*validator_addr)
                    .or_insert(0) += weighted_vote;
            }
        }
        Ok(())
    }

    fn should_punish_validator(&self, reporter_participation: &[bool], signatures: &[BlockParticipation]) -> i32 {
        let mut skipped_blocks = 0;
        let mut invalid_signatures = 0;
        let mut total_blocks = 0;

        for (participated, signature) in reporter_participation.iter().zip(signatures.iter()) {
            if !participated {
                continue;
            }

            total_blocks += 1;

            match signature {
                BlockParticipation::InvalidSignature => invalid_signatures += 1,
                BlockParticipation::NotParticipated => skipped_blocks += 1,
                _ => ()
            }
        }

        if total_blocks == 0 {
            return 0;
        }

        let weight = (FIXED_POINT_ONE as usize * total_blocks) / self.blocks_to_track;

        let threshold_percentage = 50;

        let skip_percentage = (skipped_blocks * 100) / total_blocks;
        let invalid_percentage = (invalid_signatures * 100) / total_blocks;

        if skip_percentage > threshold_percentage || invalid_percentage > threshold_percentage {
            weight as i32
        } else {
            -(weight as i32)
        }
    }

    async fn run(mut self) {
        println!("\nSlasher: Listening for statistics...");
        while let Some((reporter, cell)) = self.stats_receiver.recv().await {
            if let Err(e) = self.receive_stats(reporter, cell).await {
                println!("\nReceive stats error: {}", e);
            }
        }
        println!("\nSlasher: Generating report...\n");
        self.print_report().await;
    }

    async fn calculate_all_metrics(&self) -> Vec<(ValidatorAddress, u32)> {
        let votes = self.votes.lock().await;
        let mut vote_totals: HashMap<ValidatorAddress, u32> = HashMap::new();

        for (_reporter, targets) in votes.iter() {
            for (target, count) in targets {
                *vote_totals.entry(*target).or_insert(0) += *count as u32;
            }
        }

        let mut results: Vec<_> = vote_totals.into_iter().collect();
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }

    async fn print_report(&self) {
        println!("╔══════════════════════════════════════════════════════════════════════╗");
        println!("║                      SLASHER PERFORMANCE REPORT                      ║");
        println!("╚══════════════════════════════════════════════════════════════════════╝");

        let votes = self.votes.lock().await;

        let mut all_validators: Vec<ValidatorAddress> = self.validator_set.values().copied().collect();
        all_validators.sort_by_key(|v| v.0);

        print!("\n        ");
        for target in &all_validators {
            print!(" {:02x}", target[0]);
        }
        println!();

        print!("        ");
        for _ in &all_validators {
            print!("───");
        }
        println!();

        for reporter in &all_validators {
            print!("{:02x}{:02x} │ ", reporter[0], reporter[1]);

            for target in &all_validators {
                if reporter == target {
                    print!("  -");
                } else if let Some(reporter_votes) = votes.get(reporter) {
                    if let Some(count) = reporter_votes.get(target) {
                        // Показываем реальное значение с учетом знака
                        let display_value = count >> FIXED_POINT_SHIFT;
                        if display_value >= 0 {
                            print!(" {:>3}", display_value);
                        } else {
                            print!("{:>4}", display_value);
                        }
                    } else {
                        print!("  .");
                    }
                } else {
                    print!("  .");
                }
            }
            println!();
        }

        let results = self.calculate_all_metrics().await;

        println!("\n\nVALIDATOR PUNISHMENT SUMMARY:");
        println!("┌──────────────┬───────────────────────────┬────────────────────────┐");
        println!("│  Validator   │ Total Votes to Punish     │  Final Score           │");
        println!("├──────────────┼───────────────────────────┼────────────────────────┤");

        for (rank, (validator, vote_count)) in results.iter().enumerate() {
            let validator_short = format!("{:02x}{:02x}...{:02x}{:02x}",
                                          validator[0], validator[1], validator[30], validator[31]);

            // Показываем как raw значение, так и в человеко-читаемом формате
            let display_score = (*vote_count as i32) >> FIXED_POINT_SHIFT;

            println!("│ #{:2} {}│      {:10}            │     {:>6}             │",
                     rank + 1, validator_short, vote_count, display_score);
        }
        println!("└──────────────┴───────────────────────────┴────────────────────────┘");

        // Подсчет с учетом знака
        let positive_votes = results.iter().filter(|(_, count)| *count as i32 > 0).count();
        let negative_votes = results.iter().filter(|(_, count)| (*count as i32) < 0).count();
        let neutral_votes = results.iter().filter(|(_, count)| *count == 0).count();

        println!("\nVOTE DISTRIBUTION:");
        println!("┌────────────────────────────────────────────┐");
        println!("│ Should be punished (>0):  {:2} validators  │", positive_votes);
        println!("│ Should NOT be punished (<0): {:2} validators│", negative_votes);
        println!("│ Neutral (=0):             {:2} validators  │", neutral_votes);
        println!("└────────────────────────────────────────────┘");
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
    let percentage = ((value as u64 * 10000) >> FIXED_POINT_SHIFT) as u32;
    format!("{}.{:02}", percentage / 100, percentage % 100)
}

async fn simulate_slashing_system() {
    println!("Starting blockchain slashing simulation...\n");

    const NUM_BLOCKS: usize = 10;
    const BLOCK_INTERVAL_MS: u64 = 50;

    let validator_profiles = create_validators(2, 0, 0, 8);
    let num_validators = validator_profiles.len();

    println!("CONFIGURATION:");
    println!("  Validators: {}", num_validators);
    println!("  Blocks: {}", NUM_BLOCKS);
    println!("  Block interval: {}ms", BLOCK_INTERVAL_MS);

    let validator_set = Arc::new(RwLock::new(HashMap::new()));
    let validator_id_map = Arc::new(RwLock::new(HashMap::new()));
    let (stats_tx, stats_rx) = tokio::sync::mpsc::channel(100);

    let mut validators = Vec::new();
    let mut validator_addresses = Vec::new();

    for (idx, profile) in validator_profiles.into_iter().enumerate() {
        let validator = Arc::new(Validator::new(
            idx as u32,
            NUM_BLOCKS,
            Arc::clone(&validator_set),
            Arc::clone(&validator_id_map),
            profile
        ));
        validator.set_stats_sender(stats_tx.clone()).await;
        validator_addresses.push(validator.address);
        validators.push(validator);
    }
    drop(stats_tx);

    {
        let mut registry = validator_set.write().await;
        let mut id_map = validator_id_map.write().await;
        for validator in &validators {
            registry.insert(validator.address, Arc::clone(validator));
            id_map.insert(validator.address, validator.validator_id);
        }
    }

    println!("\nVALIDATOR PROFILES:");
    println!("┌──────────────┬────────────┬──────────────┬─────────────────────┐");
    println!("│  Validator   │    Type    │  Particip %  │  Malicious Sig %    │");
    println!("├──────────────┼────────────┼──────────────┼─────────────────────┤");

    for validator in &validators {
        let validator_short = format!("{:02x}{:02x}...{:02x}{:02x}",
                                      validator.address[0], validator.address[1],
                                      validator.address[30], validator.address[31]);
        let part_pct = display_percentage(validator.behavior_config.participation_rate);
        let mal_pct = display_percentage(validator.behavior_config.malicious_signature_probability);
        println!("│ {} │ {:10} │   {:>6}%  │       {:>6}%      │",
                 validator_short, validator.profile.name(), part_pct, mal_pct);
    }
    println!("└──────────────┴────────────┴──────────────┴─────────────────────┘");

    let (producer, _) = BlockProducer::new(NUM_BLOCKS, Duration::from_millis(BLOCK_INTERVAL_MS));
    let slasher = Slasher::new(validator_addresses, NUM_BLOCKS, stats_rx);

    println!("\nStarting simulation...\n");

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

    println!("\nSimulation completed!");
}

#[tokio::main]
async fn main() {
    simulate_slashing_system().await;
}