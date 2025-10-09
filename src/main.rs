use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::sync::Arc;
use rand::RngCore;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{sleep, Duration, interval};
use tycho_types::cell::{Cell, CellBuilder, HashBytes, Store, Load, CellContext, CellSlice};
use tycho_types::error::Error;
use tycho_types::prelude::Dict;

type ValidatorAddress = HashBytes;

const FIXED_POINT_SHIFT: u32 = 16;
const FIXED_POINT_ONE: u32 = 1 << FIXED_POINT_SHIFT;

const MAX_BLOCK_WINDOW: u8 = 25;

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

    // fn should_participate(&self) -> bool {
    //     let random_value = rand::random::<u32>() % FIXED_POINT_ONE;
    //     random_value < self.participation_rate
    // }
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
    fn to_bits(self) -> (bool, bool, bool) {
        match self {
            Self::ValidSignature => (true, true, false),
            Self::InvalidSignature => (true, false, true),
            Self::NotParticipated => (false, false, true),
        }
    }

    // fn from_bits(participated: bool, sig_valid: bool, sig_invalid_or_missing: bool) -> Self {
    //     match (participated, sig_valid, sig_invalid_or_missing) {
    //         (true, true, _) => Self::ValidSignature,
    //         (true, false, true) => Self::InvalidSignature,
    //         _ => Self::NotParticipated,
    //     }
    // }
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
struct ValidatorStats {
    blocks_count: u8,
    cell: Cell,
}

#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    start_block_seqno: u32,
    block_mask: Vec<bool>,
    signatures: Vec<ValidatorSignatures>,
}

#[derive(Clone, Debug)]
pub struct ValidatorSignatures {
    id: u32,
    is_valid: bool,
}

impl Store for ValidatorInfo {
    fn store_into(&self, builder: &mut CellBuilder, context: &dyn CellContext) -> Result<(), Error> {
        builder.store_u32(self.start_block_seqno)?;
        if self.block_mask.len() > MAX_BLOCK_WINDOW as usize {
            return Err(Error::InvalidData);
        }
        for i in self.block_mask.iter() {
            builder.store_bit(*i)?;
        }

        let mut val_info = Dict::<u32, bool>::new();
        for i in self.signatures.iter() {
            val_info.set(i.id, i.is_valid)?;
        }
        val_info.store_into(builder, context)?;

        Ok(())
    }
}

impl<'a> Load<'a> for ValidatorInfo {
    fn load_from(slice: &mut CellSlice<'a>) -> Result<Self, Error> {
        let start_block_seqno = slice.load_u32()?;
        
        let mut block_mask = Vec::with_capacity(MAX_BLOCK_WINDOW as usize);
        for _ in 0..MAX_BLOCK_WINDOW {
            let bit = slice.load_bit()?;
            block_mask.push(bit);
        }
        
        let mut signatures = Vec::with_capacity(MAX_BLOCK_WINDOW as usize);
        let dict = Dict::<u32, bool>::load_from(slice)?;
        for i in dict.iter() {
            let (key, value) = i?;
            signatures.push(ValidatorSignatures {
                id: key,
                is_valid: value,
            });
        }
        
        Ok(ValidatorInfo {
            start_block_seqno,
            block_mask,
            signatures
        })
    }
}


impl ValidatorStats {
    fn new(start_block: u32, blocks_count: usize) -> anyhow::Result<Self> {
        let total_bits = blocks_count * 3;
        let mut builder = CellBuilder::new();
        let _ = builder.store_u32(start_block)?;
        for _ in 0..total_bits {
            builder.store_bit(false)?;
        }
        
        Ok(Self {
            blocks_count: blocks_count as u8,
            cell: builder.build()?,
        })
    }

    fn update_block_stats(&mut self, block_idx: usize, participation: BlockParticipation) {
        if block_idx >= self.blocks_count as usize {
            return;
        }

        let total_bits = self.blocks_count * 3;
        let mut current_bits = Vec::with_capacity(total_bits as usize);
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

    // fn get_block_stats(&self, block_idx: usize) -> BlockParticipation {
    //     if block_idx >= self.blocks_count {
    //         return BlockParticipation::NotParticipated;
    //     }
    //
    //     let mut slice = self.cell.as_slice().unwrap();
    //     for _ in 0..block_idx {
    //         let _ = slice.load_bit();
    //     }
    //     let participated = slice.load_bit().unwrap_or(false);
    //
    //     for _ in (block_idx + 1)..self.blocks_count {
    //         let _ = slice.load_bit();
    //     }
    //     for _ in 0..block_idx {
    //         let _ = slice.load_bit();
    //         let _ = slice.load_bit();
    //     }
    //
    //     let sig_valid = slice.load_bit().unwrap_or(false);
    //     let sig_invalid_or_missing = slice.load_bit().unwrap_or(false);
    //
    //     BlockParticipation::from_bits(participated, sig_valid, sig_invalid_or_missing)
    // }
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
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    local_stats: Arc<RwLock<HashMap<ValidatorAddress, ValidatorStats>>>,
    blocks_to_track: usize,
    validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
    stats_sender: Arc<Mutex<Option<tokio::sync::mpsc::Sender<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>>>>,
    behavior_config: ValidatorBehaviorConfig,
    profile: ValidatorProfile,
    block_participation: Arc<RwLock<HashMap<u64, bool>>>,
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

    async fn set_stats_sender(&self, sender: tokio::sync::mpsc::Sender<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>) {
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

    async fn update_local_stats(&self, block_idx: usize, signatures: &[BlockSignature]) {
        let mut stats = self.local_stats.write().await;
        let registry = self.validator_set.read().await;
        let signature_map: HashMap<ValidatorAddress, &BlockSignature> =
            signatures.iter().map(|s| (s.validator, s)).collect();

        for (validator_addr, _validator) in registry.iter() {
            if *validator_addr == self.address {
                continue;
            }

            let validator_stats = stats.entry(*validator_addr)
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
                    BlockParticipation::ValidSignature => BlockParticipation::InvalidSignature,
                    BlockParticipation::InvalidSignature => BlockParticipation::ValidSignature,
                    BlockParticipation::NotParticipated => BlockParticipation::NotParticipated,
                }
            } else {
                actual_participation
            };

            validator_stats.update_block_stats(block_idx, reported_participation);
        }
    }

    async fn send_stats_to_slasher(&self) {
        let stats = self.local_stats.read().await.clone();
        if let Some(sender) = self.stats_sender.lock().await.as_ref() {
            let _ = sender.send((self.address, stats)).await;
        }
    }

    async fn run(self: Arc<Self>, mut block_rx: broadcast::Receiver<Block>) {
        loop {
            match block_rx.recv().await {
                Ok(block) => {
                    let block_idx = block.seqno as usize;
                    let signaturesя = self.collect_signatures(&block).await;
                    self.update_local_stats(block_idx, &signatures).await;

                    if block_idx == self.blocks_to_track - 1 {
                        self.send_stats_to_slasher().await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        drop(self.stats_sender.lock().await.take());
    }
}

struct Slasher {
    validator_set: HashMap<u32, ValidatorAddress>,
    votes: Arc<Mutex<HashMap<ValidatorAddress, HashMap<ValidatorAddress, u8>>>>,
    blocks_to_track: usize,
    stats_receiver: tokio::sync::mpsc::Receiver<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>,
}

impl Slasher {
    fn new(
        validator_addresses: Vec<ValidatorAddress>,
        blocks_to_track: usize,
        stats_receiver: tokio::sync::mpsc::Receiver<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>,
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

    async fn receive_stats(&mut self, reporter: ValidatorAddress, stats: HashMap<ValidatorAddress, ValidatorStats>) {
        let mut votes = self.votes.lock().await;

        for (validator_addr, validator_stats) in stats {
            if reporter == validator_addr {
                continue;
            }

            if let Ok(true) = self.should_punish_validator(&validator_stats) {
                *votes.entry(reporter)
                    .or_insert_with(HashMap::new)
                    .entry(validator_addr)
                    .or_insert(0) += 1;
            }
        }
    }

    fn should_punish_validator(&self, stats: &ValidatorStats) -> anyhow::Result<bool> {
        let mut skipped_blocks = 0;
        let mut invalid_signatures = 0;

        let mut slice = stats.cell.as_slice()?;
        for _ in 0..self.blocks_to_track {
            let participated = slice.load_bit()?;
            if !participated {
                skipped_blocks += 1;
            }
        }

        for _ in 0..self.blocks_to_track {
            let _ = slice.load_bit()?;
            let invalid_or_missing = slice.load_bit()?;
            if invalid_or_missing {
                invalid_signatures += 1;
            }
        }

        if skipped_blocks * 100 / self.blocks_to_track > 50 {
            return Ok(true);
        }

        if invalid_signatures * 100 / self.blocks_to_track > 50 {
            return Ok(true);
        }

        Ok(false)
    }


    async fn run(mut self) {
        println!("\nSlasher: Listening for statistics...");
        while let Some((reporter, stats)) = self.stats_receiver.recv().await {
            self.receive_stats(reporter, stats).await;
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
                        if *count > 9 {
                            print!("  +");
                        } else {
                            print!("  {}", count);
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
        println!("┌──────────────┬───────────────────────────┐");
        println!("│  Validator   │ Total Votes to Punish     │");
        println!("├──────────────┼───────────────────────────┤");

        for (rank, (validator, vote_count)) in results.iter().enumerate() {
            let validator_short = format!("{:02x}{:02x}...{:02x}{:02x}",
                                          validator[0], validator[1], validator[30], validator[31]);

            println!("│ #{:2} {}│           {:3}             │",
                     rank + 1, validator_short, vote_count);
        }
        println!("└──────────────┴───────────────────────────┘");

        let high_votes = results.iter().filter(|(_, count)| *count >= 10).count();
        let medium_votes = results.iter().filter(|(_, count)| *count >= 5 && *count < 10).count();
        let low_votes = results.iter().filter(|(_, count)| *count > 0 && *count < 5).count();

        println!("\nVOTE DISTRIBUTION:");
        println!("┌────────────────────────────────────────────┐");
        println!("│ High (≥10 votes):      {:2} validators     │", high_votes);
        println!("│ Medium (5-9 votes):    {:2} validators     │", medium_votes);
        println!("│ Low (1-4 votes):       {:2} validators     │", low_votes);
        println!("│ Clean (0 votes):       {:2} validators     │", all_validators.len() - results.len());
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
    let (stats_tx, stats_rx) = tokio::sync::mpsc::channel(100);

    let mut validators = Vec::new();
    let mut validator_addresses = Vec::new();

    for profile in validator_profiles {
        let validator = Arc::new(Validator::new(NUM_BLOCKS, Arc::clone(&validator_set), profile));
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