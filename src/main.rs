use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::sync::Arc;
use rand::RngCore;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{sleep, Duration, interval};
use tycho_types::cell::{Cell, CellBuilder, CellSlice, HashBytes};


// Validator address
type ValidatorAddress = HashBytes;

// Blockchain block
#[derive(Clone, Debug)]
struct Block {
    height: u64,
    hash: [u8; 32],
    data: Vec<u8>,
}

// Block signature from validator
#[derive(Clone)]
struct BlockSignature {
    validator: ValidatorAddress,
    signature: Signature,
    is_valid: bool,
}

// Statistics for one validator across N blocks using CellSlice
// Bit format:
// - First N bits: validation participation (0 - didn't participate, 1 - participated)
// - Next 2*N bits: for each block 2 bits:
//   - first bit: received valid signature (1) or not (0)
//   - second bit: received invalid signature or no signature at all (1) or not (0)
#[derive(Clone, Debug)]
struct ValidatorStats {
    blocks_count: usize,
    cell: Cell, // Store bits in Cell
}

impl ValidatorStats {
    fn new(blocks_count: usize) -> Self {
        // Need N + 2*N = 3*N bits
        let total_bits = blocks_count * 3;

        // Create a Cell with zeros
        let mut builder = CellBuilder::new();
        for _ in 0..total_bits {
            builder.store_bit(false).unwrap();
        }

        Self {
            blocks_count,
            cell: builder.build().unwrap(),
        }
    }


    fn update_block_stats(&mut self, block_idx: usize, participated: bool, sig_valid: bool, sig_invalid_or_missing: bool) {
        if block_idx >= self.blocks_count {
            return;
        }

        // Create new cell with updated bits
        let mut builder = CellBuilder::new();
        let mut slice = self.cell.as_slice().unwrap();

        let total_bits = self.blocks_count * 3;

        for bit_idx in 0..total_bits {
            let bit = if bit_idx == block_idx {
                // Participation bit
                participated
            } else if bit_idx == self.blocks_count + block_idx * 2 {
                // Valid signature bit
                sig_valid
            } else if bit_idx == self.blocks_count + block_idx * 2 + 1 {
                // Invalid/missing signature bit
                sig_invalid_or_missing
            } else {
                // Keep existing bit
                slice.load_bit().unwrap_or(false)
            };

            builder.store_bit(bit).unwrap();
        }

        self.cell = builder.build().unwrap();
    }

    // Get statistics for block
    fn get_block_stats(&self, block_idx: usize) -> (bool, bool, bool) {
        if block_idx >= self.blocks_count {
            return (false, false, false);
        }

        let mut slice = self.cell.as_slice().unwrap();

        // Skip to participation bit
        for _ in 0..block_idx {
            let _ = slice.load_bit();
        }
        let participated = slice.load_bit().unwrap_or(false);

        // Reset slice and skip to signature bits
        let mut slice = self.cell.as_slice().unwrap();
        let sig_bit_start = self.blocks_count + block_idx * 2;
        for _ in 0..sig_bit_start {
            let _ = slice.load_bit();
        }

        let sig_valid = slice.load_bit().unwrap_or(false);
        let sig_invalid_or_missing = slice.load_bit().unwrap_or(false);

        (participated, sig_valid, sig_invalid_or_missing)
    }

    // Create from existing Cell
    fn from_cell(cell: Cell, blocks_count: usize) -> Self {
        Self {
            blocks_count,
            cell,
        }
    }

    // Get the underlying Cell
    fn as_cell(&self) -> &Cell {
        &self.cell
    }

    // Debug print statistics in readable format
    fn debug_print(&self) {
        println!("ValidatorStats for {} blocks:", self.blocks_count);
        for i in 0..self.blocks_count {
            let (participated, valid, invalid) = self.get_block_stats(i);
            println!("  Block {}: participated={}, valid_sig={}, invalid_or_missing={}",
                     i, participated, valid, invalid);
        }
    }
}

// Metrics for validator evaluation
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

    fn calculate_from_stats(stats: &ValidatorStats) -> Self {
        let mut metrics = Self::new();
        metrics.total_blocks = stats.blocks_count;

        for block_idx in 0..stats.blocks_count {
            let (participated, valid_sig, invalid_or_missing) = stats.get_block_stats(block_idx);

            if participated {
                metrics.participated_blocks += 1;

                if valid_sig {
                    metrics.valid_signatures += 1;
                    metrics.score += 5; // +5 for valid signature
                } else if invalid_or_missing {
                    metrics.invalid_signatures += 1;
                    metrics.score -= 5; // -5 for invalid signature
                }
            } else {
                metrics.missed_blocks += 1;
                metrics.score -= 2; // -2 for missed block
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
        match self.score {
            s if s >= 20 => "Excellent",
            s if s >= 10 => "Good",
            s if s >= 0 => "Average",
            s if s >= -10 => "Poor",
            _ => "Critical",
        }
    }
}

// Block producer - generates blocks and broadcasts them
struct BlockProducer {
    tx: broadcast::Sender<Block>,
    block_interval: Duration,
    total_blocks: usize,
}

impl BlockProducer {
    fn new(total_blocks: usize, block_interval: Duration) -> (Self, broadcast::Receiver<Block>) {
        let (tx, rx) = broadcast::channel(100);

        (Self {
            tx,
            block_interval,
            total_blocks,
        }, rx)
    }

    // Start producing blocks
    async fn start_producing(self) {
        let mut interval = interval(self.block_interval);

        for block_idx in 0..self.total_blocks {
            interval.tick().await;

            // Create new block
            let block = Block {
                height: block_idx as u64,
                hash: {
                    let mut hash = [0u8; 32];
                    hash[0] = block_idx as u8;
                    let mut rng = rand::rng();
                    rng.fill_bytes(&mut hash);
                    hash
                },
                data: vec![block_idx as u8; 100],
            };

            println!("Block producer: Broadcasting block #{}", block.height);

            // Broadcast to all subscribers
            let _ = self.tx.send(block);
        }
        println!("Block producer: Finished producing {} blocks", self.total_blocks);
    }
}

// Validator
struct Validator {
    address: ValidatorAddress,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    // Statistics of other validators from this validator's perspective
    local_stats: Arc<RwLock<HashMap<ValidatorAddress, ValidatorStats>>>,
    blocks_to_track: usize,
    // Shared reference to all validators for querying
    validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
    // Channel to send stats to slasher
    stats_sender: Arc<Mutex<Option<tokio::sync::mpsc::Sender<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>>>>,
}

impl Validator {
    fn new(
        blocks_to_track: usize,
        validator_set: Arc<RwLock<HashMap<ValidatorAddress, Arc<Validator>>>>,
    ) -> Self {
        let mut rng = rand::rng();

        // Generate a random 32-byte secret key
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let mut address = HashBytes([0u8; 32]);
        address.0.copy_from_slice(verifying_key.as_bytes());

        Self {
            address,
            signing_key,
            verifying_key,
            local_stats: Arc::new(RwLock::new(HashMap::new())),
            blocks_to_track,
            validator_set,
            stats_sender: Arc::new(Mutex::new(None)),
        }
    }

    // Set the stats sender channel
    async fn set_stats_sender(&self, sender: tokio::sync::mpsc::Sender<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>) {
        *self.stats_sender.lock().await = Some(sender);
    }

    // Sign block
    async fn sign_block(&self, block: &Block) -> Signature {
        // Simulate async signing work
        sleep(Duration::from_millis(1)).await;
        let message = [&block.height.to_le_bytes()[..], &block.hash[..]].concat();
        self.signing_key.sign(&message)
    }

    // Request signature from another validator
    async fn request_signature(&self, validator: &Arc<Validator>, block: &Block) -> Option<BlockSignature> {
        // Simulate validator behavior based on its address
        let validator_behavior = (validator.address[0] as f32) / 255.0;

        // Signature probability depends on validator "quality"
        let sign_probability = if validator_behavior < 0.2 {
            0.5  // Poor validator
        } else if validator_behavior < 0.8 {
            0.9  // Normal validator
        } else {
            0.98 // Excellent validator
        };

        if rand::random::<f32>() < sign_probability {
            let signature = validator.sign_block(block).await;

            // Valid signature probability
            let valid_probability = if validator_behavior < 0.2 {
                0.7
            } else if validator_behavior < 0.8 {
                0.95
            } else {
                0.99
            };

            let is_valid = rand::random::<f32>() < valid_probability;

            Some(BlockSignature {
                validator: validator.address,
                signature: if is_valid { signature } else {
                    let mut sig_bytes = signature.to_bytes();
                    sig_bytes[0] ^= 0xFF;
                    Signature::from_bytes(&sig_bytes)
                },
                is_valid,
            })
        } else {
            None
        }
    }

    // Collect signatures for block in random order until 2/3 + 1
    async fn collect_signatures(&self, block: &Block) -> Vec<BlockSignature> {
        let registry = self.validator_set.read().await;
        let all_validators: Vec<_> = registry.values().cloned().collect();
        let threshold = (all_validators.len() * 2 / 3) + 1;

        let mut signatures = Vec::new();

        // Create random order for querying validators
        let mut validator_indices: Vec<usize> = (0..all_validators.len()).collect();
        use rand::seq::SliceRandom;
        validator_indices.shuffle(&mut rand::rng());

        println!("  Validator {:02x}{:02x}: Collecting signatures for block #{}",
                 self.address[0], self.address[1], block.height);

        // Query validators in random order
        for idx in validator_indices {
            if signatures.len() >= threshold {
                break;
            }

            let validator = &all_validators[idx];

            // Don't query ourselves
            if validator.address == self.address {
                // Self-sign
                let signature = self.sign_block(block).await;
                signatures.push(BlockSignature {
                    validator: self.address,
                    signature,
                    is_valid: true,
                });
            } else {
                // Request signature from other validator
                if let Some(sig) = self.request_signature(validator, block).await {
                    signatures.push(sig);
                }
            }
        }

        println!("  Validator {:02x}{:02x}: Collected {}/{} signatures",
                 self.address[0], self.address[1], signatures.len(), threshold);

        signatures
    }

    // Update local statistics based on collected signatures
    async fn update_local_stats(&self, block_idx: usize, signatures: &[BlockSignature]) {
        let mut stats = self.local_stats.write().await;
        let registry = self.validator_set.read().await;

        // Create map of addresses from which signatures were received
        let signature_map: HashMap<ValidatorAddress, &BlockSignature> =
            signatures.iter().map(|s| (s.validator, s)).collect();

        for validator_addr in registry.keys() {
            let validator_stats = stats.entry(*validator_addr)
                .or_insert_with(|| ValidatorStats::new(self.blocks_to_track));

            if let Some(sig) = signature_map.get(validator_addr) {
                // Received signature
                validator_stats.update_block_stats(
                    block_idx,
                    true,  // participated
                    sig.is_valid,  // signature valid
                    !sig.is_valid  // signature invalid
                );
            } else {
                // No signature received
                validator_stats.update_block_stats(
                    block_idx,
                    false, // didn't participate
                    false, // no valid signature
                    true   // no signature received
                );
            }
        }
    }

    // Send statistics to slasher
    async fn send_stats_to_slasher(&self, block_id: usize,) {
        let stats = self.local_stats.read().await.clone();

        if let Some(sender) = self.stats_sender.lock().await.as_ref() {
            let _ = sender.send((self.address, stats)).await;
            println!("  Validator {:02x}{:02x}: Sent statistics to slasher for block {block_id}",
                     self.address[0], self.address[1]);
        }
    }

    // Main validator loop - subscribe to blocks and process them
    async fn run(self: Arc<Self>, mut block_rx: broadcast::Receiver<Block>) {
        let mut block_count = 0;

        loop {
            match block_rx.recv().await {
                Ok(block) => {
                    let block_idx = block.height as usize;

                    // Collect signatures for this block
                    let signatures = self.collect_signatures(&block).await;

                    // Update local statistics
                    self.update_local_stats(block_idx, &signatures).await;

                    block_count += 1;

                    // Send stats to slasher periodically (every 5 blocks) or at the end
                    if block_count % 5 == 0 || block_idx == self.blocks_to_track - 1 {
                        self.send_stats_to_slasher(block_idx).await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    println!("  Validator {:02x}{:02x}: Lagged by {} blocks",
                             self.address[0], self.address[1], n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    println!("  Validator {:02x}{:02x}: Block producer finished",
                             self.address[0], self.address[1]);
                    break;
                }
            }
        }
        drop(self.stats_sender.lock().await.take());
    }
}

// Slasher - aggregates statistics from all validators
struct Slasher {
    validator_set: Vec<ValidatorAddress>,
    // Aggregated statistics
    aggregated_stats: Arc<Mutex<HashMap<ValidatorAddress, Vec<(ValidatorAddress, ValidatorStats)>>>>,
    blocks_to_track: usize,
    // Channel to receive stats from validators
    stats_receiver: tokio::sync::mpsc::Receiver<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>,
}

impl Slasher {
    fn new(
        validator_set: Vec<ValidatorAddress>,
        blocks_to_track: usize,
        stats_receiver: tokio::sync::mpsc::Receiver<(ValidatorAddress, HashMap<ValidatorAddress, ValidatorStats>)>,
    ) -> Self {
        Self {
            validator_set,
            aggregated_stats: Arc::new(Mutex::new(HashMap::new())),
            blocks_to_track,
            stats_receiver,
        }
    }

    // Process incoming statistics
    async fn receive_stats(&mut self, reporter: ValidatorAddress, stats: HashMap<ValidatorAddress, ValidatorStats>) {
        let mut aggregated = self.aggregated_stats.lock().await;

        for (validator_addr, validator_stats) in stats {
            aggregated.entry(validator_addr)
                .or_insert_with(Vec::new)
                .push((reporter, validator_stats));
        }
    }

    // Run slasher - listen for statistics
    async fn run(mut self) {
        println!("\nSlasher: Started listening for validator statistics...");

        while let Some((reporter, stats)) = self.stats_receiver.recv().await {
            println!("  Slasher: Received stats from validator {:02x}{:02x}",
                     reporter[0], reporter[1]);
            self.receive_stats(reporter, stats).await;
            println!("rrr");
        }

        println!("\nSlasher: All statistics received, generating report...");
        self.print_aggregated_stats().await;
    }

    // Aggregate statistics for validator
    async fn aggregate_validator_stats(&self, validator: ValidatorAddress) -> Option<ValidatorStats> {
        let aggregated = self.aggregated_stats.lock().await;
        let reports = aggregated.get(&validator)?;

        if reports.is_empty() {
            return None;
        }

        let mut final_stats = ValidatorStats::new(self.blocks_to_track);

        // Aggregate statistics for each block
        for block_idx in 0..self.blocks_to_track {
            let mut participated_votes = 0;
            let mut valid_sig_votes = 0;
            let mut invalid_sig_votes = 0;
            let total_reports = reports.len();

            for (_reporter, stats) in reports {
                let (participated, valid, invalid) = stats.get_block_stats(block_idx);
                if participated { participated_votes += 1; }
                if valid { valid_sig_votes += 1; }
                if invalid { invalid_sig_votes += 1; }
            }

            // Apply majority rule
            let participated = participated_votes > total_reports / 2;
            let sig_valid = valid_sig_votes > total_reports / 2;
            let sig_invalid = invalid_sig_votes > total_reports / 2;

            final_stats.update_block_stats(block_idx, participated, sig_valid, sig_invalid);
        }

        Some(final_stats)
    }

    // Calculate metrics for all validators
    async fn calculate_all_metrics(&self) -> Vec<(ValidatorAddress, ValidatorMetrics)> {
        let mut metrics_list = Vec::new();

        for validator in &self.validator_set {
            if let Some(stats) = self.aggregate_validator_stats(*validator).await {
                let metrics = ValidatorMetrics::calculate_from_stats(&stats);
                metrics_list.push((*validator, metrics));
            }
        }

        // Sort by score
        metrics_list.sort_by(|a, b| b.1.score.cmp(&a.1.score));
        metrics_list
    }

    // Print aggregated statistics
    async fn print_aggregated_stats(&self) {
        println!("\n╔════════════════════════════════════════════════════════════════════╗");
        println!("║                     SLASHER PERFORMANCE REPORT                     ║");
        println!("╚════════════════════════════════════════════════════════════════════╝");

        let metrics_list = self.calculate_all_metrics().await;

        println!("\n📊 VALIDATOR RANKINGS:");
        println!("┌──────────────┬───────┬──────────┬────────┬─────────┬─────────┬──────────────┐");
        println!("│  Validator   │ Score │ Rating   │ Part.% │ Valid % │ Invalid │   Missed     │");
        println!("├──────────────┼───────┼──────────┼────────┼─────────┼─────────┼──────────────┤");

        for (rank, (validator, metrics)) in metrics_list.iter().enumerate() {
            let validator_short = format!("{:02x}{:02x}...{:02x}{:02x}",
                                          validator[0], validator[1], validator[30], validator[31]);

            println!("│ #{:2} {}│  {:4} │ {:8} │ {:5.1}% │  {:5.1}% │   {:3}   │     {:3}      │",
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

        // Performance distribution statistics
        let excellent_count = metrics_list.iter().filter(|(_, m)| m.score >= 20).count();
        let good_count = metrics_list.iter().filter(|(_, m)| m.score >= 10 && m.score < 20).count();
        let average_count = metrics_list.iter().filter(|(_, m)| m.score >= 0 && m.score < 10).count();
        let poor_count = metrics_list.iter().filter(|(_, m)| m.score >= -10 && m.score < 0).count();
        let critical_count = metrics_list.iter().filter(|(_, m)| m.score < -10).count();

        println!("\n📈 PERFORMANCE DISTRIBUTION:");
        println!("┌────────────────────────────────────────────┐");
        println!("│ ⭐⭐⭐ Excellent (≥20):  {:2} validators      │", excellent_count);
        println!("│ ⭐⭐  Good (10-19):     {:2} validators      │", good_count);
        println!("│ ⭐   Average (0-9):    {:2} validators      │", average_count);
        println!("│ ⚠️   Poor (-10 to -1): {:2} validators      │", poor_count);
        println!("│ ❌   Critical (<-10):  {:2} validators      │", critical_count);
        println!("└────────────────────────────────────────────┘");

        // Network health statistics
        let total_score: i32 = metrics_list.iter().map(|(_, m)| m.score).sum();
        let avg_score = if !metrics_list.is_empty() {
            total_score as f32 / metrics_list.len() as f32
        } else {
            0.0
        };

        let total_participation: f32 = if !metrics_list.is_empty() {
            metrics_list.iter()
                .map(|(_, m)| m.get_participation_rate())
                .sum::<f32>() / metrics_list.len() as f32
        } else {
            0.0
        };

        println!("\n🌐 NETWORK HEALTH:");
        println!("┌────────────────────────────────────────────┐");
        println!("│ Average Score:         {:6.1}              │", avg_score);
        println!("│ Network Participation: {:6.1}%             │", total_participation);
        println!("│ Network Status:        {}          │",
                 if avg_score >= 15.0 { "✅ Healthy    " }
                 else if avg_score >= 5.0 { "⚠️  Degraded   " }
                 else { "❌ Critical   " }
        );
        println!("└────────────────────────────────────────────┘");
    }
}


async fn simulate_slashing_system() {
    println!("🚀 Starting blockchain slashing simulation...\n");

    const NUM_VALIDATORS: usize = 15;
    const NUM_BLOCKS: usize = 10;
    const BLOCK_INTERVAL_MS: u64 = 500; // 500ms between blocks

    println!("SYSTEM CONFIGURATION:");
    println!("  • Total validators: {}", NUM_VALIDATORS);
    println!("  • Blocks to process: {}", NUM_BLOCKS);
    println!("  • Block interval: {}ms", BLOCK_INTERVAL_MS);

    // Create validator set
    let validator_set = Arc::new(RwLock::new(HashMap::new()));

    // Create channel for stats collection
    let (stats_tx, stats_rx) = tokio::sync::mpsc::channel(100);

    // Create validators
    let mut validators = Vec::new();
    let mut validator_addresses = Vec::new();

    for _ in 0..NUM_VALIDATORS {
        let validator = Arc::new(Validator::new(NUM_BLOCKS, Arc::clone(&validator_set)));
        validator.set_stats_sender(stats_tx.clone()).await;
        validator_addresses.push(validator.address);
        validators.push(validator);
    }
    // Close stats channel
    drop(stats_tx);

    // Register all validators
    {
        let mut registry = validator_set.write().await;
        for validator in &validators {
            registry.insert(validator.address, Arc::clone(validator));
        }
    }

    // Print validator quality distribution
    let mut poor_count = 0;
    let mut normal_count = 0;
    let mut excellent_count = 0;

    for validator in &validators {
        let behavior = (validator.address[0] as f32) / 255.0;
        if behavior < 0.2 {
            poor_count += 1;
        } else if behavior < 0.8 {
            normal_count += 1;
        } else {
            excellent_count += 1;
        }
    }

    println!("\nVALIDATOR DISTRIBUTION:");
    println!("  • Poor performers: {}", poor_count);
    println!("  • Normal performers: {}", normal_count);
    println!("  • Excellent performers: {}", excellent_count);

    // Create block producer
    let (producer, _) = BlockProducer::new(
        NUM_BLOCKS,
        Duration::from_millis(BLOCK_INTERVAL_MS)
    );

    // Create slasher
    let slasher = Slasher::new(validator_addresses, NUM_BLOCKS, stats_rx);


    println!("\n⚙️  STARTING SYSTEM COMPONENTS...\n");

    // Start validator tasks
    let mut validator_handles = Vec::new();
    for validator in validators {
        let rx = producer.tx.subscribe();
        let handle = tokio::spawn(validator.run(rx));
        validator_handles.push(handle);
    }

    // Start slasher task
    let slasher_handle = tokio::spawn(slasher.run());

    // Start block producer
    let producer_handle = tokio::spawn(producer.start_producing());

    // Wait for producer to finish
    let _ = producer_handle.await;

    // Wait a bit for validators to send final stats
    sleep(Duration::from_secs(3)).await;


    // Wait for slasher to finish
    let _ = slasher_handle.await;

    println!("\nSCORING SYSTEM:");
    println!("  • Valid signature: +5 points");
    println!("  • Invalid signature: -5 points");

    println!("\nSimulation completed!");
}

#[tokio::main]
async fn main() {
    simulate_slashing_system().await;
}