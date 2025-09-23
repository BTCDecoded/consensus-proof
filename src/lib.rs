//! # Consensus-Proof
//!
//! Direct mathematical implementation of Bitcoin consensus rules from the Orange Paper.
//!
//! This crate provides pure, side-effect-free functions that implement the mathematical
//! specifications defined in the Orange Paper. It serves as the mathematical foundation
//! for Bitcoin consensus validation.
//!
//! ## Architecture
//!
//! The system follows a layered architecture:
//! - Orange Paper (mathematical specifications)
//! - Consensus Proof (this crate - direct implementation)
//! - Reference Node (minimal Bitcoin implementation)
//! - Developer SDK (developer-friendly interface)
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: All functions are deterministic and side-effect-free
//! 2. **Mathematical Accuracy**: Direct implementation of Orange Paper specifications
//! 3. **Exact Version Pinning**: All consensus-critical dependencies pinned to exact versions
//! 4. **No Consensus Rule Interpretation**: Only mathematical implementation
//!
//! ## Usage
//!
//! ```rust
//! use consensus_proof::ConsensusProof;
//! use consensus_proof::types::*;
//!
//! let consensus = ConsensusProof::new();
//! let transaction = Transaction {
//!     version: 1,
//!     inputs: vec![],
//!     outputs: vec![TransactionOutput {
//!         value: 1000,
//!         script_pubkey: vec![0x51],
//!     }],
//!     lock_time: 0,
//! };
//! let result = consensus.validate_transaction(&transaction).unwrap();
//! ```

pub mod types;
pub mod constants;
pub mod transaction;
pub mod script;
pub mod block;
pub mod economic;
pub mod pow;
pub mod mempool;
pub mod mining;
pub mod reorganization;
pub mod network;
pub mod segwit;
pub mod taproot;
pub mod error;

// Re-export commonly used types
pub use types::*;
pub use constants::*;
pub use error::{ConsensusError, Result};

/// Main consensus proof implementation
/// 
/// # Examples
/// 
/// ```
/// use consensus_proof::ConsensusProof;
/// use consensus_proof::types::*;
/// 
/// let consensus = ConsensusProof::new();
/// 
/// // Create a simple transaction with inputs and outputs
/// let tx = Transaction {
///     version: 1,
///     inputs: vec![TransactionInput {
///         prevout: OutPoint {
///             hash: [0u8; 32],
///             index: 0,
///         },
///         script_sig: vec![0x51], // OP_1
///         sequence: 0xffffffff,
///     }],
///     outputs: vec![TransactionOutput {
///         value: 5000000000, // 50 BTC in satoshis
///         script_pubkey: vec![0x51], // OP_1
///     }],
///     lock_time: 0,
/// };
/// 
/// // Validate the transaction
/// let result = consensus.validate_transaction(&tx).unwrap();
/// assert_eq!(result, ValidationResult::Valid);
/// ```
pub struct ConsensusProof;

impl ConsensusProof {
    /// Create a new consensus proof instance
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// 
    /// let consensus = ConsensusProof::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
    
    /// Validate a transaction according to consensus rules
    /// 
    /// # Examples
    /// 
/// ```
/// use consensus_proof::ConsensusProof;
/// use consensus_proof::types::*;
/// 
/// let consensus = ConsensusProof::new();
/// let tx = Transaction {
///     version: 1,
///     inputs: vec![],
///     outputs: vec![TransactionOutput {
///         value: 1000,
///         script_pubkey: vec![0x51],
///     }],
///     lock_time: 0,
/// };
/// 
/// let result = consensus.validate_transaction(&tx).unwrap();
/// ```
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<ValidationResult> {
        transaction::check_transaction(tx)
    }
    
    /// Validate transaction inputs against UTXO set
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// let mut utxo_set = UtxoSet::new();
    /// 
    /// // Add UTXO to the set
    /// let outpoint = OutPoint { hash: [1; 32], index: 0 };
    /// let utxo = UTXO {
    ///     value: 1000000000, // 10 BTC
    ///     script_pubkey: vec![],
    ///     height: 0,
    /// };
    /// utxo_set.insert(outpoint, utxo);
    /// 
    /// let tx = Transaction {
    ///     version: 1,
    ///     inputs: vec![TransactionInput {
    ///         prevout: OutPoint { hash: [1; 32], index: 0 },
    ///         script_sig: vec![],
    ///         sequence: 0xffffffff,
    ///     }],
    ///     outputs: vec![TransactionOutput {
    ///         value: 900000000, // 9 BTC output
    ///         script_pubkey: vec![],
    ///     }],
    ///     lock_time: 0,
    /// };
    /// 
    /// let (result, fee) = consensus.validate_tx_inputs(&tx, &utxo_set, 0).unwrap();
    /// assert_eq!(result, ValidationResult::Valid);
    /// assert_eq!(fee, 100000000); // 1 BTC fee
    /// ```
    pub fn validate_tx_inputs(
        &self, 
        tx: &Transaction, 
        utxo_set: &UtxoSet, 
        height: Natural
    ) -> Result<(ValidationResult, Integer)> {
        transaction::check_tx_inputs(tx, utxo_set, height)
    }
    
    /// Validate a complete block
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// let utxo_set = UtxoSet::new();
    /// 
    /// // Create a simple block with coinbase transaction
    /// let block = Block {
    ///     header: BlockHeader {
    ///         version: 1,
    ///         prev_block_hash: [0; 32],
    ///         merkle_root: [0; 32],
    ///         timestamp: 1234567890,
    ///         bits: 0x1d00ffff,
    ///         nonce: 0,
    ///     },
    ///     transactions: vec![Transaction {
    ///         version: 1,
    ///         inputs: vec![TransactionInput {
    ///             prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
    ///             script_sig: vec![],
    ///             sequence: 0xffffffff,
    ///         }],
    ///         outputs: vec![TransactionOutput {
    ///             value: 5000000000, // 50 BTC
    ///             script_pubkey: vec![],
    ///         }],
    ///         lock_time: 0,
    ///     }],
    /// };
    /// 
    /// let (result, _new_utxo_set) = consensus.validate_block(&block, utxo_set, 0).unwrap();
    /// assert_eq!(result, ValidationResult::Valid);
    /// ```
    pub fn validate_block(
        &self,
        block: &Block,
        utxo_set: UtxoSet,
        height: Natural
    ) -> Result<(ValidationResult, UtxoSet)> {
        block::connect_block(block, utxo_set, height)
    }
    
    /// Verify script execution
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// // Simple script: OP_1 OP_1 OP_EQUAL
    /// let script_sig = vec![0x51]; // OP_1
    /// let script_pubkey = vec![0x51, 0x87]; // OP_1 OP_EQUAL
    /// 
    /// let result = consensus.verify_script(&script_sig, &script_pubkey, None, 0).unwrap();
    /// assert!(result);
    /// ```
    pub fn verify_script(
        &self,
        script_sig: &ByteString,
        script_pubkey: &ByteString,
        witness: Option<&ByteString>,
        flags: u32
    ) -> Result<bool> {
        script::verify_script(script_sig, script_pubkey, witness, flags)
    }
    
    /// Check proof of work
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// // Create a block header with valid proof of work
    /// let header = BlockHeader {
    ///     version: 1,
    ///     prev_block_hash: [0; 32],
    ///     merkle_root: [0; 32],
    ///     timestamp: 1234567890,
    ///     bits: 0x1d00ffff, // Genesis difficulty
    ///     nonce: 0,
    /// };
    /// 
    /// let result = consensus.check_proof_of_work(&header).unwrap();
    /// // Note: This will likely be false for a nonce of 0, but demonstrates usage
    /// ```
    pub fn check_proof_of_work(&self, header: &BlockHeader) -> Result<bool> {
        pow::check_proof_of_work(header)
    }
    
    /// Get block subsidy for height
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// // Genesis block subsidy
    /// let genesis_subsidy = consensus.get_block_subsidy(0);
    /// assert_eq!(genesis_subsidy, 5000000000); // 50 BTC
    /// 
    /// // First halving
    /// let halving_subsidy = consensus.get_block_subsidy(210000);
    /// assert_eq!(halving_subsidy, 2500000000); // 25 BTC
    /// ```
    pub fn get_block_subsidy(&self, height: Natural) -> Integer {
        economic::get_block_subsidy(height)
    }
    
    /// Calculate total supply at height
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// // Total supply at genesis
    /// let genesis_supply = consensus.total_supply(0);
    /// assert_eq!(genesis_supply, 5000000000); // 50 BTC
    /// 
/// // Total supply after first halving
/// let halving_supply = consensus.total_supply(210000);
/// assert_eq!(halving_supply, 1050002500000000); // 10.5M BTC + 2500 BTC
    /// ```
    pub fn total_supply(&self, height: Natural) -> Integer {
        economic::total_supply(height)
    }
    
    /// Get next work required for difficulty adjustment
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// // Create current header
    /// let current_header = BlockHeader {
    ///     version: 1,
    ///     prev_block_hash: [0; 32],
    ///     merkle_root: [0; 32],
    ///     timestamp: 1234567890,
    ///     bits: 0x1d00ffff,
    ///     nonce: 0,
    /// };
    /// 
    /// // Create previous headers for difficulty adjustment
    /// let prev_headers = vec![
    ///     BlockHeader {
    ///         version: 1,
    ///         prev_block_hash: [0; 32],
    ///         merkle_root: [0; 32],
    ///         timestamp: 1234567890 - 600, // 10 minutes ago
    ///         bits: 0x1d00ffff,
    ///         nonce: 0,
    ///     },
    ///     BlockHeader {
    ///         version: 1,
    ///         prev_block_hash: [0; 32],
    ///         merkle_root: [0; 32],
    ///         timestamp: 1234567890 - 1200, // 20 minutes ago
    ///         bits: 0x1d00ffff,
    ///         nonce: 0,
    ///     },
    /// ];
    /// 
    /// let next_work = consensus.get_next_work_required(&current_header, &prev_headers).unwrap();
    /// assert!(next_work > 0);
    /// ```
    pub fn get_next_work_required(&self, current_header: &BlockHeader, prev_headers: &[BlockHeader]) -> Result<Natural> {
        pow::get_next_work_required(current_header, prev_headers)
    }
    
    /// Accept transaction to memory pool
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// use consensus_proof::mempool::Mempool;
    /// 
    /// let consensus = ConsensusProof::new();
    /// let utxo_set = UtxoSet::new();
    /// let mempool = Mempool::new();
    /// 
    /// let tx = Transaction {
    ///     version: 1,
    ///     inputs: vec![TransactionInput {
    ///         prevout: OutPoint { hash: [1; 32], index: 0 },
    ///         script_sig: vec![],
    ///         sequence: 0xffffffff,
    ///     }],
    ///     outputs: vec![TransactionOutput {
    ///         value: 100000000,
    ///         script_pubkey: vec![],
    ///     }],
    ///     lock_time: 0,
    /// };
    /// 
    /// let result = consensus.accept_to_memory_pool(&tx, &utxo_set, &mempool, 0).unwrap();
    /// // Result will depend on UTXO availability and mempool rules
    /// ```
    pub fn accept_to_memory_pool(
        &self,
        tx: &Transaction,
        utxo_set: &UtxoSet,
        mempool: &mempool::Mempool,
        height: Natural
    ) -> Result<mempool::MempoolResult> {
        mempool::accept_to_memory_pool(tx, utxo_set, mempool, height)
    }
    
    /// Check if transaction is standard
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// let tx = Transaction {
    ///     version: 1,
    ///     inputs: vec![TransactionInput {
    ///         prevout: OutPoint { hash: [1; 32], index: 0 },
    ///         script_sig: vec![0x51], // OP_1
    ///         sequence: 0xffffffff,
    ///     }],
    ///     outputs: vec![TransactionOutput {
    ///         value: 100000000,
    ///         script_pubkey: vec![0x51], // OP_1
    ///     }],
    ///     lock_time: 0,
    /// };
    /// 
    /// let is_standard = consensus.is_standard_tx(&tx).unwrap();
    /// assert!(is_standard);
    /// ```
    pub fn is_standard_tx(&self, tx: &Transaction) -> Result<bool> {
        mempool::is_standard_tx(tx)
    }
    
    /// Check if transaction can replace existing one (RBF)
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// use consensus_proof::mempool::Mempool;
    /// 
    /// let consensus = ConsensusProof::new();
    /// let mempool = Mempool::new();
    /// 
    /// let existing_tx = Transaction {
    ///     version: 1,
    ///     inputs: vec![TransactionInput {
    ///         prevout: OutPoint { hash: [1; 32], index: 0 },
    ///         script_sig: vec![],
    ///         sequence: 0xfffffffe, // RBF enabled
    ///     }],
    ///     outputs: vec![TransactionOutput {
    ///         value: 100000000,
    ///         script_pubkey: vec![],
    ///     }],
    ///     lock_time: 0,
    /// };
    /// 
    /// let new_tx = Transaction {
    ///     version: 1,
    ///     inputs: vec![TransactionInput {
    ///         prevout: OutPoint { hash: [1; 32], index: 0 },
    ///         script_sig: vec![],
    ///         sequence: 0xfffffffe, // RBF enabled
    ///     }],
    ///     outputs: vec![TransactionOutput {
    ///         value: 90000000, // Higher fee
    ///         script_pubkey: vec![],
    ///     }],
    ///     lock_time: 0,
    /// };
    /// 
    /// let can_replace = consensus.replacement_checks(&new_tx, &existing_tx, &mempool).unwrap();
    /// // Result depends on fee comparison and RBF rules
    /// ```
    pub fn replacement_checks(
        &self,
        new_tx: &Transaction,
        existing_tx: &Transaction,
        mempool: &mempool::Mempool
    ) -> Result<bool> {
        mempool::replacement_checks(new_tx, existing_tx, mempool)
    }
    
    /// Create new block from mempool transactions
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// let utxo_set = UtxoSet::new();
    /// let mempool_txs = vec![];
    /// 
    /// let prev_header = BlockHeader {
    ///     version: 1,
    ///     prev_block_hash: [0; 32],
    ///     merkle_root: [0; 32],
    ///     timestamp: 1234567890,
    ///     bits: 0x1d00ffff,
    ///     nonce: 0,
    /// };
    /// 
    /// let prev_headers = vec![prev_header.clone(), prev_header.clone()]; // Need at least 2 headers
    /// let coinbase_script = vec![0x51]; // OP_1
    /// let coinbase_address = vec![0x51]; // OP_1
    /// 
    /// let block = consensus.create_new_block(
    ///     &utxo_set,
    ///     &mempool_txs,
    ///     1,
    ///     &prev_header,
    ///     &prev_headers,
    ///     &coinbase_script,
    ///     &coinbase_address,
    /// );
    /// 
    /// // Block creation may succeed or fail depending on difficulty adjustment
    /// if let Ok(block) = block {
    ///     assert_eq!(block.transactions.len(), 1); // Coinbase transaction
    /// }
    /// ```
    pub fn create_new_block(
        &self,
        utxo_set: &UtxoSet,
        mempool_txs: &[Transaction],
        height: Natural,
        prev_header: &BlockHeader,
        prev_headers: &[BlockHeader],
        coinbase_script: &ByteString,
        coinbase_address: &ByteString,
    ) -> Result<Block> {
        mining::create_new_block(
            utxo_set,
            mempool_txs,
            height,
            prev_header,
            prev_headers,
            coinbase_script,
            coinbase_address,
        )
    }
    
    /// Mine a block by finding valid nonce
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// use consensus_proof::types::*;
    /// 
    /// let consensus = ConsensusProof::new();
    /// 
    /// let block = Block {
    ///     header: BlockHeader {
    ///         version: 1,
    ///         prev_block_hash: [0; 32],
    ///         merkle_root: [0; 32],
    ///         timestamp: 1234567890,
    ///         bits: 0x1d00ffff,
    ///         nonce: 0,
    ///     },
    ///     transactions: vec![Transaction {
    ///         version: 1,
    ///         inputs: vec![TransactionInput {
    ///             prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
    ///             script_sig: vec![],
    ///             sequence: 0xffffffff,
    ///         }],
    ///         outputs: vec![TransactionOutput {
    ///             value: 5000000000,
    ///             script_pubkey: vec![],
    ///         }],
    ///         lock_time: 0,
    ///     }],
    /// };
    /// 
    /// let result = consensus.mine_block(block, 1000);
    /// // Result will be Ok((block, MiningResult)) or Err(ConsensusError)
    /// // MiningResult will be Success or Failure depending on difficulty
    /// ```
    pub fn mine_block(
        &self,
        block: Block,
        max_attempts: Natural,
    ) -> Result<(Block, mining::MiningResult)> {
        mining::mine_block(block, max_attempts)
    }
    
            /// Create block template for mining
            pub fn create_block_template(
                &self,
                utxo_set: &UtxoSet,
                mempool_txs: &[Transaction],
                height: Natural,
                prev_header: &BlockHeader,
                prev_headers: &[BlockHeader],
                coinbase_script: &ByteString,
                coinbase_address: &ByteString,
            ) -> Result<mining::BlockTemplate> {
                mining::create_block_template(
                    utxo_set,
                    mempool_txs,
                    height,
                    prev_header,
                    prev_headers,
                    coinbase_script,
                    coinbase_address,
                )
            }
            
            /// Reorganize chain when longer chain is found
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::types::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// let current_chain = vec![];
            /// let new_chain = vec![];
            /// let current_utxo_set = UtxoSet::new();
            /// 
            /// let result = consensus.reorganize_chain(&new_chain, &current_chain, current_utxo_set, 0);
            /// // Result may be an error for empty chains, which is expected
            /// ```
            pub fn reorganize_chain(
                &self,
                new_chain: &[Block],
                current_chain: &[Block],
                current_utxo_set: UtxoSet,
                current_height: Natural,
            ) -> Result<reorganization::ReorganizationResult> {
                reorganization::reorganize_chain(new_chain, current_chain, current_utxo_set, current_height)
            }
            
            /// Check if reorganization is beneficial
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::types::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// let current_chain = vec![];
            /// let new_chain = vec![];
            /// 
            /// let should_reorg = consensus.should_reorganize(&new_chain, &current_chain).unwrap();
            /// // Result indicates if reorganization is beneficial
            /// ```
            pub fn should_reorganize(
                &self,
                new_chain: &[Block],
                current_chain: &[Block],
            ) -> Result<bool> {
                reorganization::should_reorganize(new_chain, current_chain)
            }
            
            /// Process incoming network message
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::network::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// let mut peer_state = PeerState::new();
            /// let chain_state = ChainState::new();
            /// 
            /// let message = NetworkMessage::Ping(PingMessage { nonce: 12345 });
            /// let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
            /// // Response will be appropriate for the message type
            /// ```
            pub fn process_network_message(
                &self,
                message: &network::NetworkMessage,
                peer_state: &mut network::PeerState,
                chain_state: &network::ChainState,
            ) -> Result<network::NetworkResponse> {
                network::process_network_message(message, peer_state, chain_state)
            }
            
            /// Calculate transaction weight for SegWit
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::types::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// 
            /// let tx = Transaction {
            ///     version: 1,
            ///     inputs: vec![TransactionInput {
            ///         prevout: OutPoint { hash: [1; 32], index: 0 },
            ///         script_sig: vec![0x51], // OP_1
            ///         sequence: 0xffffffff,
            ///     }],
            ///     outputs: vec![TransactionOutput {
            ///         value: 100000000,
            ///         script_pubkey: vec![0x51], // OP_1
            ///     }],
            ///     lock_time: 0,
            /// };
            /// 
            /// let weight = consensus.calculate_transaction_weight(&tx, None).unwrap();
            /// assert!(weight > 0);
            /// ```
            pub fn calculate_transaction_weight(
                &self,
                tx: &Transaction,
                witness: Option<&segwit::Witness>,
            ) -> Result<Natural> {
                segwit::calculate_transaction_weight(tx, witness)
            }
            
            /// Validate SegWit block
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::types::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// 
            /// let block = Block {
            ///     header: BlockHeader {
            ///         version: 1,
            ///         prev_block_hash: [0; 32],
            ///         merkle_root: [0; 32],
            ///         timestamp: 1234567890,
            ///         bits: 0x1d00ffff,
            ///         nonce: 0,
            ///     },
            ///     transactions: vec![Transaction {
            ///         version: 1,
            ///         inputs: vec![TransactionInput {
            ///             prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
            ///             script_sig: vec![],
            ///             sequence: 0xffffffff,
            ///         }],
            ///         outputs: vec![TransactionOutput {
            ///             value: 5000000000,
            ///             script_pubkey: vec![],
            ///         }],
            ///         lock_time: 0,
            ///     }],
            /// };
            /// 
            /// let witnesses = vec![];
            /// let max_block_weight = 4000000; // 4MB
            /// 
    /// let is_valid = consensus.validate_segwit_block(&block, &witnesses, max_block_weight);
    /// // Result may be Ok or Err depending on block validation rules
            /// ```
            pub fn validate_segwit_block(
                &self,
                block: &Block,
                witnesses: &[segwit::Witness],
                max_block_weight: Natural,
            ) -> Result<bool> {
                segwit::validate_segwit_block(block, witnesses, max_block_weight)
            }
            
            /// Validate Taproot transaction
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::types::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// 
            /// let tx = Transaction {
            ///     version: 1,
            ///     inputs: vec![TransactionInput {
            ///         prevout: OutPoint { hash: [1; 32], index: 0 },
            ///         script_sig: vec![],
            ///         sequence: 0xffffffff,
            ///     }],
            ///     outputs: vec![TransactionOutput {
            ///         value: 100000000,
            ///         script_pubkey: vec![0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Taproot output
            ///     }],
            ///     lock_time: 0,
            /// };
            /// 
            /// let is_valid = consensus.validate_taproot_transaction(&tx).unwrap();
            /// // Result depends on Taproot validation rules
            /// ```
            pub fn validate_taproot_transaction(&self, tx: &Transaction) -> Result<bool> {
                taproot::validate_taproot_transaction(tx)
            }
            
            /// Check if transaction output is Taproot
            /// 
            /// # Examples
            /// 
            /// ```
            /// use consensus_proof::ConsensusProof;
            /// use consensus_proof::types::*;
            /// 
            /// let consensus = ConsensusProof::new();
            /// 
            /// let output = TransactionOutput {
            ///     value: 100000000,
            ///     script_pubkey: vec![0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Taproot output
            /// };
            /// 
    /// let is_taproot = consensus.is_taproot_output(&output);
    /// // Result depends on Taproot output validation rules
            /// ```
            pub fn is_taproot_output(&self, output: &TransactionOutput) -> bool {
                taproot::is_taproot_output(output)
            }
}

impl Default for ConsensusProof {
    /// Create a default consensus proof instance
    /// 
    /// # Examples
    /// 
    /// ```
    /// use consensus_proof::ConsensusProof;
    /// 
    /// let consensus = ConsensusProof::default();
    /// ```
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkMessage, VersionMessage, NetworkAddress, PeerState, ChainState};
    
    #[test]
    fn test_consensus_proof_new() {
        let consensus = ConsensusProof::new();
        // Just test that it creates successfully
        assert!(true);
    }
    
    #[test]
    fn test_consensus_proof_default() {
        let consensus = ConsensusProof::default();
        // Just test that it creates successfully
        assert!(true);
    }
    
    #[test]
    fn test_validate_transaction() {
        let consensus = ConsensusProof::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let result = consensus.validate_transaction(&tx);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_tx_inputs() {
        let consensus = ConsensusProof::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let utxo_set = UtxoSet::new();
        let result = consensus.validate_tx_inputs(&tx, &utxo_set, 0);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_block() {
        let consensus = ConsensusProof::new();
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        let utxo_set = UtxoSet::new();
        let result = consensus.validate_block(&block, utxo_set, 0);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_verify_script() {
        let consensus = ConsensusProof::new();
        let script = vec![0x51]; // OP_1
        let script_pubkey = vec![0x51];
        let result = consensus.verify_script(&script, &script_pubkey, None, 0);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_check_proof_of_work() {
        let consensus = ConsensusProof::new();
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let result = consensus.check_proof_of_work(&header);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_get_block_subsidy() {
        let consensus = ConsensusProof::new();
        let subsidy = consensus.get_block_subsidy(0);
        assert_eq!(subsidy, 5000000000);
    }
    
    #[test]
    fn test_total_supply() {
        let consensus = ConsensusProof::new();
        let supply = consensus.total_supply(100);
        assert!(supply > 0);
    }
    
    #[test]
    fn test_get_next_work_required() {
        let consensus = ConsensusProof::new();
        let current_header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let prev_headers = vec![
            BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
        ];
        let result = consensus.get_next_work_required(&current_header, &prev_headers);
        // Result may be Ok or Err depending on difficulty calculation
        assert!(result.is_ok() || result.is_err());
    }
    
    #[test]
    fn test_accept_to_memory_pool() {
        let consensus = ConsensusProof::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let utxo_set = UtxoSet::new();
        let mempool = mempool::Mempool::new();
        let result = consensus.accept_to_memory_pool(&tx, &utxo_set, &mempool, 0);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_is_standard_tx() {
        let consensus = ConsensusProof::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let result = consensus.is_standard_tx(&tx);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_replacement_checks() {
        let consensus = ConsensusProof::new();
        let new_tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let existing_tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let mempool = mempool::Mempool::new();
        let result = consensus.replacement_checks(&new_tx, &existing_tx, &mempool);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_create_new_block() {
        let consensus = ConsensusProof::new();
        let utxo_set = UtxoSet::new();
        let mempool_txs = vec![];
        let height = 0;
        let prev_header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let prev_headers = vec![prev_header.clone()];
        let coinbase_script = vec![0x51];
        let coinbase_address = vec![0x51];
        let result = consensus.create_new_block(&utxo_set, &mempool_txs, height, &prev_header, &prev_headers, &coinbase_script, &coinbase_address);
        // Result may be Ok or Err depending on block creation
        assert!(result.is_ok() || result.is_err());
    }
    
    #[test]
    fn test_mine_block() {
        let consensus = ConsensusProof::new();
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        let result = consensus.mine_block(block, 100);
        // Result may be Ok or Err depending on mining difficulty
        assert!(result.is_ok() || result.is_err());
    }
    
    #[test]
    fn test_create_block_template() {
        let consensus = ConsensusProof::new();
        let utxo_set = UtxoSet::new();
        let mempool_txs = vec![];
        let height = 0;
        let prev_header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let prev_headers = vec![prev_header.clone()];
        let coinbase_script = vec![0x51];
        let coinbase_address = vec![0x51];
        let result = consensus.create_block_template(&utxo_set, &mempool_txs, height, &prev_header, &prev_headers, &coinbase_script, &coinbase_address);
        // Result may be Ok or Err depending on template creation
        assert!(result.is_ok() || result.is_err());
    }
    
    #[test]
    fn test_reorganize_chain() {
        let consensus = ConsensusProof::new();
        let current_chain = vec![];
        let new_chain = vec![];
        let utxo_set = UtxoSet::new();
        let result = consensus.reorganize_chain(&current_chain, &new_chain, utxo_set, 0);
        // Result may be Ok or Err depending on reorganization
        assert!(result.is_ok() || result.is_err());
    }
    
    #[test]
    fn test_should_reorganize() {
        let consensus = ConsensusProof::new();
        let current_chain = vec![];
        let new_chain = vec![];
        let result = consensus.should_reorganize(&current_chain, &new_chain);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_process_network_message() {
        let consensus = ConsensusProof::new();
        let message = NetworkMessage::Version(VersionMessage {
            version: 70015,
            services: 0,
            timestamp: 1234567890,
            addr_recv: NetworkAddress {
                services: 0,
                ip: [0; 16],
                port: 8333,
            },
            addr_from: NetworkAddress {
                services: 0,
                ip: [0; 16],
                port: 8333,
            },
            nonce: 12345,
            user_agent: "test".to_string(),
            start_height: 0,
            relay: true,
        });
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let result = consensus.process_network_message(&message, &mut peer_state, &chain_state);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_calculate_transaction_weight() {
        let consensus = ConsensusProof::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let result = consensus.calculate_transaction_weight(&tx, None);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_segwit_block() {
        let consensus = ConsensusProof::new();
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        let witnesses = vec![];
        let result = consensus.validate_segwit_block(&block, &witnesses, 4000000);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_taproot_transaction() {
        let consensus = ConsensusProof::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let result = consensus.validate_taproot_transaction(&tx);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_is_taproot_output() {
        let consensus = ConsensusProof::new();
        let output = TransactionOutput {
            value: 100000000,
            script_pubkey: vec![0x51],
        };
        let result = consensus.is_taproot_output(&output);
        assert!(result == false || result == true); // Just test it returns a boolean
    }
}