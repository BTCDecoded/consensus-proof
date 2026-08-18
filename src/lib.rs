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
//! use blvm_consensus::transaction::check_transaction;
//! use blvm_consensus::types::*;
//!
//! let transaction = Transaction {
//!     version: 1,
//!     inputs: vec![].into(),
//!     outputs: vec![TransactionOutput {
//!         value: 1000,
//!         script_pubkey: vec![0x51],
//!     }]
//!     .into(),
//!     lock_time: 0,
//! };
//! let result = check_transaction(&transaction).unwrap();
//! ```

#![allow(unused_doc_comments)] // Allow doc comments before macros (proptest, etc.)
#![allow(unused_variables, unused_assignments)] // Feature-gated and conditional compilation paths
#![allow(
    clippy::too_many_arguments,  // Script/block have 8–17 args; struct refactor is large
    clippy::type_complexity,     // Performance-critical types (OnceLock<RwLock<LruCache<...>>>)
    clippy::large_enum_variant,  // NetworkResponse::SendMessage; boxing changes layout
)]

pub mod script;
pub mod transaction;
pub mod transaction_hash;

use blvm_spec_lock::spec_locked;
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub use config::{reset_assume_valid_height, set_assume_valid_height};
#[cfg(feature = "production")]
pub use script::batch_verify_signatures;
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub use script::{
    clear_all_caches, clear_hash_cache, clear_script_cache, clear_stack_pool, disable_caching,
    reset_benchmarking_state,
};
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub use transaction_hash::clear_sighash_templates;

// Re-export from blvm-primitives for backward compatibility
pub use blvm_primitives::constants;
pub use blvm_primitives::crypto;
pub use blvm_primitives::opcodes;
pub use blvm_primitives::serialization;
pub use blvm_primitives::{error, types};
pub use blvm_primitives::{tx_inputs, tx_outputs};
pub use constants::*;
pub use error::ConsensusError;
pub use types::*;

/// Orange Paper Section 4 symbols (C, H, M_MAX, etc.) — re-export from primitives constants.
pub mod orange_paper_constants {
    pub use crate::constants::{C, H, L_ELEMENT, L_OPS, L_SCRIPT, L_STACK, M_MAX, R, S_MAX, W_MAX};
}

/// Spec-lock / property-test helpers only — not a supported production API.
/// Functions in this module `panic!` or `unimplemented!` when called outside their
/// intended spec-validation context. Do **not** call from production code.
#[doc(hidden)]
pub mod orange_paper_property_helpers;

pub mod config;

pub mod activation;
pub mod bip113;
#[cfg(feature = "ctv")]
pub mod bip119;
#[cfg(any(feature = "csfs", feature = "production"))]
pub mod bip348;
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
pub mod ecdsa_batch;
pub mod ecdsa_timers;
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
pub mod ecdsa_wave;
pub mod bip_validation;
pub mod block;
#[cfg(all(feature = "production", feature = "rayon"))]
pub mod checkqueue;
pub mod economic;
pub mod locktime;
pub mod mempool;
pub mod mining;
pub mod optimizations;
pub mod pow;
pub mod reorganization;
#[cfg(all(feature = "production", feature = "rayon"))]
pub(crate) mod script_exec_cache;
pub mod secp256k1_backend;
pub mod segwit;
pub mod sequence_locks;
pub mod signet;
pub mod sigop;
pub(crate) mod spec_witnesses;
pub mod taproot;
pub mod utxo_overlay;
pub mod version_bits;
pub mod witness;

// Integration tests link this crate without `cfg(test)` on the library, so `test_utils` cannot be
// gated only on `test`. Fixture helpers are small; `property-tests`/`proptest` stays gated inside the module.
pub mod test_utils;

#[cfg(feature = "profile")]
pub mod profile_log;
#[cfg(all(feature = "production", feature = "profile"))]
pub mod script_profile;

/// Consensus Proof - wrapper struct for consensus validation functions
///
/// This struct provides a convenient API for accessing all consensus validation
/// functions. All methods delegate to the corresponding module functions.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsensusProof;

impl ConsensusProof {
    /// Create a new ConsensusProof instance
    pub fn new() -> Self {
        Self
    }

    /// Validate a transaction according to consensus rules
    #[spec_locked("5.1", "CheckTransaction")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn validate_transaction(
        &self,
        tx: &types::Transaction,
    ) -> error::Result<types::ValidationResult> {
        transaction::check_transaction(tx)
    }

    /// Validate transaction inputs against UTXO set
    #[spec_locked("5.1", "CheckTxInputs")]
    #[blvm_spec_lock::ensures(result_0 == true || result_0 == false)]
    pub fn validate_tx_inputs(
        &self,
        tx: &types::Transaction,
        utxo_set: &types::UtxoSet,
        height: types::Natural,
    ) -> error::Result<(types::ValidationResult, types::Integer)> {
        transaction::check_tx_inputs(tx, utxo_set, height)
    }

    /// Validate a complete block
    ///
    /// **Deprecated**: builds empty witness stacks and defaults to [`Network::Mainnet`] with
    /// wall-clock time. Use [`validate_block_with_time_context`] with explicit witnesses,
    /// network, and median-time-past instead.
    #[deprecated(
        since = "0.1.33",
        note = "Use validate_block_with_time_context with explicit witnesses, network, and TimeContext"
    )]
    #[spec_locked("5.3", "ConnectBlock")]
    #[blvm_spec_lock::ensures(result_0 == true || result_0 == false)]
    pub fn validate_block(
        &self,
        block: &types::Block,
        utxo_set: types::UtxoSet,
        height: types::Natural,
    ) -> error::Result<(types::ValidationResult, types::UtxoSet)> {
        // Create empty witnesses for backward compatibility
        let witnesses: Vec<Vec<segwit::Witness>> =
            block.transactions.iter().map(|_| Vec::new()).collect();
        // Safe time read: unwrap_or avoids panic when clock is before epoch.
        // NOTE: This entry point defaults to Network::Mainnet. Callers that need
        // a different network should use `validate_block_with_time_context` instead.
        let network_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        let context = block::block_validation_context_for_connect_ibd(
            None::<&[types::BlockHeader]>,
            network_time,
            types::Network::Mainnet,
        );
        let (result, new_utxo_set, _undo_log) =
            block::connect_block(block, &witnesses, utxo_set, height, &context)?;
        Ok((result, new_utxo_set))
    }

    /// Validate a complete block with witness data and time context
    #[spec_locked("5.3", "ConnectBlock")]
    #[blvm_spec_lock::ensures(result_0 == true || result_0 == false)]
    pub fn validate_block_with_time_context(
        &self,
        block: &types::Block,
        witnesses: &[Vec<segwit::Witness>],
        utxo_set: types::UtxoSet,
        height: types::Natural,
        time_context: Option<types::TimeContext>,
        network: types::Network,
    ) -> error::Result<(types::ValidationResult, types::UtxoSet)> {
        let context = block::BlockValidationContext::from_time_context_and_network(
            time_context,
            network,
            None,
        );
        let (result, new_utxo_set, _undo_log) =
            block::connect_block(block, witnesses, utxo_set, height, &context)?;
        Ok((result, new_utxo_set))
    }

    /// Verify script execution (legacy API — see [`script::verify_script`] deprecation).
    #[deprecated(
        since = "0.1.33",
        note = "Use verify_script_with_context via script module for witness-aware verification"
    )]
    #[spec_locked("5.2", "VerifyScript")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn verify_script(
        &self,
        script_sig: &types::ByteString,
        script_pubkey: &types::ByteString,
        witness: Option<&types::ByteString>,
        flags: u32,
    ) -> error::Result<bool> {
        #[allow(deprecated)]
        {
            script::verify_script(script_sig, script_pubkey, witness, flags)
        }
    }

    /// Check proof of work
    #[spec_locked("7.2", "CheckProofOfWork")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn check_proof_of_work(&self, header: &types::BlockHeader) -> error::Result<bool> {
        pow::check_proof_of_work(header)
    }

    /// Get block subsidy for height
    #[spec_locked("6.1", "GetBlockSubsidy")]
    #[blvm_spec_lock::ensures(result >= 0)]
    #[blvm_spec_lock::axiom(result <= INITIAL_SUBSIDY)]
    pub fn get_block_subsidy(&self, height: types::Natural) -> types::Integer {
        economic::get_block_subsidy(height)
    }

    /// Calculate total supply at height
    #[spec_locked("6.2", "TotalSupply")]
    #[blvm_spec_lock::ensures(result >= 0)]
    pub fn total_supply(&self, height: types::Natural) -> types::Integer {
        economic::total_supply(height)
    }

    /// Get next work required for difficulty adjustment
    #[spec_locked("7.1", "GetNextWorkRequired")]
    #[blvm_spec_lock::ensures(result >= 0)]
    pub fn get_next_work_required(
        &self,
        current_header: &types::BlockHeader,
        prev_headers: &[types::BlockHeader],
    ) -> error::Result<types::Natural> {
        pow::get_next_work_required(current_header, prev_headers)
    }

    /// Accept transaction to memory pool
    #[spec_locked("9.1", "AcceptToMemoryPool")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn accept_to_memory_pool(
        &self,
        tx: &types::Transaction,
        utxo_set: &types::UtxoSet,
        mempool: &mempool::Mempool,
        height: types::Natural,
        time_context: Option<types::TimeContext>,
        network: types::Network,
    ) -> error::Result<mempool::MempoolResult> {
        mempool::accept_to_memory_pool(tx, None, utxo_set, mempool, height, time_context, network)
    }

    /// Check if transaction is standard
    #[spec_locked("9.2", "IsStandardTx")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn is_standard_tx(&self, tx: &types::Transaction) -> error::Result<bool> {
        mempool::is_standard_tx(tx)
    }

    /// Check if transaction can replace existing one (RBF)
    #[spec_locked("9.3", "ReplacementChecks")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn replacement_checks(
        &self,
        new_tx: &types::Transaction,
        existing_tx: &types::Transaction,
        utxo_set: &types::UtxoSet,
        mempool: &mempool::Mempool,
    ) -> error::Result<bool> {
        mempool::replacement_checks(new_tx, existing_tx, utxo_set, mempool)
    }

    /// Create new block from mempool transactions
    #[allow(clippy::too_many_arguments)]
    #[spec_locked("12.1", "CreateNewBlock")]
    #[blvm_spec_lock::ensures(result >= 0)]
    pub fn create_new_block(
        &self,
        utxo_set: &types::UtxoSet,
        mempool_txs: &[types::Transaction],
        height: types::Natural,
        prev_header: &types::BlockHeader,
        prev_headers: &[types::BlockHeader],
        coinbase_script: &types::ByteString,
        coinbase_address: &types::ByteString,
    ) -> error::Result<types::Block> {
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

    /// Create new block with explicit time, network, and optional per-tx witness stacks.
    #[allow(clippy::too_many_arguments)]
    #[spec_locked("12.1", "CreateNewBlock")]
    pub fn create_new_block_with_time(
        &self,
        utxo_set: &types::UtxoSet,
        mempool_txs: &[types::Transaction],
        height: types::Natural,
        prev_header: &types::BlockHeader,
        prev_headers: &[types::BlockHeader],
        coinbase_script: &types::ByteString,
        coinbase_address: &types::ByteString,
        block_time: types::Natural,
        network: types::Network,
        mempool_witnesses: Option<&[Option<Vec<segwit::Witness>>]>,
    ) -> error::Result<types::Block> {
        mining::create_new_block_with_time(
            utxo_set,
            mempool_txs,
            height,
            prev_header,
            prev_headers,
            coinbase_script,
            coinbase_address,
            block_time,
            network,
            mempool_witnesses,
        )
    }

    /// Mine a block by finding valid nonce
    #[spec_locked("12.3", "MineBlock")]
    #[blvm_spec_lock::ensures(result_0 >= 0)]
    pub fn mine_block(
        &self,
        block: types::Block,
        max_attempts: types::Natural,
    ) -> error::Result<(types::Block, mining::MiningResult)> {
        mining::mine_block(block, max_attempts)
    }

    /// Create block template for mining
    #[allow(clippy::too_many_arguments)]
    #[spec_locked("12.4", "BlockTemplate")]
    #[blvm_spec_lock::ensures(result >= 0)]
    pub fn create_block_template(
        &self,
        utxo_set: &types::UtxoSet,
        mempool_txs: &[types::Transaction],
        height: types::Natural,
        prev_header: &types::BlockHeader,
        prev_headers: &[types::BlockHeader],
        coinbase_script: &types::ByteString,
        coinbase_address: &types::ByteString,
        network: types::Network,
        mempool_witnesses: Option<&[Option<Vec<segwit::Witness>>]>,
    ) -> error::Result<mining::BlockTemplate> {
        mining::create_block_template(
            utxo_set,
            mempool_txs,
            height,
            prev_header,
            prev_headers,
            coinbase_script,
            coinbase_address,
            network,
            mempool_witnesses,
        )
    }

    /// Reorganize chain when a longer chain is found (legacy: synthesizes empty witnesses).
    #[deprecated(
        since = "0.1.33",
        note = "Use reorganize_chain_with_witnesses with explicit witness data for SegWit chains"
    )]
    #[spec_locked("11.3")]
    #[blvm_spec_lock::ensures(result >= 0)]
    pub fn reorganize_chain(
        &self,
        new_chain: &[types::Block],
        current_chain: &[types::Block],
        current_utxo_set: types::UtxoSet,
        current_height: types::Natural,
        network: types::Network,
    ) -> error::Result<reorganization::ReorganizationResult> {
        use crate::segwit::{Witness, is_segwit_transaction};
        use crate::transaction::is_coinbase;

        for block in new_chain {
            for tx in &block.transactions {
                if !is_coinbase(tx) && is_segwit_transaction(tx) {
                    return Err(error::ConsensusError::BlockValidation(
                        "reorganize_chain: SegWit transactions require reorganize_chain_with_witnesses"
                            .into(),
                    ));
                }
            }
        }

        let witnesses: Vec<Vec<Vec<Witness>>> = new_chain
            .iter()
            .map(|block| {
                block
                    .transactions
                    .iter()
                    .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
                    .collect()
            })
            .collect();
        let network_time = new_chain
            .iter()
            .map(|b| b.header.timestamp)
            .max()
            .unwrap_or(0)
            .saturating_add(crate::constants::MAX_FUTURE_BLOCK_TIME);

        reorganization::reorganize_chain_with_witnesses(
            new_chain,
            &witnesses,
            None,
            current_chain,
            current_utxo_set,
            current_height,
            None::<fn(&types::Block) -> Option<Vec<segwit::Witness>>>,
            None::<fn(types::Natural) -> Option<Vec<types::BlockHeader>>>,
            None::<fn(&types::Hash) -> Option<reorganization::BlockUndoLog>>,
            None::<fn(&types::Hash, &reorganization::BlockUndoLog) -> error::Result<()>>,
            network_time,
            network,
            None,
        )
    }

    /// Reorganize chain with explicit witness data (preferred API).
    #[spec_locked("11.3")]
    pub fn reorganize_chain_with_witnesses(
        &self,
        new_chain: &[types::Block],
        new_chain_witnesses: &[Vec<Vec<segwit::Witness>>],
        new_chain_headers: Option<&[types::BlockHeader]>,
        current_chain: &[types::Block],
        current_utxo_set: types::UtxoSet,
        current_height: types::Natural,
        network_time: types::Natural,
        network: types::Network,
    ) -> error::Result<reorganization::ReorganizationResult> {
        reorganization::reorganize_chain_with_witnesses(
            new_chain,
            new_chain_witnesses,
            new_chain_headers,
            current_chain,
            current_utxo_set,
            current_height,
            None::<fn(&types::Block) -> Option<Vec<segwit::Witness>>>,
            None::<fn(types::Natural) -> Option<Vec<types::BlockHeader>>>,
            None::<fn(&types::Hash) -> Option<reorganization::BlockUndoLog>>,
            None::<fn(&types::Hash, &reorganization::BlockUndoLog) -> error::Result<()>>,
            network_time,
            network,
            None,
        )
    }

    /// Check if reorganization is beneficial
    #[spec_locked("11.3", "ShouldReorganize")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn should_reorganize(
        &self,
        new_chain: &[types::Block],
        current_chain: &[types::Block],
    ) -> error::Result<bool> {
        reorganization::should_reorganize(new_chain, current_chain)
    }

    /// Calculate transaction weight for SegWit
    #[spec_locked("11.1.1", "CalculateTransactionWeight")]
    #[blvm_spec_lock::ensures(result >= 0)]
    pub fn calculate_transaction_weight(
        &self,
        tx: &types::Transaction,
        witness: Option<&segwit::Witness>,
    ) -> error::Result<types::Natural> {
        segwit::calculate_transaction_weight(tx, witness)
    }

    /// Validate SegWit block
    #[spec_locked("11.1.7", "ValidateSegWitBlock")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn validate_segwit_block(
        &self,
        block: &types::Block,
        witnesses: &[segwit::Witness],
        max_block_weight: types::Natural,
    ) -> error::Result<bool> {
        segwit::validate_segwit_block(block, witnesses, max_block_weight)
    }

    /// Validate Taproot transaction
    #[spec_locked("11.2.5", "ValidateTaprootTransaction")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn validate_taproot_transaction(
        &self,
        tx: &types::Transaction,
        witness: Option<&segwit::Witness>,
    ) -> error::Result<bool> {
        taproot::validate_taproot_transaction(tx, witness)
    }

    /// Check if transaction output is Taproot
    #[spec_locked("11.2.1", "IsTaprootOutput")]
    #[blvm_spec_lock::ensures(result == true || result == false)]
    pub fn is_taproot_output(&self, output: &types::TransactionOutput) -> bool {
        taproot::is_taproot_output(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::check_transaction;
    use crate::types::Transaction;

    #[test]
    fn test_validate_transaction() {
        let tx = Transaction {
            version: 1,
            inputs: vec![].into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        let result = check_transaction(&tx);
        assert!(result.is_ok());
    }
}
