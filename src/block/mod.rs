//! Block validation functions from Orange Paper Section 5.3 Section 5.3
//!
//! Performance optimizations:
//! - Parallel transaction validation (production feature)
//! - Batch UTXO operations
//! - Assume-Valid Blocks - skip validation for trusted checkpoints

mod apply;
mod connect;
mod header;
mod script_cache;
pub use apply::{apply_transaction, calculate_tx_id};
pub use header::{block_header_hash, validate_prev_block_hash};
pub use script_cache::{
    calculate_base_script_flags_for_block_network, calculate_script_flags_for_block_network,
    get_block_script_flags, get_block_script_verify_flags_core, script_flag_exceptions_lookup,
    tx_has_nonempty_input_witness, tx_requires_witness_script_flags,
};

use crate::activation::{ForkActivationTable, IsForkActive};
use crate::bip113::get_median_time_past;
use crate::error::Result;
use crate::segwit::Witness;
use crate::types::*;
use blvm_spec_lock::spec_locked;
#[cfg(feature = "production")]
use rustc_hash::{FxHashMap, FxHashSet};

#[cfg(test)]
use crate::opcodes::*;
#[cfg(test)]
use crate::transaction::is_coinbase;

// Rayon is used conditionally in the code, imported where needed

/// Overlay delta for disk sync. Returned by connect_block_ibd when BLVM_USE_OVERLAY_DELTA=1.
/// Node converts to SyncBatch and calls apply_sync_batch instead of sync_block_to_batch.
/// `Arc<UTXO>` in additions avoids clone in apply_sync_batch hot path.
///
/// Single struct definition; production uses faster hashers (FxHashMap/FxHashSet).
#[derive(Debug, Clone)]
pub struct UtxoDeltaInner<M, S> {
    pub additions: M,
    pub deletions: S,
}

#[cfg(feature = "production")]
pub type UtxoDelta = UtxoDeltaInner<
    FxHashMap<OutPoint, std::sync::Arc<UTXO>>,
    FxHashSet<crate::utxo_overlay::UtxoDeletionKey>,
>;
#[cfg(not(feature = "production"))]
pub type UtxoDelta = UtxoDeltaInner<
    std::collections::HashMap<OutPoint, std::sync::Arc<UTXO>>,
    std::collections::HashSet<crate::utxo_overlay::UtxoDeletionKey>,
>;

/// Assume-valid checkpoint configuration
///
/// Blocks before this height are assumed valid (signature verification skipped)
/// for faster IBD. This is safe because:
/// 1. These blocks are in the chain history (already validated by network)
/// 2. We still validate block structure, Merkle roots, and PoW
/// 3. Only signature verification is skipped (the expensive operation)
///
/// Assume-valid: skip signature verification below configurable height
/// Default: 0 (validate all blocks) - can be configured via environment or config
/// Get assume-valid height from configuration
///
/// This function loads the assume-valid checkpoint height from environment variable
/// or configuration. Blocks before this height skip expensive signature verification
/// during initial block download for performance.
///
/// # Configuration
/// - Environment variable: `BLVM_ASSUME_VALID_HEIGHT` (decimal height)
/// - Default: 0 (validate all blocks - safest option)
/// - Benchmarking: `config::set_assume_valid_height()` when `benchmarking` feature enabled
///
/// # Safety
/// This optimization is safe because:
/// 1. These blocks are already validated by the network
/// 2. We still validate block structure, Merkle roots, and PoW
/// 3. Only signature verification is skipped (the expensive operation)
///
/// Assume-valid: skip signature verification below configurable height
#[cfg(feature = "production")]
#[cfg(all(feature = "production", feature = "rayon"))]
pub(crate) fn skip_script_exec_cache() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("BLVM_SKIP_SCRIPT_CACHE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

pub fn get_assume_valid_height() -> u64 {
    // Check for benchmarking override first
    #[cfg(feature = "benchmarking")]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static OVERRIDE: AtomicU64 = AtomicU64::new(u64::MAX);
        let override_val = OVERRIDE.load(Ordering::Relaxed);
        if override_val != u64::MAX {
            return override_val;
        }
    }

    crate::config::get_assume_valid_height()
}

/// ConnectBlock: ℬ × 𝒲* × 𝒰𝒮 × ℕ × ℋ* → {valid, invalid} × 𝒰𝒮
///
/// For block b = (h, txs) with witnesses ws, UTXO set us at height height, and recent headers:
/// 1. Validate block header h
/// 2. For each transaction tx ∈ txs:
///    - Validate tx structure
///    - Check inputs against us
///    - Verify scripts (with witness data if available)
/// 3. Let fees = Σ_{tx ∈ txs} fee(tx)
/// 4. Let subsidy = GetBlockSubsidy(height)
/// 5. If coinbase output > fees + subsidy: return (invalid, us)
/// 6. Apply all transactions to us: us' = ApplyTransactions(txs, us)
/// 7. Return (valid, us')
///
/// # Arguments
///
/// * `block` - The block to validate and connect
/// * `witnesses` - Witness data for each transaction in the block (one Witness per transaction)
/// * `utxo_set` - Current UTXO set (will be modified)
/// * `height` - Current block height
/// * `context` - Block validation context (time, network, fork activation, BIP54 boundary). Build with
///   `BlockValidationContext::from_connect_block_ibd_args`, `from_time_context_and_network`, or `for_network`.
#[track_caller]
/// ConnectBlock: Validate and apply a block to the UTXO set.
#[spec_locked("5.3", "ConnectBlock")]
pub fn connect_block(
    block: &Block,
    witnesses: &[Vec<Witness>],
    utxo_set: UtxoSet,
    height: Natural,
    context: &BlockValidationContext,
) -> Result<(
    ValidationResult,
    UtxoSet,
    crate::reorganization::BlockUndoLog,
)> {
    #[cfg(all(feature = "production", feature = "rayon"))]
    let block_arc = Some(std::sync::Arc::new(block.clone()));
    #[cfg(not(all(feature = "production", feature = "rayon")))]
    let block_arc = None;
    let (result, new_utxo_set, _tx_ids, undo_log, _delta) = connect::connect_block_inner(
        block, witnesses, utxo_set, None, height, context, None, None, block_arc, false, None,
        None,
    )?;
    Ok((result, new_utxo_set, undo_log))
}

/// ConnectBlock with explicit chainwork for assume-valid gating. Non-IBD mode: the returned
/// `UtxoSet` is fully updated (outputs added, inputs removed) just like `connect_block`.
/// The only difference from `connect_block` is that `best_header_chainwork` is forwarded to the
/// assume-valid gate so scripts are skipped when `height < assume_valid_height`.
///
/// Use this instead of `connect_block_ibd` when the caller needs to apply the returned
/// `UtxoSet` to persistent storage — `connect_block_ibd` sets `ibd_mode=true` which skips
/// UTXO mutations on the returned set.
#[cfg(feature = "benchmarking")]
pub fn connect_block_with_chainwork(
    block: &Block,
    witnesses: &[Vec<Witness>],
    utxo_set: UtxoSet,
    height: Natural,
    context: &BlockValidationContext,
    best_header_chainwork: Option<crate::pow::U256>,
) -> Result<(
    ValidationResult,
    UtxoSet,
    crate::reorganization::BlockUndoLog,
)> {
    #[cfg(all(feature = "production", feature = "rayon"))]
    let block_arc = Some(std::sync::Arc::new(block.clone()));
    #[cfg(not(all(feature = "production", feature = "rayon")))]
    let block_arc = None;
    let (result, new_utxo_set, _tx_ids, undo_log, _delta) = connect::connect_block_inner(
        block,
        witnesses,
        utxo_set,
        None,
        height,
        context,
        None,
        None,
        block_arc,
        false,
        best_header_chainwork,
        None,
    )?;
    Ok((result, new_utxo_set, undo_log))
}

/// ConnectBlock variant optimized for IBD that returns transaction IDs instead of undo log.
///
/// Returns `Vec<Hash>` (transaction IDs) instead of `BlockUndoLog`. Caller provides
/// `context` (build with `BlockValidationContext::from_connect_block_ibd_args` from
/// recent_headers, network_time, network, BIP54 override, and boundary).
///
/// * `bip30_index` - Optional index for O(1) BIP30 duplicate-coinbase check.
/// * `precomputed_tx_ids` - Optional pre-computed tx IDs; when `Some`, skips hashing in consensus
///   and returns those IDs as `Cow::Borrowed` (no per-block `Vec` clone).
/// * `best_header_chainwork` - Cumulative chainwork of the best known header (`U256`), used to
///   gate the assume-valid skip: `skip_signatures = height < assume_valid_height && chainwork_ok`
///   where `chainwork_ok = chainwork >= n_minimum_chain_work`. Pass cumulative header chainwork
///   from the node (IBD validation loop tracks this incrementally). Pass `None` in tests that
///   require full script verification regardless of assume-valid.
#[spec_locked("5.3", "ConnectBlock")]
pub fn connect_block_ibd<'a>(
    block: &Block,
    witnesses: &[Vec<Witness>],
    utxo_set: UtxoSet,
    height: Natural,
    context: &BlockValidationContext,
    bip30_index: Option<&mut crate::bip_validation::Bip30Index>,
    precomputed_tx_ids: Option<&'a [Hash]>,
    block_arc: Option<std::sync::Arc<Block>>,
    witnesses_arc: Option<&std::sync::Arc<Vec<Vec<Witness>>>>,
    best_header_chainwork: Option<crate::pow::U256>,
) -> Result<(
    ValidationResult,
    UtxoSet,
    std::borrow::Cow<'a, [Hash]>,
    Option<UtxoDelta>,
)> {
    let (result, new_utxo_set, tx_ids, _undo_log, utxo_delta) = connect::connect_block_inner(
        block,
        witnesses,
        utxo_set,
        witnesses_arc,
        height,
        context,
        bip30_index,
        precomputed_tx_ids,
        block_arc,
        true,
        best_header_chainwork,
        None,
    )?;
    Ok((result, new_utxo_set, tx_ids, utxo_delta))
}

/// Like [`connect_block_ibd`] but also returns the undo log for reorg support after IBD.
#[spec_locked("5.3", "ConnectBlock")]
pub fn connect_block_ibd_with_undo<'a>(
    block: &Block,
    witnesses: &[Vec<Witness>],
    utxo_set: UtxoSet,
    height: Natural,
    context: &BlockValidationContext,
    bip30_index: Option<&mut crate::bip_validation::Bip30Index>,
    precomputed_tx_ids: Option<&'a [Hash]>,
    block_arc: Option<std::sync::Arc<Block>>,
    witnesses_arc: Option<&std::sync::Arc<Vec<Vec<Witness>>>>,
    best_header_chainwork: Option<crate::pow::U256>,
    ibd_utxo_lookup: Option<&dyn crate::utxo_overlay::UtxoLookup>,
) -> Result<(
    ValidationResult,
    UtxoSet,
    std::borrow::Cow<'a, [Hash]>,
    Option<UtxoDelta>,
    crate::reorganization::BlockUndoLog,
)> {
    let (result, new_utxo_set, tx_ids, undo_log, utxo_delta) = connect::connect_block_inner(
        block,
        witnesses,
        utxo_set,
        witnesses_arc,
        height,
        context,
        bip30_index,
        precomputed_tx_ids,
        block_arc,
        true,
        best_header_chainwork,
        ibd_utxo_lookup,
    )?;
    Ok((result, new_utxo_set, tx_ids, utxo_delta, undo_log))
}

/// Helper to construct a `TimeContext` from recent headers and network time.
///
/// # Consensus Engine Purity
/// This function does NOT call `SystemTime::now()`. The `network_time` parameter
/// must be provided by the node layer, ensuring the consensus engine remains pure.
fn build_time_context<H: AsRef<BlockHeader>>(
    recent_headers: Option<&[H]>,
    network_time: u64,
) -> Option<crate::types::TimeContext> {
    recent_headers.map(|headers| {
        let median_time_past = get_median_time_past(headers);
        crate::types::TimeContext {
            network_time,
            median_time_past,
        }
    })
}

/// Pre-built IBD block output map (I2): shared `Arc<UTXO>` per outpoint.
#[cfg(feature = "production")]
pub type IbdBlockOutputCache =
    std::sync::Arc<rustc_hash::FxHashMap<crate::types::OutPoint, std::sync::Arc<crate::types::UTXO>>>;
#[cfg(not(feature = "production"))]
pub type IbdBlockOutputCache = std::sync::Arc<
    std::collections::HashMap<crate::types::OutPoint, std::sync::Arc<crate::types::UTXO>>,
>;

/// Block validation context: time, network, fork activation, and optional rule data.
///
/// Built by the node from headers, clock, chain params, version-bits, and config.
/// Consensus only reads; it does not compute activation or read config.
#[derive(Clone)]
pub struct BlockValidationContext {
    /// Time context for BIP113 and future-block checks.
    pub time_context: Option<crate::types::TimeContext>,
    /// Network time (Unix timestamp). Used when time_context is None for 2-week skip.
    pub network_time: u64,
    /// Network (mainnet / testnet / regtest).
    pub network: crate::types::Network,
    /// Precomputed fork activation table.
    pub activation: ForkActivationTable,
    /// When BIP54 is active and block is at period boundary, timestamps for timewarp; else None.
    pub bip54_boundary: Option<crate::types::Bip54BoundaryTimestamps>,
    /// Optional signet challenge script override (BIP325); default from `signet::default_signet_challenge`.
    pub signet_challenge: Option<ByteString>,
    /// IBD assume-valid: pre-built output `Arc<UTXO>` map for overlay apply (I2).
    pub ibd_block_outputs: Option<IbdBlockOutputCache>,
}

impl BlockValidationContext {
    /// Build context from the same inputs as `connect_block_ibd` (for migration).
    pub fn from_connect_block_ibd_args<H: AsRef<BlockHeader>>(
        recent_headers: Option<&[H]>,
        network_time: u64,
        network: crate::types::Network,
        bip54_activation_override: Option<u64>,
        bip54_boundary: Option<crate::types::Bip54BoundaryTimestamps>,
    ) -> Self {
        let time_context = build_time_context(recent_headers, network_time);
        let activation = ForkActivationTable::from_network_and_bip54_override(
            network,
            bip54_activation_override,
        );
        Self {
            time_context,
            network_time,
            network,
            activation,
            bip54_boundary,
            signet_challenge: None,
            ibd_block_outputs: None,
        }
    }

    /// Build context from precomputed time context and network.
    pub fn from_time_context_and_network(
        time_context: Option<crate::types::TimeContext>,
        network: crate::types::Network,
        bip54_boundary: Option<crate::types::Bip54BoundaryTimestamps>,
    ) -> Self {
        let network_time = time_context.as_ref().map(|c| c.network_time).unwrap_or(0);
        let activation = ForkActivationTable::from_network(network);
        Self {
            time_context,
            network_time,
            network,
            activation,
            bip54_boundary,
            signet_challenge: None,
            ibd_block_outputs: None,
        }
    }

    /// Build context for a network only (no headers, network_time 0, no BIP54). For tests and simple callers.
    pub fn for_network(network: crate::types::Network) -> Self {
        block_validation_context_for_connect_ibd(None::<&[BlockHeader]>, 0, network)
    }
}

/// Forwards to [`BlockValidationContext::from_connect_block_ibd_args`] with BIP54 activation override
/// and boundary timestamps set to `None`.
#[inline]
pub fn block_validation_context_for_connect_ibd<H: AsRef<BlockHeader>>(
    recent_headers: Option<&[H]>,
    network_time: u64,
    network: Network,
) -> BlockValidationContext {
    BlockValidationContext::from_connect_block_ibd_args(
        recent_headers,
        network_time,
        network,
        None,
        None,
    )
}

impl IsForkActive for BlockValidationContext {
    #[inline]
    fn is_fork_active(&self, fork: crate::types::ForkId, height: u64) -> bool {
        self.activation.is_fork_active(fork, height)
    }
}

#[cfg(feature = "production")]
mod tx_id_pool {
    use crate::types::{Hash, Transaction};
    use std::cell::RefCell;

    thread_local! {
        static TX_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(
            crate::optimizations::proven_bounds::MAX_TX_SIZE_PROVEN
        ));
    }

    /// Fused serialize+hash using thread-local buffer. Avoids `Vec<Vec<u8>>` allocation.
    pub fn compute_tx_id_with_pool(tx: &Transaction) -> Hash {
        use crate::crypto::OptimizedSha256;
        use crate::serialization::transaction::serialize_transaction_into;

        TX_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            serialize_transaction_into(&mut buf, tx);
            OptimizedSha256::new().hash256(&buf)
        })
    }
}

/// Compute `{ Hash(tx) : tx ∈ block.transactions }` for ComputeMerkleRoot (Orange Paper §8.4.1).
///
/// **Spec reference:** sequential `calculate_tx_id` only (no `rayon`, no `&mut Vec`, no `cfg` in the
/// body). blvm-spec-lock Z3 translates this for determinism/`ensures`. Optimized paths in
/// [`compute_block_tx_ids_into`] are tested to match this result.
#[spec_locked("8.4.1", "ComputeMerkleRoot")]
pub fn compute_block_tx_ids_spec(block: &Block) -> Vec<Hash> {
    block.transactions.iter().map(calculate_tx_id).collect()
}

/// Compute transaction IDs for a block (extracted for reuse).
/// Produces {Hash(tx) : tx ∈ block.transactions} for ComputeMerkleRoot input (Orange Paper 8.4.1).
/// Public so node layer can compute once and share between collect_gaps and connect_block_ibd (#21).
///
/// Tx-id computation is **always serial**. The previous `par_iter` path looked
/// fast in isolation but was disastrous in the IBD pipeline: the coordinator + N validation
/// workers each push hashing work into the shared rayon pool, oversubscribing the CPU and
/// stalling worker threads at ≪10% utilisation while the rayon pool burns ~5 cores spinning
/// on coordination overhead. Serial double-SHA256 over ~3000 short txs is ~500 µs/block —
/// well below the BPS budget — and the freed cores translate directly into block-level
/// parallelism (per-block work stays on one thread; cross-block work is N-way).
pub fn compute_block_tx_ids_into(block: &Block, out: &mut Vec<Hash>) {
    out.clear();
    out.reserve(block.transactions.len());

    #[cfg(feature = "production")]
    {
        out.extend(
            block
                .transactions
                .iter()
                .map(tx_id_pool::compute_tx_id_with_pool),
        );
    }

    #[cfg(not(feature = "production"))]
    {
        out.extend(block.transactions.iter().map(calculate_tx_id));
    }
}

pub fn compute_block_tx_ids(block: &Block) -> Vec<Hash> {
    let mut v = Vec::new();
    compute_block_tx_ids_into(block, &mut v);
    v
}

/// Optimized paths (`rayon` / pooled hash) must agree with [`compute_block_tx_ids_spec`] (§8.4.1).
#[test]
fn compute_block_tx_ids_spec_matches_optimized_paths() {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x03, 0x01, 0x00, 0x00],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![0x51],
        }]
        .into(),
        lock_time: 0,
    };
    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1u8; 32],
                index: 0,
            },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 10_000,
            script_pubkey: vec![0x51],
        }]
        .into(),
        lock_time: 0,
    };
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![coinbase, tx2].into_boxed_slice(),
    };
    assert_eq!(
        compute_block_tx_ids_spec(&block),
        compute_block_tx_ids(&block),
        "§8.4.1 spec reference must match compute_block_tx_ids / compute_block_tx_ids_into"
    );
}

#[test]
fn test_connect_block_invalid_header() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 0, // Invalid version
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    };

    let utxo_set = UtxoSet::default();
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| {
            (0..tx.inputs.len())
                .map(|_| Vec::with_capacity(2))
                .collect()
        })
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let (result, _, _undo_log) = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx).unwrap();

    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_block_no_transactions() {
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![].into_boxed_slice(), // No transactions
    };

    let utxo_set = UtxoSet::default();
    // One Vec<Witness> per tx (one Witness per input)
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| {
            (0..tx.inputs.len())
                .map(|_| Vec::with_capacity(2))
                .collect()
        })
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let (result, _, _undo_log) = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx).unwrap();

    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_block_first_tx_not_coinbase() {
    let regular_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![regular_tx].into_boxed_slice(), // First tx is not coinbase
    };

    let utxo_set = UtxoSet::default();
    // One Vec<Witness> per tx (one Witness per input)
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| {
            (0..tx.inputs.len())
                .map(|_| Vec::with_capacity(2))
                .collect()
        })
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let (result, _, _undo_log) = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx).unwrap();

    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_block_coinbase_exceeds_subsidy() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 6000000000, // 60 BTC - exceeds subsidy
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    };

    let utxo_set = UtxoSet::default();
    // One Vec<Witness> per tx (one Witness per input)
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| {
            (0..tx.inputs.len())
                .map(|_| Vec::with_capacity(2))
                .collect()
        })
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let (result, _, _undo_log) = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx).unwrap();

    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_apply_transaction_regular() {
    let mut utxo_set = UtxoSet::default();

    // Add a UTXO first
    let prev_outpoint = OutPoint {
        hash: [1; 32],
        index: 0,
    };
    let prev_utxo = UTXO {
        value: 1000,
        script_pubkey: vec![OP_1].into(), // OP_1
        height: 0,
        is_coinbase: false,
    };
    utxo_set.insert(prev_outpoint, std::sync::Arc::new(prev_utxo));

    let regular_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1], // OP_1
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 500,
            script_pubkey: vec![OP_2], // OP_2
        }]
        .into(),
        lock_time: 0,
    };

    let (new_utxo_set, _undo_entries) = apply_transaction(&regular_tx, utxo_set, 1).unwrap();

    // Should have 1 UTXO (the new output)
    assert_eq!(new_utxo_set.len(), 1);
}

#[test]
fn test_apply_transaction_multiple_outputs() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![
            TransactionOutput {
                value: 2500000000,
                script_pubkey: vec![OP_1],
            },
            TransactionOutput {
                value: 2500000000,
                script_pubkey: vec![OP_2],
            },
        ]
        .into(),
        lock_time: 0,
    };

    let utxo_set = UtxoSet::default();
    let (new_utxo_set, _undo_entries) = apply_transaction(&coinbase_tx, utxo_set, 0).unwrap();

    assert_eq!(new_utxo_set.len(), 2);
}

#[test]
fn test_validate_block_header_valid() {
    use sha2::{Digest, Sha256};

    // Create a valid header with non-zero merkle root
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: Sha256::digest(b"test merkle root")[..].try_into().unwrap(),
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let result = header::validate_block_header(&header, None).unwrap();
    assert!(result);
}

#[test]
fn test_validate_block_header_invalid_version() {
    let header = BlockHeader {
        version: 0, // Invalid version
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let result = header::validate_block_header(&header, None).unwrap();
    assert!(!result);
}

#[test]
fn test_validate_block_header_invalid_bits() {
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0, // Invalid bits
        nonce: 0,
    };

    let result = header::validate_block_header(&header, None).unwrap();
    assert!(!result);
}

#[test]
fn test_is_coinbase_true() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    assert!(is_coinbase(&coinbase_tx));
}

#[test]
fn test_is_coinbase_false_wrong_hash() {
    let regular_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0xffffffff,
            }, // Wrong hash
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    assert!(!is_coinbase(&regular_tx));
}

#[test]
fn test_is_coinbase_false_wrong_index() {
    let regular_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0,
            }, // Wrong index
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    assert!(!is_coinbase(&regular_tx));
}

#[test]
fn test_is_coinbase_false_multiple_inputs() {
    let regular_tx = Transaction {
        version: 1,
        inputs: vec![
            TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            },
            TransactionInput {
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            },
        ]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    assert!(!is_coinbase(&regular_tx));
}

#[test]
fn test_calculate_tx_id() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    let tx_id = calculate_tx_id(&tx);

    // Should be a 32-byte hash (double SHA256 of serialized transaction)
    assert_eq!(tx_id.len(), 32);

    // Same transaction should produce same ID (deterministic)
    let tx_id2 = calculate_tx_id(&tx);
    assert_eq!(tx_id, tx_id2);

    // Different transaction should produce different ID
    let mut tx2 = tx.clone();
    tx2.version = 2;
    let tx_id3 = calculate_tx_id(&tx2);
    assert_ne!(tx_id, tx_id3);
}

#[test]
fn test_calculate_tx_id_different_versions() {
    let tx1 = Transaction {
        version: 2,
        inputs: vec![].into(),
        outputs: vec![].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![].into(),
        outputs: vec![].into(),
        lock_time: 0,
    };

    let id1 = calculate_tx_id(&tx1);
    let id2 = calculate_tx_id(&tx2);

    // Different versions should produce different IDs
    assert_ne!(id1, id2);
}

#[test]
fn test_connect_block_empty_transactions() {
    // Test that blocks with empty transactions are rejected
    // Note: We need a valid merkle root even for empty blocks (though they're invalid)
    // For testing purposes, we'll use a zero merkle root which will fail validation
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32], // Zero merkle root - will fail validation
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![].into_boxed_slice(), // Empty transactions - invalid
    };

    let utxo_set = UtxoSet::default();
    // Optimization: Pre-allocate witness vectors with capacity
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let result = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx);
    // The result should be Ok with ValidationResult::Invalid
    assert!(result.is_ok());
    let (validation_result, _, _undo_log) = result.unwrap();
    assert!(matches!(validation_result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_block_invalid_coinbase() {
    let invalid_coinbase = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            }, // Wrong hash for coinbase
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![invalid_coinbase].into_boxed_slice(),
    };

    let utxo_set = UtxoSet::default();
    // Optimization: Pre-allocate witness vectors with capacity
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let result = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx);
    // The result should be Ok with ValidationResult::Invalid
    assert!(result.is_ok());
    let (validation_result, _, _undo_log) = result.unwrap();
    assert!(matches!(validation_result, ValidationResult::Invalid(_)));
}

#[test]
fn test_apply_transaction_insufficient_funds() {
    let mut utxo_set = UtxoSet::default();

    // Add a UTXO with insufficient value
    let prev_outpoint = OutPoint {
        hash: [1; 32],
        index: 0,
    };
    let prev_utxo = UTXO {
        value: 100, // Small value
        script_pubkey: vec![OP_1].into(),
        height: 0,
        is_coinbase: false,
    };
    utxo_set.insert(prev_outpoint, std::sync::Arc::new(prev_utxo));

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 200, // More than input value
            script_pubkey: vec![OP_2],
        }]
        .into(),
        lock_time: 0,
    };

    // `apply_transaction` updates the UTXO set only; value conservation is enforced in
    // `check_tx_inputs` during block connect, not here.
    let result = apply_transaction(&tx, utxo_set, 1);
    assert!(result.is_ok());
}

#[test]
fn test_apply_transaction_missing_utxo() {
    let utxo_set = UtxoSet::default(); // Empty UTXO set

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 100,
            script_pubkey: vec![OP_2],
        }]
        .into(),
        lock_time: 0,
    };

    // Missing prevout: `apply_transaction` still succeeds (overlay add/remove only);
    // block connect runs `check_tx_inputs` for value and existence checks.
    let result = apply_transaction(&tx, utxo_set, 1);
    assert!(result.is_ok());
}

#[test]
fn test_validate_block_header_future_timestamp() {
    use sha2::{Digest, Sha256};

    // Create header with non-zero merkle root (required for validation)
    // Timestamp validation now uses TimeContext (network time + median time-past)
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: Sha256::digest(b"test merkle root")[..].try_into().unwrap(),
        timestamp: 9999999999, // Far future timestamp (would need network time check)
        bits: 0x1d00ffff,
        nonce: 0,
    };

    // Header structure is valid (actual future timestamp check needs network context)
    let result = header::validate_block_header(&header, None).unwrap();
    assert!(result);
}

#[test]
fn test_validate_block_header_zero_timestamp() {
    use sha2::{Digest, Sha256};

    // Zero timestamp should be rejected by validate_block_header
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: Sha256::digest(b"test merkle root")[..].try_into().unwrap(),
        timestamp: 0, // Zero timestamp (invalid)
        bits: 0x1d00ffff,
        nonce: 0,
    };

    // Zero timestamp should be rejected
    let result = header::validate_block_header(&header, None).unwrap();
    assert!(!result);
}

#[test]
fn test_connect_block_coinbase_exceeds_subsidy_edge() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 2100000000000000, // Exceeds total supply
            script_pubkey: vec![],
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    };

    let utxo_set = UtxoSet::default();
    // Optimization: Pre-allocate witness vectors with capacity
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let result = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx);
    // The result should be Ok with ValidationResult::Invalid
    assert!(result.is_ok());
    let (validation_result, _, _undo_log) = result.unwrap();
    assert!(matches!(validation_result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_block_first_tx_not_coinbase_edge() {
    let regular_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_2],
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![regular_tx].into_boxed_slice(), // First tx is not coinbase
    };

    let utxo_set = UtxoSet::default();
    // Optimization: Pre-allocate witness vectors with capacity
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect();
    let ctx = BlockValidationContext::for_network(crate::types::Network::Mainnet);
    let result = connect_block(&block, &witnesses[..], utxo_set, 0, &ctx);
    // The result should be Ok with ValidationResult::Invalid
    assert!(result.is_ok());
    let (validation_result, _, _undo_log) = result.unwrap();
    assert!(matches!(validation_result, ValidationResult::Invalid(_)));
}

#[test]
fn test_apply_transaction_multiple_inputs() {
    let mut utxo_set = UtxoSet::default();

    // Add multiple UTXOs
    let outpoint1 = OutPoint {
        hash: [1; 32],
        index: 0,
    };
    let utxo1 = UTXO {
        value: 500,
        script_pubkey: vec![OP_1].into(),
        height: 0,
        is_coinbase: false,
    };
    utxo_set.insert(outpoint1, std::sync::Arc::new(utxo1));

    let outpoint2 = OutPoint {
        hash: [2; 32],
        index: 0,
    };
    let utxo2 = UTXO {
        value: 300,
        script_pubkey: vec![OP_2].into(),
        height: 0,
        is_coinbase: false,
    };
    utxo_set.insert(outpoint2, std::sync::Arc::new(utxo2));

    let tx = Transaction {
        version: 1,
        inputs: vec![
            TransactionInput {
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0,
                },
                script_sig: vec![OP_1],
                sequence: 0xffffffff,
            },
            TransactionInput {
                prevout: OutPoint {
                    hash: [2; 32],
                    index: 0,
                },
                script_sig: vec![OP_2],
                sequence: 0xffffffff,
            },
        ]
        .into(),
        outputs: vec![TransactionOutput {
            value: 700, // Total input value
            script_pubkey: vec![OP_3],
        }]
        .into(),
        lock_time: 0,
    };

    let (new_utxo_set, _undo_entries) = apply_transaction(&tx, utxo_set, 1).unwrap();
    assert_eq!(new_utxo_set.len(), 1);
}

#[test]
fn test_apply_transaction_no_outputs() {
    let mut utxo_set = UtxoSet::default();

    let prev_outpoint = OutPoint {
        hash: [1; 32],
        index: 0,
    };
    let prev_utxo = UTXO {
        value: 1000,
        script_pubkey: vec![OP_1].into(),
        height: 0,
        is_coinbase: false,
    };
    utxo_set.insert(prev_outpoint, std::sync::Arc::new(prev_utxo));

    // Test that transactions with no outputs are rejected
    // This is a validation test, not an application test
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![].into(), // No outputs - should be invalid
        lock_time: 0,
    };

    // The transaction should be invalid due to no outputs
    // We can't apply an invalid transaction, so this test verifies validation rejects it
    let validation_result = crate::transaction::check_transaction(&tx).unwrap();
    assert!(matches!(validation_result, ValidationResult::Invalid(_)));

    // For the actual apply test, use a valid transaction with at least one output
    let valid_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 500, // Valid output
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    // Now apply the valid transaction
    let (new_utxo_set, _undo_entries) = apply_transaction(&valid_tx, utxo_set, 1).unwrap();
    // After applying, the input UTXO should be removed and the output UTXO should be added
    assert_eq!(new_utxo_set.len(), 1);

    // Verify the output UTXO exists
    let output_outpoint = OutPoint {
        hash: calculate_tx_id(&valid_tx),
        index: 0,
    };
    assert!(new_utxo_set.contains_key(&output_outpoint));
}
