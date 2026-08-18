//! Mempool validation functions from Orange Paper Section 9

use crate::constants::*;
use crate::economic::calculate_fee;
use crate::error::{ConsensusError, Result};
use crate::script::verify_script_with_context;
use crate::segwit::Witness;
use crate::transaction::{check_transaction, check_tx_inputs};
use crate::types::*;
use blvm_spec_lock::spec_locked;
use std::collections::{HashMap, HashSet};

/// AcceptToMemoryPool: 𝒯𝒳 × 𝒰𝒮 → {accepted, rejected}
///
/// For transaction tx and UTXO set us:
/// 1. Check if tx is already in mempool
/// 2. Validate transaction structure
/// 3. Check inputs against UTXO set
/// 4. Verify scripts
/// 5. Check mempool-specific rules (size, fee rate, etc.)
/// 6. Check for conflicts with existing mempool transactions
/// 7. Return acceptance result
///
/// # Arguments
///
/// * `tx` - Transaction to validate
/// * `witnesses` - Optional witness data for each input (Vec<Witness> where Witness = Vec<ByteString>)
/// * `utxo_set` - Current UTXO set
/// * `mempool` - Current mempool state
/// * `height` - Current block height
/// * `time_context` - Time context with median time-past of chain tip (BIP113) for transaction finality check
/// * `network` - Chain network for script verification flags (activation heights)
#[spec_locked("9.1", "AcceptToMemoryPool")]
pub fn accept_to_memory_pool(
    tx: &Transaction,
    witnesses: Option<&[Witness]>,
    utxo_set: &UtxoSet,
    mempool: &Mempool,
    height: Natural,
    time_context: Option<TimeContext>,
    network: Network,
) -> Result<MempoolResult> {
    // Precondition assertions: Validate function inputs
    // Note: We check coinbase and empty transactions and return Rejected rather than asserting,
    // to allow tests to verify the validation logic properly
    if tx.inputs.is_empty() && tx.outputs.is_empty() {
        return Ok(MempoolResult::Rejected(
            "Transaction must have at least one input or output".to_string(),
        ));
    }
    if is_coinbase(tx) {
        return Ok(MempoolResult::Rejected(
            "Coinbase transactions cannot be added to mempool".to_string(),
        ));
    }
    if height > i64::MAX as u64 {
        return Ok(MempoolResult::Rejected(format!(
            "Block height {height} exceeds i64::MAX"
        )));
    }
    if utxo_set.len() > u32::MAX as usize {
        return Ok(MempoolResult::Rejected(format!(
            "UTXO set size {} exceeds maximum",
            utxo_set.len()
        )));
    }
    if let Some(wits) = witnesses {
        if wits.len() != tx.inputs.len() {
            return Ok(MempoolResult::Rejected(format!(
                "Witness count {} must match input count {}",
                wits.len(),
                tx.inputs.len()
            )));
        }
    }

    // 1. Check if transaction is already in mempool
    let tx_id = crate::block::calculate_tx_id(tx);
    if tx_id == [0u8; 32] {
        return Err(ConsensusError::TransactionValidation(
            "Transaction ID must be non-zero".into(),
        ));
    }
    if mempool.contains(&tx_id) {
        return Ok(MempoolResult::Rejected(
            "Transaction already in mempool".to_string(),
        ));
    }

    // 2. Validate transaction structure
    if !matches!(check_transaction(tx)?, ValidationResult::Valid) {
        return Ok(MempoolResult::Rejected(
            "Invalid transaction structure".to_string(),
        ));
    }

    // 2.5. Check transaction finality
    // Use median time-past of chain tip (BIP113) for proper locktime/sequence validation
    let block_time = time_context.map(|ctx| ctx.median_time_past).unwrap_or(0);
    if !is_final_tx(tx, height, block_time) {
        return Ok(MempoolResult::Rejected(
            "Transaction not final (locktime not satisfied)".to_string(),
        ));
    }

    // 3. Check inputs against UTXO set
    let (input_valid, fee) = check_tx_inputs(tx, utxo_set, height)?;
    use crate::constants::MAX_MONEY;
    if fee < 0 || fee > MAX_MONEY {
        return Ok(MempoolResult::Rejected(format!(
            "Fee {fee} must be in [0, MAX_MONEY]"
        )));
    }
    if !matches!(input_valid, ValidationResult::Valid) {
        return Ok(MempoolResult::Rejected(
            "Invalid transaction inputs".to_string(),
        ));
    }

    // 4. Verify scripts for non-coinbase transactions
    if !is_coinbase(tx) {
        let flags = calculate_script_flags(tx, witnesses, network);
        if let Some(msg) = verify_mempool_scripts(
            tx,
            witnesses,
            utxo_set,
            height,
            time_context,
            flags,
            network,
        )? {
            return Ok(MempoolResult::Rejected(msg));
        }
    }

    // 5. Check mempool-specific rules
    if !check_mempool_rules(tx, fee, mempool)? {
        return Ok(MempoolResult::Rejected("Failed mempool rules".to_string()));
    }

    // 6. Check for conflicts with existing mempool transactions
    if has_conflicts(tx, mempool)? {
        return Ok(MempoolResult::Rejected(
            "Transaction conflicts with mempool".to_string(),
        ));
    }

    Ok(MempoolResult::Accepted)
}

/// Calculate script verification flags based on transaction type
///
/// Returns appropriate flags for script validation:
/// - Base flags: Standard validation flags (P2SH, STRICTENC, DERSIG, LOW_S, etc.)
/// - SegWit flag (SCRIPT_VERIFY_WITNESS = 0x800): Enabled if transaction uses SegWit
/// - Taproot flag (SCRIPT_VERIFY_TAPROOT = 0x20000): Enabled if transaction uses Taproot
fn calculate_script_flags(
    tx: &Transaction,
    witnesses: Option<&[Witness]>,
    network: Network,
) -> u32 {
    // Delegate to the canonical script flag calculation used by block validation.
    //
    // Note: For mempool policy we only care about which flags are enabled, not the
    // actual witness contents here, so we rely on the transaction structure itself
    // (including SegWit/Taproot outputs) in `calculate_script_flags_for_block`.
    // Witness data is still threaded through to `verify_script` separately.
    //
    // For mempool policy, we use a height that activates all soft forks (well past all activations).
    // This ensures we validate using the most strict rules.
    // Check if witness data is present (optimization: just check bool, no witness needed)
    let has_witness = witnesses.map(|w| !w.is_empty()).unwrap_or(false);
    const MEMPOOL_POLICY_HEIGHT: u64 = 1_000_000; // All soft forks active at this height
    crate::block::calculate_script_flags_for_block_network(
        tx,
        has_witness,
        MEMPOOL_POLICY_HEIGHT,
        network,
    )
}

/// Variant of `is_standard_tx` that accepts an optional [`blvm_primitives::config::MempoolConfig`].
///
/// Applies configurable policy overrides. When config is `None`, delegates to `is_standard_tx`.
/// When config is present, config fields override the base policy for envelope protocol,
/// multiple OP_RETURN, and script size limits.
#[spec_locked("9.2", "IsStandardTxWithConfig")]
pub fn is_standard_tx_with_config(
    tx: &crate::types::Transaction,
    config: Option<&blvm_primitives::config::MempoolConfig>,
) -> Result<bool> {
    let Some(cfg) = config else {
        return is_standard_tx(tx);
    };

    // Size checks (same as base).
    let tx_size = crate::transaction::calculate_transaction_size(tx);
    if tx_size > MAX_TX_SIZE {
        return Ok(false);
    }
    for input in tx.inputs.iter() {
        if input.script_sig.len() > MAX_SCRIPT_SIZE {
            return Ok(false);
        }
    }

    let max_script = cfg.max_standard_script_size as usize;
    let max_op_return = cfg.max_op_return_size as usize;
    let reject_envelope = cfg.reject_envelope_protocol;
    let reject_multi_op_return = cfg.reject_multiple_op_return;

    let mut op_return_count = 0usize;
    for output in tx.outputs.iter() {
        let s = &output.script_pubkey;

        // Configurable max script size.
        if s.len() > max_script {
            return Ok(false);
        }

        if s.first() == Some(&0x6a) {
            // OP_RETURN: check configurable data size.
            op_return_count += 1;
            if s.len().saturating_sub(1) > max_op_return {
                return Ok(false);
            }
        } else if s.len() >= 2 && s[0] == 0x00 && s[1] == 0x63 {
            // Envelope protocol (OP_FALSE OP_IF).
            if reject_envelope {
                return Ok(false);
            }
        }
    }

    // Multiple OP_RETURN check (config-gated).
    if reject_multi_op_return && op_return_count > 1 {
        return Ok(false);
    }

    Ok(true)
}

/// IsStandardTx: 𝒯𝒳 → {true, false}
///
/// Check if transaction follows standard rules for mempool acceptance:
/// 1. Transaction size limits
/// 2. Script size limits
/// 3. Standard script types
/// 4. Fee rate requirements
#[spec_locked("9.2", "IsStandardTx")]
pub fn is_standard_tx(tx: &Transaction) -> Result<bool> {
    // 1. Check transaction size
    let tx_size = calculate_transaction_size(tx);
    if tx_size > MAX_TX_SIZE {
        return Ok(false);
    }

    // 2. Check script sizes
    for input in tx.inputs.iter() {
        if input.script_sig.len() > MAX_SCRIPT_SIZE {
            return Ok(false);
        }
    }

    for output in tx.outputs.iter() {
        if output.script_pubkey.len() > MAX_SCRIPT_SIZE {
            return Ok(false);
        }
    }

    // 3. Check for standard script types and policy
    let mut op_return_count = 0usize;
    for output in tx.outputs.iter() {
        if !is_standard_script(&output.script_pubkey)? {
            return Ok(false);
        }

        // Count OP_RETURN outputs; standard mempool policy rejects multiple OP_RETURN outputs.
        if output.script_pubkey.first() == Some(&0x6a) {
            op_return_count += 1;
        }

        // Reject envelope protocol scripts (OP_FALSE OP_IF) — non-standard in base policy.
        let s = &output.script_pubkey;
        if s.len() >= 2 && s[0] == 0x00 && s[1] == 0x63 {
            return Ok(false);
        }
    }

    // Reject transactions with more than one OP_RETURN output (base policy).
    if op_return_count > 1 {
        return Ok(false);
    }

    Ok(true)
}

/// ReplacementChecks: 𝒯𝒳 × 𝒯𝒳 × 𝒰𝒮 × Mempool → {true, false}
///
/// Check if new transaction can replace existing one (BIP125 RBF rules).
///
/// According to BIP125 and Orange Paper Section 9.3, replacement is allowed if:
/// 1. Existing transaction signals RBF (nSequence < SEQUENCE_FINAL)
/// 2. New transaction has higher fee rate: FeeRate(tx_2) > FeeRate(tx_1)
/// 3. New transaction pays absolute fee bump: Fee(tx_2) > Fee(tx_1) + MIN_RELAY_FEE
/// 4. New transaction conflicts with existing: tx_2 spends at least one input from tx_1
/// 5. No new unconfirmed dependencies: All inputs of tx_2 are confirmed or from tx_1
#[spec_locked("9.3", "ReplacementChecks")]
pub fn replacement_checks(
    new_tx: &Transaction,
    existing_tx: &Transaction,
    utxo_set: &UtxoSet,
    mempool: &Mempool,
) -> Result<bool> {
    // Precondition checks: Validate function inputs
    // Note: We check these conditions and return an error rather than asserting,
    // to allow tests to verify the validation logic properly
    // Bitcoin requires transactions to have both inputs and outputs (except coinbase)
    if new_tx.inputs.is_empty() && new_tx.outputs.is_empty() {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "New transaction must have at least one input or output"
                .to_string()
                .into(),
        ));
    }
    if existing_tx.inputs.is_empty() && existing_tx.outputs.is_empty() {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "Existing transaction must have at least one input or output"
                .to_string()
                .into(),
        ));
    }
    if is_coinbase(new_tx) {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "New transaction cannot be coinbase".to_string().into(),
        ));
    }
    if is_coinbase(existing_tx) {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "Existing transaction cannot be coinbase".to_string().into(),
        ));
    }
    if utxo_set.len() > u32::MAX as usize {
        return Err(crate::error::ConsensusError::BlockValidation(
            format!("UTXO set size {} exceeds maximum", utxo_set.len()).into(),
        ));
    }

    // 1. Check RBF signaling - existing transaction must signal RBF
    // Note: new_tx doesn't need to signal RBF per BIP125, only existing_tx does
    if !signals_rbf(existing_tx) {
        return Ok(false);
    }

    // 2. Check fee rate: FeeRate(tx_2) > FeeRate(tx_1)
    // Missing prevouts → reject replacement (fail-closed; not a soft Ok fee).
    let new_fee = match calculate_fee(new_tx, utxo_set) {
        Ok(f) => f,
        Err(crate::error::ConsensusError::UtxoNotFound(_)) => return Ok(false),
        Err(e) => return Err(e),
    };
    let existing_fee = match calculate_fee(existing_tx, utxo_set) {
        Ok(f) => f,
        Err(crate::error::ConsensusError::UtxoNotFound(_)) => return Ok(false),
        Err(e) => return Err(e),
    };
    use crate::constants::MAX_MONEY;
    if new_fee < 0 || existing_fee < 0 || new_fee > MAX_MONEY || existing_fee > MAX_MONEY {
        return Ok(false);
    }

    let new_tx_size = calculate_transaction_size_vbytes(new_tx);
    let existing_tx_size = calculate_transaction_size_vbytes(existing_tx);
    if new_tx_size == 0
        || existing_tx_size == 0
        || new_tx_size > MAX_TX_SIZE * 2
        || existing_tx_size > MAX_TX_SIZE * 2
    {
        return Ok(false);
    }

    // Use integer-based comparison to avoid floating-point precision issues
    // Compare: new_fee / new_tx_size > existing_fee / existing_tx_size
    // Equivalent to: new_fee * existing_tx_size > existing_fee * new_tx_size
    // This avoids floating-point division and precision errors

    // Use integer multiplication to avoid floating-point precision issues
    // Check: new_fee * existing_tx_size > existing_fee * new_tx_size
    let new_fee_scaled = (new_fee as u128)
        .checked_mul(existing_tx_size as u128)
        .ok_or_else(|| {
            ConsensusError::TransactionValidation("Fee rate calculation overflow".into())
        })?;
    let existing_fee_scaled = (existing_fee as u128)
        .checked_mul(new_tx_size as u128)
        .ok_or_else(|| {
            ConsensusError::TransactionValidation("Fee rate calculation overflow".into())
        })?;

    if new_fee_scaled <= existing_fee_scaled {
        return Ok(false);
    }

    // 3. Check absolute fee bump: Fee(tx_2) > Fee(tx_1) + MIN_RELAY_FEE
    if new_fee <= existing_fee + MIN_RELAY_FEE {
        return Ok(false);
    }

    // 4. Check conflict: tx_2 must spend at least one input from tx_1
    if !has_conflict_with_tx(new_tx, existing_tx) {
        return Ok(false);
    }

    // 5. Check for new unconfirmed dependencies
    // All inputs of tx_2 must be confirmed (in UTXO set) or from tx_1
    if creates_new_dependencies(new_tx, existing_tx, utxo_set, mempool)? {
        return Ok(false);
    }

    Ok(true)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Mempool data structure: transaction IDs plus outpoints spent by those transactions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mempool {
    txids: HashSet<Hash>,
    spent_outpoints: HashSet<OutPoint>,
    /// Spent outpoints per txid (populated by [`insert_transaction`](Self::insert_transaction)).
    tx_spent_outpoints: HashMap<Hash, Vec<OutPoint>>,
    /// Aggregate virtual size of indexed transactions (vbytes).
    total_vbytes: usize,
    /// Per-txid vbytes (populated by [`insert_transaction`](Self::insert_transaction)).
    tx_vsizes: HashMap<Hash, usize>,
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a transaction ID only (does not register spent outpoints).
    ///
    /// Prefer [`insert_transaction`](Self::insert_transaction) when the full transaction is
    /// available — conflict detection requires outpoint indexing.
    pub fn insert(&mut self, txid: Hash) -> bool {
        self.txids.insert(txid)
    }

    /// Register a transaction and index its spent inputs for conflict detection.
    pub fn insert_transaction(&mut self, tx: &Transaction) -> bool {
        let txid = crate::block::calculate_tx_id(tx);
        if !self.txids.insert(txid) {
            return false;
        }
        let vsize = calculate_transaction_size_vbytes(tx);
        self.total_vbytes = self.total_vbytes.saturating_add(vsize);
        self.tx_vsizes.insert(txid, vsize);
        let mut outpoints = Vec::with_capacity(tx.inputs.len());
        if !is_coinbase(tx) {
            for input in &tx.inputs {
                self.spent_outpoints.insert(input.prevout);
                outpoints.push(input.prevout);
            }
        }
        self.tx_spent_outpoints.insert(txid, outpoints);
        true
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txids.contains(txid)
    }

    pub fn spends_outpoint(&self, outpoint: &OutPoint) -> bool {
        self.spent_outpoints.contains(outpoint)
    }

    pub fn remove(&mut self, txid: &Hash) -> bool {
        if !self.txids.remove(txid) {
            return false;
        }
        if let Some(vsize) = self.tx_vsizes.remove(txid) {
            self.total_vbytes = self.total_vbytes.saturating_sub(vsize);
        }
        if let Some(outpoints) = self.tx_spent_outpoints.remove(txid) {
            for op in outpoints {
                self.spent_outpoints.remove(&op);
            }
        }
        true
    }

    /// Remove mempool entries that spend any of the given outpoints (e.g. after block connect).
    pub fn remove_spending_any(&mut self, outpoints: &HashSet<OutPoint>) -> Vec<Hash> {
        if outpoints.is_empty() {
            return Vec::new();
        }
        let to_remove: Vec<Hash> = self
            .tx_spent_outpoints
            .iter()
            .filter(|(_, ops)| ops.iter().any(|op| outpoints.contains(op)))
            .map(|(id, _)| *id)
            .collect();
        let mut removed = Vec::new();
        for id in to_remove {
            if self.remove(&id) {
                removed.push(id);
            }
        }
        removed
    }

    pub fn len(&self) -> usize {
        self.txids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txids.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Hash> {
        self.txids.iter()
    }

    pub fn clear(&mut self) {
        self.txids.clear();
        self.spent_outpoints.clear();
        self.tx_spent_outpoints.clear();
        self.total_vbytes = 0;
        self.tx_vsizes.clear();
    }

    /// Total virtual size of transactions indexed via [`insert_transaction`](Self::insert_transaction).
    pub fn total_vbytes(&self) -> usize {
        self.total_vbytes
    }
}

/// Returns true when adding `additional_vsize` would meet or exceed pool limits.
pub(crate) fn mempool_size_limits_exceeded(
    mempool: &Mempool,
    additional_vsize: usize,
    max_txs: usize,
    max_bytes: usize,
) -> bool {
    if mempool.len() >= max_txs {
        return true;
    }
    max_bytes > 0 && mempool.total_vbytes().saturating_add(additional_vsize) > max_bytes
}

/// Result of mempool acceptance
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolResult {
    Accepted,
    Rejected(String),
}

/// Update mempool after block connection
///
/// Removes transactions that were included in the block and transactions
/// that became invalid due to spent inputs.
///
/// This function should be called after successfully connecting a block
/// to keep the mempool synchronized with the blockchain state.
///
/// # Arguments
///
/// * `mempool` - Mutable reference to the mempool
/// * `block` - The block that was just connected
/// * `utxo_set` - The updated UTXO set after block connection
///
/// # Returns
///
/// Returns a vector of transaction IDs that were removed from the mempool.
///
/// # Example
///
/// ```rust
/// use blvm_consensus::mempool::{Mempool, update_mempool_after_block};
/// use blvm_consensus::block::{connect_block, BlockValidationContext};
/// use blvm_consensus::ValidationResult;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use blvm_consensus::types::*;
/// # use blvm_consensus::mining::calculate_merkle_root;
/// # let coinbase_tx = Transaction {
/// #     version: 1,
/// #     inputs: vec![TransactionInput {
/// #         prevout: OutPoint { hash: [0; 32].into(), index: 0xffffffff },
/// #         script_sig: vec![],
/// #         sequence: 0xffffffff,
/// #     }].into(),
/// #     outputs: vec![TransactionOutput { value: 5000000000, script_pubkey: vec![].into() }].into(),
/// #     lock_time: 0,
/// # };
/// # let merkle_root = calculate_merkle_root(&[coinbase_tx.clone()]).unwrap();
/// # let block = Block {
/// #     header: BlockHeader {
/// #         version: 1, prev_block_hash: [0; 32], merkle_root,
/// #         timestamp: 1234567890, bits: 0x1d00ffff, nonce: 0,
/// #     },
/// #     transactions: vec![coinbase_tx].into(),
/// # };
/// // One `Vec<Witness>` per tx; coinbase has one input → one empty witness stack.
/// # let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> = vec![vec![vec![]]];
/// # let mut utxo_set = UtxoSet::default();
/// # let height = 0;
/// # let mut mempool = Mempool::new();
/// let ctx = BlockValidationContext::for_network(Network::Regtest);
/// let (result, new_utxo_set, _) = connect_block(&block, &witnesses, utxo_set, height, &ctx)?;
/// if matches!(result, ValidationResult::Valid) {
///     let removed = update_mempool_after_block(&mut mempool, &block, &new_utxo_set)?;
///     println!("Removed {} transactions from mempool", removed.len());
/// }
/// # Ok(())
/// # }
/// ```
pub fn update_mempool_after_block(
    mempool: &mut Mempool,
    block: &crate::types::Block,
    _utxo_set: &crate::types::UtxoSet,
) -> Result<Vec<Hash>> {
    let mut removed = Vec::new();

    // 1. Remove transactions that were included in the block
    for tx in &block.transactions {
        let tx_id = crate::block::calculate_tx_id(tx);
        if mempool.remove(&tx_id) {
            removed.push(tx_id);
        }
    }

    // 2. Remove mempool txs that spend inputs consumed by the block (outpoint index).
    let mut spent_by_block = HashSet::new();
    for tx in &block.transactions {
        if !is_coinbase(tx) {
            for input in &tx.inputs {
                spent_by_block.insert(input.prevout);
            }
        }
    }
    removed.extend(mempool.remove_spending_any(&spent_by_block));

    Ok(removed)
}

/// Update mempool after block connection (with transaction lookup)
///
/// This is a more complete version that can check if mempool transactions
/// became invalid. Requires a way to look up transactions by ID.
///
/// # Arguments
///
/// * `mempool` - Mutable reference to the mempool
/// * `block` - The block that was just connected
/// * `get_tx_by_id` - Function to look up transactions by ID
///
/// # Returns
///
/// Returns a vector of transaction IDs that were removed from the mempool.
pub fn update_mempool_after_block_with_lookup<F>(
    mempool: &mut Mempool,
    block: &crate::types::Block,
    get_tx_by_id: F,
) -> Result<Vec<Hash>>
where
    F: Fn(&Hash) -> Option<crate::types::Transaction>,
{
    let mut removed = Vec::new();

    // 1. Remove transactions that were included in the block
    for tx in &block.transactions {
        let tx_id = crate::block::calculate_tx_id(tx);
        if mempool.remove(&tx_id) {
            removed.push(tx_id);
        }
    }

    // 2. Remove transactions that became invalid (inputs were spent by block)
    // Collect spent outpoints from the block
    let mut spent_outpoints = std::collections::HashSet::new();
    for tx in &block.transactions {
        if !crate::transaction::is_coinbase(tx) {
            for input in &tx.inputs {
                spent_outpoints.insert(input.prevout);
            }
        }
    }

    // Check each mempool transaction to see if it spends any of the spent outpoints
    let mut invalid_tx_ids = Vec::new();
    for &tx_id in mempool.iter() {
        if let Some(tx) = get_tx_by_id(&tx_id) {
            // Check if any input of this transaction was spent by the block
            for input in &tx.inputs {
                if spent_outpoints.contains(&input.prevout) {
                    invalid_tx_ids.push(tx_id);
                    break;
                }
            }
        }
    }

    // Remove invalid transactions
    for tx_id in invalid_tx_ids {
        if mempool.remove(&tx_id) {
            removed.push(tx_id);
        }
    }

    Ok(removed)
}

/// Check mempool-specific rules (relay policy).
#[spec_locked("9.1", "CheckMempoolRules")]
pub(crate) fn check_mempool_rules(
    tx: &Transaction,
    fee: Integer,
    mempool: &Mempool,
) -> Result<bool> {
    // Check minimum fee rate and pool size using integer sat/vB math (no f64 compare).
    let vsize = calculate_transaction_size_vbytes(tx);
    if vsize == 0 {
        return Ok(false);
    }

    let config = crate::config::get_consensus_config_ref();
    let min_fee_rate = config.mempool.min_relay_fee_rate;
    let min_tx_fee = config.mempool.min_tx_fee;

    if fee < min_tx_fee {
        return Ok(false);
    }

    let required_fee = (min_fee_rate as u128).saturating_mul(vsize as u128);
    if (fee as u128) < required_fee {
        return Ok(false);
    }

    let max_bytes = (config.mempool.max_mempool_mb as usize).saturating_mul(1_000_000);
    if mempool_size_limits_exceeded(mempool, vsize, config.mempool.max_mempool_txs, max_bytes) {
        return Ok(false);
    }

    Ok(true)
}

/// Check for transaction conflicts
fn has_conflicts(tx: &Transaction, mempool: &Mempool) -> Result<bool> {
    for input in &tx.inputs {
        if mempool.spends_outpoint(&input.prevout) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verify all input scripts using the full witness-aware API (same path as block connect).
fn verify_mempool_scripts(
    tx: &Transaction,
    witnesses: Option<&[Witness]>,
    utxo_set: &UtxoSet,
    height: Natural,
    _time_context: Option<TimeContext>,
    flags: u32,
    network: Network,
) -> Result<Option<String>> {
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if let Some(utxo) = utxo_set.get(&input.prevout) {
            prevouts.push(TransactionOutput {
                value: utxo.value,
                script_pubkey: utxo.script_pubkey.as_ref().to_vec(),
            });
        } else {
            prevouts.push(TransactionOutput {
                value: 0,
                script_pubkey: ByteString::new(),
            });
        }
    }

    for (i, input) in tx.inputs.iter().enumerate() {
        let Some(utxo) = utxo_set.get(&input.prevout) else {
            continue;
        };
        let witness = witnesses.and_then(|wits| wits.get(i));
        let is_valid = verify_script_with_context(
            &input.script_sig,
            utxo.script_pubkey.as_ref(),
            witness,
            flags,
            tx,
            i,
            &prevouts,
            Some(height),
            network,
        )?;
        if !is_valid {
            return Ok(Some(format!("Invalid script at input {i}")));
        }
    }

    Ok(None)
}

/// Whether an unconfirmed input is allowed when replacing `existing_tx` (BIP125 rule 5).
fn input_allowed_for_replacement(
    input: &TransactionInput,
    existing_tx: &Transaction,
    utxo_set: &UtxoSet,
) -> bool {
    if utxo_set.contains_key(&input.prevout) {
        return true;
    }
    if existing_tx
        .inputs
        .iter()
        .any(|existing_input| existing_input.prevout == input.prevout)
    {
        return true;
    }
    let existing_id = crate::block::calculate_tx_id(existing_tx);
    (input.prevout.hash == existing_id)
        && ((input.prevout.index as usize) < existing_tx.outputs.len())
}

/// Check if transaction is final (Orange Paper Section 9.1 - Transaction Finality)
///
/// IsFinalTx — locktime/sequence validation (BIP65/68).
///
/// A transaction is final if:
/// 1. tx.lock_time == 0 (no locktime restriction), OR
/// 2. If locktime < LOCKTIME_THRESHOLD (block height): height > tx.lock_time
/// 3. If locktime >= LOCKTIME_THRESHOLD (timestamp): block_time > tx.lock_time
/// 4. OR if all inputs have SEQUENCE_FINAL (0xffffffff), locktime is ignored
///
/// Mathematical specification:
/// ∀ tx ∈ Transaction, height ∈ ℕ, block_time ∈ ℕ:
/// - is_final_tx(tx, height, block_time) = true ⟹
///   (tx.lock_time = 0 ∨
///   (tx.lock_time < LOCKTIME_THRESHOLD ∧ height > tx.lock_time) ∨
///   (tx.lock_time >= LOCKTIME_THRESHOLD ∧ block_time > tx.lock_time) ∨
///   (∀ input ∈ tx.inputs: input.sequence == SEQUENCE_FINAL))
///
/// Check if transaction is final (Orange Paper Section 9.1 - Transaction Finality)
///
/// IsFinalTx — locktime/sequence validation (BIP65/68).
///
/// A transaction is final if:
/// 1. tx.lock_time == 0 (no locktime restriction), OR
/// 2. If locktime < LOCKTIME_THRESHOLD (block height): height > tx.lock_time
/// 3. If locktime >= LOCKTIME_THRESHOLD (timestamp): block_time > tx.lock_time
/// 4. OR if all inputs have SEQUENCE_FINAL (0xffffffff), locktime is ignored
///
/// Mathematical specification:
/// ∀ tx ∈ Transaction, height ∈ ℕ, block_time ∈ ℕ:
/// - is_final_tx(tx, height, block_time) = true ⟹
///   (tx.lock_time = 0 ∨
///   (tx.lock_time < LOCKTIME_THRESHOLD ∧ height > tx.lock_time) ∨
///   (tx.lock_time >= LOCKTIME_THRESHOLD ∧ block_time > tx.lock_time) ∨
///   (∀ input ∈ tx.inputs: input.sequence == SEQUENCE_FINAL))
///
/// # Arguments
/// * `tx` - Transaction to check
/// * `height` - Current block height
/// * `block_time` - Median time-past of chain tip (BIP113) for timestamp locktime validation
#[spec_locked("9.1.1", "CheckFinalTxAtTip")]
pub fn is_final_tx(tx: &Transaction, height: Natural, block_time: Natural) -> bool {
    use crate::constants::SEQUENCE_FINAL;

    // If locktime is 0, transaction is always final
    if tx.lock_time == 0 {
        return true;
    }

    // Check if locktime is satisfied based on type
    // If locktime < threshold, compare to block height; else compare to block time
    // This means: locktime < (condition ? height : block_time)
    // So: if locktime < threshold, check locktime < height
    //     if locktime >= threshold, check locktime < block_time
    let locktime_satisfied = if (tx.lock_time as u32) < LOCKTIME_THRESHOLD {
        // Block height locktime: check if locktime < height
        (tx.lock_time as Natural) < height
    } else {
        // Timestamp locktime: check if locktime < block_time
        (tx.lock_time as Natural) < block_time
    };

    if locktime_satisfied {
        return true;
    }

    // Even if locktime isn't satisfied, transaction is final if all inputs have SEQUENCE_FINAL
    // This allows transactions to bypass locktime by setting all sequences to 0xffffffff
    // If all inputs have SEQUENCE_FINAL, locktime is ignored
    for input in &tx.inputs {
        if (input.sequence as u32) != SEQUENCE_FINAL {
            return false;
        }
    }

    // All inputs have SEQUENCE_FINAL - transaction is final regardless of locktime
    true
}

/// Check if transaction signals RBF
///
/// Returns true if any input has nSequence < SEQUENCE_FINAL (0xffffffff)
#[spec_locked("9.3", "SignalsRBF")]
pub fn signals_rbf(tx: &Transaction) -> bool {
    for input in &tx.inputs {
        if (input.sequence as u32) < SEQUENCE_FINAL {
            return true;
        }
    }
    false
}

/// Calculate transaction size in virtual bytes (vbytes)
///
/// Uses BIP141 weight/4 when weight can be computed; otherwise falls back to stripped size.
fn calculate_transaction_size_vbytes(tx: &Transaction) -> usize {
    use crate::segwit::calculate_transaction_weight;
    use crate::witness::weight_to_vsize;
    match calculate_transaction_weight(tx, None) {
        Ok(weight) => weight_to_vsize(weight) as usize,
        Err(_) => calculate_transaction_size(tx),
    }
}

/// Check if new transaction conflicts with existing transaction
///
/// A conflict exists if new_tx spends at least one input from existing_tx.
/// This is requirement #4 of BIP125.
#[spec_locked("9.3", "HasConflictWithTx")]
pub fn has_conflict_with_tx(new_tx: &Transaction, existing_tx: &Transaction) -> bool {
    for new_input in &new_tx.inputs {
        for existing_input in &existing_tx.inputs {
            if new_input.prevout == existing_input.prevout {
                return true;
            }
        }
    }
    false
}

/// Check if new transaction creates new unconfirmed dependencies
///
/// BIP125 requirement #5: All inputs of tx_2 must be:
/// - Confirmed (in UTXO set), OR
/// - From tx_1 (spending the same inputs)
#[spec_locked("9.3", "CreatesNewDependencies")]
pub(crate) fn creates_new_dependencies(
    new_tx: &Transaction,
    existing_tx: &Transaction,
    utxo_set: &UtxoSet,
    _mempool: &Mempool,
) -> Result<bool> {
    for input in &new_tx.inputs {
        // Check if input is confirmed (in UTXO set)
        if utxo_set.contains_key(&input.prevout) {
            continue;
        }

        // Check if input was spent by existing transaction
        let mut found_in_existing = false;
        for existing_input in &existing_tx.inputs {
            if existing_input.prevout == input.prevout {
                found_in_existing = true;
                break;
            }
        }

        if found_in_existing {
            continue;
        }

        if input_allowed_for_replacement(input, existing_tx, utxo_set) {
            continue;
        }

        return Ok(true);
    }

    Ok(false)
}

/// Advance past one opcode + push data in a script (for policy scanning).
fn script_opcode_advance(script: &[u8], pc: usize) -> usize {
    let opcode = script[pc];
    match opcode {
        0x01..=0x4b => 1 + opcode as usize,
        0x4c => {
            if pc + 1 < script.len() {
                2 + script[pc + 1] as usize
            } else {
                1
            }
        }
        0x4d => {
            if pc + 2 < script.len() {
                3 + u16::from_le_bytes([script[pc + 1], script[pc + 2]]) as usize
            } else {
                1
            }
        }
        0x4e => {
            if pc + 4 < script.len() {
                5 + u32::from_le_bytes([
                    script[pc + 1],
                    script[pc + 2],
                    script[pc + 3],
                    script[pc + 4],
                ]) as usize
            } else {
                1
            }
        }
        _ => 1,
    }
}

/// Disabled opcodes that make a scriptPubKey non-standard (mempool policy).
#[inline]
fn is_disabled_policy_opcode(opcode: u8) -> bool {
    use crate::opcodes::{
        OP_2DIV, OP_2MUL, OP_AND, OP_CAT, OP_DIV, OP_INVERT, OP_LEFT, OP_LSHIFT, OP_MOD, OP_MUL,
        OP_OR, OP_RIGHT, OP_RSHIFT, OP_SUBSTR, OP_VER, OP_VERIF, OP_VERNOTIF, OP_XOR,
    };
    matches!(
        opcode,
        OP_VER
            | OP_VERIF
            | OP_VERNOTIF
            | OP_CAT
            | OP_SUBSTR
            | OP_LEFT
            | OP_RIGHT
            | OP_INVERT
            | OP_AND
            | OP_OR
            | OP_XOR
            | OP_2MUL
            | OP_2DIV
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_LSHIFT
            | OP_RSHIFT
    )
}

/// Check if script is standard
#[spec_locked("9.1", "IsStandardScript")]
pub(crate) fn is_standard_script(script: &ByteString) -> Result<bool> {
    if script.is_empty() {
        return Ok(false);
    }

    if script.len() > MAX_SCRIPT_SIZE {
        return Ok(false);
    }

    // OP_RETURN (0x6a) outputs are standard and allowed (with size constraints).
    // An OP_RETURN script is recognized by its first byte being 0x6a.
    if script[0] == 0x6a {
        // OP_RETURN outputs are standard up to 83 bytes total (1 opcode + 1 push + 80 data).
        return Ok(script.len() <= 83);
    }

    // Walk opcodes (skip push payloads) and reject disabled / reserved opcodes.
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];
        if is_disabled_policy_opcode(opcode) {
            return Ok(false);
        }
        let advance = script_opcode_advance(script, pc);
        if advance == 0 {
            break;
        }
        pc += advance;
    }

    Ok(true)
}

/// Calculate transaction ID (deprecated - use crate::block::calculate_tx_id instead)
///
/// This function is kept for backward compatibility but delegates to the
/// standard implementation in block.rs.
#[deprecated(note = "Use crate::block::calculate_tx_id instead")]
#[spec_locked("5.1", "CalculateTxId")]
pub fn calculate_tx_id(tx: &Transaction) -> Hash {
    crate::block::calculate_tx_id(tx)
}

/// Transaction size in bytes (consensus serialization, no witness).
///
/// Delegates to `transaction::calculate_transaction_size` for consistency with block weight checks.
fn calculate_transaction_size(tx: &Transaction) -> usize {
    use crate::transaction::calculate_transaction_size as tx_size;
    tx_size(tx)
}

/// Check if transaction is coinbase
fn is_coinbase(tx: &Transaction) -> bool {
    // Optimization: Use constant folding for zero hash check
    #[cfg(feature = "production")]
    {
        use crate::optimizations::constant_folding::is_zero_hash;
        tx.inputs.len() == 1
            && is_zero_hash(&tx.inputs[0].prevout.hash)
            && tx.inputs[0].prevout.index == 0xffffffff
    }

    #[cfg(not(feature = "production"))]
    {
        tx.inputs.len() == 1
            && tx.inputs[0].prevout.hash == [0u8; 32]
            && tx.inputs[0].prevout.index == 0xffffffff
    }
}

// ============================================================================
// FORMAL VERIFICATION
// ============================================================================

/// Mathematical Specification for Mempool:
/// ∀ tx ∈ 𝒯𝒳, utxo_set ∈ 𝒰𝒮, mempool ∈ Mempool:
/// - accept_to_memory_pool(tx, utxo_set, mempool, height, time_context, network) = Accepted ⟹
///   (tx ∉ mempool ∧
///    CheckTransaction(tx) = valid ∧
///    CheckTxInputs(tx, utxo_set) = valid ∧
///    VerifyScripts(tx) = valid ∧
///    ¬has_conflicts(tx, mempool))
///
/// Invariants:
/// - Mempool never contains duplicate transactions
/// - Mempool never contains conflicting transactions
/// - Accepted transactions are valid
/// - RBF rules are enforced

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::*;

    #[test]
    fn test_accept_to_memory_pool_valid() {
        // Skip script validation for now - focus on mempool logic
        let tx = create_valid_transaction();
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        // Script: sig=OP_1, spk=OP_1 (UTXO). Stack after: [[1],[1]], top truthy → Accepted.
        let time_context = Some(TimeContext {
            network_time: 1234567890,
            median_time_past: 1234567890,
        });
        let result = accept_to_memory_pool(
            &tx,
            None,
            &utxo_set,
            &mempool,
            100,
            time_context,
            Network::Mainnet,
        )
        .unwrap();
        assert!(matches!(result, MempoolResult::Accepted));
    }

    #[test]
    fn test_accept_to_memory_pool_duplicate() {
        let tx = create_valid_transaction();
        let utxo_set = create_test_utxo_set();
        let mut mempool = Mempool::new();
        mempool.insert(crate::block::calculate_tx_id(&tx));

        let time_context = Some(TimeContext {
            network_time: 1234567890,
            median_time_past: 1234567890,
        });
        let result = accept_to_memory_pool(
            &tx,
            None,
            &utxo_set,
            &mempool,
            100,
            time_context,
            Network::Mainnet,
        )
        .unwrap();
        assert!(matches!(result, MempoolResult::Rejected(_)));
    }

    #[test]
    fn test_is_standard_tx_valid() {
        let tx = create_valid_transaction();
        assert!(is_standard_tx(&tx).unwrap());
    }

    #[test]
    fn test_is_standard_tx_too_large() {
        let mut tx = create_valid_transaction();
        // Make transaction too large by adding many inputs
        // MAX_INPUTS (100,000) * ~42 bytes/input >> MAX_TX_SIZE (1,000,000)
        for _ in 0..MAX_INPUTS {
            tx.inputs.push(create_dummy_input());
        }
        // Transaction exceeds MAX_TX_SIZE so it should NOT be standard
        assert!(!is_standard_tx(&tx).unwrap());
    }

    #[test]
    fn test_replacement_checks_all_requirements() {
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        // Create existing transaction with RBF signaling and lower fee
        let mut existing_tx = create_valid_transaction();
        existing_tx.inputs[0].sequence = SEQUENCE_RBF as u64;
        existing_tx.outputs[0].value = 9000; // Fee = 10000 - 9000 = 1000 sats

        // Create new transaction that:
        // 1. Signals RBF (or doesn't - per BIP125 only existing needs to signal)
        // 2. Conflicts with existing (same input)
        // 3. Has higher fee rate and absolute fee
        let mut new_tx = existing_tx.clone();
        new_tx.outputs[0].value = 8000; // Fee = 10000 - 8000 = 2000 sats
        // Higher fee rate and absolute fee bump (2000 > 1000 + 1000 = 2000, needs >)
        new_tx.outputs[0].value = 7999; // Fee = 10000 - 7999 = 2001 sats

        // Should pass all BIP125 checks
        let result = replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap();
        assert!(result, "Valid RBF replacement should be accepted");
    }

    #[test]
    fn test_replacement_checks_no_rbf_signal() {
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        let new_tx = create_valid_transaction();
        let existing_tx = create_valid_transaction(); // No RBF signal

        // Should fail: existing transaction doesn't signal RBF
        assert!(!replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap());
    }

    #[test]
    fn test_replacement_checks_no_conflict() {
        let mut utxo_set = create_test_utxo_set();
        // Add UTXO for the new transaction's input
        let new_outpoint = OutPoint {
            hash: [2; 32],
            index: 0,
        };
        let new_utxo = UTXO {
            value: 10000,
            script_pubkey: vec![OP_1].into(),
            height: 0,
            is_coinbase: false,
        };
        utxo_set.insert(new_outpoint, std::sync::Arc::new(new_utxo));

        let mempool = Mempool::new();

        let mut existing_tx = create_valid_transaction();
        existing_tx.inputs[0].sequence = SEQUENCE_RBF as u64;

        // New transaction with different input (no conflict)
        let mut new_tx = create_valid_transaction();
        new_tx.inputs[0].prevout.hash = [2; 32]; // Different input
        new_tx.inputs[0].sequence = SEQUENCE_RBF as u64;
        // Ensure output value doesn't exceed input value to avoid negative fee
        new_tx.outputs[0].value = 5000; // Less than input value of 10000

        // Should fail: no conflict (requirement #4)
        assert!(!replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap());
    }

    #[test]
    fn test_replacement_checks_fee_rate_too_low() {
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        // Existing transaction with higher fee rate
        let mut existing_tx = create_valid_transaction();
        existing_tx.inputs[0].sequence = SEQUENCE_RBF as u64;
        existing_tx.outputs[0].value = 5000; // Fee = 5000 sats, size = small

        // New transaction with same or lower fee rate (but higher absolute fee)
        let mut new_tx = existing_tx.clone();
        new_tx.outputs[0].value = 4999; // Fee = 5001 sats, but same size so same fee rate

        // Should fail: fee rate not higher (requirement #2)
        assert!(!replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap());
    }

    #[test]
    fn test_replacement_checks_absolute_fee_insufficient() {
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        // Existing transaction
        let mut existing_tx = create_valid_transaction();
        existing_tx.inputs[0].sequence = SEQUENCE_RBF as u64;
        existing_tx.outputs[0].value = 9000; // Fee = 1000 sats

        // New transaction with higher fee rate but insufficient absolute fee bump
        // Fee must be > 1000 + 1000 = 2000, so need > 2000
        let mut new_tx = existing_tx.clone();
        new_tx.outputs[0].value = 8001; // Fee = 1999 sats (insufficient)

        // Should fail: absolute fee not high enough (requirement #3)
        assert!(!replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap());

        // Now with sufficient fee
        new_tx.outputs[0].value = 7999; // Fee = 2001 sats (sufficient)
        // Should still fail on other checks (conflict, etc.), but fee check passes
        // For full test, need to ensure conflict exists
    }

    // ============================================================================
    // COMPREHENSIVE MEMPOOL TESTS
    // ============================================================================

    #[test]
    fn test_accept_to_memory_pool_coinbase() {
        let coinbase_tx = create_coinbase_transaction();
        let utxo_set = UtxoSet::default();
        let mempool = Mempool::new();
        // Coinbase transactions should be rejected from mempool
        let time_context = Some(TimeContext {
            network_time: 0,
            median_time_past: 0,
        });
        let result = accept_to_memory_pool(
            &coinbase_tx,
            None,
            &utxo_set,
            &mempool,
            100,
            time_context,
            Network::Mainnet,
        )
        .unwrap();
        assert!(matches!(result, MempoolResult::Rejected(_)));
    }

    #[test]
    fn test_is_standard_tx_large_script() {
        let mut tx = create_valid_transaction();
        // Create a script that's too large
        tx.inputs[0].script_sig = vec![OP_1; MAX_SCRIPT_SIZE + 1];

        let result = is_standard_tx(&tx).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_is_standard_tx_large_output_script() {
        let mut tx = create_valid_transaction();
        // Create an output script that's too large
        tx.outputs[0].script_pubkey = vec![OP_1; MAX_SCRIPT_SIZE + 1];

        let result = is_standard_tx(&tx).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_replacement_checks_new_unconfirmed_dependency() {
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        // Existing transaction
        let mut existing_tx = create_valid_transaction();
        existing_tx.inputs[0].sequence = SEQUENCE_RBF as u64;

        // New transaction that adds a new unconfirmed input
        let mut new_tx = existing_tx.clone();
        new_tx.inputs.push(TransactionInput {
            prevout: OutPoint {
                hash: [99; 32],
                index: 0,
            }, // Not in UTXO set
            script_sig: vec![],
            sequence: SEQUENCE_RBF as u64,
        });
        new_tx.outputs[0].value = 7000; // Higher fee

        // Should fail: creates new unconfirmed dependency (requirement #5)
        assert!(!replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap());
    }

    #[test]
    fn test_has_conflict_with_tx_true() {
        let tx1 = create_valid_transaction();
        let mut tx2 = create_valid_transaction();
        tx2.inputs[0].prevout = tx1.inputs[0].prevout; // Same input = conflict

        assert!(has_conflict_with_tx(&tx2, &tx1));
    }

    #[test]
    fn test_has_conflict_with_tx_false() {
        let tx1 = create_valid_transaction();
        let mut tx2 = create_valid_transaction();
        tx2.inputs[0].prevout.hash = [2; 32]; // Different input = no conflict

        assert!(!has_conflict_with_tx(&tx2, &tx1));
    }

    #[test]
    fn test_replacement_checks_minimum_relay_fee() {
        let utxo_set = create_test_utxo_set();
        let mempool = Mempool::new();

        // Existing transaction
        let mut existing_tx = create_valid_transaction();
        existing_tx.inputs[0].sequence = SEQUENCE_RBF as u64;
        existing_tx.outputs[0].value = 9500; // Fee = 500 sats

        // New transaction with exactly MIN_RELAY_FEE bump (not enough, need >)
        let mut new_tx = existing_tx.clone();
        new_tx.outputs[0].value = 8500; // Fee = 1500 sats (1500 > 500 + 1000 = 1500? No, need >)
        assert!(!replacement_checks(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap());

        // New transaction with sufficient bump
        // Fee = 1501 sats (1501 > 500 + 1000 = 1500)
        // Conflict detection and fee rate validation are handled by accept_to_memory_pool
        new_tx.outputs[0].value = 8499;
    }

    #[test]
    fn test_check_mempool_rules_low_fee() {
        let tx = create_valid_transaction();
        let fee = 1; // Very low fee
        let mempool = Mempool::new();

        let result = check_mempool_rules(&tx, fee, &mempool).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_check_mempool_rules_high_fee() {
        let tx = create_valid_transaction();
        let fee = 10000; // High fee
        let mempool = Mempool::new();

        let result = check_mempool_rules(&tx, fee, &mempool).unwrap();
        assert!(result);
    }

    #[test]
    fn test_mempool_total_vbytes_tracking() {
        let mut mempool = Mempool::new();
        let tx = create_valid_transaction();
        let vsize = calculate_transaction_size_vbytes(&tx);
        let txid = crate::block::calculate_tx_id(&tx);

        mempool.insert_transaction(&tx);
        assert_eq!(mempool.total_vbytes(), vsize);

        mempool.remove(&txid);
        assert_eq!(mempool.total_vbytes(), 0);
    }

    #[test]
    fn test_mempool_byte_limit_exceeded() {
        let mut mempool = Mempool::new();
        let tx = create_valid_transaction();
        let vsize = calculate_transaction_size_vbytes(&tx);
        mempool.insert_transaction(&tx);

        let at_limit = mempool.total_vbytes();
        assert!(!mempool_size_limits_exceeded(
            &mempool, 0, 1_000_000, at_limit
        ));
        assert!(mempool_size_limits_exceeded(
            &mempool, 1, 1_000_000, at_limit
        ));
        assert!(!mempool_size_limits_exceeded(
            &mempool,
            vsize,
            1_000_000,
            at_limit.saturating_add(vsize)
        ));
    }

    #[test]
    fn test_check_mempool_rules_full_mempool() {
        let tx = create_valid_transaction();
        let fee = 10000;
        let mut mempool = Mempool::new();

        // Fill mempool to the tx-count limit (default max_mempool_txs is 100,000).
        for i in 0..100_000 {
            let mut hash = [0u8; 32];
            hash[0] = (i & 0xff) as u8;
            hash[1] = ((i >> 8) & 0xff) as u8;
            hash[2] = ((i >> 16) & 0xff) as u8;
            hash[3] = ((i >> 24) & 0xff) as u8;
            mempool.insert(hash);
        }

        assert_eq!(mempool.len(), 100_000);

        let result = check_mempool_rules(&tx, fee, &mempool).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_has_conflicts_no_conflicts() {
        let tx = create_valid_transaction();
        let mempool = Mempool::new();

        let result = has_conflicts(&tx, &mempool).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_has_conflicts_with_conflicts() {
        let tx = create_valid_transaction();
        let mut mempool = Mempool::new();

        // Add a conflicting transaction to mempool (same outpoint, different txid)
        let mut pool_tx = tx.clone();
        pool_tx.version = 2;
        mempool.insert_transaction(&pool_tx);

        let result = has_conflicts(&tx, &mempool).unwrap();
        assert!(result);
    }

    #[test]
    fn test_signals_rbf_true() {
        let mut tx = create_valid_transaction();
        tx.inputs[0].sequence = 0xfffffffe; // RBF signal

        assert!(signals_rbf(&tx));
    }

    #[test]
    fn test_signals_rbf_false() {
        let tx = create_valid_transaction(); // sequence = 0xffffffff (final)

        assert!(!signals_rbf(&tx));
    }

    #[test]
    fn test_calculate_fee_rate() {
        let tx = create_valid_transaction();
        let utxo_set = create_test_utxo_set();
        let fee = calculate_fee(&tx, &utxo_set);

        // Fee should be calculable (may be 0 for valid transactions)
        assert!(fee.is_ok());
    }

    #[test]
    fn test_creates_new_dependencies_no_new() {
        let new_tx = create_valid_transaction();
        let existing_tx = create_valid_transaction();
        let mempool = Mempool::new();

        let utxo_set = create_test_utxo_set();
        let result = creates_new_dependencies(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_creates_new_dependencies_with_new() {
        let mut new_tx = create_valid_transaction();
        let existing_tx = create_valid_transaction();
        let mempool = Mempool::new();

        // Make new_tx spend a different input
        new_tx.inputs[0].prevout.hash = [2; 32];

        let utxo_set = create_test_utxo_set();
        let result = creates_new_dependencies(&new_tx, &existing_tx, &utxo_set, &mempool).unwrap();
        assert!(result);
    }

    #[test]
    fn test_is_standard_script_empty() {
        let script = vec![];
        let result = is_standard_script(&script).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_is_standard_script_too_large() {
        let script = vec![OP_1; MAX_SCRIPT_SIZE + 1];
        let result = is_standard_script(&script).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_is_standard_script_non_standard_opcode() {
        let script = vec![OP_VERIF]; // Non-standard opcode (disabled)
        let result = is_standard_script(&script).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_is_standard_script_valid() {
        let script = vec![OP_1];
        let result = is_standard_script(&script).unwrap();
        assert!(result);
    }

    #[test]
    fn test_calculate_tx_id() {
        let tx = create_valid_transaction();
        let tx_id = crate::block::calculate_tx_id(&tx);

        // Should be a 32-byte hash
        assert_eq!(tx_id.len(), 32);

        // Same transaction should produce same ID
        let tx_id2 = crate::block::calculate_tx_id(&tx);
        assert_eq!(tx_id, tx_id2);
    }

    #[test]
    fn test_calculate_tx_id_different_txs() {
        let tx1 = create_valid_transaction();
        let mut tx2 = tx1.clone();
        tx2.version = 2; // Different version

        let id1 = crate::block::calculate_tx_id(&tx1);
        let id2 = crate::block::calculate_tx_id(&tx2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_calculate_transaction_size() {
        let tx = create_valid_transaction();
        let size = calculate_transaction_size(&tx);

        assert!(size > 0);

        // Size should be deterministic
        let size2 = calculate_transaction_size(&tx);
        assert_eq!(size, size2);
    }

    #[test]
    fn test_calculate_transaction_size_multiple_inputs_outputs() {
        let mut tx = create_valid_transaction();
        tx.inputs.push(create_dummy_input());
        tx.outputs.push(create_dummy_output());

        let size = calculate_transaction_size(&tx);
        assert!(size > 0);
    }

    #[test]
    fn test_is_coinbase_true() {
        let coinbase_tx = create_coinbase_transaction();
        assert!(is_coinbase(&coinbase_tx));
    }

    #[test]
    fn test_is_coinbase_false() {
        let regular_tx = create_valid_transaction();
        assert!(!is_coinbase(&regular_tx));
    }

    // Helper functions for tests
    fn create_valid_transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![create_dummy_input()].into(),
            outputs: vec![create_dummy_output()].into(),
            lock_time: 0,
        }
    }

    fn create_dummy_input() -> TransactionInput {
        TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }
    }

    fn create_dummy_output() -> TransactionOutput {
        TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1], // OP_1 for valid script
        }
    }

    fn create_test_utxo_set() -> UtxoSet {
        let mut utxo_set = UtxoSet::default();
        let outpoint = OutPoint {
            hash: [1; 32],
            index: 0,
        };
        let utxo = UTXO {
            value: 10000,
            script_pubkey: vec![OP_1].into(), // OP_1 for valid script
            height: 0,
            is_coinbase: false,
        };
        utxo_set.insert(outpoint, std::sync::Arc::new(utxo));
        utxo_set
    }

    fn create_coinbase_transaction() -> Transaction {
        Transaction {
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
        }
    }
}
