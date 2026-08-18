//! Apply block effects: apply_transaction, apply_transaction_with_id, calculate_tx_id.
//!
//! Clear "apply block effects" API; used by connect_block and external callers.

use crate::bip_validation::Bip30Index;
use crate::constants::MAX_MONEY;
use crate::error::Result;
use crate::reorganization::UndoEntry;
use crate::transaction::is_coinbase;
use crate::types::{Hash, Natural, OutPoint, Transaction, UTXO, UtxoSet};
use blvm_spec_lock::spec_locked;

/// ApplyTransaction (Orange Paper 5.3.2)
///
/// For transaction tx and UTXO set us:
/// 1. If tx is coinbase: us' = us ∪ {(tx.id, i) ↦ tx.outputs\[i\] : i ∈ \[0, |tx.outputs|)}
/// 2. Otherwise: us' = (us \ {i.prevout : i ∈ tx.inputs}) ∪ {(tx.id, i) ↦ tx.outputs\[i\] : i ∈ \[0, |tx.outputs|)}
/// 3. Return us'
///
/// This function computes the transaction ID internally.
/// For batch operations, use `apply_transaction_with_id` instead.
///
/// Returns both the new UTXO set and undo entries for all UTXO changes.
#[spec_locked("5.3.2", "ApplyTransaction")]
#[track_caller]
pub fn apply_transaction(
    tx: &Transaction,
    utxo_set: UtxoSet,
    height: Natural,
) -> Result<(UtxoSet, Vec<UndoEntry>)> {
    let tx_id = calculate_tx_id(tx);
    let mut no_index = None;
    apply_transaction_with_id(tx, tx_id, utxo_set, height, &mut no_index, true)
}

/// ApplyTransaction with pre-computed transaction ID
///
/// Same as `apply_transaction` but accepts a pre-computed transaction ID
/// to avoid redundant computation when transaction IDs are batch-computed.
///
/// Returns both the new UTXO set and undo entries for all UTXO changes.
/// When `bip30_index` is Some, updates it for coinbase add/remove (O(1) BIP30 checks).
#[spec_locked("5.3.2", "ApplyTransaction")]
pub(crate) fn apply_transaction_with_id(
    tx: &Transaction,
    tx_id: Hash,
    mut utxo_set: UtxoSet,
    height: Natural,
    bip30_index: &mut Option<&mut Bip30Index>,
    collect_undo: bool,
) -> Result<(UtxoSet, Vec<UndoEntry>)> {
    // Preconditions → Err (not panic): structure should have rejected these under AV=0;
    // under AV-skip IBD, apply is a fail-closed backstop.
    if tx.inputs.is_empty() && !is_coinbase(tx) {
        return Err(crate::error::ConsensusError::TransactionValidation(
            "Transaction must have inputs unless it's a coinbase".into(),
        ));
    }
    if tx.outputs.is_empty() {
        return Err(crate::error::ConsensusError::TransactionValidation(
            "Transaction must have at least one output".into(),
        ));
    }
    if height > i64::MAX as u64 {
        return Err(crate::error::ConsensusError::BlockValidation(
            format!("Block height {height} must fit in i64").into(),
        ));
    }

    let mut undo_entries = if collect_undo {
        Vec::with_capacity(tx.inputs.len().saturating_add(tx.outputs.len()))
    } else {
        Vec::new()
    };
    let initial_utxo_count = utxo_set.len();

    #[cfg(feature = "production")]
    {
        let estimated_new_size = utxo_set
            .len()
            .saturating_add(tx.outputs.len())
            .saturating_sub(if is_coinbase(tx) { 0 } else { tx.inputs.len() });
        if estimated_new_size > utxo_set.capacity() {
            utxo_set.reserve(estimated_new_size.saturating_sub(utxo_set.len()));
        }
    }

    if !is_coinbase(tx) {
        for input in &tx.inputs {
            if input.prevout.hash == [0u8; 32] && input.prevout.index == 0xffffffff {
                return Err(crate::error::ConsensusError::TransactionValidation(
                    "Prevout must be valid for non-coinbase input".into(),
                ));
            }

            if let Some(arc) = utxo_set.remove(&input.prevout) {
                let previous_utxo = arc.as_ref();
                if let Some(idx) = bip30_index.as_deref_mut() {
                    if previous_utxo.is_coinbase {
                        if let std::collections::hash_map::Entry::Occupied(mut o) =
                            idx.entry(input.prevout.hash)
                        {
                            *o.get_mut() = o.get().saturating_sub(1);
                            if *o.get() == 0 {
                                o.remove();
                            }
                        }
                    }
                }

                if previous_utxo.value < 0 || previous_utxo.value > MAX_MONEY {
                    return Err(crate::error::ConsensusError::EconomicValidation(
                        format!(
                            "Previous UTXO value {} must be in [0, MAX_MONEY]",
                            previous_utxo.value
                        )
                        .into(),
                    ));
                }

                if collect_undo {
                    undo_entries.push(UndoEntry {
                        outpoint: input.prevout,
                        previous_utxo: Some(std::sync::Arc::clone(&arc)),
                        new_utxo: None,
                    });
                }
            }
        }
    }

    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value < 0 || output.value > MAX_MONEY {
            return Err(crate::error::ConsensusError::EconomicValidation(
                format!("Output value {} must be in [0, MAX_MONEY]", output.value).into(),
            ));
        }

        let outpoint = OutPoint {
            hash: tx_id,
            index: i as u32,
        };

        let utxo = UTXO {
            value: output.value,
            script_pubkey: output.script_pubkey.as_slice().into(),
            height,
            is_coinbase: is_coinbase(tx),
        };

        let utxo_arc = std::sync::Arc::new(utxo);
        if collect_undo {
            undo_entries.push(UndoEntry {
                outpoint,
                previous_utxo: None,
                new_utxo: Some(std::sync::Arc::clone(&utxo_arc)),
            });
        }

        utxo_set.insert(outpoint, utxo_arc);

        if let Some(idx) = bip30_index.as_deref_mut() {
            if is_coinbase(tx) {
                *idx.entry(tx_id).or_insert(0) += 1;
            }
        }
    }

    if !is_coinbase(tx) {
        let current_count = utxo_set.len();
        let expected_count = initial_utxo_count
            .saturating_sub(tx.inputs.len())
            .saturating_add(tx.outputs.len());
        if current_count < expected_count {
            for (j, output) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    hash: tx_id,
                    index: j as u32,
                };
                utxo_set.entry(op).or_insert_with(|| {
                    let utxo = UTXO {
                        value: output.value,
                        script_pubkey: output.script_pubkey.as_slice().into(),
                        height,
                        is_coinbase: false,
                    };
                    std::sync::Arc::new(utxo)
                });
            }
        }
    }

    let final_utxo_count = utxo_set.len();
    if is_coinbase(tx) {
        if final_utxo_count < initial_utxo_count
            || final_utxo_count > initial_utxo_count + tx.outputs.len()
        {
            return Err(crate::error::ConsensusError::BlockValidation(
                format!(
                    "UTXO set size {final_utxo_count} out of range after coinbase (was {initial_utxo_count}, outputs {})",
                    tx.outputs.len()
                )
                .into(),
            ));
        }
    } else {
        let actual_change = final_utxo_count as i64 - initial_utxo_count as i64;
        let lower = -(tx.inputs.len() as i64);
        if actual_change < lower {
            return Err(crate::error::ConsensusError::BlockValidation(
                format!("UTXO set size change {actual_change} below lower bound {lower}").into(),
            ));
        }
    }
    if utxo_set.len() > u32::MAX as usize {
        return Err(crate::error::ConsensusError::BlockValidation(
            format!("UTXO set size {} must not exceed maximum", utxo_set.len()).into(),
        ));
    }

    Ok((utxo_set, undo_entries))
}

/// Calculate transaction ID using proper Bitcoin double SHA256
///
/// Transaction ID is SHA256(SHA256(serialized_tx)) where serialized_tx
/// is the transaction in Bitcoin wire format.
///
/// For batch operations, use serialize_transaction + batch_double_sha256 instead.
#[inline(always)]
#[spec_locked("5.1", "CalculateTxId")]
pub fn calculate_tx_id(tx: &Transaction) -> Hash {
    use crate::crypto::OptimizedSha256;
    use crate::serialization::transaction::serialize_transaction;

    let serialized = serialize_transaction(tx);
    OptimizedSha256::new().hash256(&serialized)
}
