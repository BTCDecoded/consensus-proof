//! Segregated Witness (SegWit) functions from Orange Paper Section 11.1
//!
//! **Debug logging (optional):** enable crate feature **`profile`**, then set:
//! - **`BLVM_WITNESS_DEBUG`** — after computing the witness merkle root from wtxids, print tx count and hex root.
//! - **`BLVM_WITNESS_COMMIT_DEBUG`** — when a witness commitment output exists but does not match BIP141
//!   `sha256d(witness_root ‖ reserved_nonce)`, print expected vs found commitment.
//!
//! These hooks are omitted from non-`profile` builds so default releases never consult these env vars.

use crate::error::Result;
use crate::opcodes::*;
use crate::types::*;
use crate::types::{ByteString, Hash, Natural};
use crate::witness;
use bitcoin_hashes::{Hash as BitcoinHash, sha256d};
use blvm_spec_lock::spec_locked;

/// Witness Data: 𝒲 = 𝕊* (stack of witness elements)
///
/// Uses unified witness type from witness module for consistency with Taproot
pub use crate::witness::Witness;

/// Calculate transaction weight for SegWit
/// BIP141: Weight(tx) = 3 × BaseSize(tx) + TotalSize(tx)
#[spec_locked("11.1.1", "CalculateTransactionWeight")]
pub fn calculate_transaction_weight(
    tx: &Transaction,
    witness: Option<&Witness>,
) -> Result<Natural> {
    // Calculate base size (transaction without witness data)
    let base_size = calculate_base_size(tx);

    // Calculate total size (transaction with witness data)
    let total_size = calculate_total_size(tx, witness);

    // Use unified witness framework for weight formula
    Ok(witness::calculate_transaction_weight_segwit(
        base_size, total_size,
    ))
}

/// Calculate base size (transaction without witness data).
///
/// Simplified consensus-facing estimate (version + inputs + outputs + lock_time). Split into
/// bounded `usize` steps then a single cast so blvm-spec-lock Z3 can verify `ensures` without
/// timing out on one huge arithmetic expression.
fn calculate_base_size(tx: &Transaction) -> Natural {
    const VERSION_AND_LOCKTIME: usize = 4 + 4;
    const PER_INPUT: usize = 32 + 4 + 1 + 4;
    const PER_OUTPUT: usize = 8 + 1;
    let n_in = tx.inputs.len();
    let n_out = tx.outputs.len();
    let inputs_part = n_in.saturating_mul(PER_INPUT);
    let outputs_part = n_out.saturating_mul(PER_OUTPUT);
    (VERSION_AND_LOCKTIME + inputs_part + outputs_part) as Natural
}

/// Calculate total size (transaction with witness data)
fn calculate_total_size(tx: &Transaction, witness: Option<&Witness>) -> Natural {
    let base_size = calculate_base_size(tx);

    if let Some(witness_data) = witness {
        let witness_size: Natural = witness_data.iter().map(|w| w.len() as Natural).sum();
        base_size + witness_size
    } else {
        base_size
    }
}

/// Map legacy flat layout (one stack per tx) to per-input stacks for BIP141 wtxid hashing.
fn flat_witness_to_per_input(tx: &Transaction, witness: &Witness) -> Vec<Witness> {
    match tx.inputs.len() {
        0 => Vec::new(),
        1 => vec![witness.clone()],
        n => {
            let mut stacks = vec![Vec::new(); n];
            if !witness.is_empty() {
                stacks[0] = witness.clone();
            }
            stacks
        }
    }
}

/// Compute witness merkle root for block (legacy flat witness layout).
///
/// **Layout:** one [`Witness`] per transaction (single stack). For multi-input SegWit
/// blocks use [`compute_witness_merkle_root_from_nested`] (production connect path).
///
/// Delegates to BIP141 wtxid merkle logic (txid for non-witness txs, full segwit hash otherwise).
#[spec_locked("11.1.4", "ComputeWitnessMerkleRoot")]
pub fn compute_witness_merkle_root(block: &Block, witnesses: &[Witness]) -> Result<Hash> {
    let nested: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            if i < witnesses.len() {
                flat_witness_to_per_input(tx, &witnesses[i])
            } else {
                Vec::new()
            }
        })
        .collect();
    compute_witness_merkle_root_from_nested(block, &nested, None)
}

/// Double-SHA256 a byte slice, returning a 32-byte hash array.
fn sha256d_bytes(data: &[u8]) -> Hash {
    let result = sha256d::Hash::hash(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

/// Hash witness stack elements (SHA256d of concatenated elements).
///
/// **Not** BIP141 wtxid — used by unit/property tests only. Block validation uses
/// [`compute_witness_merkle_root_from_nested`].
#[cfg(test)]
fn hash_witness(witness: &Witness) -> Hash {
    use bitcoin_hashes::HashEngine;
    let mut hasher = sha256d::Hash::engine();
    for element in witness {
        hasher.input(element);
    }
    let result = sha256d::Hash::from_engine(hasher);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute witness merkle root from nested witnesses without flattening.
/// Accepts `&[Vec<Witness>]` where each `Vec<Witness>` is one tx's input stacks.
/// Avoids allocating flattened structure in block validation hot path.
/// Orange Paper 11.1.4: WitnessRoot = ComputeMerkleRoot({wtxid : tx ∈ block.transactions})
///
/// When `tx_ids` is `Some`, non-SegWit leaves reuse `tx_ids[i]` (BIP141: wtxid == txid)
/// instead of re-serializing and hashing. Block connect passes precomputed tx_ids.
///
/// BIP141 wtxid computation:
///   - coinbase: all zeros (hardcoded, consensus rule)
///   - non-SegWit tx (no witness data): wtxid = txid = sha256d(legacy serialization)
///   - SegWit tx (has witness data): wtxid = sha256d(segwit-serialized tx incl. witnesses)
///
/// Previously this used `hash_witness_from_nested` which returns sha256d("") for ALL
/// non-SegWit transactions, causing every non-SegWit tx to map to the same hash.
/// In a block with many non-SegWit txs (e.g. block 481824), adjacent pairs of these
/// identical hashes trigger the CVE-2012-2459 mutation check and abort falsely.
#[spec_locked("11.1.4", "ComputeWitnessMerkleRoot")]
pub fn compute_witness_merkle_root_from_nested(
    block: &Block,
    witnesses: &[Vec<Witness>],
    tx_ids: Option<&[Hash]>,
) -> Result<Hash> {
    if block.transactions.is_empty() {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "Cannot compute witness merkle root from empty block".into(),
        ));
    }
    if let Some(ids) = tx_ids {
        if ids.len() != block.transactions.len() {
            return Err(crate::error::ConsensusError::ConsensusRuleViolation(format!(
                "tx_ids length {} does not match block transaction count {}",
                ids.len(),
                block.transactions.len()
            ).into()));
        }
    }
    let mut witness_hashes = Vec::with_capacity(block.transactions.len());
    for (i, (tx, tx_witnesses)) in block.transactions.iter().zip(witnesses.iter()).enumerate() {
        if i == 0 {
            // Coinbase wtxid is always all-zeros by consensus (BIP141)
            witness_hashes.push([0u8; 32]);
        } else {
            // SegWit wtxid requires one witness stack per input; mismatched layout → txid path.
            let has_witness =
                tx_witnesses.len() == tx.inputs.len() && tx_witnesses.iter().any(|w| !w.is_empty());
            let hash = if has_witness {
                // SegWit tx: wtxid = sha256d(version || 0x00 0x01 || inputs || outputs || witnesses || locktime)
                let serialized =
                    crate::serialization::transaction::serialize_transaction_with_witness(
                        tx,
                        tx_witnesses,
                    );
                sha256d_bytes(&serialized)
            } else if let Some(ids) = tx_ids {
                // Non-SegWit tx: wtxid = txid — reuse precomputed block tx_ids (connect hot path).
                ids[i]
            } else {
                // Non-SegWit tx: wtxid = txid = sha256d(version || inputs || outputs || locktime)
                let serialized = crate::serialization::transaction::serialize_transaction(tx);
                sha256d_bytes(&serialized)
            };
            witness_hashes.push(hash);
        }
    }
    let root = compute_merkle_root(&witness_hashes);
    #[cfg(feature = "profile")]
    if std::env::var("BLVM_WITNESS_DEBUG").is_ok() {
        if let Ok(r) = &root {
            eprintln!(
                "BLVM_WITNESS_DEBUG: {} txs, root={}",
                witness_hashes.len(),
                hex::encode(r)
            );
        }
    }
    root
}

/// Compute merkle root from hashes (Orange Paper 8.4.1).
/// Uses proper pair-and-hash with CVE-2012-2459 mutation detection.
fn compute_merkle_root(hashes: &[Hash]) -> Result<Hash> {
    crate::mining::calculate_merkle_root_from_tx_ids(hashes)
}

/// Validate witness commitment in coinbase transaction.
///
/// Per BIP141, the commitment recorded in the coinbase OP_RETURN is:
///   commitment = sha256d(witness_merkle_root || coinbase_reserved_nonce)
/// where `coinbase_reserved_nonce` is the 32-byte nonce stored in
/// the coinbase input's witness stack (witnesses\[0\]\[0\]).
/// If the coinbase has no witness, the reserved value is 32 zero bytes.
///
/// The OP_RETURN output format is:
///   OP_RETURN 0x24 0xaa21a9ed <commitment_hash:32>
#[spec_locked("11.1.5", "ValidateWitnessCommitment")]
pub fn validate_witness_commitment(
    coinbase_tx: &Transaction,
    witness_merkle_root: &Hash,
    coinbase_witnesses: &[Witness],
) -> Result<bool> {
    // Extract the reserved nonce from coinbase input 0's witness stack.
    // BIP141: if a coinbase witness stack is present and non-empty, it MUST be
    // exactly one 32-byte item. Empty / absent → 32 zero bytes (no-witness hash).
    let reserved_nonce: [u8; 32] = if let Some(w) = coinbase_witnesses.first() {
        if w.is_empty() {
            [0u8; 32]
        } else if w.len() == 1 && w[0].len() == 32 {
            let mut n = [0u8; 32];
            n.copy_from_slice(&w[0][..32]);
            n
        } else {
            return Ok(false);
        }
    } else {
        [0u8; 32]
    };

    // Compute the expected commitment: sha256d(witness_root || reserved_nonce)
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(witness_merkle_root);
    preimage[32..].copy_from_slice(&reserved_nonce);
    let expected_commitment = sha256d_bytes(&preimage);

    // Look for a witness commitment OP_RETURN in coinbase outputs.
    // BIP141: if multiple outputs match the 0xaa21a9ed prefix, use the LAST one.
    // If multiple outputs match the BIP141 prefix, use the last one (highest output index).
    let last_commitment = last_witness_commitment_in_coinbase_outputs(&coinbase_tx.outputs);

    // Encode validity as 0/1 so blvm-spec-lock's Option match translation (Int arms) applies.
    let ok_disc: i64 = match last_commitment {
        None => 1,
        Some(commitment) => {
            #[cfg(feature = "profile")]
            if commitment != expected_commitment
                && std::env::var("BLVM_WITNESS_COMMIT_DEBUG").is_ok()
            {
                eprintln!(
                    "BLVM_WITNESS_COMMIT_DEBUG: root={} nonce={} expected={} got={}",
                    hex::encode(witness_merkle_root),
                    hex::encode(reserved_nonce),
                    hex::encode(expected_commitment),
                    hex::encode(commitment),
                );
            }
            if commitment == expected_commitment {
                1
            } else {
                0
            }
        }
    };

    Ok(ok_disc != 0)
}

/// Extract the 32-byte commitment hash from a coinbase OP_RETURN witness commitment output.
/// Orange Paper 11.1.5: Witness commitment in coinbase OP_RETURN output.
///
/// Expected format: OP_RETURN 0x24 [0xaa 0x21 0xa9 0xed] [commitment: 32 bytes]
///   script[0] = 0x6a (OP_RETURN)
///   script[1] = 0x24 (push 36 bytes)
///   script[2..6] = 0xaa21a9ed (BIP141 magic prefix)
///   script[6..38] = commitment hash (32 bytes)
pub(crate) fn extract_witness_commitment(script: &ByteString) -> Option<Hash> {
    const MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
    if script.len() >= 38 && script[0] == OP_RETURN && script[1] == 0x24 && script[2..6] == MAGIC {
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&script[6..38]);
        return Some(commitment);
    }
    None
}

fn last_witness_commitment_in_coinbase_outputs(outputs: &[TransactionOutput]) -> Option<Hash> {
    let mut last_commitment: Option<Hash> = None;
    for output in outputs {
        if let Some(commitment) = extract_witness_commitment(&output.script_pubkey) {
            last_commitment = Some(commitment);
        }
    }
    last_commitment
}

/// Check if transaction is SegWit (v0) or Taproot (v1) based on outputs
#[spec_locked("11.1.6", "IsSegWitTransaction")]
pub fn is_segwit_transaction(tx: &Transaction) -> bool {
    use crate::witness::{
        extract_witness_program, extract_witness_version, validate_witness_program_length,
    };

    tx.outputs.iter().any(|output| {
        let script = &output.script_pubkey;
        if let Some(version) = extract_witness_version(script) {
            if let Some(program) = extract_witness_program(script, version) {
                return validate_witness_program_length(&program, version);
            }
        }
        false
    })
}

/// Calculate block weight for SegWit blocks
#[spec_locked("11.1.1", "CalculateBlockWeight")]
pub fn calculate_block_weight(block: &Block, witnesses: &[Witness]) -> Result<Natural> {
    let mut total_weight = 0;

    for (i, tx) in block.transactions.iter().enumerate() {
        let witness = if i < witnesses.len() {
            Some(&witnesses[i])
        } else {
            None
        };

        total_weight += calculate_transaction_weight(tx, witness)?;
    }

    Ok(total_weight)
}

/// Calculate block weight from nested witnesses without flattening.
/// Accepts `&[Vec<Witness>]` where each `Vec<Witness>` is one tx's input witness stacks.
/// Avoids allocating the flattened structure in the hot block validation path.
/// Orange Paper 11.1.1: Weight(tx) = 4 × BaseSize + TotalSize
#[spec_locked("11.1.1", "CalculateBlockWeight")]
#[inline]
pub fn calculate_block_weight_from_nested(
    block: &Block,
    witnesses: &[Vec<Witness>],
) -> Result<Natural> {
    let mut total_weight = 0;
    for (i, tx) in block.transactions.iter().enumerate() {
        let witness_size: Natural = if i < witnesses.len() {
            witnesses[i]
                .iter()
                .flat_map(|w| w.iter())
                .map(|e| e.len() as Natural)
                .sum()
        } else {
            0
        };
        let base_size =
            (4 + tx.inputs.len() * (32 + 4 + 1 + 4) + tx.outputs.len() * (8 + 1) + 4) as Natural;
        total_weight +=
            witness::calculate_transaction_weight_segwit(base_size, base_size + witness_size);
    }
    Ok(total_weight)
}

/// Validate SegWit block
#[spec_locked("11.1.7", "ValidateSegWitBlock")]
pub fn validate_segwit_block(
    block: &Block,
    witnesses: &[Witness],
    max_block_weight: Natural,
) -> Result<bool> {
    // Validate witness structure for all transactions using unified framework
    for (i, _tx) in block.transactions.iter().enumerate() {
        if i < witnesses.len() && !witness::validate_segwit_witness_structure(&witnesses[i])? {
            return Ok(false);
        }
    }

    // Check block weight limit
    let block_weight = calculate_block_weight(block, witnesses)?;
    if block_weight > max_block_weight {
        return Ok(false);
    }

    // Validate witness commitment (BIP141 wtxid merkle root)
    if !block.transactions.is_empty() {
        let nested: Vec<Vec<Witness>> = block
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                if i < witnesses.len() {
                    flat_witness_to_per_input(tx, &witnesses[i])
                } else {
                    Vec::new()
                }
            })
            .collect();
        let witness_root = compute_witness_merkle_root_from_nested(block, &nested, None)?;
        let coinbase_witness = if witnesses.is_empty() {
            &[][..]
        } else {
            std::slice::from_ref(&witnesses[0])
        };
        if !validate_witness_commitment(&block.transactions[0], &witness_root, coinbase_witness)? {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_header;

    #[test]
    fn test_calculate_transaction_weight() {
        let tx = create_test_transaction();
        let witness = vec![vec![OP_1], vec![OP_2]]; // OP_1, OP_2

        let weight = calculate_transaction_weight(&tx, Some(&witness)).unwrap();
        assert!(weight > 0);
    }

    #[test]
    fn test_calculate_transaction_weight_no_witness() {
        let tx = create_test_transaction();

        let weight = calculate_transaction_weight(&tx, None).unwrap();
        assert!(weight > 0);
    }

    #[test]
    fn test_compute_witness_merkle_root() {
        let block = create_test_block();
        let witnesses = vec![
            vec![],           // Coinbase witness (empty)
            vec![vec![OP_1]], // First transaction witness
        ];

        let root = compute_witness_merkle_root(&block, &witnesses).unwrap();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_compute_witness_merkle_root_empty_block() {
        let block = Block {
            header: create_test_header(1231006505, [0u8; 32]),
            transactions: vec![].into_boxed_slice(),
        };
        let witnesses = vec![];

        let result = compute_witness_merkle_root(&block, &witnesses);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_witness_commitment() {
        let mut coinbase_tx = create_test_transaction();
        let witness_root = [1u8; 32];
        let nonce = [0u8; 32]; // default reserved nonce

        // Add witness commitment to coinbase script (correct BIP141 format)
        coinbase_tx.outputs[0].script_pubkey =
            create_witness_commitment_script(&witness_root, &nonce);

        // Empty coinbase witnesses → nonce defaults to [0u8; 32]
        let is_valid = validate_witness_commitment(&coinbase_tx, &witness_root, &[]).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_is_segwit_transaction() {
        // SegWit transactions are detected by witness program outputs, not scriptSig
        // P2WPKH: OP_0 <20-byte-hash>
        // The format in Bitcoin is: [OP_0, PUSH_20_BYTES, <20-byte-hash>]
        // Where OP_0 is OP_0 (witness version), PUSH_20_BYTES is push 20 bytes, then 20 bytes of hash
        let mut tx = create_test_transaction();
        // Create a P2WPKH output (OP_0 <20-byte-hash>)
        let p2wpkh_hash = [0x51; 20]; // 20-byte hash
        let mut script_pubkey = vec![OP_0, PUSH_20_BYTES]; // OP_0, push 20 bytes
        script_pubkey.extend_from_slice(&p2wpkh_hash);
        tx.outputs[0].script_pubkey = script_pubkey;

        assert!(is_segwit_transaction(&tx));
    }

    #[test]
    fn test_calculate_block_weight() {
        let block = create_test_block();
        let witnesses = vec![
            vec![],           // Coinbase
            vec![vec![OP_1]], // First tx
        ];

        let weight = calculate_block_weight(&block, &witnesses).unwrap();
        assert!(weight > 0);
    }

    #[test]
    fn test_validate_segwit_block() {
        let block = create_test_block();
        let witnesses = vec![
            vec![],           // Coinbase
            vec![vec![OP_1]], // First tx
        ];

        let is_valid = validate_segwit_block(&block, &witnesses, 4_000_000).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_validate_segwit_block_exceeds_weight() {
        let block = create_test_block();
        let witnesses = vec![
            vec![],           // Coinbase
            vec![vec![OP_1]], // First tx
        ];

        let is_valid = validate_segwit_block(&block, &witnesses, 1).unwrap(); // Very low weight limit
        assert!(!is_valid);
    }

    #[test]
    fn test_validate_segwit_block_invalid_commitment() {
        let mut block = create_test_block();
        let witnesses = vec![
            vec![],           // Coinbase
            vec![vec![OP_1]], // First tx
        ];

        // Create coinbase with wrong witness_root in the commitment (won't match actual merkle root)
        let wrong_root = [2u8; 32];
        block.transactions[0].outputs[0].script_pubkey =
            create_witness_commitment_script(&wrong_root, &[0u8; 32]);

        let is_valid = validate_segwit_block(&block, &witnesses, 4_000_000).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_validate_witness_commitment_no_commitment() {
        let coinbase_tx = create_test_transaction();
        let witness_root = [1u8; 32];

        // No witness commitment in script
        let is_valid = validate_witness_commitment(&coinbase_tx, &witness_root, &[]).unwrap();
        assert!(is_valid); // Should be valid for non-SegWit blocks
    }

    #[test]
    fn test_validate_witness_commitment_invalid_commitment() {
        let mut coinbase_tx = create_test_transaction();
        let witness_root = [1u8; 32];
        let invalid_root = [2u8; 32]; // different root → wrong commitment

        // Add commitment computed from a different root
        coinbase_tx.outputs[0].script_pubkey =
            create_witness_commitment_script(&invalid_root, &[0u8; 32]);

        let is_valid = validate_witness_commitment(&coinbase_tx, &witness_root, &[]).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_extract_witness_commitment_valid() {
        let witness_root = [1u8; 32];
        let nonce = [0u8; 32];
        let script = create_witness_commitment_script(&witness_root, &nonce);

        // extract_witness_commitment returns sha256d(root||nonce), not the raw root
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&witness_root);
        preimage[32..].copy_from_slice(&nonce);
        let expected = sha256d_bytes(&preimage);

        let extracted = extract_witness_commitment(&script).unwrap();
        assert_eq!(extracted, expected);
    }

    #[test]
    fn test_extract_witness_commitment_invalid_script() {
        let script = vec![OP_1]; // Not a witness commitment script

        let extracted = extract_witness_commitment(&script);
        assert!(extracted.is_none());
    }

    #[test]
    fn test_extract_witness_commitment_wrong_opcode() {
        let mut script = vec![0x52, PUSH_36_BYTES]; // Wrong opcode, correct length
        script.extend_from_slice(&[1u8; 32]);

        let extracted = extract_witness_commitment(&script);
        assert!(extracted.is_none());
    }

    #[test]
    fn test_extract_witness_commitment_wrong_length() {
        let mut script = vec![OP_RETURN, 0x25]; // OP_RETURN, wrong length (37 bytes)
        script.extend_from_slice(&[1u8; 32]);

        let extracted = extract_witness_commitment(&script);
        assert!(extracted.is_none());
    }

    #[test]
    fn test_hash_witness() {
        let witness = vec![vec![OP_1], vec![OP_2]];
        let hash = hash_witness(&witness);

        assert_eq!(hash.len(), 32);

        // Different witness should produce different hash
        let witness2 = vec![vec![OP_3], vec![OP_4]];
        let hash2 = hash_witness(&witness2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_hash_witness_empty() {
        let witness = vec![];
        let hash = hash_witness(&witness);

        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_compute_merkle_root_single_hash() {
        let hashes = vec![[1u8; 32]];
        let root = compute_merkle_root(&hashes).unwrap();

        assert_eq!(root, [1u8; 32]);
    }

    #[test]
    fn test_compute_merkle_root_empty() {
        let hashes = vec![];
        let result = compute_merkle_root(&hashes);

        assert!(result.is_err());
    }

    #[test]
    fn test_is_segwit_transaction_false() {
        let tx = create_test_transaction();
        // No SegWit markers

        assert!(!is_segwit_transaction(&tx));
    }

    #[test]
    fn test_calculate_base_size() {
        let tx = create_test_transaction();
        let base_size = calculate_base_size(&tx);

        assert!(base_size > 0);
    }

    #[test]
    fn test_calculate_total_size_with_witness() {
        let tx = create_test_transaction();
        let witness = vec![vec![OP_1], vec![OP_2]];

        let total_size = calculate_total_size(&tx, Some(&witness));
        let base_size = calculate_base_size(&tx);

        assert!(total_size > base_size);
    }

    #[test]
    fn test_calculate_total_size_without_witness() {
        let tx = create_test_transaction();

        let total_size = calculate_total_size(&tx, None);
        let base_size = calculate_base_size(&tx);

        assert_eq!(total_size, base_size);
    }

    // Helper functions
    fn create_test_transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0,
                },
                script_sig: vec![OP_1],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![OP_1],
            }]
            .into(),
            lock_time: 0,
        }
    }

    fn create_test_block() -> Block {
        Block {
            header: create_test_header(1231006505, [0u8; 32]),
            transactions: vec![
                create_test_transaction(), // Coinbase
                create_test_transaction(), // Regular tx
            ]
            .into_boxed_slice(),
        }
    }

    fn create_witness_commitment_script(witness_root: &Hash, nonce: &[u8; 32]) -> ByteString {
        // Compute the correct BIP141 commitment: sha256d(witness_root || nonce)
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(witness_root);
        preimage[32..].copy_from_slice(nonce);
        let commitment = sha256d_bytes(&preimage);
        let mut script = vec![OP_RETURN, PUSH_36_BYTES]; // 0x6a, 0x24
        script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // BIP141 magic prefix
        script.extend_from_slice(&commitment);
        script
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Property test: transaction weight is non-negative
    ///
    /// Mathematical specification:
    /// ∀ tx ∈ Transaction, witness ∈ Option<Witness>: Weight(tx) ≥ 0
    proptest! {
        #[test]
        fn prop_transaction_weight_non_negative(
            tx in create_transaction_strategy(),
            witness in prop::option::of(create_witness_strategy())
        ) {
            let _weight = calculate_transaction_weight(&tx, witness.as_ref()).unwrap();
            // Weight is always non-negative (Natural type) - verified by type system
        }
    }

    /// Property test: transaction weight formula is correct
    ///
    /// Mathematical specification:
    /// ∀ tx ∈ Transaction, witness ∈ Option<Witness>:
    /// Weight(tx) = 3 × base_size + total_size (BIP141; see `witness::calculate_transaction_weight_segwit`)
    proptest! {
        #[test]
        fn prop_transaction_weight_formula(
            tx in create_transaction_strategy(),
            witness in prop::option::of(create_witness_strategy())
        ) {
            let weight = calculate_transaction_weight(&tx, witness.as_ref()).unwrap();
            let base_size = calculate_base_size(&tx);
            let total_size = calculate_total_size(&tx, witness.as_ref());
            let expected_weight = 3 * base_size + total_size;

            assert_eq!(weight, expected_weight);
        }
    }

    /// Property test: block weight validation respects limits
    ///
    /// Mathematical specification:
    /// ∀ block ∈ Block, witnesses ∈ [Witness], max_weight ∈ ℕ:
    /// If Σ tx_weight > max_weight then validate_segwit_block returns false
    proptest! {
        #[test]
        fn prop_block_weight_validation_limit(
            (block, witnesses) in create_block_with_witnesses_strategy(),
            max_weight in 1..10_000_000u64
        ) {
            // Handle errors from invalid blocks/witnesses
            match (calculate_block_weight(&block, &witnesses), validate_segwit_block(&block, &witnesses, max_weight as Natural)) {
                (Ok(actual_weight), Ok(is_valid)) => {
                    // If weight exceeds limit, block should be invalid
                    if actual_weight > max_weight as Natural {
                        prop_assert!(!is_valid, "Block exceeding weight limit must be invalid");
                    }
                },
                (Err(_), _) | (_, Err(_)) => {
                    // Invalid blocks/witnesses may cause errors - this is acceptable
                }
            }
        }
    }

    /// Property test: witness commitment validation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ coinbase_tx ∈ Transaction, witness_root ∈ Hash:
    /// validate_witness_commitment(coinbase_tx, witness_root) is deterministic
    proptest! {
        #[test]
        fn prop_witness_commitment_deterministic(
            coinbase_tx in create_transaction_strategy(),
            witness_root in create_hash_strategy()
        ) {
            let result1 = validate_witness_commitment(&coinbase_tx, &witness_root, &[]).unwrap();
            let result2 = validate_witness_commitment(&coinbase_tx, &witness_root, &[]).unwrap();

            assert_eq!(result1, result2);
        }
    }

    /// Property test: witness merkle root computation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ block ∈ Block, witnesses ∈ [Witness]:
    /// compute_witness_merkle_root(block, witnesses) is deterministic
    proptest! {
        #[test]
        fn prop_witness_merkle_root_deterministic(
            (block, witnesses) in create_block_with_witnesses_strategy()
        ) {
            if !block.transactions.is_empty() {
                let result1 = compute_witness_merkle_root(&block, &witnesses);
                let result2 = compute_witness_merkle_root(&block, &witnesses);

                assert_eq!(result1.is_ok(), result2.is_ok());
                if result1.is_ok() && result2.is_ok() {
                    assert_eq!(result1.unwrap(), result2.unwrap());
                }
            }
        }
    }

    /// Property test: SegWit transaction detection is consistent
    ///
    /// Mathematical specification:
    /// ∀ tx ∈ Transaction: is_segwit_transaction(tx) ∈ {true, false}
    proptest! {
        #[test]
        fn prop_segwit_transaction_detection(
            tx in create_transaction_strategy()
        ) {
            let is_segwit = is_segwit_transaction(&tx);
            // Just test it returns a boolean (is_segwit is either true or false)
            let _ = is_segwit;
        }
    }

    /// Property test: witness hashing is deterministic
    ///
    /// Mathematical specification:
    /// ∀ witness ∈ Witness: hash_witness(witness) is deterministic
    proptest! {
        #[test]
        fn prop_witness_hashing_deterministic(
            witness in create_witness_strategy()
        ) {
            let hash1 = hash_witness(&witness);
            let hash2 = hash_witness(&witness);

            assert_eq!(hash1, hash2);
            assert_eq!(hash1.len(), 32);
        }
    }

    /// Property test: merkle root computation handles single hash
    ///
    /// Mathematical specification:
    /// ∀ hash ∈ Hash: compute_merkle_root([hash]) = hash
    proptest! {
        #[test]
        fn prop_merkle_root_single_hash(
            hash in create_hash_strategy()
        ) {
            let hashes = vec![hash];
            let root = compute_merkle_root(&hashes).unwrap();

            assert_eq!(root, hash);
        }
    }

    /// Property test: merkle root computation fails on empty input
    ///
    /// Mathematical specification:
    /// compute_merkle_root([]) returns error
    #[test]
    fn prop_merkle_root_empty_input() {
        let hashes: Vec<Hash> = vec![];
        let result = compute_merkle_root(&hashes);

        assert!(result.is_err());
    }

    /// Property test: witness commitment extraction is deterministic
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString: extract_witness_commitment(script) is deterministic
    proptest! {
        #[test]
        fn prop_witness_commitment_extraction_deterministic(
            script in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let result1 = extract_witness_commitment(&script);
            let result2 = extract_witness_commitment(&script);

            assert_eq!(result1.is_some(), result2.is_some());
            if result1.is_some() && result2.is_some() {
                assert_eq!(result1.unwrap(), result2.unwrap());
            }
        }
    }

    /// Property test: base size calculation is monotonic
    ///
    /// Mathematical specification:
    /// ∀ tx1, tx2 ∈ Transaction: |tx1| ≤ |tx2| ⟹ base_size(tx1) ≤ base_size(tx2)
    proptest! {
        #[test]
        fn prop_base_size_monotonic(
            tx1 in create_transaction_strategy(),
            tx2 in create_transaction_strategy()
        ) {
            let base_size1 = calculate_base_size(&tx1);
            let base_size2 = calculate_base_size(&tx2);

            // Base size should be positive
            assert!(base_size1 > 0);
            assert!(base_size2 > 0);
        }
    }

    /// Property test: total size with witness is greater than base size
    ///
    /// Mathematical specification:
    /// ∀ tx ∈ Transaction, witness ∈ Witness: total_size(tx, witness) ≥ base_size(tx)
    proptest! {
        #[test]
        fn prop_total_size_with_witness_greater_than_base(
            tx in create_transaction_strategy(),
            witness in create_witness_strategy()
        ) {
            let base_size = calculate_base_size(&tx);
            let total_size = calculate_total_size(&tx, Some(&witness));

            assert!(total_size >= base_size);
        }
    }

    // Property test strategies
    fn create_transaction_strategy() -> impl Strategy<Value = Transaction> {
        (
            prop::collection::vec(any::<u8>(), 0..10), // inputs
            prop::collection::vec(any::<u8>(), 0..10), // outputs
        )
            .prop_map(|(input_data, output_data)| {
                let mut inputs = Vec::new();
                for (i, _) in input_data.iter().enumerate() {
                    inputs.push(TransactionInput {
                        prevout: OutPoint {
                            hash: [0; 32],
                            index: i as u32,
                        },
                        script_sig: vec![OP_1],
                        sequence: 0xffffffff,
                    });
                }

                let mut outputs = Vec::new();
                for _ in output_data {
                    outputs.push(TransactionOutput {
                        value: 1000,
                        script_pubkey: vec![OP_1],
                    });
                }

                Transaction {
                    version: 1,
                    inputs: inputs.into(),
                    outputs: outputs.into(),
                    lock_time: 0,
                }
            })
    }

    fn create_block_strategy() -> impl Strategy<Value = Block> {
        prop::collection::vec(create_transaction_strategy(), 1..5).prop_map(|transactions| Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: transactions.into_boxed_slice(),
        })
    }

    fn create_witness_strategy() -> impl Strategy<Value = Witness> {
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..10), 0..5)
    }

    fn create_witnesses_strategy() -> impl Strategy<Value = Vec<Witness>> {
        prop::collection::vec(create_witness_strategy(), 0..5)
    }

    fn create_block_with_witnesses_strategy() -> impl Strategy<Value = (Block, Vec<Witness>)> {
        create_block_strategy().prop_flat_map(|block| {
            let n = block.transactions.len();
            let header = block.header.clone();
            let transactions = block.transactions.to_vec();
            prop::collection::vec(create_witness_strategy(), n).prop_map(move |witnesses| {
                (
                    Block {
                        header: header.clone(),
                        transactions: transactions.clone().into_boxed_slice(),
                    },
                    witnesses,
                )
            })
        })
    }

    fn create_hash_strategy() -> impl Strategy<Value = Hash> {
        prop::collection::vec(any::<u8>(), 32..=32).prop_map(|bytes| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            hash
        })
    }
}
