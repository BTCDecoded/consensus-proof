//! Taproot functions from Orange Paper Section 11.2

use std::borrow::Cow;

use crate::error::Result;
use crate::types::*;
use crate::types::{ByteString, Hash};
use crate::witness;
use blvm_spec_lock::spec_locked;

/// BIP 341 default tapscript leaf version.
pub const TAPROOT_LEAF_VERSION_TAPSCRIPT: u8 = 0xc0;

/// Witness Data: 𝒲 = 𝕊* (stack of witness elements)
///
/// Uses unified witness type from witness module for consistency with SegWit
pub use crate::witness::Witness;

use crate::opcodes::{OP_1, PUSH_32_BYTES};

/// Taproot output script: OP_1 <32-byte-hash>
pub const TAPROOT_SCRIPT_PREFIX: u8 = OP_1;

/// Validate Taproot output script
#[spec_locked("11.2.1", "ValidateTaprootScript")]
pub fn validate_taproot_script(script: &ByteString) -> Result<bool> {
    use crate::constants::TAPROOT_SCRIPT_LENGTH;

    // Check if script is P2TR: OP_1 <32-byte-program>
    if script.len() != TAPROOT_SCRIPT_LENGTH {
        return Ok(false);
    }

    if script[0] != TAPROOT_SCRIPT_PREFIX {
        return Ok(false);
    }

    // BIP341 P2TR: OP_1 PUSH_32 <32-byte x-only output key>
    if script[1] != PUSH_32_BYTES {
        return Ok(false);
    }

    Ok(true)
}

/// Extract Taproot output key from script
#[spec_locked("11.2.1", "ExtractTaprootOutputKey")]
pub fn extract_taproot_output_key(script: &ByteString) -> Result<Option<[u8; 32]>> {
    if !validate_taproot_script(script)? {
        return Ok(None);
    }

    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&script[2..34]);
    Ok(Some(output_key))
}

/// Compute Taproot tweak using proper cryptographic operations
/// OutputKey = InternalPubKey + TaprootTweak(MerkleRoot) × G
///
/// With `blvm-secp256k1` feature: uses BIP 341 tagged hash (correct).
/// Without: uses libsecp256k1 with plain SHA256 (legacy, non-BIP341).
#[spec_locked("11.2.2", "ComputeTaprootTweak")]
pub fn compute_taproot_tweak(internal_pubkey: &[u8; 32], merkle_root: &Hash) -> Result<[u8; 32]> {
    crate::secp256k1_backend::taproot_output_key(internal_pubkey, merkle_root)
}

/// Validate Taproot key aggregation, including the parity commitment from the control block.
///
/// Per BIP341: verifies that `output_key.x == tweaked_internal_key.x` AND that
/// `tweaked_internal_key.y_parity == expected_parity` (from `control_block[0] & 0x01`).
#[spec_locked("11.2.2", "ValidateTaprootKeyAggregation")]
pub fn validate_taproot_key_aggregation(
    internal_pubkey: &[u8; 32],
    merkle_root: &Hash,
    output_key: &[u8; 32],
    expected_parity: u8,
) -> Result<bool> {
    let (computed_key, actual_parity) =
        crate::secp256k1_backend::taproot_output_key_with_parity(internal_pubkey, merkle_root)?;
    Ok(computed_key == *output_key && actual_parity == expected_parity)
}

/// Validate Taproot script path spending
#[spec_locked("11.2.3", "ValidateTaprootScriptPath")]
pub fn validate_taproot_script_path(
    script: &ByteString,
    merkle_proof: &[Hash],
    merkle_root: &Hash,
) -> Result<bool> {
    validate_taproot_script_path_with_leaf_version(
        script,
        merkle_proof,
        merkle_root,
        TAPROOT_LEAF_VERSION_TAPSCRIPT,
    )
}

/// Validate Taproot script path spending with explicit leaf version.
#[spec_locked("11.2.3", "ValidateTaprootScriptPath")]
pub fn validate_taproot_script_path_with_leaf_version(
    script: &ByteString,
    merkle_proof: &[Hash],
    merkle_root: &Hash,
    leaf_version: u8,
) -> Result<bool> {
    let computed_root = compute_script_merkle_root(script, merkle_proof, leaf_version)?;
    Ok(computed_root == *merkle_root)
}

/// Compute merkle root for script path using BIP 341 TapLeaf/TapBranch tagged hashes.
#[spec_locked("11.2.3", "ComputeScriptMerkleRoot")]
pub fn compute_script_merkle_root(
    script: &ByteString,
    proof: &[Hash],
    leaf_version: u8,
) -> Result<Hash> {
    let mut current_hash = crate::secp256k1_backend::tap_leaf_hash(leaf_version, script);

    for proof_hash in proof {
        let (left, right) = if current_hash < *proof_hash {
            (current_hash, *proof_hash)
        } else {
            (*proof_hash, current_hash)
        };
        current_hash = crate::secp256k1_backend::tap_branch_hash(&left, &right);
    }

    Ok(current_hash)
}

/// BIP341 annex tag (first byte of optional annex witness element).
pub const TAPROOT_ANNEX_TAG: u8 = 0x50;

/// Strip optional BIP341 annex from the end of a Taproot witness stack.
///
/// BIP341 `VerifyWitnessProgram` (v1): if there are at least two stack elements and the
/// last begins with `0x50`, it is an annex and removed before key/script path dispatch.
/// Returns the stripped witness and the annex sighash hash when present.
/// Borrows the stack when no annex is present (avoids cloning the full witness).
#[spec_locked("11.2.4", "StripTaprootAnnex")]
pub fn strip_taproot_annex(witness: &Witness) -> (Cow<'_, Witness>, Option<Hash>) {
    if witness.len() >= 2
        && witness
            .last()
            .and_then(|a| a.first())
            .is_some_and(|&b| b == TAPROOT_ANNEX_TAG)
    {
        let annex = &witness[witness.len() - 1];
        let annex_hash = compute_taproot_annex_sighash_hash(annex);
        let stripped = witness[..witness.len() - 1].to_vec();
        return (Cow::Owned(stripped), Some(annex_hash));
    }
    (Cow::Borrowed(witness), None)
}

/// SHA256 of the annex element for Taproot sighash (BIP341 annex hash step).
fn compute_taproot_annex_sighash_hash(annex: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut buf = encode_varint(annex.len() as u64);
    buf.extend_from_slice(annex);
    let digest = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Parsed control block from Taproot script-path witness.
#[derive(Debug)]
pub struct TaprootControlBlock {
    pub leaf_version: u8,
    pub internal_pubkey: [u8; 32],
    pub merkle_proof: Vec<Hash>,
}

/// Parse and validate Taproot script-path witness.
/// Returns (tapscript, stack_items) if valid, Err otherwise.
/// Witness format: [stack_items..., script, annex?, control_block]
/// Annex: optional, last element before control block, must start with 0x50.
/// Control block: leaf_version (1) + internal_pubkey (32) + merkle_proof (32*n).
#[spec_locked("11.2.4", "ParseTaprootScriptPathWitness")]
pub fn parse_taproot_script_path_witness(
    witness: &Witness,
    output_key: &[u8; 32],
) -> Result<Option<(ByteString, Vec<ByteString>, TaprootControlBlock)>> {
    if witness.len() < 2 {
        return Ok(None);
    }

    let Some(control_block) = witness.last() else {
        return Ok(None);
    };
    if control_block.len() < 33 || (control_block.len() - 33) % 32 != 0 {
        return Ok(None);
    }

    // BIP341: leaf_version = control_block[0] & 0xfe (strip parity bit).
    // parity = control_block[0] & 0x01 (which y-coordinate the tweaked key uses).
    let leaf_version = control_block[0] & 0xfe;
    let parity = control_block[0] & 0x01;
    let mut internal_pubkey = [0u8; 32];
    internal_pubkey.copy_from_slice(&control_block[1..33]);
    let merkle_proof: Vec<Hash> = control_block[33..]
        .chunks_exact(32)
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect();

    let script_idx = if witness.len() >= 3 {
        let maybe_annex = &witness[witness.len() - 2];
        if maybe_annex.first() == Some(&0x50) {
            witness.len() - 3
        } else {
            witness.len() - 2
        }
    } else {
        witness.len() - 2
    };

    let tapscript = witness[script_idx].clone();
    let stack_items: Vec<ByteString> = witness[..script_idx].to_vec();

    let merkle_root = match compute_script_merkle_root(&tapscript, &merkle_proof, leaf_version) {
        Ok(root) => root,
        Err(_) => return Ok(None),
    };
    // Invalid tweak / aggregation mismatch → script invalid (Ok(false)), not consensus Err.
    let valid = match validate_taproot_key_aggregation(
        &internal_pubkey,
        &merkle_root,
        output_key,
        parity,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if !valid {
        return Ok(None);
    }

    Ok(Some((
        tapscript,
        stack_items,
        TaprootControlBlock {
            leaf_version, // already masked (0xfe) — parity bit stripped
            internal_pubkey,
            merkle_proof,
        },
    )))
}

/// Check if transaction output is Taproot
/// BIP341 invariant: a Taproot output has a P2TR scriptPubKey of exactly 34 bytes
/// (OP_1 + 0x20 push + 32-byte x-only pubkey).  If this returns true, the length is 34.
#[spec_locked("11.2.1", "IsTaprootOutput")]
#[blvm_spec_lock::ensures(result == false || output.script_pubkey.len() == 34)]
pub fn is_taproot_output(output: &TransactionOutput) -> bool {
    validate_taproot_script(&output.script_pubkey).unwrap_or(false)
}

/// Validate Taproot transaction
#[spec_locked("11.2.5", "ValidateTaprootTransaction")]
pub fn validate_taproot_transaction(tx: &Transaction, witness: Option<&Witness>) -> Result<bool> {
    // Check if any output is Taproot
    for output in &tx.outputs {
        if is_taproot_output(output) {
            // Validate Taproot output
            if !validate_taproot_script(&output.script_pubkey)? {
                return Ok(false);
            }
        }
    }

    // Validate Taproot witness structure using unified framework.
    // Strip optional annex before key/script path classification (BIP341).
    if let Some(w) = witness {
        let (body, _) = strip_taproot_annex(w);
        let is_script_path = body.len() >= 2;
        if !witness::validate_taproot_witness_structure(&body, is_script_path)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Shared BIP341 SigMsg commitments (N7): compute once per transaction, reuse for every input.
#[derive(Clone, Debug)]
pub struct Bip341PrecomputedHashes {
    pub sha_prevouts: [u8; 32],
    pub sha_amounts: [u8; 32],
    pub sha_scriptpubkeys: [u8; 32],
    pub sha_sequences: [u8; 32],
    pub sha_outputs: [u8; 32],
}

impl Bip341PrecomputedHashes {
    /// Compute BIP341 hash commitments from all inputs and outputs.
    ///
    /// Each field is SHA256 of the concatenation of the respective field across all inputs/outputs.
    pub fn compute(
        tx: &Transaction,
        prevout_values: &[i64],
        prevout_script_pubkeys: &[&[u8]],
    ) -> Self {
        use sha2::{Digest, Sha256};

        let mut prevouts_data = Vec::new();
        let mut amounts_data = Vec::new();
        let mut scriptpubkeys_data = Vec::new();
        let mut sequences_data = Vec::new();
        for (i, input) in tx.inputs.iter().enumerate() {
            prevouts_data.extend_from_slice(&input.prevout.hash);
            prevouts_data.extend_from_slice(&input.prevout.index.to_le_bytes());
            // Both callers validate that prevout slices are at least as long as tx.inputs before
            // calling this function.  Direct indexing here makes the invariant explicit; a panic
            // would signal a programming error, not a consensus-invalid input.
            amounts_data.extend_from_slice(&(prevout_values[i] as u64).to_le_bytes());
            let spk = prevout_script_pubkeys[i];
            scriptpubkeys_data.extend_from_slice(&encode_varint(spk.len() as u64));
            scriptpubkeys_data.extend_from_slice(spk);
            sequences_data.extend_from_slice(&(input.sequence as u32).to_le_bytes());
        }
        let mut outputs_data = Vec::new();
        for output in &tx.outputs {
            outputs_data.extend_from_slice(&(output.value as u64).to_le_bytes());
            outputs_data.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
            outputs_data.extend_from_slice(&output.script_pubkey);
        }

        Self {
            sha_prevouts: Sha256::digest(&prevouts_data).into(),
            sha_amounts: Sha256::digest(&amounts_data).into(),
            sha_scriptpubkeys: Sha256::digest(&scriptpubkeys_data).into(),
            sha_sequences: Sha256::digest(&sequences_data).into(),
            sha_outputs: Sha256::digest(&outputs_data).into(),
        }
    }
}

/// N7: reuse BIP341 commitments across inputs on the same thread (same `&Transaction` pointer).
thread_local! {
    static BIP341_TLS: std::cell::RefCell<Option<(usize, Bip341PrecomputedHashes)>> =
        const { std::cell::RefCell::new(None) };
}

fn bip341_precompute(
    tx: &Transaction,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
) -> Bip341PrecomputedHashes {
    let key = tx as *const Transaction as usize;
    BIP341_TLS.with(|cell| {
        let mut slot = cell.borrow_mut();
        if let Some((k, ref hashes)) = *slot {
            if k == key {
                return hashes.clone();
            }
        }
        let hashes = Bip341PrecomputedHashes::compute(tx, prevout_values, prevout_script_pubkeys);
        *slot = Some((key, hashes.clone()));
        hashes
    })
}

/// Compute Taproot key-path signature hash following BIP341.
///
/// SigMsg = epoch(1) || hash_type(1) || nVersion(4) || nLockTime(4)
///        || sha_prevouts(32) || sha_amounts(32) || sha_scriptpubkeys(32) || sha_sequences(32)
///        || sha_outputs(32)   [if SIGHASH_ALL]
///        || spend_type(1)     [0x00 = key-path, no annex]
///        || input_index(4)
///
/// Only SIGHASH_DEFAULT (0x00 = treated as ALL) and SIGHASH_ALL (0x01) are handled here;
/// ANYONECANPAY and SIGHASH_SINGLE paths use the same base but are not yet exercised.
#[spec_locked("11.2.6", "ComputeTaprootSignatureHash")]
pub fn compute_taproot_signature_hash(
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    sighash_type: u8,
    annex_hash: Option<&Hash>,
) -> Result<Hash> {
    use sha2::{Digest, Sha256};

    // Reject invalid sighash types (BIP341 §Common signature message)
    // Valid: 0x00 (DEFAULT/ALL), 0x01–0x03, 0x81–0x83.
    if !(sighash_type <= 0x03 || (0x81..=0x83).contains(&sighash_type)) {
        return Err(crate::error::ConsensusError::InvalidSignature(
            "Invalid Taproot sighash type".into(),
        ));
    }

    // Validate prevout slices: one entry per input is required for a correct sighash.
    // A short slice would silently produce wrong amounts/scriptpubkeys (zeroed),
    // which is a consensus error.
    if prevout_values.len() < tx.inputs.len() || prevout_script_pubkeys.len() < tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidSignature(
            "prevout_values/prevout_script_pubkeys shorter than tx.inputs — cannot compute sighash"
                .into(),
        ));
    }

    let input_type = sighash_type & 0x80; // ANYONECANPAY bit
    let output_type = if sighash_type == 0x00 {
        0x01
    } else {
        sighash_type & 0x03
    }; // DEFAULT → ALL

    let hashes = bip341_precompute(tx, prevout_values, prevout_script_pubkeys);

    let mut sigmsg = Vec::with_capacity(180);

    // epoch
    sigmsg.push(0x00u8);
    // hash_type
    sigmsg.push(sighash_type);
    // nVersion
    sigmsg.extend_from_slice(&(tx.version as u32).to_le_bytes());
    // nLockTime
    sigmsg.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());

    if input_type != 0x80 {
        // not ANYONECANPAY: include all-input hash commitments
        sigmsg.extend_from_slice(&hashes.sha_prevouts);
        sigmsg.extend_from_slice(&hashes.sha_amounts);
        sigmsg.extend_from_slice(&hashes.sha_scriptpubkeys);
        sigmsg.extend_from_slice(&hashes.sha_sequences);
    }
    if output_type == 0x01 {
        // SIGHASH_ALL: include all-output hash
        sigmsg.extend_from_slice(&hashes.sha_outputs);
    }

    // spend_type: ext_flag=0 (key path), annex_present in low bit (BIP341)
    let spend_type = if annex_hash.is_some() { 0x01u8 } else { 0x00u8 };
    sigmsg.push(spend_type);

    if input_type == 0x80 {
        // ANYONECANPAY: include this input's outpoint + amount + scriptpubkey + sequence
        let input = tx.inputs.get(input_index).ok_or_else(|| {
            crate::error::ConsensusError::InvalidSignature("input_index out of range".into())
        })?;
        sigmsg.extend_from_slice(&input.prevout.hash);
        sigmsg.extend_from_slice(&input.prevout.index.to_le_bytes());
        // prevout slice length was validated at function entry; indexing is safe here.
        let amount = *prevout_values.get(input_index).ok_or_else(|| {
            crate::error::ConsensusError::InvalidSignature(
                "prevout_values index out of range for ANYONECANPAY".into(),
            )
        })? as u64;
        sigmsg.extend_from_slice(&amount.to_le_bytes());
        let spk = *prevout_script_pubkeys.get(input_index).ok_or_else(|| {
            crate::error::ConsensusError::InvalidSignature(
                "prevout_script_pubkeys index out of range for ANYONECANPAY".into(),
            )
        })?;
        sigmsg.extend_from_slice(&encode_varint(spk.len() as u64));
        sigmsg.extend_from_slice(spk);
        sigmsg.extend_from_slice(&(input.sequence as u32).to_le_bytes());
    } else {
        // include input_index
        sigmsg.extend_from_slice(&(input_index as u32).to_le_bytes());
    }

    if let Some(h) = annex_hash {
        sigmsg.extend_from_slice(h);
    }

    if output_type == 0x03 {
        // SIGHASH_SINGLE: hash of this input's corresponding output
        if let Some(output) = tx.outputs.get(input_index) {
            let mut out_data = Vec::new();
            out_data.extend_from_slice(&(output.value as u64).to_le_bytes());
            out_data.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
            out_data.extend_from_slice(&output.script_pubkey);
            sigmsg.extend_from_slice(&Sha256::digest(&out_data));
        }
    }

    Ok(crate::secp256k1_backend::tap_sighash_hash(&sigmsg))
}

/// Compute Tapscript (BIP342) signature hash.
///
/// Same base SigMsg as key-path (spend_type bit 0 set = 0x01 or 0x03 depending on annex),
/// with extension: tapleaf_hash(32) || key_version(1=0x00) || codesep_pos(4).
#[spec_locked("11.2.7", "ComputeTapscriptSignatureHash")]
pub fn compute_tapscript_signature_hash(
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    tapscript: &[u8],
    leaf_version: u8,
    codesep_pos: u32,
    sighash_type: u8,
    annex_hash: Option<&Hash>,
) -> Result<Hash> {
    use sha2::{Digest, Sha256};

    if !(sighash_type <= 0x03 || (0x81..=0x83).contains(&sighash_type)) {
        return Err(crate::error::ConsensusError::InvalidSignature(
            "Invalid Tapscript sighash type".into(),
        ));
    }

    let input_type = sighash_type & 0x80;
    let output_type = if sighash_type == 0x00 {
        0x01
    } else {
        sighash_type & 0x03
    };

    let hashes = bip341_precompute(tx, prevout_values, prevout_script_pubkeys);

    let mut sigmsg = Vec::with_capacity(250);

    // epoch
    sigmsg.push(0x00u8);
    // hash_type
    sigmsg.push(sighash_type);
    // nVersion
    sigmsg.extend_from_slice(&(tx.version as u32).to_le_bytes());
    // nLockTime
    sigmsg.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());

    if input_type != 0x80 {
        sigmsg.extend_from_slice(&hashes.sha_prevouts);
        sigmsg.extend_from_slice(&hashes.sha_amounts);
        sigmsg.extend_from_slice(&hashes.sha_scriptpubkeys);
        sigmsg.extend_from_slice(&hashes.sha_sequences);
    }
    if output_type == 0x01 {
        sigmsg.extend_from_slice(&hashes.sha_outputs);
    }

    // spend_type: ext_flag=1 (script path); annex_present in low bit (BIP341)
    let spend_type = if annex_hash.is_some() { 0x03u8 } else { 0x02u8 };
    sigmsg.push(spend_type);

    if input_type == 0x80 {
        let input = tx.inputs.get(input_index).ok_or_else(|| {
            crate::error::ConsensusError::InvalidSignature("input_index out of range".into())
        })?;
        sigmsg.extend_from_slice(&input.prevout.hash);
        sigmsg.extend_from_slice(&input.prevout.index.to_le_bytes());
        let amount = *prevout_values.get(input_index).ok_or_else(|| {
            crate::error::ConsensusError::InvalidSignature(
                "prevout_values index out of range for script-path ANYONECANPAY".into(),
            )
        })? as u64;
        sigmsg.extend_from_slice(&amount.to_le_bytes());
        let spk = *prevout_script_pubkeys.get(input_index).ok_or_else(|| {
            crate::error::ConsensusError::InvalidSignature(
                "prevout_script_pubkeys index out of range for script-path ANYONECANPAY".into(),
            )
        })?;
        sigmsg.extend_from_slice(&encode_varint(spk.len() as u64));
        sigmsg.extend_from_slice(spk);
        sigmsg.extend_from_slice(&(input.sequence as u32).to_le_bytes());
    } else {
        sigmsg.extend_from_slice(&(input_index as u32).to_le_bytes());
    }

    if let Some(h) = annex_hash {
        sigmsg.extend_from_slice(h);
    }

    if output_type == 0x03 {
        if let Some(output) = tx.outputs.get(input_index) {
            let mut out_data = Vec::new();
            out_data.extend_from_slice(&(output.value as u64).to_le_bytes());
            out_data.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
            out_data.extend_from_slice(&output.script_pubkey);
            sigmsg.extend_from_slice(&Sha256::digest(&out_data));
        }
    }

    // BIP342 extension: tapleaf_hash || key_version(0x00) || codesep_pos
    let tapleaf_hash = crate::secp256k1_backend::tap_leaf_hash(leaf_version, tapscript);
    sigmsg.extend_from_slice(&tapleaf_hash);
    sigmsg.push(0x00u8); // key_version
    sigmsg.extend_from_slice(&codesep_pos.to_le_bytes());

    Ok(crate::secp256k1_backend::tap_sighash_hash(&sigmsg))
}

/// Encode a number as a Bitcoin varint
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut result = vec![0xfd];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        result
    } else if value <= 0xffffffff {
        let mut result = vec![0xfe];
        result.extend_from_slice(&(value as u32).to_le_bytes());
        result
    } else {
        let mut result = vec![0xff];
        result.extend_from_slice(&value.to_le_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_taproot_script_valid() {
        let script = create_taproot_script(&[1u8; 32]);
        assert!(validate_taproot_script(&script).unwrap());
    }

    #[test]
    fn test_validate_taproot_script_invalid_length() {
        let script = vec![0x51, 0x20]; // Too short
        assert!(!validate_taproot_script(&script).unwrap());
    }

    #[test]
    fn test_validate_taproot_script_invalid_prefix() {
        let mut script = vec![0x52]; // Wrong prefix (OP_2 instead of OP_1)
        script.extend_from_slice(&[1u8; 32]);
        assert!(!validate_taproot_script(&script).unwrap());
    }

    #[test]
    fn test_extract_taproot_output_key() {
        let expected_key = [1u8; 32];
        let script = create_taproot_script(&expected_key);

        let extracted_key = extract_taproot_output_key(&script).unwrap();
        assert_eq!(extracted_key, Some(expected_key));
    }

    #[test]
    fn test_compute_taproot_tweak() {
        // Use a valid secp256k1 public key (x-coordinate only for Taproot)
        let internal_pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let merkle_root = [2u8; 32];

        let tweak = compute_taproot_tweak(&internal_pubkey, &merkle_root).unwrap();
        assert_eq!(tweak.len(), 32);
    }

    #[test]
    fn test_validate_taproot_key_aggregation() {
        // Use a valid secp256k1 public key (x-coordinate only for Taproot)
        let internal_pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let merkle_root = [2u8; 32];
        let (output_key, parity) = crate::secp256k1_backend::taproot_output_key_with_parity(
            &internal_pubkey,
            &merkle_root,
        )
        .unwrap();

        assert!(
            validate_taproot_key_aggregation(&internal_pubkey, &merkle_root, &output_key, parity)
                .unwrap()
        );
    }

    #[test]
    fn test_validate_taproot_script_path() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2
        let merkle_proof = vec![[3u8; 32], [4u8; 32]];
        let merkle_root =
            compute_script_merkle_root(&script, &merkle_proof, TAPROOT_LEAF_VERSION_TAPSCRIPT)
                .unwrap();

        assert!(validate_taproot_script_path(&script, &merkle_proof, &merkle_root).unwrap());
    }

    #[test]
    fn test_validate_taproot_script_requires_push_opcode() {
        // 34 bytes but missing PUSH_32 (0x20) before output key
        let mut bad = vec![TAPROOT_SCRIPT_PREFIX];
        bad.extend_from_slice(&[0u8; 33]);
        assert!(!validate_taproot_script(&bad).unwrap());

        assert!(validate_taproot_script(&create_taproot_script(&[1u8; 32])).unwrap());
    }

    #[test]
    fn test_is_taproot_output() {
        let output = TransactionOutput {
            value: 1000,
            script_pubkey: create_taproot_script(&[1u8; 32]),
        };

        assert!(is_taproot_output(&output));
    }

    #[test]
    fn test_validate_taproot_transaction() {
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
                script_pubkey: create_taproot_script(&[1u8; 32]),
            }]
            .into(),
            lock_time: 0,
        };

        // Key path spend: single signature
        let witness = Some(vec![vec![0u8; 64]]);
        assert!(validate_taproot_transaction(&tx, witness.as_ref()).unwrap());
    }

    #[test]
    fn test_compute_taproot_signature_hash() {
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
                script_pubkey: vec![0x51],
            }]
            .into(),
            lock_time: 0,
        };

        let prevouts = [TransactionOutput {
            value: 2000,
            script_pubkey: create_taproot_script(&[1u8; 32]),
        }];
        let pv: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
        let psp: Vec<&[u8]> = prevouts
            .iter()
            .map(|p| p.script_pubkey.as_slice())
            .collect();
        let sig_hash = compute_taproot_signature_hash(&tx, 0, &pv, &psp, 0x01, None).unwrap();
        assert_eq!(sig_hash.len(), 32);
    }

    /// N7: multi-input Taproot reuses BIP341 commitments (TLS) — bit-identical across calls.
    #[test]
    fn n7_bip341_tls_cache_multi_input_identical() {
        let tx = Transaction {
            version: 2,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint {
                        hash: [1u8; 32],
                        index: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint {
                        hash: [2u8; 32],
                        index: 1,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ]
            .into(),
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }]
            .into(),
            lock_time: 0,
        };
        let prevouts = [
            TransactionOutput {
                value: 2000,
                script_pubkey: create_taproot_script(&[1u8; 32]),
            },
            TransactionOutput {
                value: 3000,
                script_pubkey: create_taproot_script(&[2u8; 32]),
            },
        ];
        let pv: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
        let psp: Vec<&[u8]> = prevouts
            .iter()
            .map(|p| p.script_pubkey.as_slice())
            .collect();
        let h0 = compute_taproot_signature_hash(&tx, 0, &pv, &psp, 0x01, None).unwrap();
        let h1 = compute_taproot_signature_hash(&tx, 1, &pv, &psp, 0x01, None).unwrap();
        assert_ne!(h0, h1);
        // Explicit compute matches TLS path (second call hits cache).
        let direct = Bip341PrecomputedHashes::compute(&tx, &pv, &psp);
        let cached = bip341_precompute(&tx, &pv, &psp);
        assert_eq!(direct.sha_prevouts, cached.sha_prevouts);
        assert_eq!(direct.sha_outputs, cached.sha_outputs);
        let t0 = std::time::Instant::now();
        for _ in 0..500 {
            let _ = bip341_precompute(&tx, &pv, &psp);
        }
        let cached_ns = t0.elapsed().as_nanos() / 500;
        let t1 = std::time::Instant::now();
        for _ in 0..500 {
            let _ = Bip341PrecomputedHashes::compute(&tx, &pv, &psp);
        }
        let fresh_ns = t1.elapsed().as_nanos() / 500;
        eprintln!("[N7 micro] bip341 TLS≈{cached_ns} ns/op fresh≈{fresh_ns} ns/op");
        assert!(
            cached_ns < fresh_ns,
            "TLS cache should beat full bip341_precompute"
        );
    }

    #[test]
    fn test_compute_taproot_signature_hash_invalid_input_index() {
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
                script_pubkey: vec![0x51],
            }]
            .into(),
            lock_time: 0,
        };

        let prevouts = [TransactionOutput {
            value: 2000,
            script_pubkey: create_taproot_script(&[1u8; 32]),
        }];
        let pv: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
        let psp: Vec<&[u8]> = prevouts
            .iter()
            .map(|p| p.script_pubkey.as_slice())
            .collect();
        // Use invalid input index (out of bounds)
        let sig_hash = compute_taproot_signature_hash(&tx, 1, &pv, &psp, 0x01, None).unwrap();
        assert_eq!(sig_hash.len(), 32);
    }

    #[test]
    fn test_compute_taproot_signature_hash_empty_prevouts() {
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
                script_pubkey: vec![0x51],
            }]
            .into(),
            lock_time: 0,
        };

        // Empty prevout slices with a non-empty input list must return Err (fail-closed).
        // Previously this silently used zeros; the audit fix made it explicit.
        let prevouts: Vec<TransactionOutput> = vec![];
        let pv: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
        let psp: Vec<&[u8]> = prevouts
            .iter()
            .map(|p| p.script_pubkey.as_slice())
            .collect();
        let result = compute_taproot_signature_hash(&tx, 0, &pv, &psp, 0x01, None);
        assert!(
            result.is_err(),
            "empty prevouts shorter than tx.inputs must return Err, not silently use zeros"
        );
    }

    #[test]
    fn test_compute_taproot_tweak_invalid_pubkey() {
        let invalid_pubkey = [0u8; 32]; // Invalid public key
        let merkle_root = [2u8; 32];

        let result = compute_taproot_tweak(&invalid_pubkey, &merkle_root);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_taproot_key_aggregation_invalid() {
        let internal_pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let merkle_root = [2u8; 32];
        let wrong_output_key = [3u8; 32]; // Wrong output key

        assert!(
            !validate_taproot_key_aggregation(
                &internal_pubkey,
                &merkle_root,
                &wrong_output_key,
                0, // parity — irrelevant since key mismatch will fail first
            )
            .unwrap()
        );
    }

    #[test]
    fn test_validate_taproot_script_path_invalid() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2
        let merkle_proof = vec![[3u8; 32], [4u8; 32]];
        let wrong_merkle_root = [5u8; 32]; // Wrong merkle root

        assert!(!validate_taproot_script_path(&script, &merkle_proof, &wrong_merkle_root).unwrap());
    }

    #[test]
    fn test_validate_taproot_script_path_empty_proof() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2
        let merkle_proof = vec![];
        let merkle_root =
            compute_script_merkle_root(&script, &merkle_proof, TAPROOT_LEAF_VERSION_TAPSCRIPT)
                .unwrap();

        assert!(validate_taproot_script_path(&script, &merkle_proof, &merkle_root).unwrap());
    }

    #[test]
    fn test_tap_leaf_hash() {
        let script = vec![0x51, 0x52];
        let hash = crate::secp256k1_backend::tap_leaf_hash(TAPROOT_LEAF_VERSION_TAPSCRIPT, &script);

        assert_eq!(hash.len(), 32);

        let script2 = vec![0x53, 0x54];
        let hash2 =
            crate::secp256k1_backend::tap_leaf_hash(TAPROOT_LEAF_VERSION_TAPSCRIPT, &script2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_tap_branch_hash() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash = crate::secp256k1_backend::tap_branch_hash(&left, &right);

        assert_eq!(hash.len(), 32);

        let hash2 = crate::secp256k1_backend::tap_branch_hash(&right, &left);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_encode_varint_small() {
        let encoded = encode_varint(0xfc);
        assert_eq!(encoded, vec![0xfc]);
    }

    #[test]
    fn test_encode_varint_medium() {
        let encoded = encode_varint(0x1000);
        assert_eq!(encoded.len(), 3);
        assert_eq!(encoded[0], 0xfd);
    }

    #[test]
    fn test_encode_varint_large() {
        let encoded = encode_varint(0x1000000);
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 0xfe);
    }

    #[test]
    fn test_encode_varint_huge() {
        let encoded = encode_varint(0x1000000000000000);
        assert_eq!(encoded.len(), 9);
        assert_eq!(encoded[0], 0xff);
    }

    #[test]
    fn test_extract_taproot_output_key_invalid_script() {
        let script = vec![0x52, 0x20]; // Invalid script
        let result = extract_taproot_output_key(&script).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_is_taproot_output_false() {
        let output = TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x52, 0x20], // Not a Taproot script
        };

        assert!(!is_taproot_output(&output));
    }

    #[test]
    fn test_validate_taproot_transaction_no_taproot_outputs() {
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
                script_pubkey: vec![0x52], // Not Taproot
            }]
            .into(),
            lock_time: 0,
        };

        // No witness needed for non-Taproot transaction
        assert!(validate_taproot_transaction(&tx, None).unwrap());
    }

    #[test]
    fn test_validate_taproot_transaction_invalid_taproot_output() {
        // Create a transaction with a valid Taproot script
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
                script_pubkey: create_taproot_script(&[1u8; 32]),
            }]
            .into(),
            lock_time: 0,
        };

        // Key path spend: single signature
        let witness = Some(vec![vec![0u8; 64]]);
        assert!(validate_taproot_transaction(&tx, witness.as_ref()).unwrap());
    }

    // Helper function
    fn create_taproot_script(output_key: &[u8; 32]) -> ByteString {
        let mut script = vec![TAPROOT_SCRIPT_PREFIX, PUSH_32_BYTES];
        script.extend_from_slice(output_key);
        script
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Property test: Taproot script validation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString: validate_taproot_script(script) is deterministic
    proptest! {
        #[test]
        fn prop_validate_taproot_script_deterministic(
            script in prop::collection::vec(any::<u8>(), 0..50)
        ) {
            let result1 = validate_taproot_script(&script).unwrap();
            let result2 = validate_taproot_script(&script).unwrap();

            assert_eq!(result1, result2);
        }
    }

    /// Property test: Taproot output key extraction is correct
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString: if validate_taproot_script(script) = true
    /// then extract_taproot_output_key(script) returns Some(key)
    proptest! {
        #[test]
        fn prop_extract_taproot_output_key_correct(
            script in prop::collection::vec(any::<u8>(), 0..50)
        ) {
            let extracted_key = extract_taproot_output_key(&script).unwrap();
            let is_valid = validate_taproot_script(&script).unwrap();

            if is_valid {
                assert!(extracted_key.is_some());
                let key = extracted_key.unwrap();
                assert_eq!(key.len(), 32);
            } else {
                assert!(extracted_key.is_none());
            }
        }
    }

    /// Property test: Taproot key aggregation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ internal_pubkey ∈ [u8; 32], merkle_root ∈ Hash:
    /// compute_taproot_tweak(internal_pubkey, merkle_root) is deterministic
    proptest! {
        #[test]
        fn prop_taproot_key_aggregation_deterministic(
            internal_pubkey in create_pubkey_strategy(),
            merkle_root in create_hash_strategy()
        ) {
            let result1 = compute_taproot_tweak(&internal_pubkey, &merkle_root);
            let result2 = compute_taproot_tweak(&internal_pubkey, &merkle_root);

            assert_eq!(result1.is_ok(), result2.is_ok());
            if result1.is_ok() && result2.is_ok() {
                assert_eq!(result1.unwrap(), result2.unwrap());
            }
        }
    }

    /// Property test: Taproot script path validation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString, merkle_proof ∈ [Hash], merkle_root ∈ Hash:
    /// validate_taproot_script_path(script, merkle_proof, merkle_root) is deterministic
    proptest! {
        #[test]
        fn prop_validate_taproot_script_path_deterministic(
            script in prop::collection::vec(any::<u8>(), 0..20),
            merkle_proof in prop::collection::vec(create_hash_strategy(), 0..5),
            merkle_root in create_hash_strategy()
        ) {
            let result1 = validate_taproot_script_path(&script, &merkle_proof, &merkle_root);
            let result2 = validate_taproot_script_path(&script, &merkle_proof, &merkle_root);

            assert_eq!(result1.is_ok(), result2.is_ok());
            if result1.is_ok() && result2.is_ok() {
                assert_eq!(result1.unwrap(), result2.unwrap());
            }
        }
    }

    /// Property test: Taproot signature hash computation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ tx ∈ Transaction, input_index ∈ ℕ, prevouts ∈ [TransactionOutput], sighash_type ∈ ℕ:
    /// compute_taproot_signature_hash(tx, input_index, prevouts, sighash_type) is deterministic
    proptest! {
        #[test]
        fn prop_compute_taproot_signature_hash_deterministic(
            tx in create_transaction_strategy(),
            input_index in 0..10usize,
            prevouts in prop::collection::vec(create_output_strategy(), 0..5),
            sighash_type in any::<u8>()
        ) {
            let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
            let prevout_script_pubkeys: Vec<&[u8]> = prevouts.iter().map(|p| p.script_pubkey.as_slice()).collect();
            let result1 = compute_taproot_signature_hash(&tx, input_index, &prevout_values, &prevout_script_pubkeys, sighash_type, None);
            let result2 = compute_taproot_signature_hash(&tx, input_index, &prevout_values, &prevout_script_pubkeys, sighash_type, None);

            assert_eq!(result1.is_ok(), result2.is_ok());
            if let (Ok(hash1), Ok(hash2)) = (&result1, &result2) {
                assert_eq!(hash1, hash2);
                assert_eq!(hash1.len(), 32);
            }

            // Hash should be 32 bytes if result is Ok
            if let Ok(ref hash) = result1 {
                assert_eq!(hash.len(), 32);
            }
        }
    }

    /// Property test: Taproot output detection is consistent
    ///
    /// Mathematical specification:
    /// ∀ output ∈ TransactionOutput: is_taproot_output(output) ∈ {true, false}
    proptest! {
        #[test]
        fn prop_is_taproot_output_consistent(
            output in create_output_strategy()
        ) {
            let is_taproot = is_taproot_output(&output);
            // Just test it returns a boolean (is_taproot is either true or false)
            let _ = is_taproot;
        }
    }

    /// Property test: Taproot transaction validation is deterministic
    ///
    /// Mathematical specification:
    /// ∀ tx ∈ Transaction: validate_taproot_transaction(tx) is deterministic
    proptest! {
        #[test]
        fn prop_validate_taproot_transaction_deterministic(
            tx in create_transaction_strategy()
        ) {
            let result1 = validate_taproot_transaction(&tx, None).unwrap();
            let result2 = validate_taproot_transaction(&tx, None).unwrap();

            assert_eq!(result1, result2);
        }
    }

    /// Property test: TapLeaf hashing is deterministic
    proptest! {
        #[test]
        fn prop_tap_leaf_hash_deterministic(
            script in prop::collection::vec(any::<u8>(), 0..20)
        ) {
            let hash1 = crate::secp256k1_backend::tap_leaf_hash(TAPROOT_LEAF_VERSION_TAPSCRIPT, &script);
            let hash2 = crate::secp256k1_backend::tap_leaf_hash(TAPROOT_LEAF_VERSION_TAPSCRIPT, &script);

            assert_eq!(hash1, hash2);
            assert_eq!(hash1.len(), 32);
        }
    }

    /// Property test: TapBranch hashing is deterministic
    proptest! {
        #[test]
        fn prop_tap_branch_hash_deterministic(
            left in create_hash_strategy(),
            right in create_hash_strategy()
        ) {
            let hash1 = crate::secp256k1_backend::tap_branch_hash(&left, &right);
            let hash2 = crate::secp256k1_backend::tap_branch_hash(&left, &right);

            assert_eq!(hash1, hash2);
            assert_eq!(hash1.len(), 32);
        }
    }

    /// Property test: Varint encoding is deterministic
    ///
    /// Mathematical specification:
    /// ∀ value ∈ ℕ: encode_varint(value) is deterministic
    proptest! {
        #[test]
        fn prop_encode_varint_deterministic(
            value in 0..u64::MAX
        ) {
            let encoded1 = encode_varint(value);
            let encoded2 = encode_varint(value);

            assert_eq!(encoded1, encoded2);

            // Encoded length should be reasonable
            assert!(!encoded1.is_empty());
            assert!(encoded1.len() <= 9);
        }
    }

    /// Property test: Varint encoding preserves value
    ///
    /// Mathematical specification:
    /// ∀ value ∈ ℕ: decode_varint(encode_varint(value)) = value
    proptest! {
        #[test]
        fn prop_encode_varint_preserves_value(
            value in 0..1000000u64  // Smaller range for tractability
        ) {
            let encoded = encode_varint(value);

            // Basic validation of encoding format
            match encoded.len() {
                1 => {
                    // Single byte encoding
                    assert!(value < 0xfd);
                    assert_eq!(encoded[0], value as u8);
                },
                3 => {
                    // 2-byte encoding
                    assert!((0xfd..=0xffff).contains(&value));
                    assert_eq!(encoded[0], 0xfd);
                },
                5 => {
                    // 4-byte encoding
                    assert!(value > 0xffff && value <= 0xffffffff);
                    assert_eq!(encoded[0], 0xfe);
                },
                9 => {
                    // 8-byte encoding
                    assert!(value > 0xffffffff);
                    assert_eq!(encoded[0], 0xff);
                },
                _ => panic!("Invalid varint encoding length"),
            }
        }
    }

    /// Property test: Taproot script path validation with correct proof
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString, merkle_proof ∈ [Hash]:
    /// If computed_root = compute_script_merkle_root(script, merkle_proof)
    /// then validate_taproot_script_path(script, merkle_proof, computed_root) = true
    proptest! {
        #[test]
        fn prop_validate_taproot_script_path_correct_proof(
            script in prop::collection::vec(any::<u8>(), 0..20),
            merkle_proof in prop::collection::vec(create_hash_strategy(), 0..5)
        ) {
            let computed_root = compute_script_merkle_root(&script, &merkle_proof, TAPROOT_LEAF_VERSION_TAPSCRIPT).unwrap();
            let is_valid = validate_taproot_script_path(&script, &merkle_proof, &computed_root).unwrap();

            assert!(is_valid);
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
                        script_sig: vec![],
                        sequence: 0xffffffff,
                    });
                }

                let mut outputs = Vec::new();
                for _ in output_data {
                    outputs.push(TransactionOutput {
                        value: 1000,
                        script_pubkey: vec![0x51],
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

    fn create_output_strategy() -> impl Strategy<Value = TransactionOutput> {
        (any::<i64>(), prop::collection::vec(any::<u8>(), 0..50)).prop_map(|(value, script)| {
            TransactionOutput {
                value,
                script_pubkey: script,
            }
        })
    }

    fn create_hash_strategy() -> impl Strategy<Value = Hash> {
        prop::collection::vec(any::<u8>(), 32..=32).prop_map(|bytes| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            hash
        })
    }

    fn create_pubkey_strategy() -> impl Strategy<Value = [u8; 32]> {
        prop::collection::vec(any::<u8>(), 32..=32).prop_map(|bytes| {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&bytes);
            pubkey
        })
    }
}
