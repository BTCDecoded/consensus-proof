//! Unified witness validation framework for SegWit (BIP141) and Taproot (BIP340/341/342)
//!
//! Provides shared functions for witness structure validation, weight calculation,
//! and witness data handling that are common to both SegWit and Taproot.

use crate::error::Result;
use crate::opcodes::*;
use crate::types::*;
use blvm_spec_lock::spec_locked;

/// Witness Data: 𝒲 = 𝕊* (stack of witness elements)
///
/// Re-export from primitives for backward compatibility.
/// Witness validation logic stays in this module.
pub use crate::types::Witness;

/// Witness version for SegWit (v0) and Taproot (v1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessVersion {
    /// SegWit version 0
    SegWitV0 = 0,
    /// Taproot version 1
    TaprootV1 = 1,
}

/// Validate witness structure for SegWit
///
/// BIP141: Witness must be a vector of byte strings (stack elements).
/// Each element can be up to MAX_SCRIPT_ELEMENT_SIZE bytes.
#[spec_locked("11.1.2", "ValidateSegWitWitnessStructure")]
pub fn validate_segwit_witness_structure(witness: &Witness) -> Result<bool> {
    // Check each witness element size
    // BIP141: Each witness element can be up to 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
    // Using 520 as the limit per Bitcoin consensus rules
    const MAX_WITNESS_ELEMENT_SIZE: usize = 520;
    for element in witness {
        if element.len() > MAX_WITNESS_ELEMENT_SIZE {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Validate witness structure for Taproot
///
/// BIP341: Taproot witness structure depends on spending path:
/// - Key path: single signature (64 bytes)
/// - Script path: script, control block (33 + 32n bytes), and witness items
#[spec_locked("11.2.4", "ValidateTaprootWitnessStructure")]
pub fn validate_taproot_witness_structure(witness: &Witness, is_script_path: bool) -> Result<bool> {
    if witness.is_empty() {
        return Ok(false);
    }

    if is_script_path {
        // Script path: at least script + control block
        if witness.len() < 2 {
            return Ok(false);
        }

        // Control block must be at least 33 bytes (internal key + leaf version + parity)
        let control_block = &witness[witness.len() - 1];
        if control_block.len() < 33 {
            return Ok(false);
        }

        // Control block size: 33 + 32n (where n is number of merkle proof levels)
        // Must be valid multiple
        if (control_block.len() - 33) % 32 != 0 {
            return Ok(false);
        }
    } else {
        // Key path: single Schnorr signature (64 or 65 bytes per BIP340)
        if witness.len() != 1 {
            return Ok(false);
        }
        let len = witness[0].len();
        if len != 64 && len != 65 {
            return Ok(false);
        }
        if len == 65 && witness[0][64] == 0x00 {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Calculate transaction weight using SegWit formula
///
/// BIP141: Weight(tx) = 3 × BaseSize(tx) + TotalSize(tx)
/// BaseSize: Transaction size without witness data
/// TotalSize: Transaction size with witness data
///
/// BIP141: weight = base_size * 3 + total_size; result is always ≥ total_size
/// because the base_size term adds non-negative weight.
#[spec_locked("11.1.1", "CalculateTransactionWeight")]
#[blvm_spec_lock::requires(total_size >= base_size)]
#[blvm_spec_lock::ensures(result >= total_size)]
#[blvm_spec_lock::ensures(result >= 4 * base_size)]
pub fn calculate_transaction_weight_segwit(base_size: Natural, total_size: Natural) -> Natural {
    3 * base_size + total_size
}

/// Calculate virtual size (vsize) from weight
///
/// BIP141: vsize = ceil(weight / 4)
/// Used for fee calculation in SegWit transactions
///
/// Mathematical specification:
/// - vsize = ⌈weight / 4⌉
///
/// Ceiling-division invariant: result * 4 ≥ weight (vsize * 4 is always ≥ weight).
#[spec_locked("11.1.1", "WeightToVSize")]
#[blvm_spec_lock::ensures(result * 4 >= weight)]
#[blvm_spec_lock::ensures(result <= weight)]
pub fn weight_to_vsize(weight: Natural) -> Natural {
    let result = weight.div_ceil(4);

    // Runtime assertion: Verify ceiling division property
    // vsize must be >= weight / 4 (ceiling property)
    let weight_div_4 = weight / 4;
    debug_assert!(
        result >= weight_div_4,
        "Vsize ({result}) must be >= weight / 4 ({weight_div_4})"
    );

    // Runtime assertion: vsize must be <= (weight / 4) + 1 (ceiling property)
    // Note: When weight % 4 == 0, result == weight/4, otherwise result == (weight/4) + 1
    let weight_div_4_plus_1 = weight_div_4 + 1;
    debug_assert!(
        result <= weight_div_4_plus_1,
        "Vsize ({result}) must be <= (weight / 4) + 1 ({weight_div_4_plus_1})"
    );

    // Natural is always non-negative - no assertion needed

    result
}

/// True when `scriptPubKey` is a witness program that is not standard v0 (P2WPKH/P2WSH) or v1 P2TR.
///
/// Used with `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`.
#[inline]
pub fn is_upgradable_witness_program(script: &[u8]) -> bool {
    if script.len() < 4 {
        return false;
    }
    let version = script[0];
    if version > OP_16 {
        return false;
    }
    let push = script[1];
    if !(0x02..=0x28).contains(&push) {
        return false;
    }
    let program_len = push as usize;
    if script.len() != 2 + program_len {
        return false;
    }
    if version == OP_0 {
        return program_len != 20 && program_len != 32;
    }
    if version == OP_1 && program_len == 32 {
        return false;
    }
    true
}

/// Validate witness version in scriptPubKey
///
/// Shared function for extracting and validating witness version
/// from SegWit v0 (OP_0 <witness-program>) or Taproot v1 (OP_1 <witness-program>)
#[spec_locked("11.1.3", "ExtractWitnessVersion")]
pub fn extract_witness_version(script: &ByteString) -> Option<WitnessVersion> {
    // BIP141 §witness_program: scriptPubKey must be exactly [version, push, program_bytes]
    // where program_bytes is 2–40 bytes. Minimum valid length is 4 bytes (version + push + 2).
    if script.len() < 4 {
        return None;
    }

    // Validate the push opcode encodes a 2–40 byte program.
    let push_opcode = script[1];
    let program_len = push_opcode as usize; // direct push opcodes (0x02..=0x28) encode their length
    if !(2..=40).contains(&program_len) {
        return None;
    }
    // The script must be exactly version(1) + push(1) + program_bytes
    if script.len() != 2 + program_len {
        return None;
    }

    match script[0] {
        OP_1 => Some(WitnessVersion::TaprootV1),
        OP_0 => Some(WitnessVersion::SegWitV0),
        _ => None,
    }
}

/// Extract witness program from scriptPubKey
///
/// For SegWit v0: Returns bytes after OP_0 and push opcode
/// For Taproot v1: Returns bytes after OP_1 and push opcode
///
/// Format: [version_opcode, push_opcode, program_bytes]
/// Returns: program_bytes (without push opcode)
#[spec_locked("11.1.3", "ExtractWitnessProgram")]
pub fn extract_witness_program(
    script: &ByteString,
    _version: WitnessVersion,
) -> Option<ByteString> {
    if script.len() < 4 {
        return None;
    }

    let push_opcode = script[1];
    // BIP141 witness programs use direct push opcodes only (0x02..=0x28).
    if !(0x02..=0x28).contains(&push_opcode) {
        return None;
    }
    let program_len = push_opcode as usize;
    if script.len() != 2 + program_len {
        return None;
    }

    Some(script[2..2 + program_len].to_vec())
}

/// Validate witness program length
///
/// BIP141: SegWit v0 programs are 20 or 32 bytes (P2WPKH or P2WSH)
/// BIP341: Taproot v1 programs are 32 bytes (P2TR)
///
/// Length invariant: when the function returns true, the program is exactly 20 or 32 bytes.
/// (P2WPKH = 20, P2WSH = P2TR = 32; no other lengths are valid.)
#[spec_locked("11.1.3", "ValidateWitnessProgramLength")]
#[blvm_spec_lock::ensures(result == false || program.len() == 20 || program.len() == 32)]
pub fn validate_witness_program_length(program: &ByteString, version: WitnessVersion) -> bool {
    use crate::constants::{SEGWIT_P2WPKH_LENGTH, SEGWIT_P2WSH_LENGTH, TAPROOT_PROGRAM_LENGTH};

    match version {
        WitnessVersion::SegWitV0 => {
            // P2WPKH: 20 bytes, P2WSH: 32 bytes
            program.len() == SEGWIT_P2WPKH_LENGTH || program.len() == SEGWIT_P2WSH_LENGTH
        }
        WitnessVersion::TaprootV1 => {
            // P2TR: 32 bytes
            program.len() == TAPROOT_PROGRAM_LENGTH
        }
    }
}

/// Check if witness is empty (non-witness transaction)
///
/// Non-emptiness invariant: if the function returns false, the witness must have at
/// least one stack element (len > 0).  An empty witness stack trivially returns true.
#[spec_locked("11.1.2", "IsWitnessEmpty")]
#[blvm_spec_lock::ensures(result == true || witness.len() > 0)]
pub fn is_witness_empty(witness: &Witness) -> bool {
    witness.is_empty() || witness.iter().all(|elem| elem.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_segwit_witness_structure() {
        let witness = vec![
            vec![0x01; 20], // P2WPKH witness
            vec![0x02; 72], // Signature
        ];
        assert!(validate_segwit_witness_structure(&witness).unwrap());

        // Too large element
        let invalid_witness = vec![vec![0x01; crate::constants::MAX_SCRIPT_ELEMENT_SIZE + 1]];
        assert!(!validate_segwit_witness_structure(&invalid_witness).unwrap());
    }

    #[test]
    fn test_validate_taproot_witness_structure_key_path() {
        // Key path: single 64-byte signature
        let witness = vec![vec![0x01; 64]];
        assert!(validate_taproot_witness_structure(&witness, false).unwrap());

        // Invalid: wrong length
        let invalid = vec![vec![0x01; 63]];
        assert!(!validate_taproot_witness_structure(&invalid, false).unwrap());

        // Valid: 65-byte sig with explicit SIGHASH_ALL (accepted by BIP340 rules)
        let with_hashtype = vec![
            vec![0x01; 64]
                .into_iter()
                .chain([0x01u8])
                .collect::<Vec<_>>(),
        ];
        assert!(validate_taproot_witness_structure(&with_hashtype, false).unwrap());

        // Invalid: explicit SIGHASH_DEFAULT suffix
        let invalid_hashtype = vec![
            vec![0x01; 64]
                .into_iter()
                .chain([0x00u8])
                .collect::<Vec<_>>(),
        ];
        assert!(!validate_taproot_witness_structure(&invalid_hashtype, false).unwrap());

        // Invalid: multiple elements
        let invalid2 = vec![vec![0x01; 64], vec![0x02; 32]];
        assert!(!validate_taproot_witness_structure(&invalid2, false).unwrap());
    }

    #[test]
    fn test_validate_taproot_witness_structure_script_path() {
        // Script path: script + control block (33 bytes minimum)
        let witness = vec![
            vec![OP_1],    // Script
            vec![0u8; 33], // Control block (internal key + leaf version + parity)
        ];
        assert!(validate_taproot_witness_structure(&witness, true).unwrap());

        // Invalid: control block too small
        let invalid = vec![vec![OP_1], vec![0u8; 32]];
        assert!(!validate_taproot_witness_structure(&invalid, true).unwrap());

        // Invalid: only one element
        let invalid2 = vec![vec![OP_1]];
        assert!(!validate_taproot_witness_structure(&invalid2, true).unwrap());
    }

    #[test]
    fn test_calculate_transaction_weight_segwit() {
        let base_size = 100;
        let total_size = 150;
        let weight = calculate_transaction_weight_segwit(base_size, total_size);
        assert_eq!(weight, 3 * base_size + total_size); // BIP141
    }

    #[test]
    fn test_weight_to_vsize() {
        assert_eq!(weight_to_vsize(400), 100); // Exact division
        assert_eq!(weight_to_vsize(401), 101); // Ceiling
        assert_eq!(weight_to_vsize(403), 101); // Ceiling
        assert_eq!(weight_to_vsize(404), 101); // Ceiling
    }

    #[test]
    fn test_extract_witness_version() {
        // P2WPKH: OP_0 PUSH_20 <20 bytes> — must be exactly 22 bytes (BIP141).
        let mut segwit_script = vec![OP_0, PUSH_20_BYTES];
        segwit_script.extend([0x01u8; 20]);
        assert_eq!(
            extract_witness_version(&segwit_script),
            Some(WitnessVersion::SegWitV0)
        );

        // P2TR: OP_1 PUSH_32 <32 bytes> — must be exactly 34 bytes (BIP341).
        let mut taproot_script = vec![OP_1, PUSH_32_BYTES];
        taproot_script.extend([0x02u8; 32]);
        assert_eq!(
            extract_witness_version(&taproot_script),
            Some(WitnessVersion::TaprootV1)
        );

        let non_witness_script = vec![OP_DUP, OP_HASH160]; // OP_DUP OP_HASH160
        assert_eq!(extract_witness_version(&non_witness_script), None);
    }

    #[test]
    fn test_extract_witness_program() {
        // P2WPKH format: [OP_0, PUSH_20_BYTES, <20-byte-hash>]
        // Where OP_0 is OP_0 (witness version), PUSH_20_BYTES is push 20 bytes, then 20 bytes of hash
        // extract_witness_program should return just the program bytes (after push opcode)
        // Note: 0x01 to PUSH_20_BYTES is 20 bytes (1, 2, 3, ..., 20)
        let segwit_script = vec![
            OP_0,
            PUSH_20_BYTES,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            PUSH_20_BYTES,
        ];
        let program = extract_witness_program(&segwit_script, WitnessVersion::SegWitV0);
        // Should return the 20 bytes after the push opcode (PUSH_20_BYTES)
        assert_eq!(
            program,
            Some(vec![
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0a,
                0x0b,
                0x0c,
                0x0d,
                0x0e,
                0x0f,
                0x10,
                0x11,
                0x12,
                0x13,
                PUSH_20_BYTES
            ])
        );
    }

    #[test]
    fn test_extract_witness_program_rejects_non_direct_push() {
        use crate::opcodes::OP_PUSHDATA1;
        // OP_PUSHDATA1 (0x4c) is not valid in a witness program scriptPubKey
        let bad = vec![OP_0, OP_PUSHDATA1, 0x14u8];
        assert_eq!(
            extract_witness_program(&bad, WitnessVersion::SegWitV0),
            None
        );
    }

    #[test]
    fn test_validate_witness_program_length() {
        let p2wpkh = vec![0u8; 20]; // 20 bytes
        assert!(validate_witness_program_length(
            &p2wpkh,
            WitnessVersion::SegWitV0
        ));

        let p2wsh = vec![0u8; 32]; // 32 bytes
        assert!(validate_witness_program_length(
            &p2wsh,
            WitnessVersion::SegWitV0
        ));

        let p2tr = vec![0u8; 32]; // 32 bytes
        assert!(validate_witness_program_length(
            &p2tr,
            WitnessVersion::TaprootV1
        ));

        let invalid = vec![0u8; 33];
        assert!(!validate_witness_program_length(
            &invalid,
            WitnessVersion::SegWitV0
        ));
        assert!(!validate_witness_program_length(
            &invalid,
            WitnessVersion::TaprootV1
        ));
    }

    #[test]
    fn test_is_witness_empty() {
        assert!(is_witness_empty(&vec![]));
        assert!(is_witness_empty(&vec![vec![]]));
        assert!(!is_witness_empty(&vec![vec![0x01]]));
    }
}
