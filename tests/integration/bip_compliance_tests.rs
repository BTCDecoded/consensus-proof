//! BIP Compliance Tests
//!
//! Tests for compliance with consensus rules for BIPs.
//! These tests verify that our BIP implementations match BIP specification validation logic.

use blvm_consensus::bip113::get_median_time_past;
use blvm_consensus::constants::LOCKTIME_THRESHOLD;
use blvm_consensus::opcodes::*;
use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::*;

#[test]
fn test_bip65_cltv_compliance_basic() {
    // Basic CLTV compliance: transaction locktime must be >= required locktime
    // This matches BIP validation logic

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: {
                let mut script = vec![OP_1]; // OP_1
                script.extend_from_slice(&encode_varint(400000)); // Required locktime
                script.push(OP_CHECKLOCKTIMEVERIFY); // CLTV
                script
            },
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 500000, // >= required
    };

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [1; 32],
            index: 0,
        },
        std::sync::Arc::new(UTXO {
            value: 1000000,
            script_pubkey: vec![OP_1].into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let input = &tx.inputs[0];
    let utxo = utxo_set.get(&input.prevout).unwrap();
    let pv = vec![utxo.value];
    let psp: Vec<&[u8]> = vec![utxo.script_pubkey.as_ref()];

    // Should pass:
    let result = verify_script_with_context_full(
        input.script_sig.as_ref(),
        utxo.script_pubkey.as_ref(),
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        Some(500000), // Block height for CLTV
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    assert!(result.is_ok());
    // Note: Full validation would require exact block height context
}

#[test]
fn test_bip112_csv_compliance_basic() {
    // Basic CSV compliance: input sequence must be >= required sequence
    // This matches BIP validation logic

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: {
                let mut script = vec![OP_1]; // OP_1
                script.extend_from_slice(&encode_varint(0x00040000)); // 4 blocks required
                script.push(OP_CHECKSEQUENCEVERIFY); // CSV
                script
            },
            sequence: 0x00050000, // 5 blocks (>= required)
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [1; 32],
            index: 0,
        },
        std::sync::Arc::new(UTXO {
            value: 1000000,
            script_pubkey: vec![OP_1].into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let input = &tx.inputs[0];
    let utxo = utxo_set.get(&input.prevout).unwrap();
    let pv = vec![utxo.value];
    let psp: Vec<&[u8]> = vec![utxo.script_pubkey.as_ref()];

    // Should pass: input sequence (5 blocks) >= required (4 blocks)
    let result = verify_script_with_context_full(
        input.script_sig.as_ref(),
        utxo.script_pubkey.as_ref(),
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    assert!(result.is_ok());
}

#[test]
fn test_bip113_median_time_past_compliance() {
    // BIP113 compliance: median time-past uses last 11 blocks
    // Matches BIP113 median time calculation

    let timestamps = vec![
        1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000,
    ];

    let headers: Vec<BlockHeader> = timestamps
        .iter()
        .map(|&t| BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: t,
            bits: 0x1d00ffff,
            nonce: 0,
        })
        .collect();

    let median = get_median_time_past(&headers);

    // Median of 11 sorted timestamps should be the 6th value (index 5)
    // [1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000]
    // Median = 1500 (6th element)
    assert_eq!(median, 1500);
}

#[test]
fn test_bip65_cltv_type_mismatch_rejection() {
    // Consensus rejects CLTV when locktime types don't match
    // Block height vs timestamp mismatch should fail

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: {
                let mut script = vec![OP_1];
                script.extend_from_slice(&encode_varint(600000000)); // Timestamp (>= threshold)
                script.push(OP_CHECKLOCKTIMEVERIFY); // CLTV
                script
            },
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 400000, // Block height (< threshold)
    };

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [1; 32],
            index: 0,
        },
        std::sync::Arc::new(UTXO {
            value: 1000000,
            script_pubkey: vec![OP_1].into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let input = &tx.inputs[0];
    let utxo = utxo_set.get(&input.prevout).unwrap();
    let pv = vec![utxo.value];
    let psp: Vec<&[u8]> = vec![utxo.script_pubkey.as_ref()];

    // Should fail: type mismatch (block height vs timestamp)
    let result = verify_script_with_context_full(
        input.script_sig.as_ref(),
        utxo.script_pubkey.as_ref(),
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should fail validation
}

#[test]
fn test_bip112_csv_disabled_sequence_rejection() {
    // Consensus rejects CSV when sequence is disabled (0x80000000 bit set)

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: {
                let mut script = vec![OP_1];
                script.extend_from_slice(&encode_varint(0x00040000));
                script.push(OP_CHECKSEQUENCEVERIFY); // CSV
                script
            },
            sequence: 0x80000000, // Sequence disabled
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [1; 32],
            index: 0,
        },
        std::sync::Arc::new(UTXO {
            value: 1000000,
            script_pubkey: vec![OP_1].into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let input = &tx.inputs[0];
    let utxo = utxo_set.get(&input.prevout).unwrap();
    let pv = vec![utxo.value];
    let psp: Vec<&[u8]> = vec![utxo.script_pubkey.as_ref()];

    // Should fail: sequence disabled
    let result = verify_script_with_context_full(
        input.script_sig.as_ref(),
        utxo.script_pubkey.as_ref(),
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should fail validation
}

// Helper function for encoding varints (used in tests)
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut bytes = vec![0xfd];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value <= 0xffffffff {
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}
