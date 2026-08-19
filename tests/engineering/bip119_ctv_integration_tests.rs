//! BIP119 CTV (OP_CHECKTEMPLATEVERIFY) Integration Tests
//!
//! Comprehensive integration tests for OP_CHECKTEMPLATEVERIFY.
//! Tests CTV in full transaction validation context, including:
//! - Template hash calculation correctness
//! - OP_CHECKTEMPLATEVERIFY opcode execution
//! - Transaction validation with CTV scripts
//! - Block validation with CTV transactions
//! - Edge cases and error conditions
//! - Use case scenarios (vaults, payment channels, etc.)
//!
//! **Feature Flag**: These tests require the `ctv` feature to be enabled.
//! Run with: `cargo test --features ctv --test bip119_ctv_integration_tests`

#![cfg(feature = "ctv")]

use blvm_consensus::opcodes::*;
use blvm_consensus::*;
use blvm_consensus::bip119::{calculate_template_hash, validate_template_hash, is_ctv_script};
use blvm_consensus::script::verify_script_with_context_full;
use super::bip_test_helpers::*;

// ============================================================================
// Template Hash Calculation Tests
// ============================================================================

#[test]
fn test_template_hash_basic_calculation() {
    // Create a simple transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![OP_1], // OP_1 (not included in template)
            sequence: 0xffffffff,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_DUP, OP_HASH160, PUSH_20_BYTES, 0x00, OP_EQUAL].into(), // P2PKH
        }].into(),
        lock_time: 0,
    };

    // Calculate template hash
    let hash = calculate_template_hash(&tx, 0).unwrap();

    // Hash should be 32 bytes
    assert_eq!(hash.len(), 32);

    // Hash should be deterministic
    let hash2 = calculate_template_hash(&tx, 0).unwrap();
    assert_eq!(hash, hash2);
}

#[test]
fn test_template_hash_multiple_inputs() {
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TransactionInput {
                prevout: OutPoint {
                    hash: [0x01; 32].into(),
                    index: 0,
                },
                script_sig: vec![OP_1],
                sequence: 0,
            },
            TransactionInput {
                prevout: OutPoint {
                    hash: [0x02; 32],
                    index: 1,
                },
                script_sig: vec![OP_2],
                sequence: 0,
            },
        ].into(),
        outputs: vec![TransactionOutput {
            value: 2000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Different input indices should produce different hashes
    let hash0 = calculate_template_hash(&tx, 0).unwrap();
    let hash1 = calculate_template_hash(&tx, 1).unwrap();

    assert_ne!(hash0, hash1, "Different input indices must produce different template hashes");
}

#[test]
fn test_template_hash_multiple_outputs() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![
            TransactionOutput {
                value: 1000,
                script_pubkey: vec![OP_1].into(),
            },
            TransactionOutput {
                value: 2000,
                script_pubkey: vec![OP_2].into(),
            },
        ].into(),
        lock_time: 0,
    };

    let hash = calculate_template_hash(&tx, 0).unwrap();
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_template_hash_script_sig_independence() {
    // Create two transactions with different scriptSigs but same structure
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![OP_1], // OP_1
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![OP_2, OP_3], // Different scriptSig
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Template hashes should be identical (scriptSig not included)
    let hash1 = calculate_template_hash(&tx1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx2, 0).unwrap();

    assert_eq!(hash1, hash2, "Template hash should not include scriptSig");
}

#[test]
fn test_template_hash_version_dependency() {
    let tx_v1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let tx_v2 = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let hash1 = calculate_template_hash(&tx_v1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx_v2, 0).unwrap();

    assert_ne!(hash1, hash2, "Different versions must produce different template hashes");
}

#[test]
fn test_template_hash_locktime_dependency() {
    let tx_lt0 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let tx_lt100 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 100,
    };

    let hash1 = calculate_template_hash(&tx_lt0, 0).unwrap();
    let hash2 = calculate_template_hash(&tx_lt100, 0).unwrap();

    assert_ne!(hash1, hash2, "Different locktimes must produce different template hashes");
}

// ============================================================================
// OP_CHECKTEMPLATEVERIFY Opcode Tests
// ============================================================================

#[test]
fn test_ctv_opcode_valid_template() {
    // Create transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Calculate template hash
    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Create script: push template hash + OP_CHECKTEMPLATEVERIFY
    let mut script = Vec::new();
    script.push(PUSH_32_BYTES); // Push 32 bytes
    script.extend_from_slice(&template_hash);
    script.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY

    let pv = vec![1000i64];
    let sp: blvm_consensus::types::ByteString = vec![OP_1].into();
    let psp: Vec<&[u8]> = vec![sp.as_ref()];

    // Verify script with context
    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &script,
        None, // witness
        0, // flags
        &tx,
        0, // input_index
        &pv,
        &psp,
        None, // block_height
        None, // median_time_past
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // CTV should pass with correct template hash
    assert!(result.is_ok() && result.unwrap(), "CTV should pass with valid template hash");
}

#[test]
fn test_ctv_opcode_invalid_template() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Use wrong template hash
    let wrong_hash = [0xff; 32];

    // Create script with wrong hash
    let mut script = Vec::new();
    script.push(PUSH_32_BYTES); // Push 32 bytes
    script.extend_from_slice(&wrong_hash);
    script.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY

    let pv = vec![1000i64];
    let sp: blvm_consensus::types::ByteString = vec![OP_1].into();
    let psp: Vec<&[u8]> = vec![sp.as_ref()];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // CTV should fail with wrong template hash
    assert!(result.is_ok() && !result.unwrap(), "CTV should fail with invalid template hash");
}

#[test]
fn test_ctv_opcode_wrong_hash_size() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Use wrong size (31 bytes instead of 32)
    let wrong_size = vec![0x00; 31];

    let mut script = Vec::new();
    script.push(0x1f); // Push 31 bytes
    script.extend_from_slice(&wrong_size);
    script.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY

    let pv = vec![1000i64];
    let sp: blvm_consensus::types::ByteString = vec![OP_1].into();
    let psp: Vec<&[u8]> = vec![sp.as_ref()];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // CTV should fail with wrong hash size
    assert!(result.is_ok() && !result.unwrap(), "CTV should fail with wrong hash size");
}

#[test]
fn test_ctv_opcode_empty_stack() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Script with just OP_CHECKTEMPLATEVERIFY (no hash on stack)
    let script = vec![OP_CHECKTEMPLATEVERIFY]; // OP_CHECKTEMPLATEVERIFY

    let pv = vec![1000i64];
    let sp: blvm_consensus::types::ByteString = vec![OP_1].into();
    let psp: Vec<&[u8]> = vec![sp.as_ref()];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // CTV should fail with empty stack
    assert!(result.is_ok() && !result.unwrap(), "CTV should fail with empty stack");
}

// ============================================================================
// Transaction Validation Tests
// ============================================================================

#[test]
fn test_ctv_transaction_validation_passes() {
    // Create transaction with CTV script
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![OP_1], // OP_1
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Calculate template hash
    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Create CTV scriptPubkey: push hash + OP_CHECKTEMPLATEVERIFY
    let mut script_pubkey = Vec::new();
    script_pubkey.push(PUSH_32_BYTES); // Push 32 bytes
    script_pubkey.extend_from_slice(&template_hash);
    script_pubkey.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY

    // Update output with CTV script
    tx.outputs[0].script_pubkey = script_pubkey.clone().into();

    // Create UTXO with CTV script
    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint { hash: [0x01; 32], index: 0 },
        std::sync::Arc::new(UTXO {
            value: 1000,
            script_pubkey: script_pubkey.into(),
            is_coinbase: false,
        height: 0,
        }),
    );

    // Verify script
    let pv = vec![1000i64];
    let psp: Vec<&blvm_consensus::types::ByteString> = vec![&tx.outputs[0].script_pubkey];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &tx.outputs[0].script_pubkey,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // Should pass: template hash matches
    assert!(result.is_ok() && result.unwrap(), "CTV transaction validation should pass");
}

#[test]
fn test_ctv_transaction_validation_fails_wrong_structure() {
    // Create transaction
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Calculate template hash for tx1
    let template_hash = calculate_template_hash(&tx1, 0).unwrap();

    // Create tx2 with different structure but same template hash in script
    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 2000, // Different value
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    // Create CTV script with tx1's template hash
    let mut script_pubkey = Vec::new();
    script_pubkey.push(PUSH_32_BYTES);
    script_pubkey.extend_from_slice(&template_hash);
    script_pubkey.push(OP_CHECKTEMPLATEVERIFY);

    // Try to validate tx2 with tx1's template hash
    let pv = vec![1000i64];
    let psp: Vec<&[u8]> = vec![script_pubkey.as_ref()];

    let result = verify_script_with_context_full(
        &tx2.inputs[0].script_sig,
        &script_pubkey,
        None,
        0,
        &tx2,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // Should fail: template hash doesn't match tx2's structure
    assert!(result.is_ok() && !result.unwrap(), "CTV should fail when transaction structure doesn't match template");
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_template_hash_empty_inputs_error() {
    let tx = Transaction {
        version: 1,
        inputs: vec![].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let result = calculate_template_hash(&tx, 0);
    assert!(result.is_err(), "Template hash should fail with empty inputs");
}

#[test]
fn test_template_hash_empty_outputs_error() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![].into(),
        lock_time: 0,
    };

    let result = calculate_template_hash(&tx, 0);
    assert!(result.is_err(), "Template hash should fail with empty outputs");
}

#[test]
fn test_template_hash_input_index_out_of_bounds() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    // Try with input index 1, but only 1 input (index 0)
    let result = calculate_template_hash(&tx, 1);
    assert!(result.is_err(), "Template hash should fail with out-of-bounds input index");
}

#[test]
fn test_template_hash_large_transaction() {
    // Create transaction with many inputs and outputs
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    for i in 0..10 {
        inputs.push(TransactionInput {
            prevout: OutPoint {
                hash: [i as u8; 32],
                index: i,
            },
            script_sig: vec![],
            sequence: 0,
        });

        outputs.push(TransactionOutput {
            value: 1000 * (i + 1) as i64,
            script_pubkey: vec![OP_1].into(),
        });
    }

    let tx = Transaction {
        version: 1,
            inputs: inputs.into(),
            outputs: outputs.into(),
        lock_time: 0,
    };

    // Should handle large transactions
    let hash = calculate_template_hash(&tx, 0).unwrap();
    assert_eq!(hash.len(), 32);
}

// ============================================================================
// Use Case Tests
// ============================================================================

#[test]
fn test_ctv_vault_contract() {
    // Vault contract: CTV with specific output structure
    // This simulates a vault that can only be spent to a specific address
    
    let withdrawal_address = vec![OP_DUP, OP_HASH160, PUSH_20_BYTES, 0x00, OP_EQUAL]; // P2PKH
    
    // Create transaction template for vault withdrawal
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000000, // Full vault amount
            script_pubkey: withdrawal_address.clone().into(),
        }].into(),
        lock_time: 0,
    };

    // Calculate template hash
    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Create vault scriptPubkey: CTV with template hash
    let mut vault_script = Vec::new();
    vault_script.push(PUSH_32_BYTES);
    vault_script.extend_from_slice(&template_hash);
    vault_script.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY

    // Verify vault withdrawal matches template
    let pv = vec![1000000i64];
    let psp: Vec<&[u8]> = vec![vault_script.as_ref()];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &vault_script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    assert!(result.is_ok() && result.unwrap(), "Vault withdrawal should pass with correct template");
}

#[test]
fn test_ctv_payment_channel() {
    // Payment channel: CTV with state update
    // Channel can only be closed with specific output structure
    
    let channel_output = TransactionOutput {
        value: 500000,
        script_pubkey: vec![OP_1].into(),
    };

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![channel_output.clone()].into(),
        lock_time: 0,
    };

    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Channel script with CTV
    let mut channel_script = Vec::new();
    channel_script.push(PUSH_32_BYTES);
    channel_script.extend_from_slice(&template_hash);
    channel_script.push(OP_CHECKTEMPLATEVERIFY);

    let pv = vec![channel_output.value];
    let psp: Vec<&blvm_consensus::types::ByteString> = vec![&channel_output.script_pubkey];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &channel_script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    assert!(result.is_ok() && result.unwrap(), "Payment channel closure should pass with correct template");
}

#[test]
fn test_ctv_transaction_batching() {
    // Transaction batching: CTV with multiple outputs
    // Allows batching multiple payments into one transaction
    
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![
            TransactionOutput {
                value: 100000,
                script_pubkey: vec![OP_1].into(), // Payment 1
            },
            TransactionOutput {
                value: 200000,
                script_pubkey: vec![OP_2].into(), // Payment 2
            },
            TransactionOutput {
                value: 300000,
                script_pubkey: vec![OP_3].into(), // Payment 3
            },
        ].into(),
        lock_time: 0,
    };

    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Batch script with CTV
    let mut batch_script = Vec::new();
    batch_script.push(PUSH_32_BYTES);
    batch_script.extend_from_slice(&template_hash);
    batch_script.push(OP_CHECKTEMPLATEVERIFY);

    let pv = vec![600000i64];
    let psp: Vec<&[u8]> = vec![batch_script.as_ref()];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &batch_script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    assert!(result.is_ok() && result.unwrap(), "Transaction batching should pass with correct template");
}

// ============================================================================
// Additional Edge Cases
// ============================================================================

#[test]
fn test_template_hash_sequence_dependency() {
    // Different sequence values should produce different hashes
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let hash1 = calculate_template_hash(&tx1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx2, 0).unwrap();

    assert_ne!(hash1, hash2, "Different sequence values must produce different template hashes");
}

#[test]
fn test_template_hash_output_value_dependency() {
    // Different output values should produce different hashes
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 2000, // Different value
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    let hash1 = calculate_template_hash(&tx1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx2, 0).unwrap();

    assert_ne!(hash1, hash2, "Different output values must produce different template hashes");
}

#[test]
fn test_template_hash_output_script_dependency() {
    // Different output scripts should produce different hashes
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(), // OP_1
        }].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_2].into(), // OP_2 (different script)
        }].into(),
        lock_time: 0,
    };

    let hash1 = calculate_template_hash(&tx1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx2, 0).unwrap();

    assert_ne!(hash1, hash2, "Different output scripts must produce different template hashes");
}

#[test]
fn test_template_hash_prevout_dependency() {
    // Different prevouts should produce different hashes
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x02; 32].into(), // Different hash
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let hash1 = calculate_template_hash(&tx1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx2, 0).unwrap();

    assert_ne!(hash1, hash2, "Different prevouts must produce different template hashes");
}

#[test]
fn test_template_hash_prevout_index_dependency() {
    // Different prevout indices should produce different hashes
    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x00; 32].into(),
                index: 1, // Different index
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    let hash1 = calculate_template_hash(&tx1, 0).unwrap();
    let hash2 = calculate_template_hash(&tx2, 0).unwrap();

    assert_ne!(hash1, hash2, "Different prevout indices must produce different template hashes");
}

#[test]
fn test_ctv_with_cltv_combined() {
    // CTV can be combined with CLTV for time-locked templates
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 500000, // Block height locktime
    };

    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Create script: CLTV + CTV
    let mut script = Vec::new();
    // Push locktime value for CLTV
    script.extend_from_slice(&[0x03, 0x20, 0xa1, 0x07]); // Push 500000
    script.push(OP_CHECKLOCKTIMEVERIFY);
    // Push template hash for CTV
    script.push(PUSH_32_BYTES);
    script.extend_from_slice(&template_hash);
    script.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY

    let prevouts = vec![TransactionOutput {
        value: 1000,
        script_pubkey: vec![OP_1].into(),
    }];

    // Note: This test verifies scripts can be combined, but full validation
    // would require proper block height context for CLTV
    assert!(is_ctv_script(&script), "Script should contain CTV");
}

#[test]
fn test_ctv_validation_hash_size_check() {
    // Test that validate_template_hash correctly checks hash size
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![].into(),
        }].into(),
        lock_time: 0,
    };

    // Wrong size (31 bytes)
    let wrong_size = vec![0x00; 31];
    assert!(!validate_template_hash(&tx, 0, &wrong_size).unwrap());

    // Wrong size (33 bytes)
    let wrong_size = vec![0x00; 33];
    assert!(!validate_template_hash(&tx, 0, &wrong_size).unwrap());

    // Correct size (32 bytes)
    let correct_hash = calculate_template_hash(&tx, 0).unwrap();
    assert!(validate_template_hash(&tx, 0, &correct_hash).unwrap());
}

#[test]
fn test_template_hash_max_values() {
    // Test with maximum values to ensure no overflow
    let tx = Transaction {
        version: i64::MAX,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0xff; 32].into(),
                index: u32::MAX,
            },
            script_sig: vec![],
            sequence: u64::MAX,
        }].into(),
        outputs: vec![TransactionOutput {
            value: i64::MAX,
            script_pubkey: vec![0xff; 100].into(), // Large script
        }].into(),
        lock_time: u64::MAX,
    };

    // Should handle max values without panic
    let result = calculate_template_hash(&tx, 0);
    assert!(result.is_ok(), "Template hash should handle maximum values");
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn test_ctv_multiple_ctv_in_script() {
    // Test script with multiple CTV opcodes (should work, but second one will fail)
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x01; 32].into(),
                index: 0,
            },
            script_sig: vec![],
            sequence: 0,
        }].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(),
        }].into(),
        lock_time: 0,
    };

    let template_hash = calculate_template_hash(&tx, 0).unwrap();

    // Create script with two CTV opcodes
    let mut script = Vec::new();
    script.push(PUSH_32_BYTES);
    script.extend_from_slice(&template_hash);
    script.push(OP_CHECKTEMPLATEVERIFY); // First CTV
    script.push(PUSH_32_BYTES);
    script.extend_from_slice(&template_hash);
    script.push(OP_CHECKTEMPLATEVERIFY); // Second CTV

    // First CTV should pass, but second will fail (no hash on stack)
    // This tests that CTV consumes the hash from stack
    let pv = vec![1000i64];
    let sp: blvm_consensus::types::ByteString = vec![OP_1].into();
    let psp: Vec<&[u8]> = vec![sp.as_ref()];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &script,
        None,
        0,
        &tx,
        0,
        &pv,
        &psp,
        None,
        None,
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
    
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
        );

    // Should fail because second CTV has no hash on stack
    assert!(result.is_ok() && !result.unwrap(), "Multiple CTV opcodes should fail (second has no hash)");
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to create a CTV script with template hash
fn create_ctv_script(template_hash: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(PUSH_32_BYTES); // Push 32 bytes
    script.extend_from_slice(template_hash);
    script.push(OP_CHECKTEMPLATEVERIFY); // OP_CHECKTEMPLATEVERIFY
    script
}

#[test]
fn test_is_ctv_script_helper() {
    let template_hash = [0x00; 32];
    let script = create_ctv_script(&template_hash);
    
    assert!(is_ctv_script(&script), "Script should be identified as CTV script");
    
    let non_ctv_script = vec![OP_1, OP_EQUAL];
    assert!(!is_ctv_script(&non_ctv_script), "Non-CTV script should not be identified as CTV");
}

