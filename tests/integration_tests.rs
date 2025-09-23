//! Integration tests for consensus-proof

use consensus_proof::*;
use std::collections::HashMap;

#[test]
fn test_consensus_proof_basic_functionality() {
    let consensus = ConsensusProof::new();
    
    // Test valid transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0; 32], index: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx).unwrap();
    assert_eq!(result, ValidationResult::Valid);
}

#[test]
fn test_consensus_proof_coinbase_validation() {
    let consensus = ConsensusProof::new();
    
    // Test coinbase transaction
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
            script_sig: vec![],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 5000000000, // 50 BTC
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };
    
    let utxo_set = UtxoSet::new();
    let (result, fee) = consensus.validate_tx_inputs(&coinbase_tx, &utxo_set, 0).unwrap();
    
    assert_eq!(result, ValidationResult::Valid);
    assert_eq!(fee, 0); // Coinbase has no fee
}

#[test]
fn test_consensus_proof_invalid_transaction() {
    let consensus = ConsensusProof::new();
    
    // Test invalid transaction (empty inputs)
    let invalid_tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&invalid_tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_consensus_proof_utxo_validation() {
    let consensus = ConsensusProof::new();
    
    // Create a transaction that spends from a UTXO
    let prevout = OutPoint { hash: [1; 32], index: 0 };
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: prevout.clone(),
            script_sig: vec![],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 500,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };
    
    // Create UTXO set with the input
    let mut utxo_set = UtxoSet::new();
    utxo_set.insert(prevout, UTXO {
        value: 1000,
        script_pubkey: vec![],
        height: 0,
    });
    
    let (result, fee) = consensus.validate_tx_inputs(&tx, &utxo_set, 1).unwrap();
    
    assert_eq!(result, ValidationResult::Valid);
    assert_eq!(fee, 500); // 1000 - 500 = 500 fee
}

#[test]
fn test_consensus_proof_insufficient_funds() {
    let consensus = ConsensusProof::new();
    
    // Create a transaction that tries to spend more than available
    let prevout = OutPoint { hash: [1; 32], index: 0 };
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: prevout.clone(),
            script_sig: vec![],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 2000, // More than available
            script_pubkey: vec![],
        }],
        lock_time: 0,
    };
    
    // Create UTXO set with insufficient funds
    let mut utxo_set = UtxoSet::new();
    utxo_set.insert(prevout, UTXO {
        value: 1000, // Less than output
        script_pubkey: vec![],
        height: 0,
    });
    
    let (result, _fee) = consensus.validate_tx_inputs(&tx, &utxo_set, 1).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}
