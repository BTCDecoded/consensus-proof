//! Unit tests for transaction validation functions

use consensus_proof::*;
use consensus_proof::transaction::*;
use consensus_proof::types::*;

#[test]
fn test_check_transaction_valid() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = check_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_check_transaction_empty_inputs() {
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = check_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_check_transaction_too_many_inputs() {
    let mut inputs = Vec::new();
    for i in 0..=MAX_INPUTS {
        inputs.push(TransactionInput {
            prevout: OutPoint { hash: [i as u8; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        });
    }
    
    let tx = Transaction {
        version: 1,
        inputs,
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = check_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_check_transaction_too_many_outputs() {
    let mut outputs = Vec::new();
    for _ in 0..=MAX_OUTPUTS {
        outputs.push(TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        });
    }
    
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs,
        lock_time: 0,
    };
    
    let result = check_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_check_transaction_negative_output() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: -1000, // Negative value
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = check_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_check_transaction_excessive_output() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: MAX_MONEY + 1, // Exceeds max money
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = check_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_is_coinbase() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    assert!(is_coinbase(&coinbase_tx));
    
    let regular_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    assert!(!is_coinbase(&regular_tx));
}

#[test]
fn test_calculate_transaction_size() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51, 0x52],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51, 0x52, 0x53],
        }],
        lock_time: 0,
    };
    
    let size = calculate_transaction_size(&tx);
    assert!(size > 0);
    assert!(size <= MAX_TX_SIZE);
}
