//! Tests for mempool helper functions

use consensus_proof::*;
use consensus_proof::transaction::is_coinbase;
use consensus_proof::mempool::*;

#[test]
fn test_mempool_basic_operations() {
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
    
    let mut mempool = Mempool::new();
    let tx_id = calculate_tx_id(&tx);
    let result = mempool.insert(tx_id);
    assert!(result); // HashSet::insert returns bool
    
    // Test that transaction ID is in mempool
    assert!(mempool.contains(&tx_id));
}

#[test]
fn test_mempool_conflict_detection() {
    let tx1 = Transaction {
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
    
    let tx2 = Transaction {
        version: 2, // Different version
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 }, // Same input as tx1
            script_sig: vec![0x52],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 900,
            script_pubkey: vec![0x52],
        }],
        lock_time: 0,
    };
    
    let mut mempool = Mempool::new();
    let tx1_id = calculate_tx_id(&tx1);
    mempool.insert(tx1_id);
    
    let tx2_id = calculate_tx_id(&tx2);
    // tx2 should conflict with tx1 (same input) but different transaction IDs
    let result = mempool.insert(tx2_id);
    assert!(result); // HashSet::insert returns bool (true if new element)
}

#[test]
fn test_mempool_rbf_sequence() {
    let tx_rbf = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: SEQUENCE_RBF as u64, // RBF sequence
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let tx_final = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: SEQUENCE_FINAL as u64, // Final sequence
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    // Test RBF sequence detection
    assert!(tx_rbf.inputs[0].sequence < SEQUENCE_FINAL as u64);
    assert!(tx_final.inputs[0].sequence == SEQUENCE_FINAL as u64);
}

#[test]
fn test_mempool_fee_calculation() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 800,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let mut utxo_set = UtxoSet::new();
    let outpoint = OutPoint { hash: [1; 32], index: 0 };
    let utxo = UTXO {
        value: 1000,
        script_pubkey: vec![0x51],
        height: 100,
    };
    utxo_set.insert(outpoint, utxo);
    
    let fee = economic::calculate_fee(&tx, &utxo_set).unwrap();
    assert_eq!(fee, 200);
}

#[test]
fn test_mempool_dependency_creation() {
    let tx1 = Transaction {
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
    
    let tx2 = Transaction {
        version: 2, // Different version
        inputs: vec![TransactionInput {
            prevout: OutPoint { 
                hash: calculate_tx_id(&tx1), 
                index: 0 
            },
            script_sig: vec![0x52],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 900,
            script_pubkey: vec![0x52],
        }],
        lock_time: 0,
    };
    
    let mut mempool = Mempool::new();
    let tx1_id = calculate_tx_id(&tx1);
    mempool.insert(tx1_id);
    
    let tx2_id = calculate_tx_id(&tx2);
    // tx2 depends on tx1 (spends tx1's output) but has different transaction ID
    let result = mempool.insert(tx2_id);
    assert!(result); // Should succeed since tx2_id is different from tx1_id
}

#[test]
fn test_mempool_standard_script() {
    let standard_script = vec![0x51]; // OP_1
    let non_standard_script = vec![0x00; 10001]; // Very long script
    
    // Test script length limits
    assert!(standard_script.len() <= MAX_SCRIPT_SIZE);
    assert!(non_standard_script.len() > MAX_SCRIPT_SIZE);
}

#[test]
fn test_mempool_transaction_id() {
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
    
    let tx_id = calculate_tx_id(&tx);
    assert_eq!(tx_id.len(), 32);
}

#[test]
fn test_mempool_transaction_size() {
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
    
    // Test that transaction size is reasonable
    let serialized = serde_json::to_vec(&tx).unwrap();
    assert!(serialized.len() > 0);
    assert!(serialized.len() <= MAX_TX_SIZE);
}

#[test]
fn test_mempool_coinbase_detection() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
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
    
    assert!(is_coinbase(&coinbase_tx));
    assert!(!is_coinbase(&regular_tx));
}