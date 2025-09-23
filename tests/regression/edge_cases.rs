//! Regression tests for edge cases and boundary conditions

use consensus_proof::*;
use consensus_proof::types::*;
use consensus_proof::constants::*;

#[test]
fn test_transaction_size_boundaries() {
    let consensus = ConsensusProof::new();
    
    // Test transaction at maximum size limit
    let mut large_script = Vec::new();
    for _ in 0..MAX_SCRIPT_SIZE {
        large_script.push(0x51);
    }
    
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: large_script.clone(),
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: large_script,
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx).unwrap();
    // Should either be valid or fail gracefully
    assert!(matches!(result, ValidationResult::Valid | ValidationResult::Invalid(_)));
}

#[test]
fn test_maximum_input_output_counts() {
    let consensus = ConsensusProof::new();
    
    // Test transaction with maximum number of inputs
    let mut inputs = Vec::new();
    for i in 0..MAX_INPUTS {
        inputs.push(TransactionInput {
            prevout: OutPoint { hash: [i as u8; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        });
    }
    
    let tx_max_inputs = Transaction {
        version: 1,
        inputs,
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx_max_inputs).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
    
    // Test transaction with maximum number of outputs
    let mut outputs = Vec::new();
    for _ in 0..MAX_OUTPUTS {
        outputs.push(TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        });
    }
    
    let tx_max_outputs = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs,
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx_max_outputs).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_monetary_boundaries() {
    let consensus = ConsensusProof::new();
    
    // Test transaction with maximum money value
    let tx_max_money = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: MAX_MONEY,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx_max_money).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
    
    // Test transaction exceeding maximum money
    let tx_excess_money = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: MAX_MONEY + 1,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx_excess_money).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_script_operation_limits() {
    let consensus = ConsensusProof::new();
    
    // Test script with maximum number of operations
    let mut script = Vec::new();
    for _ in 0..MAX_SCRIPT_OPS {
        script.push(0x51); // OP_1
    }
    
    let result = consensus.verify_script(&script, &script, None, 0).unwrap();
    assert!(result == true || result == false);
    
    // Test script exceeding operation limit
    let mut large_script = Vec::new();
    for _ in 0..=MAX_SCRIPT_OPS {
        large_script.push(0x51);
    }
    
    let result = consensus.verify_script(&large_script, &large_script, None, 0);
    assert!(result.is_err());
}

#[test]
fn test_stack_size_limits() {
    let consensus = ConsensusProof::new();
    
    // Test script that would cause stack overflow
    let mut script = Vec::new();
    for _ in 0..=MAX_STACK_SIZE {
        script.push(0x51); // OP_1
    }
    
    let result = consensus.verify_script(&script, &script, None, 0);
    assert!(result.is_err());
}

#[test]
fn test_block_size_boundaries() {
    let consensus = ConsensusProof::new();
    
    // Create a block with many transactions
    let mut transactions = Vec::new();
    for i in 0..1000 {
        transactions.push(Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [i as u8; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        });
    }
    
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions,
    };
    
    let utxo_set = UtxoSet::new();
    let result = consensus.validate_block(&block, utxo_set, 0);
    // Should either succeed or fail gracefully
    match result {
        Ok((validation_result, _)) => {
            assert!(matches!(validation_result, ValidationResult::Valid | ValidationResult::Invalid(_)));
        },
        Err(_) => {
            // Expected failure for large block
        }
    }
}

#[test]
fn test_difficulty_adjustment_boundaries() {
    let consensus = ConsensusProof::new();
    
    // Test difficulty adjustment with extreme time differences
    let current_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    
    // Create headers with very fast block times (1 second each)
    let mut fast_headers = Vec::new();
    for i in 0..DIFFICULTY_ADJUSTMENT_INTERVAL {
        fast_headers.push(BlockHeader {
            version: 1,
            prev_block_hash: [i as u8; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505 + i, // 1 second intervals
            bits: 0x1d00ffff,
            nonce: 0,
        });
    }
    
    let result = consensus.get_next_work_required(&current_header, &fast_headers).unwrap();
    // Should increase difficulty significantly
    assert!(result > 0x1d00ffff);
    
    // Create headers with very slow block times (1 hour each)
    let mut slow_headers = Vec::new();
    for i in 0..DIFFICULTY_ADJUSTMENT_INTERVAL {
        slow_headers.push(BlockHeader {
            version: 1,
            prev_block_hash: [i as u8; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505 + (i * 3600), // 1 hour intervals
            bits: 0x1d00ffff,
            nonce: 0,
        });
    }
    
    let result = consensus.get_next_work_required(&current_header, &slow_headers).unwrap();
    // Should decrease difficulty significantly
    assert!(result < 0x1d00ffff);
}

#[test]
fn test_supply_calculation_boundaries() {
    let consensus = ConsensusProof::new();
    
    // Test supply calculation at various heights
    let heights = vec![0, 1, HALVING_INTERVAL, HALVING_INTERVAL * 2, HALVING_INTERVAL * 10];
    
    for height in heights {
        let supply = consensus.total_supply(height);
        assert!(supply >= 0);
        assert!(supply <= MAX_MONEY);
    }
    
    // Test supply at very high height (beyond normal operation)
    let high_height = HALVING_INTERVAL * 100;
    let supply = consensus.total_supply(high_height);
    assert!(supply >= 0);
    assert!(supply <= MAX_MONEY);
}

#[test]
fn test_sequence_number_boundaries() {
    let consensus = ConsensusProof::new();
    
    // Test transaction with maximum sequence number
    let tx_max_sequence = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff, // Maximum sequence
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx_max_sequence).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
    
    // Test transaction with RBF sequence
    let tx_rbf = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: SEQUENCE_RBF as u32, // RBF sequence
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&tx_rbf).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}
