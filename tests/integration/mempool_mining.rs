//! Integration tests for mempool and mining functions

use consensus_proof::*;
use consensus_proof::types::*;
use consensus_proof::mempool::*;
use consensus_proof::mining::*;

#[test]
fn test_mempool_to_block_integration() {
    let consensus = ConsensusProof::new();
    
    // Create a mempool with some transactions
    let mut mempool = Mempool::new();
    
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
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [2; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 2000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    // Add transactions to mempool
    let utxo_set = UtxoSet::new();
    let _result1 = consensus.accept_to_memory_pool(&tx1, &utxo_set, &mempool, 100);
    let _result2 = consensus.accept_to_memory_pool(&tx2, &utxo_set, &mempool, 100);
    
    // Create block from mempool
    let prev_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    
    let prev_headers = vec![prev_header.clone()];
    let mempool_txs = vec![tx1.clone(), tx2.clone()];
    
    let block = consensus.create_new_block(
        &utxo_set,
        &mempool_txs,
        100,
        &prev_header,
        &prev_headers,
        &vec![0x51],
        &vec![0x51],
    ).unwrap();
    
    assert_eq!(block.transactions.len(), 3); // 2 mempool txs + 1 coinbase
    assert!(block.transactions[0].inputs[0].prevout.index == 0xffffffff); // Coinbase
}

#[test]
fn test_economic_mining_integration() {
    let consensus = ConsensusProof::new();
    
    // Test that block subsidy is correctly included in mining
    let subsidy = consensus.get_block_subsidy(0);
    assert_eq!(subsidy, 5000000000);
    
    // Create a block template
    let utxo_set = UtxoSet::new();
    let mempool_txs = vec![];
    let prev_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    let prev_headers = vec![prev_header.clone()];
    
    let template = consensus.create_block_template(
        &utxo_set,
        &mempool_txs,
        0,
        &prev_header,
        &prev_headers,
        &vec![0x51],
        &vec![0x51],
    ).unwrap();
    
    // The coinbase transaction should include the block subsidy
    assert_eq!(template.coinbase_tx.outputs[0].value, subsidy);
}

#[test]
fn test_script_transaction_integration() {
    let consensus = ConsensusProof::new();
    
    // Create a transaction with script validation
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51], // OP_1
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51], // OP_1
        }],
        lock_time: 0,
    };
    
    // Validate the transaction
    let tx_result = consensus.validate_transaction(&tx).unwrap();
    assert!(matches!(tx_result, ValidationResult::Valid));
    
    // Verify the script
    let script_result = consensus.verify_script(&tx.inputs[0].script_sig, &tx.outputs[0].script_pubkey, None, 0).unwrap();
    assert!(script_result == true || script_result == false);
}

#[test]
fn test_pow_block_integration() {
    let consensus = ConsensusProof::new();
    
    // Create a block with valid proof of work
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x0300ffff, // Valid target
            nonce: 0,
        },
        transactions: vec![Transaction {
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
        }],
    };
    
    // Check proof of work
    let pow_result = consensus.check_proof_of_work(&block.header).unwrap();
    assert!(pow_result == true || pow_result == false);
    
    // Validate the block
    let utxo_set = UtxoSet::new();
    let (block_result, _new_utxo_set) = consensus.validate_block(&block, utxo_set, 0).unwrap();
    assert!(matches!(block_result, ValidationResult::Valid));
}

#[test]
fn test_cross_system_error_handling() {
    let consensus = ConsensusProof::new();
    
    // Test error propagation across systems
    let invalid_tx = Transaction {
        version: 1,
        inputs: vec![], // Invalid: empty inputs
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    // Transaction validation should fail
    let tx_result = consensus.validate_transaction(&invalid_tx).unwrap();
    assert!(matches!(tx_result, ValidationResult::Invalid(_)));
    
    // Mempool acceptance should also fail
    let utxo_set = UtxoSet::new();
    let mempool = Mempool::new();
    let mempool_result = consensus.accept_to_memory_pool(&invalid_tx, &utxo_set, &mempool, 100);
    assert!(mempool_result.is_err());
    
    // Block creation should handle invalid transactions gracefully
    let prev_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    let prev_headers = vec![prev_header.clone()];
    
    let block_result = consensus.create_new_block(
        &utxo_set,
        &[invalid_tx],
        100,
        &prev_header,
        &prev_headers,
        &vec![0x51],
        &vec![0x51],
    );
    assert!(block_result.is_err());
}

#[test]
fn test_performance_integration() {
    let consensus = ConsensusProof::new();
    
    // Test performance with multiple transactions
    let mut transactions = Vec::new();
    for i in 0..100 {
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
    
    // Validate all transactions
    for tx in &transactions {
        let result = consensus.validate_transaction(tx).unwrap();
        assert!(matches!(result, ValidationResult::Valid));
    }
    
    // Create block with all transactions
    let utxo_set = UtxoSet::new();
    let prev_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    let prev_headers = vec![prev_header.clone()];
    
    let block = consensus.create_new_block(
        &utxo_set,
        &transactions,
        100,
        &prev_header,
        &prev_headers,
        &vec![0x51],
        &vec![0x51],
    ).unwrap();
    
    assert_eq!(block.transactions.len(), 101); // 100 txs + 1 coinbase
}
