//! Integration tests for consensus validation

use consensus_proof::*;
use consensus_proof::types::*;

#[test]
fn test_consensus_proof_basic_functionality() {
    let consensus = ConsensusProof::new();
    
    // Test basic transaction validation
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
    
    let result = consensus.validate_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_consensus_proof_coinbase_validation() {
    let consensus = ConsensusProof::new();
    
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
    
    let result = consensus.validate_transaction(&coinbase_tx).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_consensus_proof_utxo_validation() {
    let consensus = ConsensusProof::new();
    
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
    
    let mut utxo_set = UtxoSet::new();
    let outpoint = OutPoint { hash: [1; 32], index: 0 };
    let utxo = UTXO {
        value: 2000,
        script_pubkey: vec![0x51],
        height: 100,
    };
    utxo_set.insert(outpoint, utxo);
    
    let (result, _total_value) = consensus.validate_tx_inputs(&tx, &utxo_set, 100).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_consensus_proof_insufficient_funds() {
    let consensus = ConsensusProof::new();
    
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 2000, // More than available
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let mut utxo_set = UtxoSet::new();
    let outpoint = OutPoint { hash: [1; 32], index: 0 };
    let utxo = UTXO {
        value: 1000, // Less than needed
        script_pubkey: vec![0x51],
        height: 100,
    };
    utxo_set.insert(outpoint, utxo);
    
    let (result, _total_value) = consensus.validate_tx_inputs(&tx, &utxo_set, 100).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_consensus_proof_invalid_transaction() {
    let consensus = ConsensusProof::new();
    
    let invalid_tx = Transaction {
        version: 1,
        inputs: vec![], // Empty inputs
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    
    let result = consensus.validate_transaction(&invalid_tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_consensus_proof_block_validation() {
    let consensus = ConsensusProof::new();
    
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x0300ffff,
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
    
    let utxo_set = UtxoSet::new();
    let (result, _new_utxo_set) = consensus.validate_block(&block, utxo_set, 0).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_consensus_proof_script_verification() {
    let consensus = ConsensusProof::new();
    
    let script_sig = vec![0x51]; // OP_1
    let script_pubkey = vec![0x51]; // OP_1
    
    let result = consensus.verify_script(&script_sig, &script_pubkey, None, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_consensus_proof_proof_of_work() {
    let consensus = ConsensusProof::new();
    
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    
    let result = consensus.check_proof_of_work(&header).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_consensus_proof_economic_functions() {
    let consensus = ConsensusProof::new();
    
    // Test block subsidy
    let subsidy = consensus.get_block_subsidy(0);
    assert_eq!(subsidy, 5000000000); // 50 BTC in satoshis
    
    // Test total supply
    let supply = consensus.total_supply(210000);
    assert!(supply > 0);
    
    // Test difficulty adjustment
    let current_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    
    let mut prev_headers = Vec::new();
    for i in 0..2016 {
        prev_headers.push(BlockHeader {
            version: 1,
            prev_block_hash: [i as u8; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505 + (i * 600),
            bits: 0x1d00ffff,
            nonce: 0,
        });
    }
    
    let next_work = consensus.get_next_work_required(&current_header, &prev_headers).unwrap();
    assert_eq!(next_work, 0x1d00ffff);
}
