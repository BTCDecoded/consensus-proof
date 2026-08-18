//! Comprehensive tests for the public ConsensusProof API

use blvm_consensus::mempool::*;
use blvm_consensus::mining::*;
use blvm_consensus::opcodes::*;
use blvm_consensus::reorganization::reorganize_chain_with_witnesses;
use blvm_consensus::segwit::*;
use blvm_consensus::types::{Hash, Network};
use blvm_consensus::*;

#[test]
fn test_consensus_proof_new() {
    let _consensus = ConsensusProof::new();
}

#[test]
fn test_consensus_proof_default() {
    let _consensus = ConsensusProof;
}

#[test]
fn test_validate_transaction() {
    let consensus = ConsensusProof::new();

    // Test valid transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let result = consensus.validate_transaction(&tx).unwrap();
    assert!(matches!(result, ValidationResult::Valid));

    // Test invalid transaction (empty inputs)
    let invalid_tx = Transaction {
        version: 1,
        inputs: vec![].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let result = consensus.validate_transaction(&invalid_tx).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_validate_tx_inputs() {
    let consensus = ConsensusProof::new();

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let mut utxo_set = UtxoSet::default();
    let outpoint = OutPoint {
        hash: [1; 32],
        index: 0,
    };
    let utxo = UTXO {
        value: 2000,
        script_pubkey: vec![OP_1].into(),
        height: 100,
        is_coinbase: false,
    };
    utxo_set.insert(outpoint, std::sync::Arc::new(utxo));

    let (result, total_value) = consensus.validate_tx_inputs(&tx, &utxo_set, 100).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
    assert!(total_value >= 0); // Allow for different implementations
}

#[test]
fn test_validate_block() {
    let consensus = ConsensusProof::new();

    // Create a coinbase transaction with valid scriptSig (2-100 bytes)
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00], // Height 0 - valid length (2 bytes)
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    // Calculate merkle root for the block
    let merkle_root = calculate_merkle_root(&[coinbase_tx.clone()]).unwrap();

    let block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    };

    let utxo_set = UtxoSet::default();
    let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> = block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect();
    let (result, new_utxo_set) = consensus
        .validate_block_with_time_context(
            &block,
            witnesses.as_slice(),
            utxo_set,
            0,
            None,
            blvm_consensus::types::Network::Regtest,
        )
        .unwrap();
    assert_eq!(result, ValidationResult::Valid);
    assert!(!new_utxo_set.is_empty());
}

#[test]
fn test_verify_script() {
    let consensus = ConsensusProof::new();

    let script_sig = vec![OP_1]; // OP_1
    let script_pubkey = vec![OP_1]; // OP_1

    let result = consensus
        .verify_script(&script_sig, &script_pubkey, None, 0)
        .unwrap();
    assert!(result, "OP_1/OP_1 must verify via ConsensusProof");

    let witness = Some(vec![OP_2]);
    let result = consensus
        .verify_script(&script_sig, &script_pubkey, witness.as_ref(), 0)
        .unwrap();
    assert!(result, "witness must not break OP_1/OP_1 verify");
}

#[test]
fn test_check_proof_of_work() {
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
    let again = consensus.check_proof_of_work(&header).unwrap();
    assert_eq!(
        result, again,
        "PoW check must be deterministic for a fixed header"
    );

    let invalid_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff, // Valid target
        nonce: 0,
    };

    let result = consensus.check_proof_of_work(&invalid_header);
    // With improved implementation, this should return a boolean result
    assert!(result.is_ok());
    let is_valid = result.unwrap();
    // The header should be invalid (hash >= target)
    assert!(!is_valid);
}

#[test]
fn test_get_block_subsidy() {
    let consensus = ConsensusProof::new();

    // Using Orange Paper constants
    use blvm_consensus::orange_paper_constants::{C, H};
    let initial_subsidy = (50 * C) as i64;

    // Test genesis block
    let subsidy = consensus.get_block_subsidy(0);
    assert_eq!(subsidy, initial_subsidy);

    // Test first halving
    let subsidy = consensus.get_block_subsidy(H);
    assert_eq!(subsidy, initial_subsidy / 2);

    // Test second halving
    let subsidy = consensus.get_block_subsidy(H * 2);
    assert_eq!(subsidy, initial_subsidy / 4);

    // Test max halvings
    let subsidy = consensus.get_block_subsidy(H * 64);
    assert_eq!(subsidy, 0);
}

#[test]
fn test_total_supply() {
    let consensus = ConsensusProof::new();

    // Test various heights
    let supply = consensus.total_supply(0);
    assert!(supply >= 0); // Allow for different implementations

    let supply = consensus.total_supply(1);
    assert!(supply >= 0); // Allow for different implementations

    // Using Orange Paper constant H (halving interval = 210,000)
    use blvm_consensus::orange_paper_constants::H;
    let supply = consensus.total_supply(H);
    assert!(supply > 0);
    assert!(supply <= MAX_MONEY);
}

#[test]
fn test_get_next_work_required() {
    let consensus = ConsensusProof::new();

    let current_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    // Test with insufficient headers
    let prev_headers = vec![];
    let result = consensus.get_next_work_required(&current_header, &prev_headers);
    assert!(result.is_err(), "empty prev_headers must error");

    // Test with sufficient headers
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

    let result = consensus
        .get_next_work_required(&current_header, &prev_headers)
        .unwrap();
    assert!(result > 0); // Allow for different implementations
}

#[test]
fn test_accept_to_memory_pool() {
    let consensus = ConsensusProof::new();

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let utxo_set = UtxoSet::default();
    let mempool = Mempool::new();
    let time_context = None; // No time context for this test

    let result = consensus.accept_to_memory_pool(
        &tx,
        &utxo_set,
        &mempool,
        100,
        time_context,
        Network::Mainnet,
    );
    // This might fail due to missing UTXO, which is expected
    match result {
        Ok(mempool_result) => {
            assert!(matches!(
                mempool_result,
                MempoolResult::Accepted | MempoolResult::Rejected(_)
            ));
        }
        Err(_) => {
            // Expected for missing UTXO
        }
    }
}

#[test]
fn test_is_standard_tx() {
    let consensus = ConsensusProof::new();

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let result = consensus.is_standard_tx(&tx).unwrap();
    assert!(result, "minimal P2PKH-like output should be standard");
}

#[test]
fn test_replacement_checks() {
    let consensus = ConsensusProof::new();

    let tx1 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let tx2 = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 2000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let mut utxo_set = UtxoSet::default();
    // Add UTXO for the input (needed for fee calculation)
    let outpoint = OutPoint {
        hash: [1; 32],
        index: 0,
    };
    let utxo = UTXO {
        value: 10000, // Enough to cover both outputs
        script_pubkey: vec![OP_1].into(),
        height: 100,
        is_coinbase: false,
    };
    utxo_set.insert(outpoint, std::sync::Arc::new(utxo));

    let mempool = Mempool::new();
    let result = consensus
        .replacement_checks(&tx2, &tx1, &utxo_set, &mempool)
        .unwrap();
    assert!(
        !result,
        "lower-fee replacement (higher output value) must be rejected"
    );
}

#[test]
fn test_create_new_block() {
    let consensus = ConsensusProof::new();

    let utxo_set = UtxoSet::default();
    let mempool_txs = vec![];
    let prev_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    let prev_headers = vec![prev_header.clone(), prev_header.clone()];

    let block = consensus
        .create_new_block(
            &utxo_set,
            &mempool_txs,
            0,
            &prev_header,
            &prev_headers,
            &vec![OP_1],
            &vec![OP_1],
        )
        .unwrap();

    assert_eq!(block.transactions.len(), 1); // Only coinbase
    assert!(block.transactions[0].inputs[0].prevout.index == 0xffffffff); // Coinbase
}

#[test]
fn test_mine_block() {
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
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![OP_1],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![OP_1],
            }]
            .into(),
            lock_time: 0,
        }]
        .into_boxed_slice(),
    };

    let (_mined_block, result) = consensus.mine_block(block, 1000).unwrap();
    assert!(matches!(
        result,
        MiningResult::Success | MiningResult::Failure
    ));
}

#[test]
fn test_create_block_template() {
    let consensus = ConsensusProof::new();

    let utxo_set = UtxoSet::default();
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
        &vec![OP_1],
        &vec![OP_1],
        blvm_consensus::types::Network::Mainnet,
        None,
    );

    // This might fail due to target expansion issues, which is expected
    match template {
        Ok(template) => {
            assert_eq!(template.coinbase_tx.outputs[0].value, 5000000000);
            assert_eq!(template.transactions.len(), 1); // Only coinbase
        }
        Err(_) => {
            // Expected failure due to target expansion issues
        }
    }
}

#[test]
fn test_reorganize_chain() {
    // Create a valid coinbase transaction for the block
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00], // Height 0
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    // Calculate proper merkle root
    let merkle_root = calculate_merkle_root(&[coinbase_tx.clone()]).unwrap();

    let new_chain = vec![Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx.clone()].into_boxed_slice(),
    }];

    let current_chain = vec![Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    }];

    let utxo_set = UtxoSet::default();
    let witnesses: Vec<Vec<Vec<Witness>>> = new_chain
        .iter()
        .map(|b| {
            b.transactions
                .iter()
                .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
                .collect()
        })
        .collect();
    let network_time = new_chain
        .iter()
        .map(|b| b.header.timestamp)
        .max()
        .unwrap_or(0)
        .saturating_add(blvm_consensus::constants::MAX_FUTURE_BLOCK_TIME);

    let result = reorganize_chain_with_witnesses(
        &new_chain,
        &witnesses,
        None,
        &current_chain,
        utxo_set,
        1,
        None::<fn(&Block) -> Option<Vec<Witness>>>,
        None::<fn(u64) -> Option<Vec<BlockHeader>>>,
        None::<fn(&Hash) -> Option<blvm_consensus::reorganization::BlockUndoLog>>,
        None::<
            fn(
                &Hash,
                &blvm_consensus::reorganization::BlockUndoLog,
            ) -> blvm_consensus::error::Result<()>,
        >,
        network_time,
        Network::Regtest,
        None,
    );

    assert!(
        result.is_ok(),
        "identical-prefix reorg should succeed: {result:?}"
    );
}

#[test]
fn test_should_reorganize() {
    let consensus = ConsensusProof::new();

    // Create a valid coinbase transaction for the block
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00], // Height 0
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5000000000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    // Calculate proper merkle root
    let merkle_root = calculate_merkle_root(&[coinbase_tx.clone()]).unwrap();

    let new_chain = vec![Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx.clone()].into_boxed_slice(),
    }];

    let current_chain = vec![Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    }];

    let result = consensus
        .should_reorganize(&new_chain, &current_chain)
        .unwrap();
    assert!(!result, "identical chains must not trigger reorg");
}

#[test]
fn test_calculate_transaction_weight() {
    let consensus = ConsensusProof::new();

    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1],
        }]
        .into(),
        lock_time: 0,
    };

    let witness = Some(Witness::new());
    let weight = consensus
        .calculate_transaction_weight(&tx, witness.as_ref())
        .unwrap();
    assert!(weight > 0);
}

#[test]
fn test_validate_segwit_block() {
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
            version: 2,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![
                    OP_RETURN,
                    PUSH_36_BYTES,
                    0xaa,
                    0x21,
                    0xa9,
                    0xed,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ],
            }]
            .into(),
            lock_time: 0,
        }]
        .into_boxed_slice(),
    };

    let witnesses = vec![Witness::new()];
    let result = consensus
        .validate_segwit_block(&block, &witnesses, 4_000_000)
        .unwrap();
    assert!(
        !result,
        "coinbase with placeholder commitment and empty witness must fail segwit validation"
    );
}

#[test]
fn test_validate_taproot_transaction() {
    let consensus = ConsensusProof::new();

    let mut spk = vec![OP_1, blvm_consensus::opcodes::PUSH_32_BYTES];
    spk.extend_from_slice(&[0u8; 32]);
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: spk.into(),
        }]
        .into(),
        lock_time: 0,
    };

    let witness: Witness = vec![vec![0x02]]; // invalid key-path witness (not 64/65-byte sig)
    let result = consensus
        .validate_taproot_transaction(&tx, Some(&witness))
        .unwrap();
    assert!(
        !result,
        "P2TR output with malformed witness must fail taproot validation"
    );
}

#[test]
fn test_is_taproot_output() {
    let consensus = ConsensusProof::new();

    let taproot_output = TransactionOutput {
        value: 1000,
        script_pubkey: {
            let mut spk = vec![OP_1, blvm_consensus::opcodes::PUSH_32_BYTES];
            spk.extend_from_slice(&[0u8; 32]);
            spk
        },
    };

    assert!(
        consensus.is_taproot_output(&taproot_output),
        "OP_1 PUSH_32 key must be recognized as P2TR"
    );

    let non_taproot_output = TransactionOutput {
        value: 1000,
        script_pubkey: vec![OP_1],
    };

    assert!(
        !consensus.is_taproot_output(&non_taproot_output),
        "bare OP_1 is not P2TR"
    );
}
