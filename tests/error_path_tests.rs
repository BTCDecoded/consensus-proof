//! Tests for error paths and edge cases

use blvm_consensus::mining::MiningResult;
use blvm_consensus::opcodes::*;
use blvm_consensus::reorganization::reorganize_chain_with_witnesses;
use blvm_consensus::types::Hash;
use blvm_consensus::*;

#[test]
fn test_transaction_validation_errors() {
    let consensus = ConsensusProof::new();

    // Test empty transaction
    let empty_tx = Transaction {
        version: 1,
        inputs: vec![].into(),
        outputs: vec![].into(),
        lock_time: 0,
    };

    let result = consensus.validate_transaction(&empty_tx);
    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), ValidationResult::Invalid(_)),
        "empty inputs and outputs must be invalid"
    );
}

#[test]
fn test_block_validation_errors() {
    let consensus = ConsensusProof::new();

    // Test block with invalid header
    let invalid_block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,     // Invalid timestamp
            bits: 0x1d00ffff, // Use valid target; other fields make header invalid
            nonce: 0,
        },
        transactions: vec![].into_boxed_slice(),
    };

    let utxo_set = UtxoSet::default();
    let result = consensus.validate_block_with_time_context(
        &invalid_block,
        &[],
        utxo_set,
        0,
        None,
        blvm_consensus::types::Network::Regtest,
    );
    assert!(
        matches!(
            result,
            Ok((ValidationResult::Invalid(ref r), _))
                if r.contains("no transactions") || r.contains("timestamp")
        ),
        "empty block with timestamp=0 must be rejected: {result:?}"
    );
}

#[test]
fn test_proof_of_work_errors() {
    let consensus = ConsensusProof::new();

    // Test invalid proof of work
    let invalid_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff, // Valid target for testing PoW boolean
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
fn test_script_execution_errors() {
    let consensus = ConsensusProof::new();

    // Test script with too many non-push operations: OP_1 (push) + OP_DUP×202 exceeds limit
    let mut large_script = vec![OP_1];
    large_script.extend(std::iter::repeat_n(OP_DUP, MAX_SCRIPT_OPS + 1));
    let result = consensus.verify_script(&large_script, &vec![OP_1], None, 0);
    assert!(result.is_err()); // Exceeds op limit should error
}

#[test]
fn test_mempool_errors() {
    let consensus = ConsensusProof::new();

    // Test transaction that's too large
    let large_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![OP_1; MAX_TX_SIZE],
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

    let result = consensus.is_standard_tx(&large_tx);
    assert!(result.is_ok());
    // Should be false due to size limit
}

#[test]
fn test_mining_errors() {
    let consensus = ConsensusProof::new();

    // `mine_block` does not return Err for invalid header fields; it only searches nonces and
    // uses `check_proof_of_work(..).unwrap_or(false)`, so PoW/expand_target errors are not propagated.
    let invalid_block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            bits: 0x1d00ffff, // Valid compact target; timestamp still invalid for real validation
            nonce: 0,
        },
        transactions: vec![].into_boxed_slice(),
    };

    let result = consensus.mine_block(invalid_block, 1000);
    assert!(result.is_ok());
    let (_, mining_result) = result.unwrap();
    assert_eq!(mining_result, MiningResult::Failure);
}

#[test]
fn test_reorganization_errors() {
    // Test reorganization with empty chains
    let new_chain = vec![];
    let current_chain = vec![];
    let utxo_set = UtxoSet::default();

    let result = reorganize_chain_with_witnesses(
        &new_chain,
        &[],
        None,
        &current_chain,
        utxo_set,
        0,
        None::<fn(&Block) -> Option<Vec<blvm_consensus::segwit::Witness>>>,
        None::<fn(u64) -> Option<Vec<BlockHeader>>>,
        None::<fn(&Hash) -> Option<blvm_consensus::reorganization::BlockUndoLog>>,
        None::<
            fn(
                &Hash,
                &blvm_consensus::reorganization::BlockUndoLog,
            ) -> blvm_consensus::error::Result<()>,
        >,
        0,
        blvm_consensus::types::Network::Regtest,
        None,
    );
    assert!(result.is_err());
}

#[test]
fn test_segwit_errors() {
    let consensus = ConsensusProof::new();

    // Test SegWit block with invalid weight
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![].into_boxed_slice(),
    };

    let witnesses = vec![];
    let result = consensus.validate_segwit_block(&block, &witnesses, 0); // Max weight 0
    assert!(result.is_ok());
    // With empty block and witnesses, weight is 0, which equals max_weight 0, so it should be valid
    assert!(result.unwrap());
}

#[test]
fn test_taproot_errors() {
    let consensus = ConsensusProof::new();

    // Test invalid Taproot transaction
    let invalid_tx = Transaction {
        version: 1,
        inputs: vec![].into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1], // Not a valid Taproot script
        }]
        .into(),
        lock_time: 0,
    };

    let result = consensus.validate_taproot_transaction(&invalid_tx, None);
    assert!(result.is_ok());
    // Should be false due to invalid script
}

#[test]
fn test_economic_errors() {
    let consensus = ConsensusProof::new();

    // Test total supply at reasonable height
    let result = consensus.total_supply(1000000); // 1 million blocks
    assert!(result <= MAX_MONEY);
}

#[test]
fn test_difficulty_adjustment_errors() {
    let consensus = ConsensusProof::new();

    // Test difficulty adjustment with insufficient headers
    let current_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let prev_headers = vec![]; // Empty
    let result = consensus.get_next_work_required(&current_header, &prev_headers);
    // With empty headers, should return error
    assert!(result.is_err());
}

#[test]
fn test_consensus_error_display() {
    let error = ConsensusError::TransactionValidation("test error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("test error"));

    let error = ConsensusError::BlockValidation("block error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("block error"));

    let error = ConsensusError::ScriptExecution("script error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("script error"));

    let error = ConsensusError::UtxoNotFound("utxo error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("utxo error"));

    let error = ConsensusError::InvalidSignature("sig error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("sig error"));

    let error = ConsensusError::InvalidProofOfWork("pow error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("pow error"));

    let error = ConsensusError::EconomicValidation("econ error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("econ error"));

    let error = ConsensusError::Serialization("ser error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("ser error"));

    let error = ConsensusError::ConsensusRuleViolation("rule error".into());
    let error_str = format!("{error}");
    assert!(error_str.contains("rule error"));
}
