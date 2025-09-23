//! Block validation functions from Orange Paper Section 5.3 Section 5.3

use crate::types::*;
// use crate::constants::*;
use crate::error::Result;
use crate::transaction::{check_transaction, check_tx_inputs};
use crate::script::verify_script;
use crate::economic::get_block_subsidy;

/// ConnectBlock: ℬ × 𝒰𝒮 × ℕ → {valid, invalid} × 𝒰𝒮
/// 
/// For block b = (h, txs) with UTXO set us at height height:
/// 1. Validate block header h
/// 2. For each transaction tx ∈ txs:
///    - Validate tx structure
///    - Check inputs against us
///    - Verify scripts
/// 3. Let fees = Σ_{tx ∈ txs} fee(tx)
/// 4. Let subsidy = GetBlockSubsidy(height)
/// 5. If coinbase output > fees + subsidy: return (invalid, us)
/// 6. Apply all transactions to us: us' = ApplyTransactions(txs, us)
/// 7. Return (valid, us')
pub fn connect_block(
    block: &Block,
    mut utxo_set: UtxoSet,
    height: Natural
) -> Result<(ValidationResult, UtxoSet)> {
    // 1. Validate block header
    if !validate_block_header(&block.header)? {
        return Ok((ValidationResult::Invalid("Invalid block header".to_string()), utxo_set));
    }
    
    // 2. Validate all transactions
    let mut total_fees = 0i64;
    
    for (i, tx) in block.transactions.iter().enumerate() {
        // Validate transaction structure
        if !matches!(check_transaction(tx)?, ValidationResult::Valid) {
            return Ok((ValidationResult::Invalid(
                format!("Invalid transaction at index {}", i)
            ), utxo_set));
        }
        
        // Check transaction inputs and calculate fees
        let (input_valid, fee) = check_tx_inputs(tx, &utxo_set, height)?;
        if !matches!(input_valid, ValidationResult::Valid) {
            return Ok((ValidationResult::Invalid(
                format!("Invalid transaction inputs at index {}", i)
            ), utxo_set));
        }
        
        // Verify scripts for non-coinbase transactions
        if !is_coinbase(tx) {
            for (j, input) in tx.inputs.iter().enumerate() {
                if let Some(utxo) = utxo_set.get(&input.prevout) {
                    if !verify_script(
                        &input.script_sig,
                        &utxo.script_pubkey,
                        None, // TODO: Add witness support
                        0
                    )? {
                        return Ok((ValidationResult::Invalid(
                            format!("Invalid script at transaction {}, input {}", i, j)
                        ), utxo_set));
                    }
                }
            }
        }
        
        total_fees += fee;
    }
    
    // 3. Validate coinbase transaction
    if let Some(coinbase) = block.transactions.first() {
        if !is_coinbase(coinbase) {
            return Ok((ValidationResult::Invalid("First transaction must be coinbase".to_string()), utxo_set));
        }
        
        let subsidy = get_block_subsidy(height);
        let coinbase_output: i64 = coinbase.outputs.iter().map(|o| o.value).sum();
        
        if coinbase_output > total_fees + subsidy {
            return Ok((ValidationResult::Invalid(
                "Coinbase output exceeds fees + subsidy".to_string()
            ), utxo_set));
        }
    } else {
        return Ok((ValidationResult::Invalid("Block must have at least one transaction".to_string()), utxo_set));
    }
    
    // 4. Apply all transactions to UTXO set
    for tx in &block.transactions {
        utxo_set = apply_transaction(tx, utxo_set, height)?;
    }
    
    Ok((ValidationResult::Valid, utxo_set))
}

/// ApplyTransaction: 𝒯𝒳 × 𝒰𝒮 → 𝒰𝒮
/// 
/// For transaction tx and UTXO set us:
/// 1. If tx is coinbase: us' = us ∪ {(tx.id, i) ↦ tx.outputs[i] : i ∈ [0, |tx.outputs|)}
/// 2. Otherwise: us' = (us \ {i.prevout : i ∈ tx.inputs}) ∪ {(tx.id, i) ↦ tx.outputs[i] : i ∈ [0, |tx.outputs|)}
/// 3. Return us'
pub fn apply_transaction(
    tx: &Transaction,
    mut utxo_set: UtxoSet,
    height: Natural
) -> Result<UtxoSet> {
    // Remove spent inputs (except for coinbase)
    if !is_coinbase(tx) {
        for input in &tx.inputs {
            utxo_set.remove(&input.prevout);
        }
    }
    
    // Add new outputs
    let tx_id = calculate_tx_id(tx);
    for (i, output) in tx.outputs.iter().enumerate() {
        let outpoint = OutPoint {
            hash: tx_id,
            index: i as Natural,
        };
        
        let utxo = UTXO {
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            height,
        };
        
        utxo_set.insert(outpoint, utxo);
    }
    
    Ok(utxo_set)
}

/// Validate block header
fn validate_block_header(header: &BlockHeader) -> Result<bool> {
    // Check version is valid
    if header.version < 1 {
        return Ok(false);
    }
    
    // Check timestamp is reasonable (not too far in future)
    // TODO: Add proper timestamp validation
    
    // Check bits is valid
    if header.bits == 0 {
        return Ok(false);
    }
    
    // TODO: Add more header validation (merkle root, etc.)
    
    Ok(true)
}

/// Check if transaction is coinbase
fn is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1 && 
    tx.inputs[0].prevout.hash == [0u8; 32] && 
    tx.inputs[0].prevout.index == 0xffffffff
}

/// Calculate transaction ID (simplified)
fn calculate_tx_id(tx: &Transaction) -> Hash {
    // Simplified: use a hash of the transaction data
    // In real implementation, this would be SHA256(SHA256(serialized_tx))
    let mut hash = [0u8; 32];
    hash[0] = (tx.version & 0xff) as u8;
    hash[1] = (tx.inputs.len() & 0xff) as u8;
    hash[2] = (tx.outputs.len() & 0xff) as u8;
    hash[3] = (tx.lock_time & 0xff) as u8;
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_connect_block_valid() {
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
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505, // Genesis timestamp
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            transactions: vec![coinbase_tx],
        };
        
        let utxo_set = UtxoSet::new();
        let (result, new_utxo_set) = connect_block(&block, utxo_set, 0).unwrap();
        
        assert_eq!(result, ValidationResult::Valid);
        assert_eq!(new_utxo_set.len(), 1); // One new UTXO from coinbase
    }
    
    #[test]
    fn test_apply_transaction_coinbase() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let utxo_set = UtxoSet::new();
        let new_utxo_set = apply_transaction(&coinbase_tx, utxo_set, 0).unwrap();
        
        assert_eq!(new_utxo_set.len(), 1);
    }
    
    // ============================================================================
    // COMPREHENSIVE BLOCK TESTS
    // ============================================================================
    
    #[test]
    fn test_connect_block_invalid_header() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 0, // Invalid version
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };
        
        let utxo_set = UtxoSet::new();
        let (result, _) = connect_block(&block, utxo_set, 0).unwrap();
        
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_connect_block_no_transactions() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![], // No transactions
        };
        
        let utxo_set = UtxoSet::new();
        let (result, _) = connect_block(&block, utxo_set, 0).unwrap();
        
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_connect_block_first_tx_not_coinbase() {
        let regular_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![regular_tx], // First tx is not coinbase
        };
        
        let utxo_set = UtxoSet::new();
        let (result, _) = connect_block(&block, utxo_set, 0).unwrap();
        
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_connect_block_coinbase_exceeds_subsidy() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 6000000000, // 60 BTC - exceeds subsidy
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };
        
        let utxo_set = UtxoSet::new();
        let (result, _) = connect_block(&block, utxo_set, 0).unwrap();
        
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_apply_transaction_regular() {
        let mut utxo_set = UtxoSet::new();
        
        // Add a UTXO first
        let prev_outpoint = OutPoint { hash: [1; 32], index: 0 };
        let prev_utxo = UTXO {
            value: 1000,
            script_pubkey: vec![0x51], // OP_1
            height: 0,
        };
        utxo_set.insert(prev_outpoint, prev_utxo);
        
        let regular_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![0x51], // OP_1
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 500,
                script_pubkey: vec![0x52], // OP_2
            }],
            lock_time: 0,
        };
        
        let new_utxo_set = apply_transaction(&regular_tx, utxo_set, 1).unwrap();
        
        // Should have 1 UTXO (the new output)
        assert_eq!(new_utxo_set.len(), 1);
    }
    
    #[test]
    fn test_apply_transaction_multiple_outputs() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![
                TransactionOutput {
                    value: 2500000000,
                    script_pubkey: vec![0x51],
                },
                TransactionOutput {
                    value: 2500000000,
                    script_pubkey: vec![0x52],
                },
            ],
            lock_time: 0,
        };
        
        let utxo_set = UtxoSet::new();
        let new_utxo_set = apply_transaction(&coinbase_tx, utxo_set, 0).unwrap();
        
        assert_eq!(new_utxo_set.len(), 2);
    }
    
    #[test]
    fn test_validate_block_header_valid() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        
        let result = validate_block_header(&header).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_validate_block_header_invalid_version() {
        let header = BlockHeader {
            version: 0, // Invalid version
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        
        let result = validate_block_header(&header).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_validate_block_header_invalid_bits() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0, // Invalid bits
            nonce: 0,
        };
        
        let result = validate_block_header(&header).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_is_coinbase_true() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(is_coinbase(&coinbase_tx));
    }
    
    #[test]
    fn test_is_coinbase_false_wrong_hash() {
        let regular_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0xffffffff }, // Wrong hash
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(!is_coinbase(&regular_tx));
    }
    
    #[test]
    fn test_is_coinbase_false_wrong_index() {
        let regular_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 }, // Wrong index
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(!is_coinbase(&regular_tx));
    }
    
    #[test]
    fn test_is_coinbase_false_multiple_inputs() {
        let regular_tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint { hash: [1; 32], index: 0 },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(!is_coinbase(&regular_tx));
    }
    
    #[test]
    fn test_calculate_tx_id() {
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
        
        let tx_id = calculate_tx_id(&tx);
        
        // Should be a 32-byte hash
        assert_eq!(tx_id.len(), 32);
        
        // First byte should be version (1)
        assert_eq!(tx_id[0], 1);
        
        // Second byte should be input count (1)
        assert_eq!(tx_id[1], 1);
        
        // Third byte should be output count (1)
        assert_eq!(tx_id[2], 1);
        
        // Fourth byte should be lock time (0)
        assert_eq!(tx_id[3], 0);
    }
    
    #[test]
    fn test_calculate_tx_id_different_versions() {
        let tx1 = Transaction {
            version: 2,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        
        let tx2 = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        
        let id1 = calculate_tx_id(&tx1);
        let id2 = calculate_tx_id(&tx2);
        
        // Different versions should produce different IDs
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_connect_block_empty_transactions() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![], // Empty transactions
        };
        
        let utxo_set = UtxoSet::new();
        let result = connect_block(&block, utxo_set, 0);
        // The result should be Ok with ValidationResult::Invalid
        assert!(result.is_ok());
        let (validation_result, _) = result.unwrap();
        assert!(matches!(validation_result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_connect_block_invalid_coinbase() {
        let invalid_coinbase = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 }, // Wrong hash for coinbase
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![invalid_coinbase],
        };
        
        let utxo_set = UtxoSet::new();
        let result = connect_block(&block, utxo_set, 0);
        // The result should be Ok with ValidationResult::Invalid
        assert!(result.is_ok());
        let (validation_result, _) = result.unwrap();
        assert!(matches!(validation_result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_apply_transaction_insufficient_funds() {
        let mut utxo_set = UtxoSet::new();
        
        // Add a UTXO with insufficient value
        let prev_outpoint = OutPoint { hash: [1; 32], index: 0 };
        let prev_utxo = UTXO {
            value: 100, // Small value
            script_pubkey: vec![0x51],
            height: 0,
        };
        utxo_set.insert(prev_outpoint, prev_utxo);
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 200, // More than input value
                script_pubkey: vec![0x52],
            }],
            lock_time: 0,
        };
        
        // The simplified implementation doesn't validate insufficient funds
        let result = apply_transaction(&tx, utxo_set, 1);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_apply_transaction_missing_utxo() {
        let utxo_set = UtxoSet::new(); // Empty UTXO set
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 100,
                script_pubkey: vec![0x52],
            }],
            lock_time: 0,
        };
        
        // The simplified implementation doesn't validate missing UTXOs
        let result = apply_transaction(&tx, utxo_set, 1);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_block_header_future_timestamp() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 9999999999, // Far future timestamp
            bits: 0x1d00ffff,
            nonce: 0,
        };
        
        // The simplified implementation doesn't validate timestamps
        let result = validate_block_header(&header).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_validate_block_header_zero_timestamp() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0, // Zero timestamp
            bits: 0x1d00ffff,
            nonce: 0,
        };
        
        // The simplified implementation doesn't validate timestamps
        let result = validate_block_header(&header).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_connect_block_coinbase_exceeds_subsidy_edge() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 2100000000000000, // Exceeds total supply
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };
        
        let utxo_set = UtxoSet::new();
        let result = connect_block(&block, utxo_set, 0);
        // The result should be Ok with ValidationResult::Invalid
        assert!(result.is_ok());
        let (validation_result, _) = result.unwrap();
        assert!(matches!(validation_result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_connect_block_first_tx_not_coinbase_edge() {
        let regular_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x52],
            }],
            lock_time: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![regular_tx], // First tx is not coinbase
        };
        
        let utxo_set = UtxoSet::new();
        let result = connect_block(&block, utxo_set, 0);
        // The result should be Ok with ValidationResult::Invalid
        assert!(result.is_ok());
        let (validation_result, _) = result.unwrap();
        assert!(matches!(validation_result, ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_apply_transaction_multiple_inputs() {
        let mut utxo_set = UtxoSet::new();
        
        // Add multiple UTXOs
        let outpoint1 = OutPoint { hash: [1; 32], index: 0 };
        let utxo1 = UTXO {
            value: 500,
            script_pubkey: vec![0x51],
            height: 0,
        };
        utxo_set.insert(outpoint1, utxo1);
        
        let outpoint2 = OutPoint { hash: [2; 32], index: 0 };
        let utxo2 = UTXO {
            value: 300,
            script_pubkey: vec![0x52],
            height: 0,
        };
        utxo_set.insert(outpoint2, utxo2);
        
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint { hash: [1; 32], index: 0 },
                    script_sig: vec![0x51],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint { hash: [2; 32], index: 0 },
                    script_sig: vec![0x52],
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![TransactionOutput {
                value: 700, // Total input value
                script_pubkey: vec![0x53],
            }],
            lock_time: 0,
        };
        
        let new_utxo_set = apply_transaction(&tx, utxo_set, 1).unwrap();
        assert_eq!(new_utxo_set.len(), 1);
    }
    
    #[test]
    fn test_apply_transaction_no_outputs() {
        let mut utxo_set = UtxoSet::new();
        
        let prev_outpoint = OutPoint { hash: [1; 32], index: 0 };
        let prev_utxo = UTXO {
            value: 1000,
            script_pubkey: vec![0x51],
            height: 0,
        };
        utxo_set.insert(prev_outpoint, prev_utxo);
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: vec![], // No outputs
            lock_time: 0,
        };
        
        let new_utxo_set = apply_transaction(&tx, utxo_set, 1).unwrap();
        assert_eq!(new_utxo_set.len(), 0);
    }
}
