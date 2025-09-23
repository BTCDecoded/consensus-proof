//! Transaction validation functions from Orange Paper Section 5.1

use crate::types::*;
use crate::constants::*;
use crate::error::Result;

/// CheckTransaction: 𝒯𝒳 → {valid, invalid}
/// 
/// A transaction tx = (v, ins, outs, lt) is valid if and only if:
/// 1. |ins| > 0 ∧ |outs| > 0
/// 2. ∀o ∈ outs: 0 ≤ o.value ≤ M_max
/// 3. |ins| ≤ M_max_inputs
/// 4. |outs| ≤ M_max_outputs
/// 5. |tx| ≤ M_max_tx_size
pub fn check_transaction(tx: &Transaction) -> Result<ValidationResult> {
    // 1. Check inputs and outputs are not empty
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Ok(ValidationResult::Invalid("Empty inputs or outputs".to_string()));
    }
    
    // 2. Check output values are valid
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value < 0 || output.value > MAX_MONEY {
            return Ok(ValidationResult::Invalid(
                format!("Invalid output value {} at index {}", output.value, i)
            ));
        }
    }
    
    // 3. Check input count limit
    if tx.inputs.len() > MAX_INPUTS {
        return Ok(ValidationResult::Invalid(
            format!("Too many inputs: {}", tx.inputs.len())
        ));
    }
    
    // 4. Check output count limit
    if tx.outputs.len() > MAX_OUTPUTS {
        return Ok(ValidationResult::Invalid(
            format!("Too many outputs: {}", tx.outputs.len())
        ));
    }
    
    // 5. Check transaction size limit
    let tx_size = calculate_transaction_size(tx);
    if tx_size > MAX_TX_SIZE {
        return Ok(ValidationResult::Invalid(
            format!("Transaction too large: {} bytes", tx_size)
        ));
    }
    
    Ok(ValidationResult::Valid)
}

/// CheckTxInputs: 𝒯𝒳 × 𝒰𝒮 × ℕ → {valid, invalid} × ℤ
/// 
/// For transaction tx with UTXO set us at height h:
/// 1. If tx is coinbase: return (valid, 0)
/// 2. Let total_in = Σᵢ us(i.prevout).value
/// 3. Let total_out = Σₒ o.value
/// 4. If total_in < total_out: return (invalid, 0)
/// 5. Return (valid, total_in - total_out)
pub fn check_tx_inputs(
    tx: &Transaction, 
    utxo_set: &UtxoSet, 
    _height: Natural
) -> Result<(ValidationResult, Integer)> {
    // Check if this is a coinbase transaction
    if is_coinbase(tx) {
        return Ok((ValidationResult::Valid, 0));
    }
    
    let mut total_input_value = 0i64;
    
    for (i, input) in tx.inputs.iter().enumerate() {
        // Check if input exists in UTXO set
        if let Some(utxo) = utxo_set.get(&input.prevout) {
            // Check if UTXO is not spent (this would be handled by UTXO set management)
            total_input_value += utxo.value;
        } else {
            return Ok((ValidationResult::Invalid(
                format!("Input {} not found in UTXO set", i)
            ), 0));
        }
    }
    
    let total_output_value: i64 = tx.outputs.iter().map(|o| o.value).sum();
    
    if total_input_value < total_output_value {
        return Ok((ValidationResult::Invalid(
            "Insufficient input value".to_string()
        ), 0));
    }
    
    let fee = total_input_value - total_output_value;
    Ok((ValidationResult::Valid, fee))
}

/// Check if transaction is coinbase
pub fn is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1 && 
    tx.inputs[0].prevout.hash == [0u8; 32] && 
    tx.inputs[0].prevout.index == 0xffffffff
}

/// Calculate transaction size (simplified)
fn calculate_transaction_size(tx: &Transaction) -> usize {
    // Simplified size calculation
    // In reality, this would be the serialized size
    4 + // version
    tx.inputs.len() * 41 + // inputs (simplified)
    tx.outputs.len() * 9 + // outputs (simplified)
    4 // lock_time
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_check_transaction_valid() {
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
        
        assert_eq!(check_transaction(&tx).unwrap(), ValidationResult::Valid);
    }
    
    #[test]
    fn test_check_transaction_empty_inputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_tx_inputs_coinbase() {
        let tx = Transaction {
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
        let (result, fee) = check_tx_inputs(&tx, &utxo_set, 0).unwrap();
        
        assert_eq!(result, ValidationResult::Valid);
        assert_eq!(fee, 0);
    }
    
    // ============================================================================
    // COMPREHENSIVE TRANSACTION TESTS
    // ============================================================================
    
    #[test]
    fn test_check_transaction_empty_outputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_transaction_invalid_output_value_negative() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: -1, // Invalid negative value
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_transaction_invalid_output_value_too_large() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: MAX_MONEY + 1, // Invalid value exceeding max
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_transaction_max_output_value() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: MAX_MONEY, // Valid max value
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert_eq!(check_transaction(&tx).unwrap(), ValidationResult::Valid);
    }
    
    #[test]
    fn test_check_transaction_too_many_inputs() {
        let mut inputs = Vec::new();
        for i in 0..=MAX_INPUTS {
            inputs.push(TransactionInput {
                prevout: OutPoint { hash: [i as u8; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            });
        }
        
        let tx = Transaction {
            version: 1,
            inputs,
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_transaction_max_inputs() {
        let mut inputs = Vec::new();
        for i in 0..MAX_INPUTS {
            inputs.push(TransactionInput {
                prevout: OutPoint { hash: [i as u8; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            });
        }
        
        let tx = Transaction {
            version: 1,
            inputs,
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert_eq!(check_transaction(&tx).unwrap(), ValidationResult::Valid);
    }
    
    #[test]
    fn test_check_transaction_too_many_outputs() {
        let mut outputs = Vec::new();
        for _ in 0..=MAX_OUTPUTS {
            outputs.push(TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            });
        }
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs,
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_transaction_max_outputs() {
        let mut outputs = Vec::new();
        for _ in 0..MAX_OUTPUTS {
            outputs.push(TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            });
        }
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs,
            lock_time: 0,
        };
        
        assert_eq!(check_transaction(&tx).unwrap(), ValidationResult::Valid);
    }
    
    #[test]
    fn test_check_transaction_too_large() {
        // Create a transaction that will exceed MAX_TX_SIZE
        // Since calculate_transaction_size is simplified, we need to create a transaction
        // with enough inputs to exceed the size limit
        let mut inputs = Vec::new();
        for i in 0..25000 { // This should create a transaction > 1MB
            inputs.push(TransactionInput {
                prevout: OutPoint { hash: [i as u8; 32], index: 0 },
                script_sig: vec![0u8; 100], // Large script to increase size
                sequence: 0xffffffff,
            });
        }
        
        let tx = Transaction {
            version: 1,
            inputs,
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        assert!(matches!(check_transaction(&tx).unwrap(), ValidationResult::Invalid(_)));
    }
    
    #[test]
    fn test_check_tx_inputs_regular_transaction() {
        let mut utxo_set = UtxoSet::new();
        
        // Add UTXO to the set
        let outpoint = OutPoint { hash: [1; 32], index: 0 };
        let utxo = UTXO {
            value: 1000000000, // 10 BTC
            script_pubkey: vec![],
            height: 0,
        };
        utxo_set.insert(outpoint, utxo);
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 900000000, // 9 BTC output
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let (result, fee) = check_tx_inputs(&tx, &utxo_set, 0).unwrap();
        
        assert_eq!(result, ValidationResult::Valid);
        assert_eq!(fee, 100000000); // 1 BTC fee
    }
    
    #[test]
    fn test_check_tx_inputs_missing_utxo() {
        let utxo_set = UtxoSet::new(); // Empty UTXO set
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 100000000,
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let (result, fee) = check_tx_inputs(&tx, &utxo_set, 0).unwrap();
        
        assert!(matches!(result, ValidationResult::Invalid(_)));
        assert_eq!(fee, 0);
    }
    
    #[test]
    fn test_check_tx_inputs_insufficient_funds() {
        let mut utxo_set = UtxoSet::new();
        
        // Add UTXO with insufficient value
        let outpoint = OutPoint { hash: [1; 32], index: 0 };
        let utxo = UTXO {
            value: 100000000, // 1 BTC
            script_pubkey: vec![],
            height: 0,
        };
        utxo_set.insert(outpoint, utxo);
        
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 200000000, // 2 BTC output (more than input)
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let (result, fee) = check_tx_inputs(&tx, &utxo_set, 0).unwrap();
        
        assert!(matches!(result, ValidationResult::Invalid(_)));
        assert_eq!(fee, 0);
    }
    
    #[test]
    fn test_check_tx_inputs_multiple_inputs() {
        let mut utxo_set = UtxoSet::new();
        
        // Add two UTXOs
        let outpoint1 = OutPoint { hash: [1; 32], index: 0 };
        let utxo1 = UTXO {
            value: 500000000, // 5 BTC
            script_pubkey: vec![],
            height: 0,
        };
        utxo_set.insert(outpoint1, utxo1);
        
        let outpoint2 = OutPoint { hash: [2; 32], index: 0 };
        let utxo2 = UTXO {
            value: 300000000, // 3 BTC
            script_pubkey: vec![],
            height: 0,
        };
        utxo_set.insert(outpoint2, utxo2);
        
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint { hash: [1; 32], index: 0 },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint { hash: [2; 32], index: 0 },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![TransactionOutput {
                value: 700000000, // 7 BTC output
                script_pubkey: vec![],
            }],
            lock_time: 0,
        };
        
        let (result, fee) = check_tx_inputs(&tx, &utxo_set, 0).unwrap();
        
        assert_eq!(result, ValidationResult::Valid);
        assert_eq!(fee, 100000000); // 1 BTC fee (8 BTC input - 7 BTC output)
    }
    
    #[test]
    fn test_is_coinbase_edge_cases() {
        // Valid coinbase
        let valid_coinbase = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        assert!(is_coinbase(&valid_coinbase));
        
        // Wrong hash
        let wrong_hash = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0xffffffff },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        assert!(!is_coinbase(&wrong_hash));
        
        // Wrong index
        let wrong_index = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        assert!(!is_coinbase(&wrong_index));
        
        // Multiple inputs
        let multiple_inputs = Transaction {
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
            outputs: vec![],
            lock_time: 0,
        };
        assert!(!is_coinbase(&multiple_inputs));
        
        // No inputs
        let no_inputs = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        assert!(!is_coinbase(&no_inputs));
    }
    
    #[test]
    fn test_calculate_transaction_size() {
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint { hash: [0; 32], index: 0 },
                    script_sig: vec![1, 2, 3],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint { hash: [1; 32], index: 1 },
                    script_sig: vec![4, 5, 6],
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![
                TransactionOutput {
                    value: 1000,
                    script_pubkey: vec![7, 8, 9],
                },
                TransactionOutput {
                    value: 2000,
                    script_pubkey: vec![10, 11, 12],
                },
            ],
            lock_time: 12345,
        };
        
        let size = calculate_transaction_size(&tx);
        // Expected: 4 (version) + 2*41 (inputs) + 2*9 (outputs) + 4 (lock_time) = 108
        // The actual calculation includes script_sig and script_pubkey lengths
        assert_eq!(size, 108);
    }
}
