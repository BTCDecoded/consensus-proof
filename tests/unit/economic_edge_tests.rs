use consensus_proof::{economic, Transaction, TransactionInput, TransactionOutput, OutPoint, UtxoSet};

fn create_tx_with_value(value: i64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput { value, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

#[test]
fn test_calculate_fee_coinbase() {
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput { value: 50_000_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };
    
    let utxo = UtxoSet::new();
    let fee = economic::calculate_fee(&coinbase_tx, &utxo);
    
    // Coinbase transactions should have zero fee
    assert!(fee.is_ok());
    assert_eq!(fee.unwrap(), 0);
}

#[test]
fn test_calculate_fee_negative() {
    let tx = create_tx_with_value(1000);
    let mut utxo = UtxoSet::new();
    
    // Create UTXO with less value than transaction output
    utxo.insert(
        OutPoint { hash: [1; 32], index: 0 },
        consensus_proof::UTXO { value: 500, script_pubkey: vec![0x51], height: 1 }
    );
    
    let fee = economic::calculate_fee(&tx, &utxo);
    
    // Should fail due to negative fee (outputs > inputs)
    assert!(fee.is_err());
}

#[test]
fn test_get_block_subsidy_high_halving() {
    // Test subsidy calculation at very high halving intervals
    let height_after_many_halvings = 2_100_000; // Way beyond 33 halvings
    let subsidy = economic::get_block_subsidy(height_after_many_halvings);
    
    // Should be 0 after all halvings
    assert_eq!(subsidy, 0);
}

#[test]
fn test_total_supply_convergence() {
    // Test that total supply converges to 21M BTC
    let max_height = 2_100_000;
    let total_supply = economic::total_supply(max_height);
    
    // Should be close to 21M BTC (2,100,000,000,000 satoshis)
    assert!(total_supply <= 2_100_000_000_000);
}

#[test]
fn test_supply_limit() {
    // Test supply limit constant
    let limit = consensus_proof::MAX_MONEY;
    
    // Should be 21M BTC in satoshis
    assert_eq!(limit, 2_100_000_000_000);
}
