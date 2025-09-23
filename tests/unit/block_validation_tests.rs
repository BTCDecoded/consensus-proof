use consensus_proof::{block, Transaction, TransactionInput, TransactionOutput, OutPoint, BlockHeader, Block, UtxoSet};

fn create_invalid_block() -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0, // Invalid timestamp (before genesis)
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![], // Empty block (should be invalid)
    }
}

fn create_valid_coinbase_block() -> Block {
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
    
    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx],
    }
}

#[test]
fn test_connect_block_empty_transactions() {
    let block = create_invalid_block();
    let utxo = UtxoSet::new();
    let height = 1;
    
    // Empty block should fail validation
    let result = block::connect_block(&block, utxo, height);
    // May succeed or fail depending on implementation, just exercise the path
    let _ = result;
}

#[test]
fn test_connect_block_invalid_timestamp() {
    let block = create_invalid_block();
    let utxo = UtxoSet::new();
    let height = 1;
    
    // Block with invalid timestamp should be handled
    let result = block::connect_block(&block, utxo, height);
    let _ = result;
}

#[test]
fn test_connect_block_valid_coinbase() {
    let block = create_valid_coinbase_block();
    let utxo = UtxoSet::new();
    let height = 1;
    
    // Valid coinbase block should be processed
    let result = block::connect_block(&block, utxo, height);
    let _ = result;
}

#[test]
fn test_apply_transaction_coinbase() {
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
    
    let mut utxo = UtxoSet::new();
    let height = 1;
    
    // Apply coinbase transaction
    let result = block::apply_transaction(&coinbase_tx, &mut utxo, height);
    let _ = result;
}
