use consensus_proof::{mining, Transaction, TransactionInput, TransactionOutput, OutPoint, BlockHeader, Block};

fn create_coinbase_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0; 32], index: 0xffffffff },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput { value: 50_000_000_000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

#[test]
fn test_merkle_root_odd_transactions() {
    // Test Merkle root calculation with odd number of transactions
    let tx1 = create_coinbase_tx();
    let tx2 = create_coinbase_tx();
    let tx3 = create_coinbase_tx();
    
    let transactions = vec![tx1, tx2, tx3];
    let merkle_root = mining::calculate_merkle_root(&transactions);
    
    // Should succeed even with odd number
    assert!(merkle_root.is_ok());
}

#[test]
fn test_merkle_root_single_transaction() {
    // Test Merkle root with single transaction
    let tx = create_coinbase_tx();
    let transactions = vec![tx];
    let merkle_root = mining::calculate_merkle_root(&transactions);
    
    assert!(merkle_root.is_ok());
}

#[test]
fn test_block_template_creation() {
    let utxo = consensus_proof::UtxoSet::new();
    let mempool_txs = vec![];
    let height = 1;
    let prev_header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    };
    let prev_headers = vec![];
    let coinbase_script = vec![0x51];
    let coinbase_address = vec![0x51];
    
    let template = mining::create_block_template(
        &utxo,
        &mempool_txs,
        height,
        &prev_header,
        &prev_headers,
        &coinbase_script,
        &coinbase_address,
    );
    
    assert!(template.is_ok());
}

#[test]
fn test_mine_block_failure() {
    // Test mining with impossible target (should fail)
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x00000001, // Extremely difficult target
            nonce: 0,
        },
        transactions: vec![create_coinbase_tx()],
    };
    
    let result = mining::mine_block(block, 10); // Only 10 attempts
    assert!(result.is_ok());
    
    let (_, mining_result) = result.unwrap();
    // Should fail with such a difficult target and few attempts
    assert_eq!(mining_result, mining::MiningResult::Failure);
}
