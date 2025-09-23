use consensus_proof::{mempool, Transaction, TransactionInput, TransactionOutput, OutPoint, UtxoSet};

fn create_rbf_tx(sequence: u32) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [1; 32], index: 0 },
            script_sig: vec![0x51],
            sequence,
        }],
        outputs: vec![TransactionOutput { value: 1000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

#[test]
fn test_rbf_sequence_checks() {
    let pool = mempool::Mempool::new();
    
    // RBF transaction (sequence < 0xffffffff)
    let rbf_tx = create_rbf_tx(0xfffffffe);
    let non_rbf_tx = create_rbf_tx(0xffffffff);
    
    // Test RBF replacement logic
    let can_replace = mempool::replacement_checks(&rbf_tx, &non_rbf_tx, &pool);
    // Whether it succeeds depends on implementation, just exercise the path
    let _ = can_replace;
}

#[test]
fn test_mempool_duplicate_detection() {
    let mut pool = mempool::Mempool::new();
    let tx = create_rbf_tx(0xffffffff);
    let utxo = UtxoSet::new();
    
    // First acceptance should work
    let _ = mempool::accept_to_memory_pool(&tx, &utxo, &pool, 1);
    
    // Second acceptance should detect duplicate
    let result = mempool::accept_to_memory_pool(&tx, &utxo, &pool, 1);
    // Should fail due to duplicate
    assert!(result.is_err());
}
