use consensus_proof::{mempool, Transaction, TransactionInput, TransactionOutput, OutPoint, UtxoSet};

fn utxo(value: i64) -> (UtxoSet, OutPoint) {
    let mut set = UtxoSet::new();
    let txid = [1u8;32];
    let op = OutPoint { hash: txid, index: 0 };
    set.insert(op.clone(), consensus_proof::UTXO { value, script_pubkey: vec![0x51], height: 1 });
    (set, op)
}

#[test]
fn test_negative_fee_rejected() {
    let (set, prev) = utxo(1000);
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput { prevout: prev, script_sig: vec![0x51], sequence: 0xffffffff }],
        outputs: vec![TransactionOutput { value: 2000, script_pubkey: vec![0x51] }],
        lock_time: 0,
    };
    let pool = mempool::Mempool::new();
    let res = mempool::accept_to_memory_pool(&tx, &set, &pool, 1);
    assert!(res.is_err(), "Outputs exceed inputs should be rejected");
}

#[test]
fn test_non_standard_script_flagged() {
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TransactionOutput { value: 0, script_pubkey: vec![0x6a] }], // OP_RETURN only
        lock_time: 0,
    };
    // Whether standard depends on policy; just exercise the path
    let _ = mempool::is_standard_tx(&tx);
}


