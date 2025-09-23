use consensus_proof::*;

fn tx_p2pkh(value: i64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint { hash: [0;32], index: 0xffffffff },
            script_sig: vec![0x51],
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput { value, script_pubkey: vec![0x51] }],
        lock_time: 0,
    }
}

fn header_prev() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: [0;32],
        merkle_root: [0;32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    }
}

#[test]
fn test_connect_block_smoke() {
    let coinbase = tx_p2pkh(50_000_000_000);
    let block = Block { header: header_prev(), transactions: vec![coinbase] };
    let utxo = UtxoSet::new();
    let _ = block::connect_block(&block, utxo, 1);
}


