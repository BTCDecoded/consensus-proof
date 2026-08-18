//! P4.1: utxo_overlay apply ≡ ApplyTransaction differential harness.

use blvm_consensus::block::{apply_transaction, calculate_tx_id};
use blvm_consensus::opcodes::{OP_1, OP_2, OP_3};
use blvm_consensus::transaction::is_coinbase;
use blvm_consensus::utxo_overlay::{
    UtxoOverlay, apply_transaction_to_overlay_no_undo,
    apply_transaction_to_overlay_no_undo_with_output_cache, build_block_output_utxo_cache,
};
use blvm_consensus::{OutPoint, Transaction, TransactionInput, TransactionOutput, UTXO, UtxoSet};
use std::sync::Arc;

fn sample_fund_tx(seed: u8, value: i64) -> (Transaction, [u8; 32]) {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [seed; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffff_ffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value,
            script_pubkey: vec![seed].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let tx_id = calculate_tx_id(&tx);
    (tx, tx_id)
}

fn sample_spend_tx(fund_id: [u8; 32], out_value: i64, out_script: u8) -> (Transaction, [u8; 32]) {
    let spend = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: fund_id,
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffff_ffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: out_value,
            script_pubkey: vec![out_script].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let spend_id = calculate_tx_id(&spend);
    (spend, spend_id)
}

fn assert_utxo_sets_equal(a: &UtxoSet, b: &UtxoSet) {
    assert_eq!(a.len(), b.len(), "UTXO set lengths differ");
    for (k, v) in a.iter() {
        assert_eq!(b.get(k), Some(v), "key {k:?}");
    }
}

/// Apply a sequence via direct `apply_transaction` vs overlay batch; final sets must match.
fn assert_overlay_sequence_matches_direct(base: UtxoSet, steps: &[(Transaction, [u8; 32], u64)]) {
    let mut direct = base.clone();
    for (tx, _tx_id, height) in steps {
        let (next, _) = apply_transaction(tx, direct, *height).expect("apply_transaction");
        direct = next;
    }

    let mut overlay = UtxoOverlay::new(&base);
    for (tx, tx_id, height) in steps {
        apply_transaction_to_overlay_no_undo(&mut overlay, tx, *tx_id, *height);
    }
    let merged = overlay.apply_to_base();

    assert_utxo_sets_equal(&direct, &merged);
}

#[test]
fn overlay_apply_matches_apply_transaction_fund() {
    let (fund, fund_id) = sample_fund_tx(1, 50_000_000_000);
    let base = UtxoSet::default();
    let mut overlay = UtxoOverlay::new(&base);

    apply_transaction_to_overlay_no_undo(&mut overlay, &fund, fund_id, 1);
    let merged = overlay.apply_to_base();

    let (direct, _) = apply_transaction(&fund, base, 1).expect("apply_transaction");
    assert_utxo_sets_equal(&direct, &merged);
}

#[test]
fn overlay_apply_matches_apply_transaction_spend() {
    let (_fund, fund_id) = sample_fund_tx(1, 50_000_000_000);
    let outpoint = OutPoint {
        hash: fund_id,
        index: 0,
    };
    let (spend, spend_id) = sample_spend_tx(fund_id, 49_000_000_000, OP_2);
    assert!(!is_coinbase(&spend));

    let mut seed = UtxoSet::default();
    seed.insert(
        outpoint,
        Arc::new(UTXO {
            value: 50_000_000_000,
            script_pubkey: vec![OP_1].into(),
            height: 1,
            is_coinbase: false,
        }),
    );

    let mut overlay = UtxoOverlay::new(&seed);
    apply_transaction_to_overlay_no_undo(&mut overlay, &spend, spend_id, 2);
    let merged = overlay.apply_to_base();

    let (direct, _) = apply_transaction(&spend, seed, 2).expect("apply_transaction");
    assert_utxo_sets_equal(&direct, &merged);
}

#[test]
fn overlay_apply_matches_multi_output_fund() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [9; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffff_ffff,
        }]
        .into(),
        outputs: vec![
            TransactionOutput {
                value: 30_000,
                script_pubkey: vec![OP_1].into(),
            },
            TransactionOutput {
                value: 20_000,
                script_pubkey: vec![OP_2].into(),
            },
        ]
        .into(),
        lock_time: 0,
    };
    let tx_id = calculate_tx_id(&tx);
    let base = UtxoSet::default();

    assert_overlay_sequence_matches_direct(base, &[(tx, tx_id, 10)]);
}

#[test]
fn overlay_apply_matches_three_tx_chain() {
    let (fund_a, fund_a_id) = sample_fund_tx(0x10, 100_000);
    let (fund_b, fund_b_id) = sample_fund_tx(0x20, 200_000);
    let (spend_a, spend_a_id) = sample_spend_tx(fund_a_id, 90_000, OP_3);

    assert_overlay_sequence_matches_direct(
        UtxoSet::default(),
        &[
            (fund_a, fund_a_id, 1),
            (fund_b, fund_b_id, 2),
            (spend_a, spend_a_id, 3),
        ],
    );
}

#[test]
fn overlay_apply_matches_spend_from_seeded_base() {
    let (fund, fund_id) = sample_fund_tx(0x30, 75_000);
    let (spend, spend_id) = sample_spend_tx(fund_id, 70_000, OP_2);

    let base = UtxoSet::default();
    let (base, _) = apply_transaction(&fund, base, 100).expect("seed fund");
    assert_overlay_sequence_matches_direct(base, &[(spend, spend_id, 101)]);
}

#[test]
fn overlay_apply_matches_pseudo_block_sequence() {
    // Synthetic mini-block: two coinbase-like funds (non-coinbase inputs for harness simplicity)
    // then one spend consolidating one UTXO.
    let (fund_a, id_a) = sample_fund_tx(0x41, 1_000_000);
    let (fund_b, _id_b) = sample_fund_tx(0x42, 2_000_000);
    let (spend, id_s) = sample_spend_tx(id_a, 950_000, OP_2);

    let base = UtxoSet::default();
    let (base, _) = apply_transaction(&fund_a, base, 500).expect("fund a");
    let (base, _) = apply_transaction(&fund_b, base, 500).expect("fund b");

    assert_overlay_sequence_matches_direct(base, &[(spend, id_s, 501)]);
}

#[test]
fn overlay_output_cache_matches_uncached_apply() {
    let (fund_a, id_a) = sample_fund_tx(0x51, 500_000);
    let (fund_b, _id_b) = sample_fund_tx(0x52, 600_000);
    let (spend, _id_s) = sample_spend_tx(id_a, 450_000, OP_2);

    let block = blvm_consensus::Block {
        header: blvm_consensus::BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1,
            bits: 0x0f00ffff,
            nonce: 0,
        },
        transactions: vec![fund_a.clone(), fund_b.clone(), spend.clone()].into(),
    };
    let tx_ids = [
        calculate_tx_id(&fund_a),
        calculate_tx_id(&fund_b),
        calculate_tx_id(&spend),
    ];
    let height = 400_000u64;
    let cache = build_block_output_utxo_cache(&block, &tx_ids, height);

    let base = UtxoSet::default();
    let mut overlay_uncached = UtxoOverlay::new(&base);
    apply_transaction_to_overlay_no_undo(&mut overlay_uncached, &fund_a, tx_ids[0], height);
    apply_transaction_to_overlay_no_undo(&mut overlay_uncached, &fund_b, tx_ids[1], height);
    apply_transaction_to_overlay_no_undo(&mut overlay_uncached, &spend, tx_ids[2], height);

    let mut overlay_cached = UtxoOverlay::new(&base);
    apply_transaction_to_overlay_no_undo_with_output_cache(
        &mut overlay_cached, &fund_a, tx_ids[0], height, &cache,
    );
    apply_transaction_to_overlay_no_undo_with_output_cache(
        &mut overlay_cached, &fund_b, tx_ids[1], height, &cache,
    );
    apply_transaction_to_overlay_no_undo_with_output_cache(
        &mut overlay_cached, &spend, tx_ids[2], height, &cache,
    );

    assert_utxo_sets_equal(&overlay_uncached.apply_to_base(), &overlay_cached.apply_to_base());
}
