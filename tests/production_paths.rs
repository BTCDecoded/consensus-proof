//! COV-C-07a: Production-only paths — ScriptCheckQueue, batch_verify_signatures.
//!
//! Exercises code gated by `production` + `rayon` that normal unit tests skip.

#![cfg(all(feature = "production", feature = "rayon"))]

use blvm_consensus::activation::ForkActivationTable;
use blvm_consensus::checkqueue::{
    BlockSessionContext, ScriptCheck, ScriptCheckQueue, TxScriptContext,
};
use blvm_consensus::opcodes::OP_1;
use blvm_consensus::script::{SigVersion, batch_verify_signatures};
use blvm_consensus::types::{
    Block, BlockHeader, Network, OutPoint, Transaction, TransactionInput, TransactionOutput,
};
use blvm_consensus::witness::Witness;
use crossbeam_queue::SegQueue;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

fn op1_true_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0xab; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 9_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    }
}

fn minimal_block_session() -> BlockSessionContext {
    let tx = op1_true_tx();
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1_231_006_505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![tx.clone()].into(),
    };

    let script_pubkey = vec![OP_1]; // OP_1
    let script_pubkey_buffer = Arc::new(script_pubkey);
    let script_pubkey_indices_buffer = Arc::new(vec![(0usize, 1usize)]);
    let prevout_values_buffer = Arc::new(vec![10_000i64]);
    let witness_buffer = Arc::new(vec![vec![Witness::default()]]);

    let tx_context = TxScriptContext {
        tx_index: 0,
        prevout_values_range: (0, 1),
        script_pubkey_indices_range: (0, 1),
        flags: 0,
        #[cfg(feature = "production")]
        bip143: None,
        loop_idx: 0,
        fee: 0,
        ecdsa_index_base: 0,
        #[cfg(feature = "production")]
        sighash_midstate_cache: None,
    };

    BlockSessionContext {
        block: Arc::new(block),
        prevout_values_buffer,
        script_pubkey_indices_buffer,
        script_pubkey_buffer,
        witness_buffer,
        tx_contexts: Arc::new(vec![tx_context]),
        #[cfg(feature = "production")]
        ecdsa_sub_counters: Arc::new(vec![AtomicUsize::new(0)]),
        #[cfg(feature = "production")]
        schnorr_collector: None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        ecdsa_collector: None,
        height: 500_000,
        median_time_past: None,
        network: Network::Mainnet,
        activation: ForkActivationTable::from_network(Network::Mainnet),
        results: Arc::new(SegQueue::new()),
        #[cfg(feature = "production")]
        precomputed_sighashes: Arc::new(vec![None]),
        #[cfg(feature = "production")]
        precomputed_p2pkh_hashes: Arc::new(vec![None]),
    }
}

fn op1_script_check() -> ScriptCheck {
    ScriptCheck {
        tx_ctx_idx: 0,
        input_idx: 0,
        spk_offset: 0,
        spk_len: 1,
        prevout_value: 10_000,
        flags: 0,
    }
}

#[test]
fn test_batch_verify_signatures_empty() {
    let results = batch_verify_signatures(&[], 0, 0, Network::Mainnet, SigVersion::Base).unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_checkqueue_run_checks_sequential_op1() {
    let session = minimal_block_session();
    let checks = vec![op1_script_check()];
    let results = ScriptCheckQueue::run_checks_sequential(&checks, &session).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, 0);
    assert!(
        results[0].1,
        "OP_1 scriptSig + OP_1 scriptPubKey should verify"
    );
}

#[test]
fn test_checkqueue_parallel_add_complete() {
    let session = minimal_block_session();
    let queue = ScriptCheckQueue::new(2, Some(4));
    queue.start_session(session);
    queue.add(vec![op1_script_check()]);
    let results = queue.complete().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].1);
}

#[test]
fn test_checkqueue_add_from_slice() {
    let session = minimal_block_session();
    let queue = ScriptCheckQueue::new(1, Some(8));
    queue.start_session(session);
    let checks = [op1_script_check()];
    queue.add_from_slice(&checks);
    let results = queue.complete().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].1);
}

#[test]
fn test_checkqueue_run_check_with_refs_direct() {
    let session = minimal_block_session();
    let check = op1_script_check();
    let ctx = &session.tx_contexts[0];
    let buffer = session.script_pubkey_buffer.as_slice();
    let refs: Vec<&[u8]> = vec![&buffer[0..1]];
    let valid = ScriptCheckQueue::run_check_with_refs(
        &check,
        &session,
        ctx,
        &refs,
        buffer,
        None,
        Some(&buffer[0..1]),
        Some(&[10_000i64]),
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_checkqueue_run_check_with_bad_script_pubkey_bounds() {
    let session = minimal_block_session();
    let mut check = op1_script_check();
    check.spk_offset = 100;
    check.spk_len = 10;
    let ctx = &session.tx_contexts[0];
    let buffer = session.script_pubkey_buffer.as_slice();
    let refs: Vec<&[u8]> = vec![&buffer[0..1]];
    let valid = ScriptCheckQueue::run_check_with_refs(
        &check,
        &session,
        ctx,
        &refs,
        buffer,
        None,
        Some(&[]),
        Some(&[10_000i64]),
    )
    .unwrap();
    // Exercises spk_offset/spk_len out-of-bounds fallback (empty scriptPubKey slice).
    let _ = valid;
}

#[test]
fn test_checkqueue_add_empty_is_noop() {
    let session = minimal_block_session();
    let queue = ScriptCheckQueue::new(1, Some(4));
    queue.start_session(session);
    queue.add(vec![]);
    let results = queue.complete().unwrap();
    assert!(results.is_empty());
}
