//! COV-C-01: Programmatic connect_block vectors — weight, merkle, spend, multi-input paths.

#[path = "integration/helpers.rs"]
mod helpers;

use bitcoin_hashes::{Hash as BitcoinHash, hash160, sha256, sha256d};
use blvm_consensus::block::{
    BlockValidationContext, calculate_tx_id, compute_block_tx_ids, connect_block,
};
use blvm_consensus::constants::{
    BIP34_ACTIVATION_MAINNET, BIP54_MAX_SIGOPS_PER_TX, BIP65_ACTIVATION_MAINNET,
    BIP66_ACTIVATION_MAINNET, MAX_BLOCK_SIGOPS_COST,
};
use blvm_consensus::economic::get_block_subsidy;
use blvm_consensus::mining::{calculate_merkle_root, compute_merkle_root_and_mutated};
use blvm_consensus::opcodes::*;
use blvm_consensus::segwit::{Witness, compute_witness_merkle_root_from_nested};
use blvm_consensus::taproot::{TAPROOT_LEAF_VERSION_TAPSCRIPT, compute_script_merkle_root};
use blvm_consensus::transaction::calculate_transaction_size;
use blvm_consensus::types::Network;
use blvm_consensus::{
    Bip54BoundaryTimestamps, Block, BlockHeader, OutPoint, SEGWIT_ACTIVATION_MAINNET,
    TAPROOT_ACTIVATION_MAINNET, Transaction, TransactionInput, TransactionOutput, UTXO, UtxoSet,
    ValidationResult,
};
use helpers::{merkle_root_for_tx, per_tx_witnesses, push_data};
use std::sync::Arc;

/// BIP141 witness commitment header bytes (after `OP_RETURN` + `PUSH_36_BYTES`).
const WITNESS_COMMITMENT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

fn ctx() -> BlockValidationContext {
    BlockValidationContext::for_network(Network::Mainnet)
}

fn ctx_bip54_active(activation_height: u64) -> BlockValidationContext {
    BlockValidationContext::from_connect_block_ibd_args(
        None::<&[BlockHeader]>,
        0,
        Network::Mainnet,
        Some(activation_height),
        None,
    )
}

fn ctx_bip54_with_boundary(
    activation_height: u64,
    boundary: Bip54BoundaryTimestamps,
) -> BlockValidationContext {
    BlockValidationContext::from_connect_block_ibd_args(
        None::<&[BlockHeader]>,
        0,
        Network::Mainnet,
        Some(activation_height),
        Some(boundary),
    )
}

fn coinbase_bip54_compliant(height: u64, value: i64) -> Transaction {
    let mut coinbase = coinbase_at_height(height, value);
    coinbase.lock_time = height.saturating_sub(13);
    coinbase.inputs[0].sequence = 0xfffffffe;
    coinbase
}

fn tx_witness_stripped_size_64() -> Transaction {
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x64; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1,
            script_pubkey: vec![OP_1, OP_2, OP_3, OP_4].into(),
        }]
        .into(),
        lock_time: 0,
    };
    assert_eq!(
        calculate_transaction_size(&tx),
        64,
        "BIP54 64-byte fixture must stay exactly 64 bytes stripped"
    );
    tx
}

fn encode_bip34_height(height: u64) -> Vec<u8> {
    if height == 0 {
        return vec![0x00, 0xff];
    }
    let mut height_bytes = Vec::new();
    let mut n = height;
    while n > 0 {
        height_bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    if height_bytes.last().is_some_and(|&b| b & 0x80 != 0) {
        height_bytes.push(0x00);
    }
    let mut script_sig = Vec::with_capacity(1 + height_bytes.len() + 1);
    script_sig.push(height_bytes.len() as u8);
    script_sig.extend_from_slice(&height_bytes);
    if script_sig.len() < 2 {
        script_sig.push(0xff);
    }
    script_sig
}

fn coinbase_value(height: u64, fees: i64) -> i64 {
    get_block_subsidy(height) + fees
}

fn coinbase_at_height(height: u64, value: i64) -> Transaction {
    let script_sig = if height >= BIP34_ACTIVATION_MAINNET {
        encode_bip34_height(height)
    } else if height == 0 {
        vec![OP_1, OP_1]
    } else {
        // Unique per-height scriptSig (avoids duplicate coinbase txid in chain tests).
        vec![OP_1, (height & 0xff) as u8]
    };
    Transaction {
        version: if height >= BIP34_ACTIVATION_MAINNET {
            2
        } else {
            1
        },
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig,
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    }
}

fn block_with_txs(txs: Vec<Transaction>, timestamp: u64) -> Block {
    block_with_txs_at(txs, timestamp, 2)
}

fn block_with_txs_at(txs: Vec<Transaction>, timestamp: u64, version: i64) -> Block {
    let merkle_root = calculate_merkle_root(&txs).expect("merkle root");
    Block {
        header: BlockHeader {
            version,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: txs.into(),
    }
}

fn witness_commitment_script(witness_root: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(witness_root);
    preimage[32..].copy_from_slice(nonce);
    let h = sha256d::Hash::hash(&preimage);
    let mut script = vec![OP_RETURN, PUSH_36_BYTES];
    script.extend_from_slice(&WITNESS_COMMITMENT_MAGIC);
    script.extend_from_slice(&h[..]);
    script
}

fn p2wsh_scriptpubkey(witness_script: &[u8]) -> Vec<u8> {
    let hash = sha256::Hash::hash(witness_script);
    let mut spk = vec![OP_0, PUSH_32_BYTES];
    spk.extend_from_slice(hash.as_ref());
    spk
}

fn p2sh_scriptpubkey(redeem_script: &[u8]) -> Vec<u8> {
    let h = hash160::Hash::hash(redeem_script);
    let mut spk = vec![OP_HASH160, PUSH_20_BYTES];
    spk.extend_from_slice(h.as_ref());
    spk.push(OP_EQUAL);
    spk
}

fn push_redeem_script(script_sig: &mut Vec<u8>, redeem: &[u8]) {
    push_data(script_sig, redeem);
}

fn build_segwit_p2sh_p2wsh_spend_block() -> (Block, Vec<Vec<Witness>>, UtxoSet) {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let witness_script = vec![OP_1];
    let wsh_redeem = p2wsh_scriptpubkey(&witness_script);
    let prevout_spk = p2sh_scriptpubkey(&wsh_redeem);
    let nonce = [0x33u8; 32];
    let timestamp = 1_500_353_985;

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [0x78; 32],
            index: 0,
        },
        Arc::new(UTXO {
            value: 10_000,
            script_pubkey: prevout_spk.into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let fee = 1_000i64;
    let mut script_sig = Vec::new();
    push_redeem_script(&mut script_sig, &wsh_redeem);
    let spend = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x78; 32],
                index: 0,
            },
            script_sig: script_sig.into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 9_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let subsidy = coinbase_value(height, fee);
    let temp_coinbase = coinbase_at_height(height, subsidy);
    let temp_block = block_with_txs_at(vec![temp_coinbase, spend.clone()], timestamp, 4);
    let witnesses = vec![
        vec![vec![nonce.to_vec()]],
        vec![vec![witness_script.clone()]],
    ];
    let witness_root =
        compute_witness_merkle_root_from_nested(&temp_block, &witnesses, None).expect("witness root");

    let mut coinbase = coinbase_at_height(height, subsidy);
    coinbase.outputs = vec![
        TransactionOutput {
            value: subsidy,
            script_pubkey: vec![OP_1].into(),
        },
        TransactionOutput {
            value: 0,
            script_pubkey: witness_commitment_script(&witness_root, &nonce).into(),
        },
    ]
    .into();

    let block = block_with_txs_at(vec![coinbase, spend], timestamp, 4);
    (block, witnesses, utxo_set)
}

fn build_segwit_p2wsh_spend_block() -> (Block, Vec<Vec<Witness>>, UtxoSet) {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let witness_script = vec![OP_1];
    let prevout_spk = p2wsh_scriptpubkey(&witness_script);
    let nonce = [0x22u8; 32];
    let timestamp = 1_500_353_985;

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [0x77; 32],
            index: 0,
        },
        Arc::new(UTXO {
            value: 10_000,
            script_pubkey: prevout_spk.into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let fee = 1_000i64;
    let spend = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x77; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 9_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let subsidy = coinbase_value(height, fee);
    let temp_coinbase = coinbase_at_height(height, subsidy);
    let temp_block = block_with_txs_at(vec![temp_coinbase, spend.clone()], timestamp, 4);
    let witnesses = vec![
        vec![vec![nonce.to_vec()]],
        vec![vec![witness_script.clone()]],
    ];
    let witness_root =
        compute_witness_merkle_root_from_nested(&temp_block, &witnesses, None).expect("witness root");

    let mut coinbase = coinbase_at_height(height, subsidy);
    coinbase.outputs = vec![
        TransactionOutput {
            value: subsidy,
            script_pubkey: vec![OP_1].into(),
        },
        TransactionOutput {
            value: 0,
            script_pubkey: witness_commitment_script(&witness_root, &nonce).into(),
        },
    ]
    .into();

    let block = block_with_txs_at(vec![coinbase, spend], timestamp, 4);
    (block, witnesses, utxo_set)
}

fn valid_taproot_internal_key() -> [u8; 32] {
    [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ]
}

fn build_taproot_script_path_spend_block() -> (Block, Vec<Vec<Witness>>, UtxoSet) {
    let height = TAPROOT_ACTIVATION_MAINNET;
    let internal = valid_taproot_internal_key();
    let tapscript = vec![OP_1];
    let merkle_root =
        compute_script_merkle_root(&tapscript, &[], TAPROOT_LEAF_VERSION_TAPSCRIPT).expect("root");
    let (output_key, parity) =
        blvm_consensus::secp256k1_backend::taproot_output_key_with_parity(&internal, &merkle_root)
            .expect("taproot tweak");
    let mut prevout_spk = vec![OP_1, PUSH_32_BYTES];
    prevout_spk.extend_from_slice(&output_key);

    let mut control_block = vec![TAPROOT_LEAF_VERSION_TAPSCRIPT | parity];
    control_block.extend_from_slice(&internal);

    let nonce = [0x44u8; 32];
    let timestamp = 1_500_353_985;

    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [0x79; 32],
            index: 0,
        },
        Arc::new(UTXO {
            value: 10_000,
            script_pubkey: prevout_spk.into(),
            height: 0,
            is_coinbase: false,
        }),
    );

    let fee = 1_000i64;
    let spend = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x79; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 9_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let subsidy = coinbase_value(height, fee);
    let temp_coinbase = coinbase_at_height(height, subsidy);
    let temp_block = block_with_txs_at(vec![temp_coinbase, spend.clone()], timestamp, 4);
    let witnesses = vec![
        vec![vec![nonce.to_vec()]],
        vec![vec![tapscript.clone(), control_block]],
    ];
    let witness_root =
        compute_witness_merkle_root_from_nested(&temp_block, &witnesses, None).expect("witness root");

    let mut coinbase = coinbase_at_height(height, subsidy);
    coinbase.outputs = vec![
        TransactionOutput {
            value: subsidy,
            script_pubkey: vec![OP_1].into(),
        },
        TransactionOutput {
            value: 0,
            script_pubkey: witness_commitment_script(&witness_root, &nonce).into(),
        },
    ]
    .into();

    let block = block_with_txs_at(vec![coinbase, spend], timestamp, 4);
    (block, witnesses, utxo_set)
}

fn build_segwit_witness_block(invalid_commitment: bool) -> (Block, Vec<Vec<Witness>>) {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let nonce = [0x11u8; 32];
    let subsidy = coinbase_value(height, 0);
    let coinbase = coinbase_at_height(height, subsidy);
    let witnesses: Vec<Vec<Witness>> = vec![vec![vec![nonce.to_vec()]]];
    let temp_block = block_with_txs_at(vec![coinbase.clone()], 1_500_353_985, 4);
    let witness_root =
        compute_witness_merkle_root_from_nested(&temp_block, &witnesses, None).expect("witness root");
    let commitment_spk = if invalid_commitment {
        witness_commitment_script(&[0xff; 32], &nonce)
    } else {
        witness_commitment_script(&witness_root, &nonce)
    };
    let mut coinbase = coinbase_at_height(height, subsidy);
    coinbase.outputs = vec![
        TransactionOutput {
            value: subsidy,
            script_pubkey: vec![OP_1].into(),
        },
        TransactionOutput {
            value: 0,
            script_pubkey: commitment_spk.into(),
        },
    ]
    .into();
    let block = block_with_txs_at(vec![coinbase], 1_500_353_985, 4);
    (block, witnesses)
}

fn seed_op1_utxo(set: &mut UtxoSet, hash_byte: u8, value: i64, height: u64) {
    set.insert(
        OutPoint {
            hash: [hash_byte; 32],
            index: 0,
        },
        Arc::new(UTXO {
            value,
            script_pubkey: vec![OP_1].into(),
            height,
            is_coinbase: false,
        }),
    );
}

fn spend_tx(prevout_byte: u8, _input_value: i64, output_value: i64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [prevout_byte; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: output_value,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    }
}

fn spend_tx_duplicate_inputs(prevout_byte: u8, output_value: i64) -> Transaction {
    let prevout = OutPoint {
        hash: [prevout_byte; 32],
        index: 0,
    };
    Transaction {
        version: 1,
        inputs: vec![
            TransactionInput {
                prevout: prevout.clone(),
                script_sig: vec![OP_1].into(),
                sequence: 0xffffffff,
            },
            TransactionInput {
                prevout,
                script_sig: vec![OP_1].into(),
                sequence: 0xffffffff,
            },
        ]
        .into(),
        outputs: vec![TransactionOutput {
            value: output_value,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    }
}

fn connect(
    block: &Block,
    utxo_set: UtxoSet,
    height: u64,
) -> blvm_consensus::error::Result<(
    ValidationResult,
    UtxoSet,
    blvm_consensus::reorganization::BlockUndoLog,
)> {
    connect_with_ctx(block, utxo_set, height, &ctx())
}

fn connect_with_ctx(
    block: &Block,
    utxo_set: UtxoSet,
    height: u64,
    validation_ctx: &BlockValidationContext,
) -> blvm_consensus::error::Result<(
    ValidationResult,
    UtxoSet,
    blvm_consensus::reorganization::BlockUndoLog,
)> {
    connect_block(
        block,
        &per_tx_witnesses(block),
        utxo_set,
        height,
        validation_ctx,
    )
}

fn connect_with_witnesses(
    block: &Block,
    witnesses: &[Vec<Witness>],
    utxo_set: UtxoSet,
    height: u64,
) -> blvm_consensus::error::Result<(
    ValidationResult,
    UtxoSet,
    blvm_consensus::reorganization::BlockUndoLog,
)> {
    connect_block(block, witnesses, utxo_set, height, &ctx())
}

fn connect_with_witnesses_and_ctx(
    block: &Block,
    witnesses: &[Vec<Witness>],
    utxo_set: UtxoSet,
    height: u64,
    validation_ctx: &BlockValidationContext,
) -> blvm_consensus::error::Result<(
    ValidationResult,
    UtxoSet,
    blvm_consensus::reorganization::BlockUndoLog,
)> {
    connect_block(block, witnesses, utxo_set, height, validation_ctx)
}

#[test]
fn test_connect_valid_coinbase_height_1() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(matches!(result, ValidationResult::Valid));
}

#[test]
fn test_connect_rejects_empty_block() {
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1_231_006_505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![].into(),
    };
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("no transactions")),
        "empty block must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_bad_merkle_root() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let mut block = block_with_txs(vec![coinbase], 1_231_006_505);
    block.header.merkle_root = [0xff; 32];
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_rejects_block_weight_exceeded() {
    let height = 1u64;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let mut huge_script = vec![OP_RETURN];
    push_data(&mut huge_script, &vec![0u8; 1_100_000]);
    let bloat_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0xee; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 0,
            script_pubkey: huge_script.into(),
        }]
        .into(),
        lock_time: 0,
    };
    let block = block_with_txs(vec![coinbase, bloat_tx], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("weight")),
        "expected weight rejection, got {result:?}"
    );
}

#[test]
fn test_connect_valid_spend_from_utxo() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0x42, 10_000, 0);

    let fee = 10_000 - 9_000;
    let coinbase = coinbase_at_height(1, coinbase_value(1, fee));
    let spend = spend_tx(0x42, 10_000, 9_000);
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, new_set, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "OP_1 spend block should connect: {result:?}"
    );
    assert!(!new_set.is_empty());
}

#[test]
fn test_connect_rejects_spend_without_utxo() {
    let fee = 10_000 - 9_000;
    let coinbase = coinbase_at_height(1, coinbase_value(1, fee));
    let spend = spend_tx(0x99, 10_000, 9_000);
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_two_block_chain() {
    let coinbase1 = coinbase_at_height(1, coinbase_value(1, 0));
    let block1 = block_with_txs(vec![coinbase1], 1_231_006_505);
    let (r1, utxo1, _) = connect(&block1, UtxoSet::default(), 1).unwrap();
    assert!(matches!(r1, ValidationResult::Valid));
    let utxo1_len = utxo1.len();

    let coinbase2 = coinbase_at_height(2, coinbase_value(2, 0));
    let mut block2 = block_with_txs(vec![coinbase2], 1_231_006_506);
    block2.header.prev_block_hash = merkle_root_for_tx(&block1.transactions[0]);

    let (r2, utxo2, _) = connect(&block2, utxo1, 2).unwrap();
    assert!(matches!(r2, ValidationResult::Valid));
    assert!(utxo2.len() >= utxo1_len);
}

#[test]
fn test_connect_multi_input_block_35_inputs() {
    let mut utxo_set = UtxoSet::default();
    for i in 1u8..=35 {
        seed_op1_utxo(&mut utxo_set, i, 10_000, 0);
    }

    let fee_per_spend = 10_000 - 9_000;
    let total_fees = fee_per_spend * 35;
    let coinbase = coinbase_at_height(1, coinbase_value(1, total_fees));
    let mut txs = vec![coinbase];
    for i in 1u8..=35 {
        txs.push(spend_tx(i, 10_000, 9_000));
    }
    let block = block_with_txs(txs, 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "35-input block should connect (exercises parallel script path): {result:?}"
    );
}

#[test]
fn test_connect_bip34_compliant_at_activation() {
    let height = BIP34_ACTIVATION_MAINNET;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "BIP34-encoded coinbase at activation height should connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip34_at_activation() {
    let height = BIP34_ACTIVATION_MAINNET;
    let mut coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    coinbase.inputs[0].script_sig = vec![OP_1, OP_1].into();
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let result = connect(&block, UtxoSet::default(), height);
    match result {
        Ok((ValidationResult::Invalid(ref r), _, _)) => {
            assert!(
                r.contains("BIP34") || r.contains("height") || r.contains("coinbase"),
                "expected BIP34 rejection, got {r}"
            );
        }
        Err(_) => {} // scriptSig height parse error is also a rejection
        Ok((ValidationResult::Valid, _, _)) => {
            panic!("BIP34 violation must not connect at activation height");
        }
    }
}

#[test]
fn test_connect_rejects_bip90_version_at_bip34() {
    let height = BIP34_ACTIVATION_MAINNET;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let mut block = block_with_txs(vec![coinbase], 1_231_006_505);
    block.header.version = 1;
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("BIP90")),
        "expected BIP90 rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_coinbase_over_subsidy() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0) + 1);
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("subsidy") || r.contains("Coinbase output")),
        "expected coinbase subsidy rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_spend_exceeds_input_value() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0x55, 1_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let spend = spend_tx(0x55, 1_000, 2_000);
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_rejects_non_coinbase_first_tx() {
    let spend = spend_tx(0x01, 10_000, 9_000);
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    // Coinbase must be first — swap order deliberately.
    let block = block_with_txs(vec![spend, coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_connect_valid_segwit_witness_commitment() {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let (block, witnesses) = build_segwit_witness_block(false);
    let (result, _, _) =
        connect_with_witnesses(&block, &witnesses, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "SegWit block with valid witness commitment should connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_invalid_witness_commitment() {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let (block, witnesses) = build_segwit_witness_block(true);
    let (result, _, _) =
        connect_with_witnesses(&block, &witnesses, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("witness commitment")),
        "expected witness commitment rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_coinbase_scriptsig_too_short() {
    let mut coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    coinbase.inputs[0].script_sig = vec![OP_1].into();
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("scriptSig")),
        "expected coinbase scriptSig length rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_coinbase_scriptsig_too_long() {
    let mut coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    coinbase.inputs[0].script_sig = vec![OP_1; 101].into();
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("scriptSig")),
        "expected coinbase scriptSig too long rejection, got {result:?}"
    );
}

fn high_sigop_scriptpubkey(sigops: usize) -> Vec<u8> {
    vec![OP_CHECKSIG; sigops]
}

#[cfg(all(feature = "production", feature = "rayon"))]
#[test]
fn test_connect_with_script_exec_cache_enabled() {
    // Cache lookup in connect_block requires segwit_active (post-activation height + spend tx).
    unsafe { std::env::set_var("BLVM_SCRIPT_EXEC_CACHE", "1") };
    let height = SEGWIT_ACTIVATION_MAINNET;
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0x7e, 10_000, 0);

    let fee = 1_000i64;
    let coinbase = coinbase_at_height(height, coinbase_value(height, fee));
    let spend = spend_tx(0x7e, 10_000, 9_000);
    let block = block_with_txs_at(vec![coinbase, spend], 1_500_353_985, 4);

    let (r1, _, _) = connect(&block, utxo_set.clone(), height).unwrap();
    assert!(
        matches!(r1, ValidationResult::Valid),
        "first connect: {r1:?}"
    );
    let (r2, _, _) = connect(&block, utxo_set, height).unwrap();
    assert!(
        matches!(r2, ValidationResult::Valid),
        "cached replay: {r2:?}"
    );
    unsafe { std::env::remove_var("BLVM_SCRIPT_EXEC_CACHE") };
}

#[test]
fn test_connect_rejects_block_sigop_cost_exceeded() {
    // Coinbase output sigops are counted without executing the script (no signature checks).
    let sigops = (MAX_BLOCK_SIGOPS_COST / 4) as usize + 1;
    let height = 1u64;
    let value = coinbase_value(height, 0);
    let mut coinbase = coinbase_at_height(height, value);
    coinbase.outputs = vec![TransactionOutput {
        value,
        script_pubkey: high_sigop_scriptpubkey(sigops).into(),
    }]
    .into();
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("sigop cost")),
        "expected sigop limit rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip66_version_at_activation() {
    let height = BIP66_ACTIVATION_MAINNET;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let block = block_with_txs_at(vec![coinbase], 1_500_353_985, 2);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("BIP90")),
        "expected BIP90/BIP66 version rejection, got {result:?}"
    );
}

#[test]
fn test_connect_accepts_bip66_version_at_activation() {
    let height = BIP66_ACTIVATION_MAINNET;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let block = block_with_txs_at(vec![coinbase], 1_500_353_985, 3);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "version 3 at BIP66 height should connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_duplicate_inputs_in_tx() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0x44, 5_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let spend = spend_tx_duplicate_inputs(0x44, 4_000);
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);
    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "duplicate prevouts in one tx must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_merkle_mutation_cve() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let spend = spend_tx(0x66, 1_000, 900);
    // Duplicate txids must sit at paired leaf indices (1,2) and (2,3) for mutation detection.
    let txs = vec![coinbase, spend.clone(), spend.clone(), spend];
    let temp_block = Block {
        header: BlockHeader {
            version: 2,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1_231_006_505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: txs.clone().into(),
    };
    let tx_ids = compute_block_tx_ids(&temp_block);
    let (merkle_root, mutated) = compute_merkle_root_and_mutated(&tx_ids).expect("merkle");
    assert!(
        mutated,
        "duplicate txids at paired leaves should flag merkle mutation"
    );
    let block = Block {
        header: BlockHeader {
            version: 2,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1_231_006_505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: txs.into(),
    };
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("CVE-2012-2459")),
        "expected CVE-2012-2459 rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip65_version_at_activation() {
    let height = BIP65_ACTIVATION_MAINNET;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let block = block_with_txs_at(vec![coinbase], 1_500_353_985, 3);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("BIP90")),
        "expected BIP90/BIP65 version rejection, got {result:?}"
    );
}

#[test]
fn test_connect_accepts_bip65_version_at_activation() {
    let height = BIP65_ACTIVATION_MAINNET;
    let coinbase = coinbase_at_height(height, coinbase_value(height, 0));
    let block = block_with_txs_at(vec![coinbase], 1_500_353_985, 4);
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "version 4 at BIP65 height should connect: {result:?}"
    );
}

#[test]
fn test_connect_accepts_bip54_compliant_coinbase() {
    let activation = 100u64;
    let height = 500u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let ctx = ctx_bip54_active(activation);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "BIP54-compliant coinbase should connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip54_coinbase_locktime() {
    let activation = 100u64;
    let height = 500u64;
    let mut coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    coinbase.lock_time = 0;
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let ctx = ctx_bip54_active(activation);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("BIP54")),
        "expected BIP54 coinbase rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip54_64_byte_tx() {
    let activation = 100u64;
    let height = 500u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let bad_tx = tx_witness_stripped_size_64();
    let block = block_with_txs(vec![coinbase, bad_tx], 1_231_006_505);
    let ctx = ctx_bip54_active(activation);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("64 bytes")),
        "expected BIP54 64-byte tx rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip54_sigop_limit() {
    let activation = 100u64;
    let height = 500u64;
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0x54, 10_000, 0);

    let sigops = (BIP54_MAX_SIGOPS_PER_TX + 1) as usize;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 1_000));
    let mut spend = spend_tx(0x54, 10_000, 8_000);
    spend.outputs = vec![TransactionOutput {
        value: 8_000,
        script_pubkey: high_sigop_scriptpubkey(sigops).into(),
    }]
    .into();
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);
    let ctx = ctx_bip54_active(activation);
    let (result, _, _) = connect_with_ctx(&block, utxo_set, height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("BIP54") && r.contains("sigop")),
        "expected BIP54 sigop rejection, got {result:?}"
    );
}

#[test]
fn test_connect_rejects_script_verification_failure() {
    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: [0xfa; 32],
            index: 0,
        },
        Arc::new(UTXO {
            value: 10_000,
            script_pubkey: vec![OP_0].into(), // OP_0 — leaves false on stack after OP_1 scriptSig
            height: 0,
            is_coinbase: false,
        }),
    );

    let fee = 1_000i64;
    let coinbase = coinbase_at_height(1, coinbase_value(1, fee));
    let spend = spend_tx(0xfa, 10_000, 9_000);
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "script failure must reject block connect: {result:?}"
    );
}

#[test]
fn test_connect_valid_p2wsh_spend_with_witness_commitment() {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let (block, witnesses, utxo_set) = build_segwit_p2wsh_spend_block();
    let (result, new_set, _) =
        connect_with_witnesses(&block, &witnesses, utxo_set, height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "P2WSH spend with valid witness commitment should connect: {result:?}"
    );
    assert!(!new_set.is_empty());
}

#[test]
fn test_connect_valid_p2sh_p2wsh_nested_spend() {
    let height = SEGWIT_ACTIVATION_MAINNET;
    let (block, witnesses, utxo_set) = build_segwit_p2sh_p2wsh_spend_block();
    let (result, new_set, _) =
        connect_with_witnesses(&block, &witnesses, utxo_set, height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "nested P2SH→P2WSH spend should connect: {result:?}"
    );
    assert!(!new_set.is_empty());
}

#[test]
fn test_connect_rejects_negative_fee() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0xfb, 1_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let mut spend = spend_tx(0xfb, 1_000, 2_000);
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Negative fee") || r.contains("input")),
        "spend exceeding input value must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_tx_without_outputs() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0xfc, 1_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let mut spend = spend_tx(0xfc, 1_000, 500);
    spend.outputs = vec![].into();
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "tx without outputs must not connect: {result:?}"
    );
}

#[test]
fn test_connect_valid_taproot_script_path_spend() {
    let height = TAPROOT_ACTIVATION_MAINNET;
    let (block, witnesses, utxo_set) = build_taproot_script_path_spend_block();
    let (result, new_set, _) =
        connect_with_witnesses(&block, &witnesses, utxo_set, height).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "Taproot script-path OP_TRUE spend should connect: {result:?}"
    );
    assert!(!new_set.is_empty());
}

#[test]
fn test_connect_rejects_negative_output_value() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0xfd, 1_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let mut spend = spend_tx(0xfd, 1_000, 500);
    spend.outputs[0].value = -1;
    let block = block_with_txs(vec![coinbase, spend], 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Invalid output") || r.contains("output")),
        "negative output value must not connect: {result:?}"
    );
}

#[test]
fn test_bip54_sigop_count_exceeds_limit() {
    let sigops = (BIP54_MAX_SIGOPS_PER_TX + 1) as usize;
    let mut spend = spend_tx(0x54, 10_000, 8_000);
    spend.outputs = vec![TransactionOutput {
        value: 8_000,
        script_pubkey: high_sigop_scriptpubkey(sigops).into(),
    }]
    .into();
    let count = blvm_consensus::sigop::get_transaction_sigop_count_for_bip54(
        &spend,
        &UtxoSet::default(),
        None,
        0,
    )
    .expect("sigop count");
    assert!(
        count > BIP54_MAX_SIGOPS_PER_TX,
        "expected >2500 sigops for BIP54 fixture, got {count}"
    );
}

#[test]
fn test_connect_rejects_duplicate_txid_cve_2012_2459() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0xfe, 5_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let spend = spend_tx(0xfe, 5_000, 4_000);
    let duplicate_a = spend.clone();
    let duplicate_b = spend.clone();

    let txs = vec![coinbase, duplicate_a, duplicate_b, spend.clone()];
    let tx_ids: Vec<[u8; 32]> = txs.iter().map(calculate_tx_id).collect();
    let (merkle_root, mutated) = compute_merkle_root_and_mutated(&tx_ids).expect("merkle root");
    assert!(mutated, "duplicate txids must flag merkle mutation");

    let block = Block {
        header: BlockHeader {
            version: 2,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp: 1_231_006_505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: txs.into(),
    };

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(
            result,
            ValidationResult::Invalid(ref r)
                if r.contains("Duplicate transaction") || r.contains("CVE-2012-2459")
        ),
        "duplicate txid block must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_coinbase_with_inputs() {
    let mut bad_coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    bad_coinbase.inputs = vec![TransactionInput {
        prevout: OutPoint {
            hash: [0x01; 32],
            index: 0,
        },
        script_sig: vec![OP_1].into(),
        sequence: 0xffffffff,
    }]
    .into();
    let block = block_with_txs(vec![bad_coinbase], 1_231_006_505);

    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "coinbase with non-null prevout must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_double_spend_in_block() {
    let mut utxo_set = UtxoSet::default();
    seed_op1_utxo(&mut utxo_set, 0x55, 5_000, 0);

    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let spend_a = spend_tx(0x55, 5_000, 3_000);
    let spend_b = spend_tx(0x55, 5_000, 2_000);
    let block = block_with_txs(vec![coinbase, spend_a, spend_b], 1_231_006_505);

    let (result, _, _) = connect(&block, utxo_set, 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "double spend of same prevout in one block must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_invalid_header_timestamp_zero() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let block = block_with_txs(vec![coinbase], 0);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Invalid block header") || r.contains("header")),
        "timestamp=0 block must fail header validation: {result:?}"
    );
}

#[test]
fn test_connect_rejects_header_version_zero() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let mut block = block_with_txs(vec![coinbase], 1_231_006_505);
    block.header.version = 0;
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "version=0 header must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_header_bits_zero() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let mut block = block_with_txs(vec![coinbase], 1_231_006_505);
    block.header.bits = 0;
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "bits=0 header must not connect: {result:?}"
    );
}

#[test]
fn test_connect_rejects_witness_row_count_mismatch() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let bad_witnesses = [vec![Witness::default()], vec![Witness::default()]];
    let (result, _, _) =
        connect_with_witnesses(&block, &bad_witnesses, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Witness count")),
        "witness row mismatch must fail: {result:?}"
    );
}

#[test]
fn test_connect_rejects_block_height_overflow() {
    let coinbase = coinbase_at_height(1, coinbase_value(1, 0));
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let height = i64::MAX as u64 + 1;
    let (result, _, _) = connect(&block, UtxoSet::default(), height).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("height")),
        "height overflow must fail: {result:?}"
    );
}

#[test]
fn test_connect_rejects_coinbase_output_exceeds_max_money() {
    use blvm_consensus::constants::MAX_MONEY;
    let coinbase = coinbase_at_height(1, MAX_MONEY + 1);
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r)
            if r.contains("maximum money")
                || r.contains("Coinbase output")
                || r.contains("Invalid output value")),
        "coinbase above MAX_MONEY must fail: {result:?}"
    );
}

#[test]
fn test_connect_rejects_coinbase_outputs_sum_overflow() {
    let subsidy = coinbase_value(1, 0);
    let mut coinbase = coinbase_at_height(1, subsidy);
    coinbase.outputs = vec![
        TransactionOutput {
            value: subsidy / 2,
            script_pubkey: vec![OP_1].into(),
        },
        TransactionOutput {
            value: subsidy - subsidy / 2 + 1,
            script_pubkey: vec![OP_1].into(),
        },
    ]
    .into();
    let block = block_with_txs(vec![coinbase], 1_231_006_505);
    let (result, _, _) = connect(&block, UtxoSet::default(), 1).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r)
            if r.contains("exceeds fees") || r.contains("subsidy") || r.contains("Coinbase output")),
        "coinbase output above subsidy must fail: {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip54_period_end_without_boundary_timestamps() {
    let activation = 0u64;
    let height = 2015u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let mut block = block_with_txs(vec![coinbase], 1_600_000_000);
    block.header.timestamp = 1_600_000_000;
    let ctx = ctx_bip54_active(activation);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Timewarp")),
        "period-end block without boundary data must fail: {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip54_period_end_timestamp_before_first_of_period() {
    let activation = 0u64;
    let height = 2015u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let mut block = block_with_txs(vec![coinbase], 1_000_000);
    block.header.timestamp = 1_000_000;
    let boundary = Bip54BoundaryTimestamps {
        timestamp_n_minus_1: 1_500_000,
        timestamp_n_minus_2015: 1_200_000,
    };
    let ctx = ctx_bip54_with_boundary(activation, boundary);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Timewarp")),
        "timestamp before period start must fail: {result:?}"
    );
}

#[test]
fn test_connect_rejects_bip54_period_start_timestamp_too_early() {
    let activation = 0u64;
    let height = 2016u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let mut block = block_with_txs(vec![coinbase], 1_000_000);
    block.header.timestamp = 1_000_000;
    let boundary = Bip54BoundaryTimestamps {
        timestamp_n_minus_1: 1_500_000,
        timestamp_n_minus_2015: 1_200_000,
    };
    let ctx = ctx_bip54_with_boundary(activation, boundary);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Invalid(ref r) if r.contains("Timewarp")),
        "period-start timestamp timewarp violation must fail: {result:?}"
    );
}

#[test]
fn test_connect_accepts_bip54_period_start_with_valid_boundary() {
    let activation = 0u64;
    let height = 2016u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let mut block = block_with_txs(vec![coinbase], 1_493_000);
    block.header.timestamp = 1_493_000;
    let boundary = Bip54BoundaryTimestamps {
        timestamp_n_minus_1: 1_500_000,
        timestamp_n_minus_2015: 1_200_000,
    };
    let ctx = ctx_bip54_with_boundary(activation, boundary);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "valid period-start boundary should connect: {result:?}"
    );
}

#[test]
fn test_connect_accepts_bip54_period_end_with_valid_boundary() {
    let activation = 0u64;
    let height = 2015u64;
    let coinbase = coinbase_bip54_compliant(height, coinbase_value(height, 0));
    let mut block = block_with_txs(vec![coinbase], 1_300_000);
    block.header.timestamp = 1_300_000;
    let boundary = Bip54BoundaryTimestamps {
        timestamp_n_minus_1: 1_500_000,
        timestamp_n_minus_2015: 1_200_000,
    };
    let ctx = ctx_bip54_with_boundary(activation, boundary);
    let (result, _, _) = connect_with_ctx(&block, UtxoSet::default(), height, &ctx).unwrap();
    assert!(
        matches!(result, ValidationResult::Valid),
        "valid period-end boundary should connect: {result:?}"
    );
}
