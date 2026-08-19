//! Regression: block 859672 tx 2129 input 1 — Ordinals P2TR script-path (229 witness elements).
//! Core accepts; BLVM must return Ok(true).

use blvm_consensus::block::get_block_script_verify_flags_core;
use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::serialization::transaction::deserialize_transaction_with_witness;
use blvm_consensus::taproot::parse_taproot_script_path_witness;
use blvm_consensus::types::Network;
use blvm_consensus::witness::is_witness_empty;

const RAW_TX_HEX: &str = include_str!("fixtures/block859672_tx2129.hex");

#[test]
fn block859672_ordinals_tapscript_input1() {
    let raw = hex::decode(RAW_TX_HEX.trim()).expect("hex");
    let (tx, witnesses, _) =
        deserialize_transaction_with_witness(&raw).expect("deserialize tx with witness");

    let input_idx = 1usize;
    let height = 859672u64;
    let spk0 = hex::decode("0020ac1c7e41f1194d65df6b42f23d32441f5460e7aafd44e949bebb4c50af121f5a")
        .unwrap();
    let spk1 = hex::decode("51202c62873d5fb6bdaac81f8a783f6b1c43869a615db9326d3a2bda0bb258e4d27b")
        .unwrap();
    let prevout_values = [1000i64, 11000];
    let prevout_scripts: Vec<&[u8]> = vec![&spk0, &spk1];

    let witness = witnesses.get(input_idx).expect("witness vector");
    assert_eq!(
        witness.len(),
        229,
        "expected Ordinals envelope witness size"
    );

    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&spk1[2..34]);
    let parsed = parse_taproot_script_path_witness(witness, &output_key)
        .expect("parse")
        .expect("script-path parse should succeed");
    let (tapscript, stack_items, _cb) = parsed;
    eprintln!(
        "tapscript len={}, stack_items={}, tapscript opcodes~{}",
        tapscript.len(),
        stack_items.len(),
        tapscript.len()
    );

    let witness_stack = witnesses.get(input_idx).filter(|w| !is_witness_empty(w));
    let flags = get_block_script_verify_flags_core(
        &[0u8; 32],
        height,
        &blvm_consensus::activation::ForkActivationTable::from_network(Network::Mainnet),
        Network::Mainnet,
    );

    let r = verify_script_with_context_full(
        &tx.inputs[input_idx].script_sig,
        &spk1,
        witness_stack,
        flags,
        &tx,
        input_idx,
        &prevout_values,
        &prevout_scripts,
        Some(height),
        None,
        Network::Mainnet,
        SigVersion::Base,
        None,
        None,
        None,
        None,
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );
    assert_eq!(r, Ok(true), "Ordinals tapscript spend must verify: {:?}", r);
}
