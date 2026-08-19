//! Regression: block 909068 tx 1 input 0 — P2TR script-path with annex and max-size control block.
//! Core accepts; BLVM must return Ok(true).

use blvm_consensus::block::get_block_script_verify_flags_core;
use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::serialization::transaction::deserialize_transaction_with_witness;
use blvm_consensus::taproot::parse_taproot_script_path_witness;
use blvm_consensus::types::Network;
use blvm_consensus::witness::is_witness_empty;

const RAW_TX_HEX: &str = include_str!("fixtures/block909068_tx1.hex");

#[test]
fn block909068_tapscript_annex_input0() {
    let raw = hex::decode(RAW_TX_HEX.trim()).expect("hex");
    let (tx, witnesses, _) =
        deserialize_transaction_with_witness(&raw).expect("deserialize tx with witness");

    let input_idx = 0usize;
    let height = 909068u64;
    let spk = hex::decode("5120b7565f7bef476efd587ec41ce9531302b584eedad73fa214fe644b31c1d612c8")
        .unwrap();
    let prevout_values = [338089i64];
    let prevout_scripts: Vec<&[u8]> = vec![&spk];

    let witness = witnesses.get(input_idx).expect("witness vector");
    assert_eq!(
        witness.len(),
        4,
        "expected annex + max control witness size"
    );

    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&spk[2..34]);
    let (witness_body, annex_hash) = blvm_consensus::taproot::strip_taproot_annex(witness);
    assert!(annex_hash.is_some(), "annex must be present");
    let parsed = parse_taproot_script_path_witness(&witness_body, &output_key)
        .expect("parse")
        .expect("script-path parse should succeed");
    let (tapscript, stack_items, control) = parsed;
    assert_eq!(tapscript.len(), 34);
    assert_eq!(stack_items.len(), 1);
    assert_eq!(control.merkle_proof.len(), 128);

    let witness_stack = witnesses.get(input_idx).filter(|w| !is_witness_empty(w));
    let flags = get_block_script_verify_flags_core(
        &[0u8; 32],
        height,
        &blvm_consensus::activation::ForkActivationTable::from_network(Network::Mainnet),
        Network::Mainnet,
    );

    let r = verify_script_with_context_full(
        &tx.inputs[input_idx].script_sig,
        &spk,
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
    assert_eq!(
        r,
        Ok(true),
        "P2TR script-path with annex must verify: {:?}",
        r
    );
}
