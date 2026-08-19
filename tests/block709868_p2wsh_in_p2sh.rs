//! Regression: block 709868 tx 1632 — P2WSH-in-P2SH must stay WitnessV0 when WITNESS_PUBKEYTYPE (0x8000) is set.
//!
//! Tx `14ac3f7928038189d726b4c34928eab9ecf156a3729af62258582288fda3fb97` has a P2TR
//! output, so step6 ORs 0x8000. Unrelated P2SH inputs must still use WitnessV0 for nested P2WSH.

use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::serialization::deserialize_transaction_with_witness;
use blvm_consensus::types::Network;
use blvm_consensus::witness::is_witness_empty;

const RAW_TX_HEX: &str = "\
02000000000101b0b2cf415030fcf89d66c1a5961b362e910f44904161c3c7dd579a4ae94e9ffe00000000\
23220020587fa5d81851478e23138d9efa1b478cf71a00dbf12b9e44535ca1b648b5b3d8fdffffff02\
bba128010000000017a914684077b2bf62be12a51cbeacae8a0e2c1045284087f283010000000000225120\
72d275233445aa3de9757f28e32bf416589dce4bacd7b2d5a634aab596b8dd300347304402207668d885\
c9117c5b989d8fe1fd8f0fed39244ade4f4a091d3e2fd59100918674022071faf9e59536c96275c20c6\
750bd4f50a4e393c6cb6c9c25923e4b474d13f9b50147304402200e15cd13a818f613fea70bee149cd4d3\
d652ca8491fbb3a2b4e67e54e69a66ea02206b2f708a2c03912d031f827e55f6df63b08021c28248cb7\
adcddb0d08e3e4372014e2103c954e723e2e1e57c5b7dbea2a02bcddaacccd42d6d9b0a7ae9d7eaaebf7\
e921dad2103fee23cf82c5ad7963bf949275b43e1313e9fca5b56a0914321afe2557e957f9bac736403\
80ca00b26894d40a00";

const PREVOUT_SCRIPT_HEX: &str = "a91464db586a9efd2626504dbf561ad01aa2ade498cd87";
const PREVOUT_VALUE: i64 = 19_539_597;
const BLOCK_HEIGHT: u64 = 709_868;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn block709868_p2wsh_in_p2sh_with_witness_pubkeytype_flag() {
    let raw = hex(RAW_TX_HEX);
    let (tx, witnesses, _) = deserialize_transaction_with_witness(&raw).unwrap();
    let prevout_script = hex(PREVOUT_SCRIPT_HEX);
    let witness_stack = witnesses.get(0).filter(|w| !is_witness_empty(w));
    let prevout_values = vec![PREVOUT_VALUE];
    let prevout_scripts: Vec<&[u8]> = vec![&prevout_script];

    // Tx has P2TR output → step6 adds 0x8000 (WITNESS_PUBKEYTYPE)
    let flags_with_p2tr_output = 0x01 | 0x04 | 0x10 | 0x200 | 0x400 | 0x800 | 0x8000 | 0x20000;

    let pass = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &prevout_script,
        witness_stack,
        flags_with_p2tr_output,
        &tx,
        0,
        &prevout_values,
        &prevout_scripts,
        Some(BLOCK_HEIGHT),
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
    )
    .unwrap();
    assert!(
        pass,
        "P2WSH-in-P2SH must pass with WITNESS_PUBKEYTYPE; 0x8000 is not a sigversion selector"
    );
}
