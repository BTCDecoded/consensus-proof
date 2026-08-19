//! Regression: block 709635 — P2TR key-path with 65-byte witness (64-byte Schnorr + SIGHASH_ALL).
//!
//! On-chain tx `83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82`
//! (block 709635, tx index 31, inputs 0–3). Post-Taproot activation coinjoin.

use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::serialization::deserialize_transaction_with_witness;
use blvm_consensus::types::Network;
use blvm_consensus::witness::is_witness_empty;

const RAW_TX_HEX: &str = "\
020000000001041ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890000000000\
ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890100000000\
ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890200000000\
ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890300000000\
ffffffff01007ea60000000000225120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d\
0141b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b\
3dc778082fd38a9e06a1139e6eea41a8680c7010141be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748\
fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed010141466d525b977\
33d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe580\
7a1cba03a46bf3a7087e940101418dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b\
9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf90100000000";

const PREVOUT_SCRIPTS_HEX: [&str; 4] = [
    "51205f4237bd79e8fe440d102a5e0c20a75160e96d42a8b19825ac90f73f1f667768",
    "5120e914be846f7afb29f5c3b24e5f630886ed5cbcc79a28888d91009be90924508d",
    "5120d9390cafa11bdeb19de21e0a2bbd541f4d0979473999503408d40814399b7f91",
    "5120e8d645f42be8700595c7cbb278602fb51471d5bb24ccd27668321b7affd167bf",
];
const PREVOUT_VALUES: [i64; 4] = [3_400_000, 3_410_000, 3_420_000, 709_632];
const BLOCK_HEIGHT: u64 = 709_635;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn block709635_p2tr_keypath_65_byte_witness_passes() {
    let raw = hex(RAW_TX_HEX);
    let (tx, witnesses, _) =
        deserialize_transaction_with_witness(&raw).expect("deserialize segwit tx");
    assert_eq!(tx.inputs.len(), 4);
    assert_eq!(witnesses.len(), 4);

    let prevout_scripts_owned: Vec<Vec<u8>> = PREVOUT_SCRIPTS_HEX.iter().map(|s| hex(s)).collect();
    // step6-like flags @ 709635: buried forks + WITNESS + WITNESS_PUBKEYTYPE + TAPROOT
    let flags = 0x01 | 0x04 | 0x10 | 0x200 | 0x400 | 0x800 | 0x8000 | 0x20000;

    let prevout_values: Vec<i64> = PREVOUT_VALUES.to_vec();
    let prevout_scripts: Vec<&[u8]> = prevout_scripts_owned.iter().map(|s| s.as_slice()).collect();

    for input_idx in 0..4 {
        let witness_stack = witnesses.get(input_idx).filter(|w| !is_witness_empty(w));
        assert!(
            witness_stack.is_some(),
            "input {input_idx} must have witness"
        );
        assert_eq!(
            witness_stack.unwrap()[0].len(),
            65,
            "input {input_idx}: expected 64-byte sig + SIGHASH_ALL suffix"
        );

        let ok = verify_script_with_context_full(
            &tx.inputs[input_idx].script_sig,
            &prevout_scripts_owned[input_idx],
            witness_stack,
            flags,
            &tx,
            input_idx,
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
        .expect("verify ok");
        assert!(
            ok,
            "block 709635 P2TR key-path input {input_idx} must pass after Taproot fix"
        );
    }
}

#[test]
fn parse_taproot_schnorr_witness_sig_accepts_64_and_65_bytes() {
    use blvm_consensus::bip348::try_parse_taproot_schnorr_witness_sig;

    let sig64 = [0x42u8; 64];
    let (parsed, ty) = try_parse_taproot_schnorr_witness_sig(&sig64).unwrap();
    assert_eq!(parsed, sig64);
    assert_eq!(ty, 0x00);

    let mut sig65 = sig64.to_vec();
    sig65.push(0x01);
    let (parsed65, ty65) = try_parse_taproot_schnorr_witness_sig(&sig65).unwrap();
    assert_eq!(parsed65, sig64);
    assert_eq!(ty65, 0x01);

    let mut bad = sig64.to_vec();
    bad.push(0x00);
    assert!(try_parse_taproot_schnorr_witness_sig(&bad).is_none());
}
