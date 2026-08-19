//! Regression: block 659901 — P2SH conditional IF/SHA256/ELSE CLTV with nLockTime=0.
//!
//! On-chain tx `a214903085c7e4c45d66dee064e6a7a04d793a83afa1cd626bb44bab39a918a8`
//! (block 659901, tx index 1389, input 0). Sort-merge step6 logged "Script returned false".
//!
//! Redeem (89 bytes, hash160 = abb29eac…299):
//!   IF SHA256(<hash>) EQUALVERIFY DUP HASH160 <pkh1> ELSE 0 CLTV DROP DUP HASH160 <pkh2> ENDIF
//!   EQUALVERIFY CHECKSIG
//!
//! scriptSig pushes sig, pubkey, OP_0 (take ELSE), then redeemScript.
//! Tx nLockTime=0 and CLTV stack value OP_0 → Core CheckLockTime(0) passes; BLVM wrongly
//! required tx_locktime != 0 in check_bip65 (fixed in locktime.rs).

#[path = "integration/helpers.rs"]
mod helpers;

use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::types::Network;
use blvm_consensus::{OutPoint, Transaction, TransactionInput, TransactionOutput};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const RAW_TX_HEX: &str = "\
0100000001500015d349509b8c96678fa1a93e16b05f8f16037221c80bd5453ce33a10367700000000\
c647304402202e38de014fc9254a51b7967f4bf5ab159c2194de1793997026151cc4e62a960b022068e8\
b00a142d6f9132126ff3b2aace985c6e398a18e06bfde48049d00f504f890121031c357f52dd9d38e841e\
933a7c113d032401297842e536b351394b781ffbd9569004c5963a82082b4b11c3ee454eddf8316f2afd0\
33d87e931a70e77afd6182c8d6c8627882298876a914e63af048c4ec6fc2654a12cb0da48c2c62b6dd0367\
00b17576a914e2648dadee4ae6b1fe4e11b53901e7f4d34d57da6888ac000000000148a6590200000000\
1976a914e2648dadee4ae6b1fe4e11b53901e7f4d34d57da88ac00000000";

const PREVOUT_SCRIPT_HEX: &str = "a914abb29eac7531c87dec3d656a16e7284c8507f29987";
const PREVOUT_VALUE: i64 = 39439704;
const BLOCK_HEIGHT: u64 = 659901;

fn make_tx() -> Transaction {
    let raw = hex(RAW_TX_HEX);
    let mut off = 4usize;
    let read_varint = |b: &[u8], o: &mut usize| -> usize {
        let n = b[*o] as usize;
        *o += 1;
        n
    };
    let nin = read_varint(&raw, &mut off);
    assert_eq!(nin, 1);
    off += 36;
    let script_len = read_varint(&raw, &mut off);
    let script_sig = raw[off..off + script_len].to_vec();
    off += script_len;
    let sequence = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
    off += 4;
    let nout = read_varint(&raw, &mut off);
    assert_eq!(nout, 1);
    off += 8;
    let spk_len = read_varint(&raw, &mut off);
    let output_spk = raw[off..off + spk_len].to_vec();
    off += spk_len;
    let lock_time = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());

    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: hex("7736103ae33c45d50bc8217203168f5fb0163ea9a18f67968c9b5049d3150050")
                    .try_into()
                    .unwrap(),
                index: 0,
            },
            script_sig: script_sig.into(),
            sequence: sequence as u64,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 39429704,
            script_pubkey: output_spk.into(),
        }]
        .into(),
        lock_time: lock_time as u64,
    }
}

#[test]
fn block659901_p2sh_cltv_zero_locktime_passes() {
    let tx = make_tx();
    assert_eq!(tx.lock_time, 0);
    assert_eq!(tx.inputs[0].sequence, 0);

    let prevout_script = hex(PREVOUT_SCRIPT_HEX);
    let flags = 0x01 | 0x04 | 0x200 | 0x400; // P2SH | DERSIG | CLTV | CSV @ 659901

    let prevout_values = vec![PREVOUT_VALUE];
    let prevout_scripts: Vec<&[u8]> = vec![&prevout_script];

    let ok = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &prevout_script,
        None,
        flags,
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
    .expect("verify ok");
    assert!(
        ok,
        "block 659901 conditional P2SH+CLTV must pass after BIP65 fix"
    );
}

#[test]
fn check_bip65_zero_zero_matches_core() {
    use blvm_consensus::locktime::check_bip65;
    assert!(
        check_bip65(0, 0),
        "Core CheckLockTime accepts tx=0 stack=0 when sequence != FINAL"
    );
    assert!(
        !check_bip65(0, 100),
        "stack locktime above tx locktime must fail"
    );
}
