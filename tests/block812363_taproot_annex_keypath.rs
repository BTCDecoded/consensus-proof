//! Regression: P2TR key-path spend with optional annex must not return Err.
//!
//! Before fix, witness `[sig, annex]` (annex starts with 0x50) was treated as script-path,
//! mis-parsing the annex as a control block → `Invalid taproot tweak` Err on valid mainnet txs.
//! See workspace `docs/BLOCK_812363_TAPROOT_ANNEX_SCRIPT_FAILURE.md`.

use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::taproot::strip_taproot_annex;
use blvm_consensus::types::{ByteString, OutPoint};
use blvm_consensus::types::{Network, Transaction, TransactionInput, TransactionOutput};
use blvm_consensus::witness::Witness;

const BLOCK_HEIGHT: u64 = 812_363;

fn p2tr_spk(internal: [u8; 32]) -> ByteString {
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&internal);
    spk
}

#[test]
fn strip_taproot_annex_keypath_witness() {
    let mut sig = [0u8; 64];
    sig[0] = 0x01; // not a valid sig, but parseable length
    let annex = vec![0x50u8, 0x01];
    let witness: Witness = vec![sig.to_vec(), annex];
    let (body, hash) = strip_taproot_annex(&witness);
    assert_eq!(body.len(), 1);
    assert!(hash.is_some());
}

#[test]
fn taproot_keypath_with_annex_returns_result_not_error() {
    let internal = [0x02u8; 32];
    let spk = p2tr_spk(internal);
    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1u8; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: spk.clone(),
        }]
        .into(),
        lock_time: 0,
    };
    let mut sig = [0u8; 64];
    sig[0] = 0xab;
    let witness: Witness = vec![sig.to_vec(), vec![0x50, 0x00]];

    // step6-like flags post-Taproot
    let flags = 0x01u32 | 0x04 | 0x10 | 0x200 | 0x400 | 0x800 | 0x8000 | 0x20000;
    let prevout_values = vec![50_000i64];
    let prevout_scripts: Vec<&[u8]> = vec![&spk];

    let result = verify_script_with_context_full(
        &vec![],
        &spk,
        Some(&witness),
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
    );

    // Invalid sig → Ok(false), never consensus Err from mis-parsed script-path.
    match result {
        Ok(false) => {}
        Ok(true) => panic!("unexpected pass with dummy sig"),
        Err(e) => panic!("key-path+annex must not Err (was script-path mis-parse): {e:?}"),
    }
}
