//! Regression: P2WPKH-in-P2SH must verify via the interpreter path (non-production builds)
//! and via production fast-path parity.
//!
//! Bug: interpreter path cleared the stack for P2WPKH-in-P2SH but never ran witness validation,
//! causing ~10M false failures in sort-merge step 6 from block 481824 onward when the fast-path
//! did not match (e.g. empty witness stack) or when built with `--no-default-features`.

#[path = "integration/helpers.rs"]
mod helpers;

use bitcoin_hashes::{Hash as BitcoinHash, hash160};
use blvm_consensus::opcodes::{OP_0, OP_1, OP_EQUAL, OP_HASH160, PUSH_20_BYTES};
use blvm_consensus::script::flags::{SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS};
use blvm_consensus::script::{
    SigVersion, verify_script_with_context, verify_script_with_context_full,
};
use blvm_consensus::transaction_hash::calculate_bip143_sighash;
use blvm_consensus::types::Network;
use blvm_consensus::{
    OutPoint, SEGWIT_ACTIVATION_MAINNET, Transaction, TransactionInput, TransactionOutput,
};
use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

fn push_bytes(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    assert!(len <= 75, "test helper only supports pushes up to 75 bytes");
    script.push(len as u8);
    script.extend_from_slice(data);
}

fn p2sh_scriptpubkey(redeem_script: &[u8]) -> Vec<u8> {
    let h = hash160::Hash::hash(redeem_script);
    let mut spk = vec![OP_HASH160, PUSH_20_BYTES];
    spk.extend_from_slice(h.as_ref());
    spk.push(OP_EQUAL);
    spk
}

fn p2wpkh_redeem_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut redeem = vec![OP_0, PUSH_20_BYTES];
    redeem.extend_from_slice(pubkey_hash);
    redeem
}

fn implicit_p2pkh_scriptcode(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    let mut scriptcode = Vec::with_capacity(25);
    scriptcode.push(0x76);
    scriptcode.push(0xa9);
    scriptcode.push(0x14);
    scriptcode.extend_from_slice(pubkey_hash);
    scriptcode.push(0x88);
    scriptcode.push(0xac);
    scriptcode
}

fn pubkey_hash160(compressed_pubkey: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(compressed_pubkey);
    Ripemd160::digest(sha256_hash).into()
}

/// Build a valid P2WPKH-in-P2SH spend at SegWit activation height.
fn build_p2wpkh_in_p2sh_spend() -> (
    Transaction,
    Vec<u8>,
    blvm_consensus::witness::Witness,
    Vec<TransactionOutput>,
) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0x11; 32]).expect("valid test secret key");
    let pubkey = PublicKey::from_secret_key(&secp, &secret_key);
    let compressed = pubkey.serialize();
    let pubkey_hash = pubkey_hash160(&compressed);
    let redeem = p2wpkh_redeem_script(&pubkey_hash);
    let script_pubkey = p2sh_scriptpubkey(&redeem);

    let mut script_sig = Vec::new();
    push_bytes(&mut script_sig, &redeem);

    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x48; 32],
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

    let prevouts = vec![TransactionOutput {
        value: 10_000,
        script_pubkey: script_pubkey.clone().into(),
    }];

    // BIP143 §4.3: scriptCode is the P2PKH expansion, not the 22-byte witness program.
    let scriptcode = implicit_p2pkh_scriptcode(&pubkey_hash);
    let sighash = calculate_bip143_sighash(&tx, 0, &scriptcode, prevouts[0].value, 0x01, None)
        .expect("BIP143 sighash");
    let msg = Message::from_digest_slice(&sighash).expect("32-byte sighash");
    let sig = secp.sign_ecdsa(&msg, &secret_key);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL

    let witness = vec![sig_bytes, compressed.to_vec()];
    (tx, script_pubkey, witness, prevouts)
}

#[test]
fn test_p2wpkh_in_p2sh_valid_witness_succeeds() {
    let (tx, script_pubkey, witness, prevouts) = build_p2wpkh_in_p2sh_spend();
    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;

    assert!(
        verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET),
            Network::Mainnet,
        )
        .unwrap(),
        "valid P2WPKH-in-P2SH spend must verify (interpreter path when fast-path unavailable)"
    );
}

#[test]
fn test_p2wpkh_in_p2sh_empty_witness_fails() {
    let (tx, script_pubkey, _, prevouts) = build_p2wpkh_in_p2sh_spend();
    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    let empty_witness: blvm_consensus::witness::Witness = vec![];

    assert!(
        !verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            Some(&empty_witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET),
            Network::Mainnet,
        )
        .unwrap(),
        "P2WPKH-in-P2SH with empty witness must fail"
    );
}

/// Same API surface as sort-merge step 6 (`verify_script_with_context_full`).
#[test]
fn test_p2wpkh_in_p2sh_verify_script_with_context_full() {
    let (tx, script_pubkey, witness, prevouts) = build_p2wpkh_in_p2sh_spend();
    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    let prevout_values: Vec<i64> = prevouts.iter().map(|o| o.value).collect();
    let prevout_script_pubkeys: Vec<&[u8]> = prevouts
        .iter()
        .map(|o| o.script_pubkey.as_slice())
        .collect();

    assert!(
        verify_script_with_context_full(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevout_values,
            &prevout_script_pubkeys,
            Some(SEGWIT_ACTIVATION_MAINNET),
            None,
            Network::Mainnet,
            SigVersion::Base,
            #[cfg(feature = "production")]
            None,
            None,
            #[cfg(feature = "production")]
            None,
            #[cfg(feature = "production")]
            None,
            #[cfg(feature = "production")]
            None,
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            None,
        )
        .unwrap(),
        "sort-merge step6 API must accept valid P2WPKH-in-P2SH"
    );
}

#[test]
fn test_p2wpkh_in_p2sh_wrong_scriptcode_signature_fails() {
    let (tx, script_pubkey, mut witness, prevouts) = build_p2wpkh_in_p2sh_spend();
    let redeem = tx.inputs[0].script_sig.as_ref();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0x11; 32]).expect("valid test key");
    let wrong_sighash = calculate_bip143_sighash(&tx, 0, redeem, prevouts[0].value, 0x01, None)
        .expect("wrong sighash");
    let msg = Message::from_digest_slice(&wrong_sighash).expect("32-byte sighash");
    let sig = secp.sign_ecdsa(&msg, &secret_key);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(0x01);
    witness[0] = sig_bytes;

    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    assert!(
        !verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET),
            Network::Mainnet,
        )
        .unwrap(),
        "22-byte witness program as scriptCode must not verify"
    );
}
