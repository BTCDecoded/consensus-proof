//! Regression: OP_CHECKMULTISIG inside a P2WSH witness script must use BIP143 sighash
//! (WitnessV0), not legacy sighash. Legacy sighash in the interpreter caused ~955k
//! sort-merge failures from block 481824 onward.

use blvm_consensus::crypto::OptimizedSha256;
use blvm_consensus::opcodes::{OP_0, OP_1, OP_2, OP_CHECKMULTISIG};
use blvm_consensus::script::flags::SCRIPT_VERIFY_WITNESS;
use blvm_consensus::script::verify_script_with_context;
use blvm_consensus::transaction_hash::{
    SighashType, calculate_bip143_sighash, calculate_transaction_sighash_single_input,
};
use blvm_consensus::types::Network;
use blvm_consensus::{
    OutPoint, SEGWIT_ACTIVATION_MAINNET, Transaction, TransactionInput, TransactionOutput,
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

fn build_p2wsh_1of2_multisig_spend() -> (
    Transaction,
    Vec<u8>,
    blvm_consensus::witness::Witness,
    Vec<TransactionOutput>,
) {
    let secp = Secp256k1::new();
    let sk1 = SecretKey::from_slice(&[0x31; 32]).expect("sk1");
    let sk2 = SecretKey::from_slice(&[0x32; 32]).expect("sk2");
    let pk1 = PublicKey::from_secret_key(&secp, &sk1).serialize();
    let pk2 = PublicKey::from_secret_key(&secp, &sk2).serialize();

    // 1-of-2: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG (raw-key form accepted by parse_redeem_multisig)
    let mut witness_script = vec![OP_1];
    witness_script.extend_from_slice(&pk1);
    witness_script.extend_from_slice(&pk2);
    witness_script.push(OP_2);
    witness_script.push(OP_CHECKMULTISIG);

    let wsh_hash = OptimizedSha256::new().hash(&witness_script);
    let mut script_pubkey = vec![OP_0, 0x20];
    script_pubkey.extend_from_slice(&wsh_hash);

    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x44; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let prevouts = vec![TransactionOutput {
        value: 100_000,
        script_pubkey: script_pubkey.clone().into(),
    }];

    let amount = prevouts[0].value;
    let sighash1 =
        calculate_bip143_sighash(&tx, 0, &witness_script, amount, 0x01, None).expect("bip143 sig1");

    let sig1 = {
        let msg = Message::from_digest_slice(&sighash1).expect("digest");
        let mut s = secp.sign_ecdsa(&msg, &sk1).serialize_der().to_vec();
        s.push(0x01);
        s
    };

    let witness = vec![vec![OP_0], sig1, witness_script.clone()];
    (tx, script_pubkey, witness, prevouts)
}

#[test]
fn test_p2wsh_checkmultisig_valid_bip143_spend_succeeds() {
    let (tx, script_pubkey, witness, prevouts) = build_p2wsh_1of2_multisig_spend();
    let flags = SCRIPT_VERIFY_WITNESS | 0x10; // NULLDUMMY

    assert!(
        verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET + 1),
            Network::Mainnet,
        )
        .unwrap(),
        "1-of-2 P2WSH multisig with BIP143 sighash must verify"
    );
}

#[test]
fn test_p2wsh_checkmultisig_legacy_sighash_signature_fails() {
    let (tx, script_pubkey, mut witness, prevouts) = build_p2wsh_1of2_multisig_spend();
    let witness_script = witness.last().expect("witness script").clone();

    let secp = Secp256k1::new();
    let sk1 = SecretKey::from_slice(&[0x31; 32]).expect("sk1");
    let legacy_sighash = calculate_transaction_sighash_single_input(
        &tx,
        0,
        &witness_script,
        prevouts[0].value,
        SighashType::ALL,
        #[cfg(feature = "production")]
        None,
    )
    .expect("legacy sighash");
    let msg = Message::from_digest_slice(&legacy_sighash).expect("digest");
    let mut bad_sig = secp.sign_ecdsa(&msg, &sk1).serialize_der().to_vec();
    bad_sig.push(0x01);
    witness[1] = bad_sig;

    let flags = SCRIPT_VERIFY_WITNESS | 0x10;
    assert!(
        !verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET + 1),
            Network::Mainnet,
        )
        .unwrap(),
        "legacy sighash signature must not verify in P2WSH witness script"
    );
}
