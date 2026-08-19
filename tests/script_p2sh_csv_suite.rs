//! COV-C-02d: P2SH redeem and CSV script paths.

#[path = "integration/helpers.rs"]
mod helpers;

use bitcoin_hashes::{Hash as BitcoinHash, hash160, sha256};
use blvm_consensus::opcodes::{
    OP_0, OP_1, OP_2, OP_2DROP, OP_2DUP, OP_3, OP_CHECKMULTISIG, OP_CHECKSEQUENCEVERIFY, OP_DEPTH,
    OP_EQUAL, OP_HASH160, OP_PICK, OP_PUSHDATA1, OP_ROLL, PUSH_20_BYTES, PUSH_32_BYTES,
};
use blvm_consensus::script::flags::{
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS,
};
use blvm_consensus::script::{SigVersion, eval_script, verify_script, verify_script_with_context};
use blvm_consensus::types::Network;
use blvm_consensus::{
    OutPoint, SEGWIT_ACTIVATION_MAINNET, Transaction, TransactionInput, TransactionOutput,
};

fn p2sh_scriptpubkey(redeem_script: &[u8]) -> Vec<u8> {
    let h = hash160::Hash::hash(redeem_script);
    let mut spk = vec![OP_HASH160, PUSH_20_BYTES];
    spk.extend_from_slice(h.as_ref());
    spk.push(OP_EQUAL);
    spk
}

fn push_bytes(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        script.push(len as u8);
    } else {
        script.push(OP_PUSHDATA1);
        script.push(len as u8);
    }
    script.extend_from_slice(data);
}

#[test]
fn test_p2sh_op_true_redeem_succeeds() {
    let redeem = vec![OP_1];
    let script_pubkey = p2sh_scriptpubkey(&redeem);
    let mut script_sig = Vec::new();
    push_bytes(&mut script_sig, &redeem);
    assert!(verify_script(&script_sig, &script_pubkey, None, SCRIPT_VERIFY_P2SH).unwrap());
}

#[test]
fn test_p2sh_wrong_redeem_fails() {
    let redeem = vec![OP_1];
    let script_pubkey = p2sh_scriptpubkey(&redeem);
    let wrong_redeem = vec![OP_2];
    let mut script_sig = Vec::new();
    push_bytes(&mut script_sig, &wrong_redeem);
    assert!(!verify_script(&script_sig, &script_pubkey, None, SCRIPT_VERIFY_P2SH).unwrap());
}

#[test]
fn test_checkmultisig_zero_sigs_succeeds() {
    // dummy, m=0, 3 pubkeys, n=3, CHECKMULTISIG
    let script = vec![OP_0, OP_0, OP_1, OP_1, OP_1, OP_3, OP_CHECKMULTISIG];
    let mut stack = Vec::new();
    assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());
    assert_eq!(stack.len(), 1);
}

#[test]
fn test_csv_success_with_context() {
    let script_pubkey = helpers::push_locktime_script(4, OP_CHECKSEQUENCEVERIFY);
    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x31; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 5,
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
        value: 10_000,
        script_pubkey: script_pubkey.clone().into(),
    }];
    assert!(
        verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            None,
            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            &tx,
            0,
            &prevouts,
            None,
            Network::Mainnet,
        )
        .unwrap()
    );
}

#[test]
fn test_csv_fails_on_type_flag_mismatch() {
    let script_pubkey = helpers::push_locktime_script(0x0040_0100, OP_CHECKSEQUENCEVERIFY);
    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x32; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 0x0000_0100,
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
        value: 10_000,
        script_pubkey: script_pubkey.into(),
    }];
    assert!(
        !verify_script_with_context(
            &tx.inputs[0].script_sig,
            &prevouts[0].script_pubkey,
            None,
            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            &tx,
            0,
            &prevouts,
            None,
            Network::Mainnet,
        )
        .unwrap()
    );
}

#[test]
fn test_stack_manipulation_opcodes() {
    let script = vec![OP_1, OP_2, OP_3, OP_1, OP_PICK];
    let mut stack = Vec::new();
    assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());
    assert_eq!(stack.last().unwrap().as_slice(), &[2]);

    let script = vec![OP_1, OP_2, OP_3, OP_1, OP_ROLL];
    let mut stack = Vec::new();
    assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());

    let script = vec![OP_1, OP_2, OP_3, OP_2DROP];
    let mut stack = Vec::new();
    assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());
    assert_eq!(stack.len(), 1);

    let script = vec![OP_1, OP_2, OP_2DUP];
    let mut stack = Vec::new();
    assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());
    assert_eq!(stack.len(), 4);

    let script = vec![OP_1, OP_2, OP_DEPTH];
    let mut stack = Vec::new();
    assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());
    assert_eq!(stack.last().unwrap().as_slice(), &[2]);
}

#[test]
fn test_p2sh_p2wsh_nested_op_true() {
    let witness_script = vec![OP_1];
    let wsh = sha256::Hash::hash(&witness_script);
    let mut redeem = vec![OP_0, PUSH_32_BYTES];
    redeem.extend_from_slice(wsh.as_ref());
    let p2sh = hash160::Hash::hash(&redeem);
    let mut script_pubkey = vec![OP_HASH160, PUSH_20_BYTES];
    script_pubkey.extend_from_slice(p2sh.as_ref());
    script_pubkey.push(OP_EQUAL);

    let mut script_sig = Vec::new();
    push_bytes(&mut script_sig, &redeem);
    let witness = vec![witness_script];

    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x40; 32],
                index: 0,
            },
            script_sig: script_sig.into(),
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
        value: 10_000,
        script_pubkey: script_pubkey.into(),
    }];
    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    assert!(
        verify_script_with_context(
            &tx.inputs[0].script_sig,
            &prevouts[0].script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET),
            Network::Mainnet,
        )
        .unwrap()
    );
}

#[test]
fn test_p2sh_p2wsh_nested_extra_scriptsig_push_fails() {
    let witness_script = vec![OP_1];
    let wsh = sha256::Hash::hash(&witness_script);
    let mut redeem = vec![OP_0, PUSH_32_BYTES];
    redeem.extend_from_slice(wsh.as_ref());
    let p2sh = hash160::Hash::hash(&redeem);
    let mut script_pubkey = vec![OP_HASH160, PUSH_20_BYTES];
    script_pubkey.extend_from_slice(p2sh.as_ref());
    script_pubkey.push(OP_EQUAL);

    let mut script_sig = Vec::new();
    script_sig.push(OP_1);
    push_bytes(&mut script_sig, &redeem);
    let witness = vec![witness_script];

    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x41; 32],
                index: 0,
            },
            script_sig: script_sig.into(),
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
        value: 10_000,
        script_pubkey: script_pubkey.into(),
    }];
    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    assert!(
        !verify_script_with_context(
            &tx.inputs[0].script_sig,
            &prevouts[0].script_pubkey,
            Some(&witness),
            flags,
            &tx,
            0,
            &prevouts,
            Some(SEGWIT_ACTIVATION_MAINNET),
            Network::Mainnet,
        )
        .unwrap()
    );
}

#[test]
fn test_csv_input_sequence_disabled_fails() {
    let script_pubkey = vec![OP_3, OP_CHECKSEQUENCEVERIFY, OP_1];
    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x42; 32],
                index: 0,
            },
            script_sig: vec![].into(),
            sequence: 0x80000000,
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
        value: 10_000,
        script_pubkey: script_pubkey.clone().into(),
    }];
    assert!(
        !verify_script_with_context(
            &tx.inputs[0].script_sig,
            &script_pubkey,
            None,
            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            &tx,
            0,
            &prevouts,
            Some(500_000),
            Network::Mainnet,
        )
        .unwrap()
    );
}
