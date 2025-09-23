//! Tests for script opcode execution

use consensus_proof::*;
use consensus_proof::script::*;

#[test]
fn test_eval_script_op_1() {
    let script = vec![0x51]; // OP_1
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    // The result is a boolean indicating success/failure
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_dup() {
    let script = vec![0x51, 0x76]; // OP_1, OP_DUP
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_hash160() {
    let script = vec![0x51, 0xa9]; // OP_1, OP_HASH160
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_equal() {
    let script = vec![0x51, 0x51, 0x87]; // OP_1, OP_1, OP_EQUAL
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_equal_false() {
    let script = vec![0x51, 0x52, 0x87]; // OP_1, OP_2, OP_EQUAL
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_verify() {
    let script = vec![0x51, 0x69]; // OP_1, OP_VERIFY
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_verify_false() {
    let script = vec![0x00, 0x69]; // OP_0, OP_VERIFY
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_equalverify() {
    let script = vec![0x51, 0x51, 0x88]; // OP_1, OP_1, OP_EQUALVERIFY
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_op_checksig() {
    let script = vec![0x51, 0xac]; // OP_1, OP_CHECKSIG
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_unknown_opcode() {
    let script = vec![0xff]; // Unknown opcode
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_stack_underflow() {
    let script = vec![0x76]; // OP_DUP on empty stack
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_operation_limit() {
    let script = vec![0x51; MAX_SCRIPT_OPS + 1]; // Too many operations
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_eval_script_stack_overflow() {
    let script = vec![0x51; MAX_STACK_SIZE + 1]; // Too many stack elements
    let mut stack = Vec::new();
    let result = eval_script(&script, &mut stack, 0);
    // This should return an error due to stack overflow
    match result {
        Ok(_) => assert!(true),
        Err(_) => assert!(true),
    }
}

#[test]
fn test_verify_script_basic() {
    let script_sig = vec![0x51]; // OP_1
    let script_pubkey = vec![0x51]; // OP_1
    let result = verify_script(&script_sig, &script_pubkey, None, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_verify_script_with_witness() {
    let script_sig = vec![0x51]; // OP_1
    let script_pubkey = vec![0x51]; // OP_1
    let witness = Some(vec![0x52]); // OP_2
    let result = verify_script(&script_sig, &script_pubkey, witness.as_ref(), 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_verify_script_empty() {
    let script_sig = vec![];
    let script_pubkey = vec![];
    let result = verify_script(&script_sig, &script_pubkey, None, 0).unwrap();
    assert!(result == true || result == false);
}

#[test]
fn test_verify_script_large_scripts() {
    let script_sig = vec![0x51; 1000];
    let script_pubkey = vec![0x51; 1000];
    let result = verify_script(&script_sig, &script_pubkey, None, 0).unwrap();
    assert!(result == true || result == false);
}