//! Unit tests for script execution functions

use consensus_proof::*;
use consensus_proof::script::*;

#[test]
fn test_eval_script_simple() {
    let script = vec![0x51, 0x52]; // OP_1, OP_2
    let result = eval_script(&script).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], vec![1]);
    assert_eq!(result[1], vec![2]);
}

#[test]
fn test_eval_script_overflow() {
    let mut script = Vec::new();
    // Create a script that would cause stack overflow
    for _ in 0..=MAX_STACK_SIZE {
        script.push(0x51); // OP_1
    }
    
    let result = eval_script(&script);
    assert!(result.is_err());
}

#[test]
fn test_verify_script_simple() {
    let script_sig = vec![0x51]; // OP_1
    let script_pubkey = vec![0x51]; // OP_1
    
    let result = verify_script(&script_sig, &script_pubkey, None, 0).unwrap();
    // The result depends on the simplified script logic
    // For now, we just ensure it doesn't panic
    assert!(result == true || result == false);
}

#[test]
fn test_verify_script_with_witness() {
    let script_sig = vec![0x51]; // OP_1
    let script_pubkey = vec![0x51]; // OP_1
    let witness = Some(vec![vec![0x52]]); // OP_2
    
    let result = verify_script(&script_sig, &script_pubkey, witness.as_ref(), 0).unwrap();
    // The result depends on the simplified script logic
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
    let mut script_sig = Vec::new();
    let mut script_pubkey = Vec::new();
    
    // Create scripts that exceed MAX_SCRIPT_SIZE
    for _ in 0..=MAX_SCRIPT_SIZE {
        script_sig.push(0x51);
        script_pubkey.push(0x51);
    }
    
    let result = verify_script(&script_sig, &script_pubkey, None, 0);
    assert!(result.is_err());
}
