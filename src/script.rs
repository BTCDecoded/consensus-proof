//! Script execution engine from Orange Paper Section 5.2

use crate::types::*;
use crate::constants::*;
use crate::error::{Result, ConsensusError};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, PublicKey, ecdsa::Signature, Message, Context, Verification};

/// EvalScript: 𝒮𝒞 × 𝒮𝒯 × ℕ → {true, false}
/// 
/// Script execution follows a stack-based virtual machine:
/// 1. Initialize stack S = ∅
/// 2. For each opcode op in script:
///    - If |S| > L_stack: return false (stack overflow)
///    - If operation count > L_ops: return false (operation limit exceeded)
///    - Execute op with current stack state
///    - If execution fails: return false
/// 3. Return |S| = 1 ∧ S[0] ≠ 0 (exactly one non-zero value on stack)
pub fn eval_script(script: &ByteString, stack: &mut Vec<ByteString>, flags: u32) -> Result<bool> {
    let mut op_count = 0;
    
    for opcode in script {
        // Check operation limit
        op_count += 1;
        if op_count > MAX_SCRIPT_OPS {
            return Err(ConsensusError::ScriptExecution("Operation limit exceeded".to_string()));
        }
        
        // Check stack size
        if stack.len() > MAX_STACK_SIZE {
            return Err(ConsensusError::ScriptExecution("Stack overflow".to_string()));
        }
        
        // Execute opcode
        if !execute_opcode(*opcode, stack, flags)? {
            return Ok(false);
        }
    }
    
    // Final stack check: exactly one non-zero value
    Ok(stack.len() == 1 && !stack[0].is_empty() && stack[0][0] != 0)
}

/// VerifyScript: 𝒮𝒞 × 𝒮𝒞 × 𝒲 × ℕ → {true, false}
/// 
/// For scriptSig ss, scriptPubKey spk, witness w, and flags f:
/// 1. Execute ss on empty stack
/// 2. Execute spk on resulting stack
/// 3. If witness present: execute w on stack
/// 4. Return final stack has exactly one true value
pub fn verify_script(
    script_sig: &ByteString,
    script_pubkey: &ByteString,
    witness: Option<&ByteString>,
    flags: u32
) -> Result<bool> {
    let mut stack = Vec::new();
    
    // Execute scriptSig
    if !eval_script(script_sig, &mut stack, flags)? {
        return Ok(false);
    }
    
    // Execute scriptPubkey
    if !eval_script(script_pubkey, &mut stack, flags)? {
        return Ok(false);
    }
    
    // Execute witness if present
    if let Some(w) = witness {
        if !eval_script(w, &mut stack, flags)? {
            return Ok(false);
        }
    }
    
    // Final validation
    Ok(stack.len() == 1 && !stack[0].is_empty() && stack[0][0] != 0)
}

/// Execute a single opcode
fn execute_opcode(opcode: u8, stack: &mut Vec<ByteString>, flags: u32) -> Result<bool> {
    match opcode {
        // OP_0 - push empty array
        0x00 => {
            stack.push(vec![]);
            Ok(true)
        }
        
        // OP_1 to OP_16 - push numbers 1-16
        0x51..=0x60 => {
            let num = opcode - 0x50;
            stack.push(vec![num]);
            Ok(true)
        }
        
        // OP_DUP - duplicate top stack item
        0x76 => {
            if let Some(item) = stack.last().cloned() {
                stack.push(item);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_HASH160 - RIPEMD160(SHA256(x))
        0xa9 => {
            if let Some(item) = stack.pop() {
                let sha256_hash = Sha256::digest(&item);
                let ripemd160_hash = Ripemd160::digest(&sha256_hash);
                stack.push(ripemd160_hash.to_vec());
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_HASH256 - SHA256(SHA256(x))
        0xaa => {
            if let Some(item) = stack.pop() {
                let hash1 = Sha256::digest(&item);
                let hash2 = Sha256::digest(&hash1);
                stack.push(hash2.to_vec());
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_EQUAL - check if top two stack items are equal
        0x87 => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            stack.push(if a == b { vec![1] } else { vec![0] });
            Ok(true)
        }
        
        // OP_EQUALVERIFY - verify top two stack items are equal
        0x88 => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            Ok(a == b)
        }
        
        // OP_CHECKSIG - verify ECDSA signature
        0xac => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let pubkey_bytes = stack.pop().unwrap();
            let signature_bytes = stack.pop().unwrap();
            
            // Verify signature using secp256k1
            let secp = Secp256k1::new();
            let result = verify_signature(&secp, &pubkey_bytes, &signature_bytes, flags);
            
            stack.push(if result { vec![1] } else { vec![0] });
            Ok(true)
        }
        
        // OP_CHECKSIGVERIFY - verify ECDSA signature and fail if invalid
        0xad => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let pubkey_bytes = stack.pop().unwrap();
            let signature_bytes = stack.pop().unwrap();
            
            // Verify signature using secp256k1
            let secp = Secp256k1::new();
            Ok(verify_signature(&secp, &pubkey_bytes, &signature_bytes, flags))
        }
        
        // OP_RETURN - always fail
        0x6a => Ok(false),
        
        // OP_VERIFY - check if top stack item is non-zero
        0x69 => {
            if let Some(item) = stack.pop() {
                Ok(!item.is_empty() && item[0] != 0)
            } else {
                Ok(false)
            }
        }
        
        // OP_IFDUP - duplicate top stack item if it's non-zero
        0x73 => {
            if let Some(item) = stack.last().cloned() {
                if !item.is_empty() && item[0] != 0 {
                    stack.push(item);
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_DEPTH - push stack size
        0x74 => {
            let depth = stack.len() as u8;
            stack.push(vec![depth]);
            Ok(true)
        }
        
        // OP_DROP - remove top stack item
        0x75 => {
            if stack.pop().is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_NIP - remove second-to-top stack item
        0x77 => {
            if stack.len() >= 2 {
                let top = stack.pop().unwrap();
                stack.pop(); // Remove second-to-top
                stack.push(top);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_OVER - copy second-to-top stack item to top
        0x78 => {
            if stack.len() >= 2 {
                let second = stack[stack.len() - 2].clone();
                stack.push(second);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_PICK - copy nth stack item to top
        0x79 => {
            if let Some(n_bytes) = stack.pop() {
                if n_bytes.is_empty() {
                    return Ok(false);
                }
                let n = n_bytes[0] as usize;
                if n < stack.len() {
                    let item = stack[stack.len() - 1 - n].clone();
                    stack.push(item);
                    Ok(true)
                } else {
                    Ok(false)
                }
            } else {
                Ok(false)
            }
        }
        
        // OP_ROLL - move nth stack item to top
        0x7a => {
            if let Some(n_bytes) = stack.pop() {
                if n_bytes.is_empty() {
                    return Ok(false);
                }
                let n = n_bytes[0] as usize;
                if n < stack.len() {
                    let item = stack.remove(stack.len() - 1 - n);
                    stack.push(item);
                    Ok(true)
                } else {
                    Ok(false)
                }
            } else {
                Ok(false)
            }
        }
        
        // OP_ROT - rotate top 3 stack items
        0x7b => {
            if stack.len() >= 3 {
                let top = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                let third = stack.pop().unwrap();
                stack.push(second);
                stack.push(top);
                stack.push(third);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_SWAP - swap top 2 stack items
        0x7c => {
            if stack.len() >= 2 {
                let top = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(top);
                stack.push(second);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_TUCK - copy top stack item to before second-to-top
        0x7d => {
            if stack.len() >= 2 {
                let top = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(top.clone());
                stack.push(second);
                stack.push(top);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_2DROP - remove top 2 stack items
        0x6d => {
            if stack.len() >= 2 {
                stack.pop();
                stack.pop();
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_2DUP - duplicate top 2 stack items
        0x6e => {
            if stack.len() >= 2 {
                let top = stack[stack.len() - 1].clone();
                let second = stack[stack.len() - 2].clone();
                stack.push(second);
                stack.push(top);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_3DUP - duplicate top 3 stack items
        0x6f => {
            if stack.len() >= 3 {
                let top = stack[stack.len() - 1].clone();
                let second = stack[stack.len() - 2].clone();
                let third = stack[stack.len() - 3].clone();
                stack.push(third);
                stack.push(second);
                stack.push(top);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_2OVER - copy second pair of stack items to top
        0x70 => {
            if stack.len() >= 4 {
                let fourth = stack[stack.len() - 4].clone();
                let third = stack[stack.len() - 3].clone();
                stack.push(fourth);
                stack.push(third);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_2ROT - rotate second pair of stack items to top
        0x71 => {
            if stack.len() >= 6 {
                let sixth = stack.remove(stack.len() - 6);
                let fifth = stack.remove(stack.len() - 5);
                stack.push(fifth);
                stack.push(sixth);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_2SWAP - swap second pair of stack items
        0x72 => {
            if stack.len() >= 4 {
                let top = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                let third = stack.pop().unwrap();
                let fourth = stack.pop().unwrap();
                stack.push(second);
                stack.push(top);
                stack.push(fourth);
                stack.push(third);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // OP_SIZE - push size of top stack item
        0x82 => {
            if let Some(item) = stack.last().cloned() {
                let size = item.len() as u8;
                stack.push(vec![size]);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        
        // Unknown opcode
        _ => Ok(false),
    }
}

/// Verify ECDSA signature using secp256k1
fn verify_signature<C: Context + Verification>(secp: &Secp256k1<C>, pubkey_bytes: &[u8], signature_bytes: &[u8], _flags: u32) -> bool {
    // Parse public key
    let pubkey = match PublicKey::from_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    
    // Parse signature (DER format)
    let signature = match Signature::from_der(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    // Create a dummy message for verification
    // In real Bitcoin, this would be the transaction hash
    let message = Message::from_digest_slice(&[0u8; 32]).unwrap();
    
    // Verify signature
    secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_eval_script_simple() {
        let script = vec![0x51]; // OP_1
        let mut stack = Vec::new();
        
        assert!(eval_script(&script, &mut stack, 0).unwrap());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1]);
    }
    
    #[test]
    fn test_eval_script_overflow() {
        let script = vec![0x51; MAX_STACK_SIZE + 1]; // Too many pushes
        let mut stack = Vec::new();
        
        assert!(eval_script(&script, &mut stack, 0).is_err());
    }
    
    #[test]
    fn test_verify_script_simple() {
        let _script_sig = vec![0x51]; // OP_1
        let _script_pubkey = vec![0x51]; // OP_1
        
        // This should work: OP_1 pushes 1, then OP_1 pushes another 1
        // Final stack has [1, 1], which is not exactly one non-zero value
        // Let's use a script that results in exactly one value on stack
        let script_sig = vec![0x51]; // OP_1
        let script_pubkey = vec![0x76, 0x88]; // OP_DUP, OP_EQUALVERIFY
        
        // This should fail because OP_EQUALVERIFY removes both values
        assert!(!verify_script(&script_sig, &script_pubkey, None, 0).unwrap());
    }
    
    // ============================================================================
    // COMPREHENSIVE OPCODE TESTS
    // ============================================================================
    
    #[test]
    fn test_op_0() {
        let script = vec![0x00]; // OP_0
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // OP_0 pushes empty array, which is "false"
        assert_eq!(stack.len(), 1);
        assert!(stack[0].is_empty());
    }
    
    #[test]
    fn test_op_1_to_op_16() {
        // Test OP_1 through OP_16
        for i in 1..=16 {
            let opcode = 0x50 + i;
            let script = vec![opcode];
            let mut stack = Vec::new();
            let result = eval_script(&script, &mut stack, 0).unwrap();
            assert!(result);
            assert_eq!(stack.len(), 1);
            assert_eq!(stack[0], vec![i]);
        }
    }
    
    #[test]
    fn test_op_dup() {
        let script = vec![0x51, 0x76]; // OP_1, OP_DUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 2 items [1, 1], not exactly 1
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![1]);
    }
    
    #[test]
    fn test_op_dup_empty_stack() {
        let script = vec![0x76]; // OP_DUP on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_hash160() {
        let script = vec![0x51, 0xa9]; // OP_1, OP_HASH160
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(result);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20); // RIPEMD160 output is 20 bytes
    }
    
    #[test]
    fn test_op_hash160_empty_stack() {
        let script = vec![0xa9]; // OP_HASH160 on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_hash256() {
        let script = vec![0x51, 0xaa]; // OP_1, OP_HASH256
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(result);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 32); // SHA256 output is 32 bytes
    }
    
    #[test]
    fn test_op_hash256_empty_stack() {
        let script = vec![0xaa]; // OP_HASH256 on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_equal() {
        let script = vec![0x51, 0x51, 0x87]; // OP_1, OP_1, OP_EQUAL
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(result);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1]); // True
    }
    
    #[test]
    fn test_op_equal_false() {
        let script = vec![0x51, 0x52, 0x87]; // OP_1, OP_2, OP_EQUAL
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // False value (0) is not considered "true"
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![0]); // False
    }
    
    #[test]
    fn test_op_equal_insufficient_stack() {
        let script = vec![0x51, 0x87]; // OP_1, OP_EQUAL (need 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_verify() {
        let script = vec![0x51, 0x69]; // OP_1, OP_VERIFY
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack is empty, not exactly 1 item
        assert_eq!(stack.len(), 0); // OP_VERIFY consumes the top item
    }
    
    #[test]
    fn test_op_verify_false() {
        let script = vec![0x00, 0x69]; // OP_0, OP_VERIFY (false)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_verify_empty_stack() {
        let script = vec![0x69]; // OP_VERIFY on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_equalverify() {
        let script = vec![0x51, 0x51, 0x88]; // OP_1, OP_1, OP_EQUALVERIFY
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack is empty, not exactly 1 item
        assert_eq!(stack.len(), 0); // OP_EQUALVERIFY consumes both items
    }
    
    #[test]
    fn test_op_equalverify_false() {
        let script = vec![0x51, 0x52, 0x88]; // OP_1, OP_2, OP_EQUALVERIFY (false)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_op_checksig() {
        // This is a simplified test - real OP_CHECKSIG would need proper signature verification
        let script = vec![0x51, 0x51, 0xac]; // OP_1, OP_1, OP_CHECKSIG
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // OP_CHECKSIG returns false in our simplified implementation
        assert_eq!(stack.len(), 1);
        // OP_CHECKSIG result depends on implementation
    }
    
    #[test]
    fn test_op_checksig_insufficient_stack() {
        let script = vec![0x51, 0xac]; // OP_1, OP_CHECKSIG (need 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_unknown_opcode() {
        let script = vec![0xff]; // Unknown opcode
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_script_size_limit() {
        let script = vec![0x51; MAX_SCRIPT_SIZE + 1]; // Exceed size limit
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_operation_count_limit() {
        let script = vec![0x51; MAX_SCRIPT_OPS + 1]; // Exceed operation limit
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_stack_underflow_multiple_ops() {
        let script = vec![0x51, 0x87, 0x87]; // OP_1, OP_EQUAL, OP_EQUAL (second OP_EQUAL will underflow)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_final_stack_empty() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2 (two items on final stack)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_final_stack_false() {
        let script = vec![0x00]; // OP_0 (false on final stack)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_verify_script_with_witness() {
        let script_sig = vec![0x51]; // OP_1
        let script_pubkey = vec![0x51]; // OP_1
        let witness = vec![0x51]; // OP_1
        let flags = 0;
        
        let result = verify_script(&script_sig, &script_pubkey, Some(&witness), flags).unwrap();
        assert!(!result); // Final stack has 2 items [1, 1], not exactly 1
    }
    
    #[test]
    fn test_verify_script_failure() {
        let script_sig = vec![0x51]; // OP_1
        let script_pubkey = vec![0x52]; // OP_2
        let witness = None;
        let flags = 0;
        
        let result = verify_script(&script_sig, &script_pubkey, witness, flags).unwrap();
        assert!(!result);
    }
    
    // ============================================================================
    // COMPREHENSIVE SCRIPT TESTS
    // ============================================================================
    
    #[test]
    fn test_op_ifdup_true() {
        let script = vec![0x51, 0x73]; // OP_1, OP_IFDUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 2 items [1, 1], not exactly 1
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![1]);
    }
    
    #[test]
    fn test_op_ifdup_false() {
        let script = vec![0x00, 0x73]; // OP_0, OP_IFDUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 1 item [0], which is false
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![]);
    }
    
    #[test]
    fn test_op_depth() {
        let script = vec![0x51, 0x51, 0x74]; // OP_1, OP_1, OP_DEPTH
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 3 items, not exactly 1
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[2], vec![2]); // Depth should be 2 (before OP_DEPTH)
    }
    
    #[test]
    fn test_op_drop() {
        let script = vec![0x51, 0x52, 0x75]; // OP_1, OP_2, OP_DROP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(result); // Final stack has 1 item [1]
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1]);
    }
    
    #[test]
    fn test_op_drop_empty_stack() {
        let script = vec![0x75]; // OP_DROP on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 0);
    }
    
    #[test]
    fn test_op_nip() {
        let script = vec![0x51, 0x52, 0x77]; // OP_1, OP_2, OP_NIP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(result); // Final stack has 1 item [2]
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![2]);
    }
    
    #[test]
    fn test_op_nip_insufficient_stack() {
        let script = vec![0x51, 0x77]; // OP_1, OP_NIP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_over() {
        let script = vec![0x51, 0x52, 0x78]; // OP_1, OP_2, OP_OVER
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 3 items [1, 2, 1], not exactly 1
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![2]);
        assert_eq!(stack[2], vec![1]);
    }
    
    #[test]
    fn test_op_over_insufficient_stack() {
        let script = vec![0x51, 0x78]; // OP_1, OP_OVER (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_pick() {
        let script = vec![0x51, 0x52, 0x53, 0x51, 0x79]; // OP_1, OP_2, OP_3, OP_1, OP_PICK
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 4 items [1, 2, 3, 2], not exactly 1
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[3], vec![2]); // Should pick index 1 (OP_2)
    }
    
    #[test]
    fn test_op_pick_empty_n() {
        let script = vec![0x51, 0x00, 0x79]; // OP_1, OP_0, OP_PICK (n is empty)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_pick_invalid_index() {
        let script = vec![0x51, 0x52, 0x79]; // OP_1, OP_2, OP_PICK (n=2, but only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_roll() {
        let script = vec![0x51, 0x52, 0x53, 0x51, 0x7a]; // OP_1, OP_2, OP_3, OP_1, OP_ROLL
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 3 items [1, 3, 2], not exactly 1
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![3]);
        assert_eq!(stack[2], vec![2]); // Should roll index 1 (OP_2) to top
    }
    
    #[test]
    fn test_op_roll_empty_n() {
        let script = vec![0x51, 0x00, 0x7a]; // OP_1, OP_0, OP_ROLL (n is empty)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_roll_invalid_index() {
        let script = vec![0x51, 0x52, 0x7a]; // OP_1, OP_2, OP_ROLL (n=2, but only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_rot() {
        let script = vec![0x51, 0x52, 0x53, 0x7b]; // OP_1, OP_2, OP_3, OP_ROT
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 3 items [2, 3, 1], not exactly 1
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0], vec![2]);
        assert_eq!(stack[1], vec![3]);
        assert_eq!(stack[2], vec![1]);
    }
    
    #[test]
    fn test_op_rot_insufficient_stack() {
        let script = vec![0x51, 0x52, 0x7b]; // OP_1, OP_2, OP_ROT (only 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 2);
    }
    
    #[test]
    fn test_op_swap() {
        let script = vec![0x51, 0x52, 0x7c]; // OP_1, OP_2, OP_SWAP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 2 items [2, 1], not exactly 1
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vec![2]);
        assert_eq!(stack[1], vec![1]);
    }
    
    #[test]
    fn test_op_swap_insufficient_stack() {
        let script = vec![0x51, 0x7c]; // OP_1, OP_SWAP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_tuck() {
        let script = vec![0x51, 0x52, 0x7d]; // OP_1, OP_2, OP_TUCK
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 3 items [2, 1, 2], not exactly 1
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0], vec![2]);
        assert_eq!(stack[1], vec![1]);
        assert_eq!(stack[2], vec![2]);
    }
    
    #[test]
    fn test_op_tuck_insufficient_stack() {
        let script = vec![0x51, 0x7d]; // OP_1, OP_TUCK (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_2drop() {
        let script = vec![0x51, 0x52, 0x53, 0x6d]; // OP_1, OP_2, OP_3, OP_2DROP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(result); // Final stack has 1 item [1]
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1]);
    }
    
    #[test]
    fn test_op_2drop_insufficient_stack() {
        let script = vec![0x51, 0x6d]; // OP_1, OP_2DROP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_2dup() {
        let script = vec![0x51, 0x52, 0x6e]; // OP_1, OP_2, OP_2DUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 4 items [1, 2, 1, 2], not exactly 1
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![2]);
        assert_eq!(stack[2], vec![1]);
        assert_eq!(stack[3], vec![2]);
    }
    
    #[test]
    fn test_op_2dup_insufficient_stack() {
        let script = vec![0x51, 0x6e]; // OP_1, OP_2DUP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_3dup() {
        let script = vec![0x51, 0x52, 0x53, 0x6f]; // OP_1, OP_2, OP_3, OP_3DUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 6 items, not exactly 1
        assert_eq!(stack.len(), 6);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![2]);
        assert_eq!(stack[2], vec![3]);
        assert_eq!(stack[3], vec![1]);
        assert_eq!(stack[4], vec![2]);
        assert_eq!(stack[5], vec![3]);
    }
    
    #[test]
    fn test_op_3dup_insufficient_stack() {
        let script = vec![0x51, 0x52, 0x6f]; // OP_1, OP_2, OP_3DUP (only 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 2);
    }
    
    #[test]
    fn test_op_2over() {
        let script = vec![0x51, 0x52, 0x53, 0x54, 0x70]; // OP_1, OP_2, OP_3, OP_4, OP_2OVER
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 6 items, not exactly 1
        assert_eq!(stack.len(), 6);
        assert_eq!(stack[4], vec![1]); // Should copy second pair
        assert_eq!(stack[5], vec![2]);
    }
    
    #[test]
    fn test_op_2over_insufficient_stack() {
        let script = vec![0x51, 0x52, 0x53, 0x70]; // OP_1, OP_2, OP_3, OP_2OVER (only 3 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 3);
    }
    
    #[test]
    fn test_op_2rot() {
        let script = vec![0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x71]; // 6 items, OP_2ROT
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 6 items, not exactly 1
        assert_eq!(stack.len(), 6);
        assert_eq!(stack[4], vec![2]); // Should rotate second pair to top
        assert_eq!(stack[5], vec![1]);
    }
    
    #[test]
    fn test_op_2rot_insufficient_stack() {
        let script = vec![0x51, 0x52, 0x53, 0x54, 0x71]; // OP_1, OP_2, OP_3, OP_4, OP_2ROT (only 4 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 4);
    }
    
    #[test]
    fn test_op_2swap() {
        let script = vec![0x51, 0x52, 0x53, 0x54, 0x72]; // OP_1, OP_2, OP_3, OP_4, OP_2SWAP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 4 items, not exactly 1
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[0], vec![3]); // Should swap second pair
        assert_eq!(stack[1], vec![4]);
        assert_eq!(stack[2], vec![1]);
        assert_eq!(stack[3], vec![2]);
    }
    
    #[test]
    fn test_op_2swap_insufficient_stack() {
        let script = vec![0x51, 0x52, 0x53, 0x72]; // OP_1, OP_2, OP_3, OP_2SWAP (only 3 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 3);
    }
    
    #[test]
    fn test_op_size() {
        let script = vec![0x51, 0x82]; // OP_1, OP_SIZE
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Final stack has 2 items [1, 1], not exactly 1
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vec![1]);
        assert_eq!(stack[1], vec![1]); // Size of [1] is 1
    }
    
    #[test]
    fn test_op_size_empty_stack() {
        let script = vec![0x82]; // OP_SIZE on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 0);
    }
    
    #[test]
    fn test_op_return() {
        let script = vec![0x51, 0x6a]; // OP_1, OP_RETURN
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // OP_RETURN always fails
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_op_checksigverify() {
        let script = vec![0x51, 0x52, 0xad]; // OP_1, OP_2, OP_CHECKSIGVERIFY
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Should fail due to invalid signature
        assert_eq!(stack.len(), 0);
    }
    
    #[test]
    fn test_op_checksigverify_insufficient_stack() {
        let script = vec![0x51, 0xad]; // OP_1, OP_CHECKSIGVERIFY (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_unknown_opcode_comprehensive() {
        let script = vec![0x51, 0xff]; // OP_1, unknown opcode
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0).unwrap();
        assert!(!result); // Unknown opcode should fail
        assert_eq!(stack.len(), 1);
    }
    
    #[test]
    fn test_verify_signature_invalid_pubkey() {
        let secp = Secp256k1::new();
        let invalid_pubkey = vec![0x00]; // Invalid pubkey
        let signature = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]; // Valid DER signature
        let result = verify_signature(&secp, &invalid_pubkey, &signature, 0);
        assert!(!result);
    }
    
    #[test]
    fn test_verify_signature_invalid_signature() {
        let secp = Secp256k1::new();
        let pubkey = vec![0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98]; // Valid pubkey
        let invalid_signature = vec![0x00]; // Invalid signature
        let result = verify_signature(&secp, &pubkey, &invalid_signature, 0);
        assert!(!result);
    }
}
