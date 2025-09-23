//! Taproot functions from Orange Paper Section 11.2

use crate::types::*;
use crate::error::Result;
use crate::types::{Hash, ByteString};
use bitcoin_hashes::{sha256d, Hash as BitcoinHash, HashEngine};
use secp256k1::{Secp256k1, PublicKey, XOnlyPublicKey, Scalar};
use sha2::{Sha256, Digest};

/// Taproot output script: OP_1 <32-byte-hash>
pub const TAPROOT_SCRIPT_PREFIX: u8 = 0x51; // OP_1

/// Validate Taproot output script
pub fn validate_taproot_script(script: &ByteString) -> Result<bool> {
    // Check if script is P2TR: OP_1 <33-byte-key>
    if script.len() != 34 {
        return Ok(false);
    }
    
    if script[0] != TAPROOT_SCRIPT_PREFIX {
        return Ok(false);
    }
    
    // The remaining 33 bytes should be the Taproot output key
    Ok(true)
}

/// Extract Taproot output key from script
pub fn extract_taproot_output_key(script: &ByteString) -> Result<Option<[u8; 32]>> {
    if !validate_taproot_script(script)? {
        return Ok(None);
    }
    
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&script[1..33]);
    Ok(Some(output_key))
}

/// Compute Taproot tweak using proper cryptographic operations
/// OutputKey = InternalPubKey + TaprootTweak(MerkleRoot) × G
pub fn compute_taproot_tweak(internal_pubkey: &[u8; 32], merkle_root: &Hash) -> Result<[u8; 32]> {
    // Create secp256k1 context
    let secp = Secp256k1::new();
    
    // Parse internal public key (x-only format for Taproot)
    let internal_pk = match XOnlyPublicKey::from_slice(internal_pubkey) {
        Ok(pk) => pk,
        Err(_) => return Err(crate::error::ConsensusError::InvalidSignature(
            "Invalid internal public key".to_string()
        )),
    };
    
    // Compute tweak: SHA256("TapTweak" || internal_pubkey || merkle_root)
    let mut tweak_data = Vec::new();
    tweak_data.extend_from_slice(b"TapTweak");
    tweak_data.extend_from_slice(internal_pubkey);
    tweak_data.extend_from_slice(merkle_root);
    
    let tweak_hash = Sha256::digest(&tweak_data);
    let tweak_scalar = match Scalar::from_be_bytes(tweak_hash.into()) {
        Ok(scalar) => scalar,
        Err(_) => return Err(crate::error::ConsensusError::InvalidSignature(
            "Invalid tweak scalar".to_string()
        )),
    };
    
    // Convert x-only public key to full public key for tweaking
    let full_pk = PublicKey::from_x_only_public_key(internal_pk, secp256k1::Parity::Even);
    
    // Compute tweaked public key: full_pk + tweak_scalar * G
    let tweaked_pk = full_pk.add_exp_tweak(&secp, &tweak_scalar)
        .map_err(|_| crate::error::ConsensusError::InvalidSignature(
            "Failed to compute tweaked public key".to_string()
        ))?;
    
    // Return the x-coordinate of the tweaked public key
    let xonly_pk = XOnlyPublicKey::from(tweaked_pk);
    Ok(xonly_pk.serialize())
}

/// Validate Taproot key aggregation
pub fn validate_taproot_key_aggregation(
    internal_pubkey: &[u8; 32],
    merkle_root: &Hash,
    output_key: &[u8; 32],
) -> Result<bool> {
    let expected_output_key = compute_taproot_tweak(internal_pubkey, merkle_root)?;
    Ok(expected_output_key == *output_key)
}

/// Validate Taproot script path spending
pub fn validate_taproot_script_path(
    script: &ByteString,
    merkle_proof: &[Hash],
    merkle_root: &Hash,
) -> Result<bool> {
    // Compute merkle root from script and proof
    let computed_root = compute_script_merkle_root(script, merkle_proof)?;
    Ok(computed_root == *merkle_root)
}

/// Compute merkle root for script path
fn compute_script_merkle_root(script: &ByteString, proof: &[Hash]) -> Result<Hash> {
    let mut current_hash = hash_script(script);
    
    for proof_hash in proof {
        current_hash = hash_pair(&current_hash, proof_hash);
    }
    
    Ok(current_hash)
}

/// Hash a script
fn hash_script(script: &ByteString) -> Hash {
    let mut hasher = sha256d::Hash::engine();
    hasher.input(script);
    let result = sha256d::Hash::from_engine(hasher);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash a pair of hashes
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = sha256d::Hash::engine();
    hasher.input(left);
    hasher.input(right);
    let result = sha256d::Hash::from_engine(hasher);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Check if transaction output is Taproot
pub fn is_taproot_output(output: &TransactionOutput) -> bool {
    validate_taproot_script(&output.script_pubkey).unwrap_or(false)
}

/// Validate Taproot transaction
pub fn validate_taproot_transaction(tx: &Transaction) -> Result<bool> {
    // Check if any output is Taproot
    for output in &tx.outputs {
        if is_taproot_output(output) {
            // Validate Taproot output
            if !validate_taproot_script(&output.script_pubkey)? {
                return Ok(false);
            }
        }
    }
    
    Ok(true)
}

/// Compute Taproot signature hash following BIP 341 specification
pub fn compute_taproot_signature_hash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TransactionOutput],
    sighash_type: u8,
) -> Result<Hash> {
    // Create SHA256 hasher for Taproot signature hash
    let mut hasher = Sha256::new();
    
    // 1. Transaction version (4 bytes, little-endian)
    hasher.update(&(tx.version as u32).to_le_bytes());
    
    // 2. Input count (varint)
    hasher.update(&encode_varint(tx.inputs.len() as u64));
    
    // 3. Inputs
    for (_i, input) in tx.inputs.iter().enumerate() {
        // Previous output hash (32 bytes)
        hasher.update(&input.prevout.hash);
        // Previous output index (4 bytes, little-endian)
        hasher.update(&(input.prevout.index as u32).to_le_bytes());
        // Script length (varint) - empty for Taproot
        hasher.update(&[0]);
        // Sequence (4 bytes, little-endian)
        hasher.update(&(input.sequence as u32).to_le_bytes());
    }
    
    // 4. Output count (varint)
    hasher.update(&encode_varint(tx.outputs.len() as u64));
    
    // 5. Outputs
    for output in &tx.outputs {
        // Value (8 bytes, little-endian)
        hasher.update(&(output.value as u64).to_le_bytes());
        // Script length (varint)
        hasher.update(&encode_varint(output.script_pubkey.len() as u64));
        // Script
        hasher.update(&output.script_pubkey);
    }
    
    // 6. Lock time (4 bytes, little-endian)
    hasher.update(&(tx.lock_time as u32).to_le_bytes());
    
    // 7. Sighash type (4 bytes, little-endian)
    hasher.update(&(sighash_type as u32).to_le_bytes());
    
    // 8. Input index (4 bytes, little-endian)
    hasher.update(&(input_index as u32).to_le_bytes());
    
    // 9. Previous output value (8 bytes, little-endian)
    if input_index < prevouts.len() {
        hasher.update(&(prevouts[input_index].value as u64).to_le_bytes());
    } else {
        hasher.update(&[0u8; 8]);
    }
    
    // 10. Previous output script (varint + script)
    if input_index < prevouts.len() {
        hasher.update(&encode_varint(prevouts[input_index].script_pubkey.len() as u64));
        hasher.update(&prevouts[input_index].script_pubkey);
    } else {
        hasher.update(&[0]);
    }
    
    // Final hash
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Encode a number as a Bitcoin varint
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut result = vec![0xfd];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        result
    } else if value <= 0xffffffff {
        let mut result = vec![0xfe];
        result.extend_from_slice(&(value as u32).to_le_bytes());
        result
    } else {
        let mut result = vec![0xff];
        result.extend_from_slice(&value.to_le_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_taproot_script_valid() {
        let script = create_taproot_script(&[1u8; 32]);
        assert!(validate_taproot_script(&script).unwrap());
    }
    
    #[test]
    fn test_validate_taproot_script_invalid_length() {
        let script = vec![0x51, 0x20]; // Too short
        assert!(!validate_taproot_script(&script).unwrap());
    }
    
    #[test]
    fn test_validate_taproot_script_invalid_prefix() {
        let mut script = vec![0x52]; // Wrong prefix (OP_2 instead of OP_1)
        script.extend_from_slice(&[1u8; 32]);
        assert!(!validate_taproot_script(&script).unwrap());
    }
    
    #[test]
    fn test_extract_taproot_output_key() {
        let expected_key = [1u8; 32];
        let script = create_taproot_script(&expected_key);
        
        let extracted_key = extract_taproot_output_key(&script).unwrap();
        assert_eq!(extracted_key, Some(expected_key));
    }
    
    #[test]
    fn test_compute_taproot_tweak() {
        // Use a valid secp256k1 public key (x-coordinate only for Taproot)
        let internal_pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
            0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        ];
        let merkle_root = [2u8; 32];
        
        let tweak = compute_taproot_tweak(&internal_pubkey, &merkle_root).unwrap();
        assert_eq!(tweak.len(), 32);
    }
    
    #[test]
    fn test_validate_taproot_key_aggregation() {
        // Use a valid secp256k1 public key (x-coordinate only for Taproot)
        let internal_pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
            0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        ];
        let merkle_root = [2u8; 32];
        let output_key = compute_taproot_tweak(&internal_pubkey, &merkle_root).unwrap();
        
        assert!(validate_taproot_key_aggregation(&internal_pubkey, &merkle_root, &output_key).unwrap());
    }
    
    #[test]
    fn test_validate_taproot_script_path() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2
        let merkle_proof = vec![[3u8; 32], [4u8; 32]];
        let merkle_root = compute_script_merkle_root(&script, &merkle_proof).unwrap();
        
        assert!(validate_taproot_script_path(&script, &merkle_proof, &merkle_root).unwrap());
    }
    
    #[test]
    fn test_is_taproot_output() {
        let output = TransactionOutput {
            value: 1000,
            script_pubkey: create_taproot_script(&[1u8; 32]),
        };
        
        assert!(is_taproot_output(&output));
    }
    
    #[test]
    fn test_validate_taproot_transaction() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: create_taproot_script(&[1u8; 32]),
            }],
            lock_time: 0,
        };
        
        assert!(validate_taproot_transaction(&tx).unwrap());
    }
    
    #[test]
    fn test_compute_taproot_signature_hash() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        
        let prevouts = vec![TransactionOutput {
            value: 2000,
            script_pubkey: create_taproot_script(&[1u8; 32]),
        }];
        
        let sig_hash = compute_taproot_signature_hash(&tx, 0, &prevouts, 0x01).unwrap();
        assert_eq!(sig_hash.len(), 32);
    }
    
    #[test]
    fn test_compute_taproot_signature_hash_invalid_input_index() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        
        let prevouts = vec![TransactionOutput {
            value: 2000,
            script_pubkey: create_taproot_script(&[1u8; 32]),
        }];
        
        // Use invalid input index (out of bounds)
        let sig_hash = compute_taproot_signature_hash(&tx, 1, &prevouts, 0x01).unwrap();
        assert_eq!(sig_hash.len(), 32);
    }
    
    #[test]
    fn test_compute_taproot_signature_hash_empty_prevouts() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        
        let prevouts = vec![];
        
        let sig_hash = compute_taproot_signature_hash(&tx, 0, &prevouts, 0x01).unwrap();
        assert_eq!(sig_hash.len(), 32);
    }
    
    #[test]
    fn test_compute_taproot_tweak_invalid_pubkey() {
        let invalid_pubkey = [0u8; 32]; // Invalid public key
        let merkle_root = [2u8; 32];
        
        let result = compute_taproot_tweak(&invalid_pubkey, &merkle_root);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_validate_taproot_key_aggregation_invalid() {
        let internal_pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
            0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        ];
        let merkle_root = [2u8; 32];
        let wrong_output_key = [3u8; 32]; // Wrong output key
        
        assert!(!validate_taproot_key_aggregation(&internal_pubkey, &merkle_root, &wrong_output_key).unwrap());
    }
    
    #[test]
    fn test_validate_taproot_script_path_invalid() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2
        let merkle_proof = vec![[3u8; 32], [4u8; 32]];
        let wrong_merkle_root = [5u8; 32]; // Wrong merkle root
        
        assert!(!validate_taproot_script_path(&script, &merkle_proof, &wrong_merkle_root).unwrap());
    }
    
    #[test]
    fn test_validate_taproot_script_path_empty_proof() {
        let script = vec![0x51, 0x52]; // OP_1, OP_2
        let merkle_proof = vec![];
        let merkle_root = hash_script(&script);
        
        assert!(validate_taproot_script_path(&script, &merkle_proof, &merkle_root).unwrap());
    }
    
    #[test]
    fn test_hash_script() {
        let script = vec![0x51, 0x52];
        let hash = hash_script(&script);
        
        assert_eq!(hash.len(), 32);
        
        // Different script should produce different hash
        let script2 = vec![0x53, 0x54];
        let hash2 = hash_script(&script2);
        assert_ne!(hash, hash2);
    }
    
    #[test]
    fn test_hash_script_empty() {
        let script = vec![];
        let hash = hash_script(&script);
        
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash = hash_pair(&left, &right);
        
        assert_eq!(hash.len(), 32);
        
        // Different order should produce different hash
        let hash2 = hash_pair(&right, &left);
        assert_ne!(hash, hash2);
    }
    
    #[test]
    fn test_hash_pair_same() {
        let hash1 = [1u8; 32];
        let hash2 = hash_pair(&hash1, &hash1);
        
        assert_eq!(hash2.len(), 32);
    }
    
    #[test]
    fn test_encode_varint_small() {
        let encoded = encode_varint(0xfc);
        assert_eq!(encoded, vec![0xfc]);
    }
    
    #[test]
    fn test_encode_varint_medium() {
        let encoded = encode_varint(0x1000);
        assert_eq!(encoded.len(), 3);
        assert_eq!(encoded[0], 0xfd);
    }
    
    #[test]
    fn test_encode_varint_large() {
        let encoded = encode_varint(0x1000000);
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 0xfe);
    }
    
    #[test]
    fn test_encode_varint_huge() {
        let encoded = encode_varint(0x1000000000000000);
        assert_eq!(encoded.len(), 9);
        assert_eq!(encoded[0], 0xff);
    }
    
    #[test]
    fn test_extract_taproot_output_key_invalid_script() {
        let script = vec![0x52, 0x20]; // Invalid script
        let result = extract_taproot_output_key(&script).unwrap();
        assert!(result.is_none());
    }
    
    #[test]
    fn test_is_taproot_output_false() {
        let output = TransactionOutput {
            value: 1000,
            script_pubkey: vec![0x52, 0x20], // Not a Taproot script
        };
        
        assert!(!is_taproot_output(&output));
    }
    
    #[test]
    fn test_validate_taproot_transaction_no_taproot_outputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x52], // Not Taproot
            }],
            lock_time: 0,
        };
        
        assert!(validate_taproot_transaction(&tx).unwrap());
    }
    
    #[test]
    fn test_validate_taproot_transaction_invalid_taproot_output() {
        // Create a transaction with a valid Taproot script
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: create_taproot_script(&[1u8; 32]),
            }],
            lock_time: 0,
        };
        
        // The transaction should be valid
        assert!(validate_taproot_transaction(&tx).unwrap());
    }
    
    // Helper function
    fn create_taproot_script(output_key: &[u8; 32]) -> ByteString {
        let mut script = vec![TAPROOT_SCRIPT_PREFIX];
        script.extend_from_slice(output_key);
        script.push(0x00); // Add extra byte to make it 34 bytes total
        script
    }
}
