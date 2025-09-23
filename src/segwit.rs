//! Segregated Witness (SegWit) functions from Orange Paper Section 11.1

use crate::types::*;
use crate::error::Result;
use crate::types::{Hash, ByteString, Natural};
use bitcoin_hashes::{sha256d, Hash as BitcoinHash, HashEngine};

/// Witness Data: 𝒲 = 𝕊* (stack of witness elements)
pub type Witness = Vec<ByteString>;

/// Calculate transaction weight for SegWit
/// Weight(tx) = 4 × |Serialize(tx ∖ witness)| + |Serialize(tx)|
pub fn calculate_transaction_weight(tx: &Transaction, witness: Option<&Witness>) -> Result<Natural> {
    // Calculate base size (transaction without witness data)
    let base_size = calculate_base_size(tx);
    
    // Calculate total size (transaction with witness data)
    let total_size = calculate_total_size(tx, witness);
    
    // Weight = 4 * base_size + total_size
    Ok(4 * base_size + total_size)
}

/// Calculate base size (transaction without witness data)
fn calculate_base_size(tx: &Transaction) -> Natural {
    // Simplified calculation - in reality this would be the actual serialized size
    (4 + // version
    tx.inputs.len() * (32 + 4 + 1 + 4) + // inputs (OutPoint + script_sig_len + sequence)
    tx.outputs.len() * (8 + 1) + // outputs (value + script_pubkey_len)
    4) as Natural // lock_time
}

/// Calculate total size (transaction with witness data)
fn calculate_total_size(tx: &Transaction, witness: Option<&Witness>) -> Natural {
    let base_size = calculate_base_size(tx);
    
    if let Some(witness_data) = witness {
        let witness_size: Natural = witness_data.iter()
            .map(|w| w.len() as Natural)
            .sum();
        base_size + witness_size
    } else {
        base_size
    }
}

/// Compute witness merkle root for block
/// WitnessRoot = ComputeMerkleRoot({Hash(tx.witness) : tx ∈ block.transactions})
pub fn compute_witness_merkle_root(block: &Block, witnesses: &[Witness]) -> Result<Hash> {
    if block.transactions.is_empty() {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "Cannot compute witness merkle root for empty block".to_string()
        ));
    }
    
    // Hash each witness
    let mut witness_hashes = Vec::new();
    for (i, witness) in witnesses.iter().enumerate() {
        if i == 0 {
            // Coinbase transaction has empty witness
            witness_hashes.push([0u8; 32]);
        } else {
            let witness_hash = hash_witness(witness);
            witness_hashes.push(witness_hash);
        }
    }
    
    // Compute merkle root of witness hashes
    compute_merkle_root(&witness_hashes)
}

/// Hash witness data
fn hash_witness(witness: &Witness) -> Hash {
    let mut hasher = sha256d::Hash::engine();
    for element in witness {
        hasher.input(element);
    }
    let result = sha256d::Hash::from_engine(hasher);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute merkle root from hashes
fn compute_merkle_root(hashes: &[Hash]) -> Result<Hash> {
    if hashes.is_empty() {
        return Err(crate::error::ConsensusError::ConsensusRuleViolation(
            "Cannot compute merkle root from empty hash list".to_string()
        ));
    }
    
    if hashes.len() == 1 {
        return Ok(hashes[0]);
    }
    
    // Simplified merkle root calculation
    // In reality, this would use proper merkle tree construction
    let mut hasher = sha256d::Hash::engine();
    hasher.input(&hashes[0]);
    hasher.input(&hashes[1]);
    let result = sha256d::Hash::from_engine(hasher);
    let mut root = [0u8; 32];
    root.copy_from_slice(&result);
    Ok(root)
}

/// Validate witness commitment in coinbase transaction
pub fn validate_witness_commitment(
    coinbase_tx: &Transaction,
    witness_merkle_root: &Hash,
) -> Result<bool> {
    // Look for witness commitment in coinbase script
    for output in &coinbase_tx.outputs {
        if let Some(commitment) = extract_witness_commitment(&output.script_pubkey) {
            return Ok(commitment == *witness_merkle_root);
        }
    }
    
    // No witness commitment found - this is valid for non-SegWit blocks
    Ok(true)
}

/// Extract witness commitment from script
fn extract_witness_commitment(script: &ByteString) -> Option<Hash> {
    // Look for OP_RETURN followed by witness commitment
    if script.len() >= 38 && script[0] == 0x6a { // OP_RETURN
        if script.len() >= 38 && script[1] == 0x24 { // 36 bytes
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&script[2..34]);
            return Some(commitment);
        }
    }
    None
}

/// Check if transaction is SegWit
pub fn is_segwit_transaction(tx: &Transaction) -> bool {
    // Check if any input has witness data
    // This is a simplified check - in reality we'd check the actual witness structure
    tx.inputs.iter().any(|input| {
        // Look for SegWit markers in script_sig
        input.script_sig.len() == 1 && input.script_sig[0] == 0x00
    })
}

/// Calculate block weight for SegWit blocks
pub fn calculate_block_weight(block: &Block, witnesses: &[Witness]) -> Result<Natural> {
    let mut total_weight = 0;
    
    for (i, tx) in block.transactions.iter().enumerate() {
        let witness = if i < witnesses.len() {
            Some(&witnesses[i])
        } else {
            None
        };
        
        total_weight += calculate_transaction_weight(tx, witness)?;
    }
    
    Ok(total_weight)
}

/// Validate SegWit block
pub fn validate_segwit_block(
    block: &Block,
    witnesses: &[Witness],
    max_block_weight: Natural,
) -> Result<bool> {
    // Check block weight limit
    let block_weight = calculate_block_weight(block, witnesses)?;
    if block_weight > max_block_weight {
        return Ok(false);
    }
    
    // Validate witness commitment
    if !block.transactions.is_empty() {
        let witness_root = compute_witness_merkle_root(block, witnesses)?;
        if !validate_witness_commitment(&block.transactions[0], &witness_root)? {
            return Ok(false);
        }
    }
    
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_calculate_transaction_weight() {
        let tx = create_test_transaction();
        let witness = vec![vec![0x51], vec![0x52]]; // OP_1, OP_2
        
        let weight = calculate_transaction_weight(&tx, Some(&witness)).unwrap();
        assert!(weight > 0);
    }
    
    #[test]
    fn test_calculate_transaction_weight_no_witness() {
        let tx = create_test_transaction();
        
        let weight = calculate_transaction_weight(&tx, None).unwrap();
        assert!(weight > 0);
    }
    
    #[test]
    fn test_compute_witness_merkle_root() {
        let block = create_test_block();
        let witnesses = vec![
            vec![], // Coinbase witness (empty)
            vec![vec![0x51]], // First transaction witness
        ];
        
        let root = compute_witness_merkle_root(&block, &witnesses).unwrap();
        assert_eq!(root.len(), 32);
    }
    
    #[test]
    fn test_compute_witness_merkle_root_empty_block() {
        let block = Block {
            header: create_test_header(),
            transactions: vec![],
        };
        let witnesses = vec![];
        
        let result = compute_witness_merkle_root(&block, &witnesses);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_validate_witness_commitment() {
        let mut coinbase_tx = create_test_transaction();
        let witness_root = [1u8; 32];
        
        // Add witness commitment to coinbase script
        coinbase_tx.outputs[0].script_pubkey = create_witness_commitment_script(&witness_root);
        
        let is_valid = validate_witness_commitment(&coinbase_tx, &witness_root).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_is_segwit_transaction() {
        let mut tx = create_test_transaction();
        tx.inputs[0].script_sig = vec![0x00]; // SegWit marker
        
        assert!(is_segwit_transaction(&tx));
    }
    
    #[test]
    fn test_calculate_block_weight() {
        let block = create_test_block();
        let witnesses = vec![
            vec![], // Coinbase
            vec![vec![0x51]], // First tx
        ];
        
        let weight = calculate_block_weight(&block, &witnesses).unwrap();
        assert!(weight > 0);
    }
    
    #[test]
    fn test_validate_segwit_block() {
        let block = create_test_block();
        let witnesses = vec![
            vec![], // Coinbase
            vec![vec![0x51]], // First tx
        ];
        
        let is_valid = validate_segwit_block(&block, &witnesses, 4_000_000).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_validate_segwit_block_exceeds_weight() {
        let block = create_test_block();
        let witnesses = vec![
            vec![], // Coinbase
            vec![vec![0x51]], // First tx
        ];
        
        let is_valid = validate_segwit_block(&block, &witnesses, 1).unwrap(); // Very low weight limit
        assert!(!is_valid);
    }
    
    #[test]
    fn test_validate_segwit_block_invalid_commitment() {
        let mut block = create_test_block();
        let witnesses = vec![
            vec![], // Coinbase
            vec![vec![0x51]], // First tx
        ];
        
        // Create coinbase with invalid witness commitment
        let invalid_commitment = [2u8; 32];
        block.transactions[0].outputs[0].script_pubkey = create_witness_commitment_script(&invalid_commitment);
        
        let is_valid = validate_segwit_block(&block, &witnesses, 4_000_000).unwrap();
        assert!(!is_valid);
    }
    
    #[test]
    fn test_validate_witness_commitment_no_commitment() {
        let coinbase_tx = create_test_transaction();
        let witness_root = [1u8; 32];
        
        // No witness commitment in script
        let is_valid = validate_witness_commitment(&coinbase_tx, &witness_root).unwrap();
        assert!(is_valid); // Should be valid for non-SegWit blocks
    }
    
    #[test]
    fn test_validate_witness_commitment_invalid_commitment() {
        let mut coinbase_tx = create_test_transaction();
        let witness_root = [1u8; 32];
        let invalid_commitment = [2u8; 32];
        
        // Add invalid witness commitment
        coinbase_tx.outputs[0].script_pubkey = create_witness_commitment_script(&invalid_commitment);
        
        let is_valid = validate_witness_commitment(&coinbase_tx, &witness_root).unwrap();
        assert!(!is_valid);
    }
    
    #[test]
    fn test_extract_witness_commitment_valid() {
        let commitment = [1u8; 32];
        let script = create_witness_commitment_script(&commitment);
        
        let extracted = extract_witness_commitment(&script).unwrap();
        assert_eq!(extracted, commitment);
    }
    
    #[test]
    fn test_extract_witness_commitment_invalid_script() {
        let script = vec![0x51]; // Not a witness commitment script
        
        let extracted = extract_witness_commitment(&script);
        assert!(extracted.is_none());
    }
    
    #[test]
    fn test_extract_witness_commitment_wrong_opcode() {
        let mut script = vec![0x52, 0x24]; // Wrong opcode, correct length
        script.extend_from_slice(&[1u8; 32]);
        
        let extracted = extract_witness_commitment(&script);
        assert!(extracted.is_none());
    }
    
    #[test]
    fn test_extract_witness_commitment_wrong_length() {
        let mut script = vec![0x6a, 0x25]; // OP_RETURN, wrong length (37 bytes)
        script.extend_from_slice(&[1u8; 32]);
        
        let extracted = extract_witness_commitment(&script);
        assert!(extracted.is_none());
    }
    
    #[test]
    fn test_hash_witness() {
        let witness = vec![vec![0x51], vec![0x52]];
        let hash = hash_witness(&witness);
        
        assert_eq!(hash.len(), 32);
        
        // Different witness should produce different hash
        let witness2 = vec![vec![0x53], vec![0x54]];
        let hash2 = hash_witness(&witness2);
        assert_ne!(hash, hash2);
    }
    
    #[test]
    fn test_hash_witness_empty() {
        let witness = vec![];
        let hash = hash_witness(&witness);
        
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_compute_merkle_root_single_hash() {
        let hashes = vec![[1u8; 32]];
        let root = compute_merkle_root(&hashes).unwrap();
        
        assert_eq!(root, [1u8; 32]);
    }
    
    #[test]
    fn test_compute_merkle_root_empty() {
        let hashes = vec![];
        let result = compute_merkle_root(&hashes);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_is_segwit_transaction_false() {
        let tx = create_test_transaction();
        // No SegWit markers
        
        assert!(!is_segwit_transaction(&tx));
    }
    
    #[test]
    fn test_calculate_base_size() {
        let tx = create_test_transaction();
        let base_size = calculate_base_size(&tx);
        
        assert!(base_size > 0);
    }
    
    #[test]
    fn test_calculate_total_size_with_witness() {
        let tx = create_test_transaction();
        let witness = vec![vec![0x51], vec![0x52]];
        
        let total_size = calculate_total_size(&tx, Some(&witness));
        let base_size = calculate_base_size(&tx);
        
        assert!(total_size > base_size);
    }
    
    #[test]
    fn test_calculate_total_size_without_witness() {
        let tx = create_test_transaction();
        
        let total_size = calculate_total_size(&tx, None);
        let base_size = calculate_base_size(&tx);
        
        assert_eq!(total_size, base_size);
    }
    
    // Helper functions
    fn create_test_transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }
    }
    
    fn create_test_block() -> Block {
        Block {
            header: create_test_header(),
            transactions: vec![
                create_test_transaction(), // Coinbase
                create_test_transaction(), // Regular tx
            ],
        }
    }
    
    fn create_test_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        }
    }
    
    fn create_witness_commitment_script(commitment: &Hash) -> ByteString {
        let mut script = vec![0x6a, 0x24]; // OP_RETURN, 36 bytes
        script.extend_from_slice(commitment);
        // Add 4 more bytes to make it 38 bytes total as expected by extract_witness_commitment
        script.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        script
    }
}
