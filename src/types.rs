//! Core Bitcoin types for consensus validation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Hash type: 256-bit hash
pub type Hash = [u8; 32];

/// Byte string type
pub type ByteString = Vec<u8>;

/// Natural number type
pub type Natural = u64;

/// Integer type  
pub type Integer = i64;

/// OutPoint: 𝒪 = ℍ × ℕ
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub hash: Hash,
    pub index: Natural,
}

/// Transaction Input: ℐ = 𝒪 × 𝕊 × ℕ
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInput {
    pub prevout: OutPoint,
    pub script_sig: ByteString,
    pub sequence: Natural,
}

/// Transaction Output: 𝒯 = ℤ × 𝕊
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub value: Integer,
    pub script_pubkey: ByteString,
}

/// Transaction: 𝒯𝒳 = ℕ × ℐ* × 𝒯* × ℕ
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: Natural,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: Natural,
}

/// Block Header: ℋ = ℤ × ℍ × ℍ × ℕ × ℕ × ℕ
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: Integer,
    pub prev_block_hash: Hash,
    pub merkle_root: Hash,
    pub timestamp: Natural,
    pub bits: Natural,
    pub nonce: Natural,
}

/// Block: ℬ = ℋ × 𝒯𝒳*
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

/// UTXO: 𝒰 = ℤ × 𝕊 × ℕ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXO {
    pub value: Integer,
    pub script_pubkey: ByteString,
    pub height: Natural,
}

/// UTXO Set: 𝒰𝒮 = 𝒪 → 𝒰
pub type UtxoSet = HashMap<OutPoint, UTXO>;

/// Validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid(String),
}

/// Script execution context
#[derive(Debug, Clone)]
pub struct ScriptContext {
    pub script_sig: ByteString,
    pub script_pubkey: ByteString,
    pub witness: Option<ByteString>,
    pub flags: u32,
}

/// Block validation context
#[derive(Debug, Clone)]
pub struct BlockContext {
    pub height: Natural,
    pub prev_headers: Vec<BlockHeader>,
    pub utxo_set: UtxoSet,
}
