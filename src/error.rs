//! Error types for consensus validation

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),
    
    #[error("Block validation failed: {0}")]
    BlockValidation(String),
    
    #[error("Script execution failed: {0}")]
    ScriptExecution(String),
    
    #[error("UTXO not found: {0}")]
    UtxoNotFound(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Invalid proof of work: {0}")]
    InvalidProofOfWork(String),
    
    #[error("Economic validation failed: {0}")]
    EconomicValidation(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Consensus rule violation: {0}")]
    ConsensusRuleViolation(String),
}

pub type Result<T> = std::result::Result<T, ConsensusError>;
