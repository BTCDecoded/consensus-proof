//! Helper functions for BIP integration tests
//!
//! Provides utilities for creating test transactions, block contexts, and
//! validation scenarios for testing BIP65, BIP112, and related BIPs.

use blvm_consensus::bip113::get_median_time_past;
use blvm_consensus::opcodes::*;
use blvm_consensus::script::verify_script_with_context_full;
use blvm_consensus::*;

/// Create a block header with specified timestamp. Uses library test_utils when feature is enabled.
#[cfg(feature = "test-utils")]
pub use blvm_consensus::test_utils::create_test_header;

#[cfg(not(feature = "test-utils"))]
/// Create a block header with specified timestamp
pub fn create_test_header(timestamp: u64, prev_hash: [u8; 32]) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root: [0u8; 32],
        timestamp,
        bits: 0x1d00ffff,
        nonce: 0,
    }
}

/// Create a chain of block headers with timestamps
pub fn create_header_chain(timestamps: Vec<u64>) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let mut prev_hash = [0u8; 32];

    for timestamp in timestamps {
        let header = create_test_header(timestamp, prev_hash);
        // Use a simple hash derivation for testing
        prev_hash = {
            let mut hash = [0u8; 32];
            hash[0..8].copy_from_slice(&timestamp.to_le_bytes());
            hash[8..16].copy_from_slice(&prev_hash[0..8]);
            hash
        };
        headers.push(header);
    }

    headers
}

/// Calculate median time-past for testing
pub fn get_test_median_time_past(timestamps: Vec<u64>) -> u64 {
    let headers = create_header_chain(timestamps);
    get_median_time_past(&headers)
}

/// Push raw bytes using standard script push encoding.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(OP_PUSHDATA1);
        script.push(len as u8);
    } else if len <= 65535 {
        script.push(OP_PUSHDATA2);
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(OP_PUSHDATA4);
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

fn encode_script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let neg = n < 0;
    let mut absvalue = n.unsigned_abs();
    let mut result = Vec::new();
    while absvalue > 0 {
        result.push((absvalue & 0xff) as u8);
        absvalue >>= 8;
    }
    if result.last().is_some_and(|&b| b & 0x80 != 0) {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *result.last_mut().unwrap() |= 0x80;
    }
    result
}

fn push_script_num(script: &mut Vec<u8>, n: i64) {
    if n == -1 {
        script.push(OP_1NEGATE);
        return;
    }
    if (0..=16).contains(&n) {
        script.push(if n == 0 { OP_0 } else { OP_1 + (n as u8) - 1 });
        return;
    }
    push_data(script, &encode_script_num(n));
}

/// Encode a value as script integer push (minimal CScriptNum encoding).
pub fn encode_script_int(value: u32) -> Vec<u8> {
    let mut script = Vec::new();
    push_script_num(&mut script, value as i64);
    script
}

/// Create a transaction with CLTV opcode
pub fn create_cltv_transaction(
    locktime: u32,
    required_locktime: u32,
    script_sig: Vec<u8>,
) -> Transaction {
    let mut script = script_sig.clone();

    // Add required locktime to script
    script.extend_from_slice(&encode_script_int(required_locktime));

    // Add CLTV opcode
    script.push(OP_CHECKLOCKTIMEVERIFY);

    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: script,
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(), // OP_1
        }]
        .into(),
        lock_time: locktime as u64,
    }
}

/// Create a transaction with CSV opcode
pub fn create_csv_transaction(
    input_sequence: u32,
    required_sequence: u32,
    script_sig: Vec<u8>,
) -> Transaction {
    let mut script = script_sig.clone();

    // Add required sequence to script
    script.extend_from_slice(&encode_script_int(required_sequence));

    // Add CSV opcode
    script.push(OP_CHECKSEQUENCEVERIFY);

    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: script,
            sequence: input_sequence as u64,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1000,
            script_pubkey: vec![OP_1].into(), // OP_1
        }]
        .into(),
        lock_time: 0,
    }
}

/// Validate a transaction with CLTV/CSV using full context
pub fn validate_with_context(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    block_height: u64,
    median_time_past: u64,
    flags: u32,
) -> Result<bool, ConsensusError> {
    // Get the scriptPubkey from UTXO
    let input = &tx.inputs[0];
    let utxo = utxo_set
        .get(&input.prevout)
        .ok_or_else(|| ConsensusError::UtxoNotFound("UTXO not found".into()))?;

    let pv = vec![utxo.value];
    let psp: Vec<&[u8]> = vec![utxo.script_pubkey.as_ref()];

    // Verify script with context (now supports block height and median time-past)
    verify_script_with_context_full(
        &input.script_sig,
        &utxo.script_pubkey,
        None, // No witness for basic tests
        flags,
        tx,
        0, // Input index
        &pv,
        &psp,
        Some(block_height),     // Optional block height
        Some(median_time_past), // Optional median time-past
        blvm_consensus::types::Network::Mainnet,
        blvm_consensus::script::SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None, // precomputed_bip143
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    )
}
