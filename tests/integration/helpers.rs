//! Shared helpers for integration tests (connect_block API, script verification).

use blvm_consensus::opcodes::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use blvm_consensus::script::flags::{
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
};
use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::segwit::Witness;
use blvm_consensus::types::{BlockHeader, ByteString, Network};
use blvm_consensus::{Block, Transaction};

pub const BIP65_BIP112_FLAGS: u32 =
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;

pub fn merkle_root_for_tx(tx: &Transaction) -> [u8; 32] {
    blvm_consensus::mining::calculate_merkle_root(std::slice::from_ref(tx)).unwrap()
}

pub fn sample_prev_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [1; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    }
}

pub fn sample_prev_headers() -> (BlockHeader, Vec<BlockHeader>) {
    let h = sample_prev_header();
    (h.clone(), vec![h.clone(), h])
}

pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
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

pub fn push_locktime_script(locktime: u64, opcode: u8) -> Vec<u8> {
    let mut script = Vec::new();
    let bytes = encode_script_int(locktime);
    push_data(&mut script, &bytes);
    script.push(opcode);
    script
}

pub fn per_tx_witnesses(block: &Block) -> Vec<Vec<Witness>> {
    block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect()
}

pub fn encode_script_int(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut result = Vec::new();
    let mut n = value;
    while n > 0 {
        result.push((n & 0xff) as u8);
        n >>= 8;
    }
    if result.last().is_some_and(|&b| b & 0x80 != 0) {
        result.push(0x00);
    }
    result
}

pub fn verify_input_script(
    tx: &Transaction,
    input_index: usize,
    flags: u32,
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    sigversion: SigVersion,
) -> blvm_consensus::error::Result<bool> {
    let input = &tx.inputs[input_index];
    let sp = input.script_sig.as_ref();
    let pv = vec![0i64; tx.inputs.len()];
    let psp: Vec<&[u8]> = vec![&[]; tx.inputs.len()];
    verify_script_with_context_full(
        sp,
        sp,
        None,
        flags,
        tx,
        input_index,
        &pv,
        &psp,
        block_height,
        median_time_past,
        Network::Mainnet,
        sigversion,
        #[cfg(feature = "production")]
        None,
        None,
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

pub fn verify_against_utxo(
    tx: &Transaction,
    script_sig: &ByteString,
    script_pubkey: &[u8],
    prevout_value: i64,
    flags: u32,
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    sigversion: SigVersion,
) -> blvm_consensus::error::Result<bool> {
    let pv = vec![prevout_value];
    let psp: Vec<&[u8]> = vec![script_pubkey];
    verify_script_with_context_full(
        script_sig,
        script_pubkey,
        None,
        flags,
        tx,
        0,
        &pv,
        &psp,
        block_height,
        median_time_past,
        Network::Mainnet,
        sigversion,
        #[cfg(feature = "production")]
        None,
        None,
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
