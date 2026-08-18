//! Transaction hash calculation for signature verification
//!
//! Implements Bitcoin's transaction sighash algorithm for ECDSA signature verification.
//! This is critical for proper signature validation in script execution.
//!
//! Performance optimizations:
//! - Precomputed sighash templates for common transaction patterns

use crate::crypto::OptimizedSha256;
use crate::error::Result;
use crate::types::*;
use blvm_spec_lock::spec_locked;

// OPTIMIZATION: Inline varint encoding helper to avoid Vec allocations in hot path
#[inline]
fn write_varint_to_vec(vec: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        vec.push(value as u8);
    } else if value <= 0xffff {
        vec.push(0xfd);
        vec.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        vec.push(0xfe);
        vec.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        vec.push(0xff);
        vec.extend_from_slice(&value.to_le_bytes());
    }
}

/// Serialize scriptCode bytes for legacy sighash, stripping OP_CODESEPARATOR (0xab) opcodes.
///
/// Legacy sighash scriptCode serialization: remove each OP_CODESEPARATOR (0xab) opcode
/// from the byte stream (not bytes inside push-data payloads). Orange Paper §5.1.1.
#[spec_locked("5.1.1", "SerializeScriptCode")]
pub fn serialize_script_code_for_legacy_sighash(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    append_stripped_codeseparators(&mut out, script);
    out
}

/// BIP143 scriptCode for P2WPKH: P2PKH expansion of the 20-byte pubkey hash (BIP143 §4.3).
#[spec_locked("11.1.9.1", "DeriveWitnessScriptCode")]
pub fn derive_bip143_script_code_p2wpkh(pubkey_hash: &[u8; 20]) -> [u8; 25] {
    use crate::opcodes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, PUSH_20_BYTES};
    let mut script_code = [0u8; 25];
    script_code[0] = OP_DUP;
    script_code[1] = OP_HASH160;
    script_code[2] = PUSH_20_BYTES;
    script_code[3..23].copy_from_slice(pubkey_hash);
    script_code[23] = OP_EQUALVERIFY;
    script_code[24] = OP_CHECKSIG;
    script_code
}

/// Derive BIP143 scriptCode for SegWit v0 spends.
///
/// - P2WPKH program (`OP_0 PUSH_20`): P2PKH expansion via [`derive_bip143_script_code_p2wpkh`].
/// - P2WSH program (`OP_0 PUSH_32`): full witness script (last witness stack element).
#[spec_locked("11.1.9.1", "DeriveWitnessScriptCode")]
pub fn derive_bip143_script_code(
    witness_program: &[u8],
    witness_script: Option<&[u8]>,
) -> Option<Vec<u8>> {
    use crate::opcodes::{OP_0, PUSH_20_BYTES, PUSH_32_BYTES};
    if witness_program.len() == 22
        && witness_program[0] == OP_0
        && witness_program[1] == PUSH_20_BYTES
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&witness_program[2..22]);
        return Some(derive_bip143_script_code_p2wpkh(&hash).to_vec());
    }
    if witness_program.len() == 34
        && witness_program[0] == OP_0
        && witness_program[1] == PUSH_32_BYTES
    {
        return witness_script.map(|s| s.to_vec());
    }
    None
}

/// Write scriptCode into a legacy sighash preimage (varint length + bytes).
///
/// Strips each OP_CODESEPARATOR opcode from both the length prefix and the byte stream.
/// Only bytes at actual opcode positions are removed — 0xab inside push-data payloads
/// is preserved. Orange Paper §5.1.1.
#[inline]
fn write_script_code_for_sighash(preimage: &mut Vec<u8>, code: &[u8]) {
    let n_codeseps = count_opcode_codeseparators(code);
    write_varint_to_vec(preimage, (code.len() - n_codeseps) as u64);
    if n_codeseps == 0 {
        preimage.extend_from_slice(code);
    } else {
        append_stripped_codeseparators(preimage, code);
    }
}

/// Count OP_CODESEPARATOR (0xab) opcodes in a script, skipping bytes inside push-data.
#[inline]
fn count_opcode_codeseparators(script: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        let advance = if (0x01..=0x4b).contains(&op) {
            1 + op as usize
        } else if op == 0x4c {
            if i + 1 >= script.len() {
                break;
            }
            2 + script[i + 1] as usize
        } else if op == 0x4d {
            if i + 2 >= script.len() {
                break;
            }
            3 + u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize
        } else if op == 0x4e {
            if i + 4 >= script.len() {
                break;
            }
            5 + u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
                as usize
        } else {
            if op == 0xab {
                count += 1;
            }
            1
        };
        i += advance.min(script.len() - i);
    }
    count
}

/// Append script bytes to `out`, skipping OP_CODESEPARATOR opcode bytes.
fn append_stripped_codeseparators(out: &mut Vec<u8>, code: &[u8]) {
    let mut i = 0usize;
    while i < code.len() {
        let op = code[i];
        if (0x01..=0x4b).contains(&op) {
            let end = (i + 1 + op as usize).min(code.len());
            out.extend_from_slice(&code[i..end]);
            i = end;
        } else if op == 0x4c {
            if i + 1 >= code.len() {
                out.push(op);
                break;
            }
            let len = code[i + 1] as usize;
            let end = (i + 2 + len).min(code.len());
            out.extend_from_slice(&code[i..end]);
            i = end;
        } else if op == 0x4d {
            if i + 2 >= code.len() {
                out.extend_from_slice(&code[i..]);
                break;
            }
            let len = u16::from_le_bytes([code[i + 1], code[i + 2]]) as usize;
            let end = (i + 3 + len).min(code.len());
            out.extend_from_slice(&code[i..end]);
            i = end;
        } else if op == 0x4e {
            if i + 4 >= code.len() {
                out.extend_from_slice(&code[i..]);
                break;
            }
            let len =
                u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]) as usize;
            let end = (i + 5 + len).min(code.len());
            out.extend_from_slice(&code[i..end]);
            i = end;
        } else if op == 0xab {
            i += 1; // skip OP_CODESEPARATOR
        } else {
            out.push(op);
            i += 1;
        }
    }
}

#[cfg(feature = "production")]
use lru::LruCache;
#[cfg(feature = "production")]
use rustc_hash::{FxHashMap, FxHasher};
#[cfg(feature = "production")]
use std::cell::RefCell;
#[cfg(feature = "production")]
use std::hash::{Hash as StdHash, Hasher};

/// Per-block sighash cache: (prevout, code_hash, sighash_byte) -> hash.
/// Uses hash of scriptCode instead of owned Vec to avoid allocation on insert.
#[cfg(feature = "production")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SighashCacheKey {
    prevout: crate::types::OutPoint,
    code_hash: u64,
    sighash_byte: u8,
}

#[cfg(feature = "production")]
impl std::hash::Hash for SighashCacheKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.code_hash);
    }
}

#[cfg(feature = "production")]
pub type SighashMidstateCache =
    std::sync::Arc<std::sync::Mutex<FxHashMap<SighashCacheKey, [u8; 32]>>>;

/// Thread-local midstate cache: (prevout, code_hash, sighash_byte) -> hash. Avoids Mutex contention
/// across script-check workers. Used when block passes None (parallel script-check / rayon path).
/// LRU-bounded: unbounded growth OOM'd sort-merge step6 at ~450k blocks (~80 GiB RSS).
#[cfg(feature = "production")]
thread_local! {
    static SIGHASH_MIDSTATE_CACHE: RefCell<LruCache<SighashCacheKey, [u8; 32]>> = RefCell::new({
        // ATTR-rebind: P2PKH/sighash host binds collect HOL — larger TLS LRU (was 256k).
        let cap = std::env::var("BLVM_SIGHASH_MIDSTATE_CACHE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_048_576)
            .clamp(65_536, 2_097_152);
        LruCache::new(std::num::NonZeroUsize::new(cap).unwrap())
    });
}

#[cfg(feature = "production")]
fn insert_midstate_cache(
    sighash_cache: Option<&SighashMidstateCache>,
    prevout: crate::types::OutPoint,
    code: &[u8],
    sighash_byte: u8,
    hash: [u8; 32],
) {
    let key_hash = sighash_cache_hash(&prevout, code, sighash_byte);
    let key = SighashCacheKey {
        prevout,
        code_hash: key_hash,
        sighash_byte,
    };
    if let Some(c) = sighash_cache {
        let _ = c.lock().map(|mut g| g.insert(key, hash));
    } else {
        SIGHASH_MIDSTATE_CACHE.with(|cell| {
            cell.borrow_mut().put(key, hash);
        });
    }
}

/// Hash (prevout, code, sighash_byte) with FxHasher for cache bucket lookup.
#[cfg(feature = "production")]
#[inline]
fn sighash_cache_hash(prevout: &crate::types::OutPoint, code: &[u8], sighash_byte: u8) -> u64 {
    let mut hasher = FxHasher::default();
    prevout.hash(&mut hasher);
    code.hash(&mut hasher);
    sighash_byte.hash(&mut hasher);
    hasher.finish()
}

/// Sighash cache: first_hash (SHA256 of preimage) -> final hash (double-SHA256).
/// Thread-local to avoid Mutex contention across script-check workers.
/// Saves one SHA256 per cache hit. LRU evicts oldest entries when capacity reached.
/// Capacity: 256k default (BLVM_SIGHASH_CACHE_SIZE); 65k min. IBD: larger helps reorg/assumeutxo.
#[cfg(feature = "production")]
thread_local! {
    static SIGHASH_CACHE: RefCell<LruCache<[u8; 32], [u8; 32]>> = RefCell::new({
        let cap = std::env::var("BLVM_SIGHASH_CACHE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(262_144)
            .clamp(65_536, 2_097_152);
        LruCache::new(std::num::NonZeroUsize::new(cap).unwrap())
    });
}

/// Thread-local buffer for sighash preimage (avoids ~3-6k Vec allocs/block in non-template path)
#[cfg(feature = "production")]
thread_local! {
    static SIGHASH_PREIMAGE_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(4096));
}

/// Thread-local buffer for Bip143PrecomputedHashes (prevouts/sequence/outputs serialization)
/// Reused across hash_prevouts, hash_sequence, hash_outputs to avoid 3 Vec allocs per SegWit tx
#[cfg(feature = "production")]
thread_local! {
    static BIP143_SERIALIZE_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(131_072)); // 128KB, covers max tx
}

/// Thread-local buffer for BIP143 per-input sighash preimage (avoids alloc per input in batch)
#[cfg(feature = "production")]
thread_local! {
    static BIP143_PREIMAGE_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(1024));
}

/// Thread-local buffer for SIGHASH_SINGLE per-output serialization (8+var+script < 256 bytes)
#[cfg(feature = "production")]
thread_local! {
    static BIP143_SINGLE_OUTPUT_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(256));
}

/// Thread-local reusable preimage buffers for batch_compute_legacy_sighashes.
/// Avoids N Vec allocs per block.
#[cfg(feature = "production")]
thread_local! {
    static LEGACY_BATCH_PREIMAGES: std::cell::RefCell<Vec<Vec<u8>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// SIGHASH types for transaction signature verification
///
/// IMPORTANT: The enum values match the canonical sighash bytes used in sighash computation.
/// Early Bitcoin allowed sighash type 0x00 (treated as SIGHASH_ALL behavior), which we
/// Wraps the raw sighash byte from the signature, preserving its exact value for
/// preimage serialization. consensus uses the raw byte directly in the sighash
/// preimage — before STRICTENC activation (BIP66), ANY sighash byte was accepted.
/// The base type is determined by masking with 0x1f: NONE=2, SINGLE=3, else ALL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SighashType(pub u8);

impl SighashType {
    // Standard sighash type constants
    pub const ALL_LEGACY: Self = SighashType(0x00);
    pub const ALL: Self = SighashType(0x01);
    pub const NONE: Self = SighashType(0x02);
    pub const SINGLE: Self = SighashType(0x03);
    pub const ALL_ANYONECANPAY: Self = SighashType(0x81);
    pub const NONE_ANYONECANPAY: Self = SighashType(0x82);
    pub const SINGLE_ANYONECANPAY: Self = SighashType(0x83);

    /// Create from raw sighash byte — accepts ANY value (pre-STRICTENC compatibility).
    /// consensus determines behavior from `byte & 0x1f` and uses the raw byte in the preimage.
    pub fn from_byte(byte: u8) -> Self {
        SighashType(byte)
    }

    /// Raw byte value for preimage serialization
    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }

    /// Base sighash type (lower 5 bits), matching consensus's `nHashType & 0x1f`
    pub fn base_type(&self) -> u8 {
        self.0 & 0x1f
    }

    /// Whether ANYONECANPAY flag is set (bit 7)
    pub fn is_anyonecanpay(&self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Whether this has SIGHASH_ALL behavior (base type is not NONE or SINGLE)
    pub fn is_all(&self) -> bool {
        let base = self.base_type();
        base != 0x02 && base != 0x03
    }

    /// Whether base type is SIGHASH_NONE
    pub fn is_none(&self) -> bool {
        self.base_type() == 0x02
    }

    /// Whether base type is SIGHASH_SINGLE
    pub fn is_single(&self) -> bool {
        self.base_type() == 0x03
    }
}

/// Common sighash patterns (documentation; cache applies to all).
#[cfg(feature = "production")]
#[allow(dead_code)]
#[inline]
fn is_cacheable_sighash_pattern(
    tx: &Transaction,
    input_index: usize,
    sighash_type: SighashType,
) -> bool {
    if sighash_type.is_anyonecanpay() {
        return false;
    }
    // SIGHASH_ALL: 1-in-1-out, 1-in-2-out, 2-in-1-out, 2-in-2-out, 1-in-N, N-in-1 (N<=4)
    let base = sighash_type.base_type();
    if base == 0x01 || base == 0x00 {
        let ni = tx.inputs.len();
        let no = tx.outputs.len();
        (ni == 1 && (1..=4).contains(&no))
            || ((1..=4).contains(&ni) && no == 1)
            || (ni == 2 && no == 2)
            || (ni == 1 && no == 1)
    } else if base == 0x02 {
        // SIGHASH_NONE: no outputs
        !tx.inputs.is_empty() && tx.inputs.len() <= 4
    } else if base == 0x03 {
        // SIGHASH_SINGLE: output at input index
        input_index < tx.outputs.len() && tx.inputs.len() <= 4
    } else {
        false
    }
}

/// Compute sighash with cache. First hash (of preimage) is cache key.
/// On hit: return cached double-SHA256. On miss: compute, cache, return.
/// Uses OptimizedSha256 (SHA-NI when available) for ~10× faster hashing vs generic sha2.
/// Thread-local cache avoids Mutex contention across script-check workers.
#[cfg(feature = "production")]
fn sighash_with_cache(preimage: &[u8]) -> Hash {
    let hasher = OptimizedSha256::new();
    let first_hash: [u8; 32] = hasher.hash(preimage);
    SIGHASH_CACHE.with(|cell| {
        let mut cache = cell.borrow_mut();
        if let Some(cached) = cache.get(&first_hash) {
            return *cached;
        }
        let second_hash = hasher.hash(&first_hash);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second_hash);
        cache.put(first_hash, result);
        result
    })
}

/// Compute legacy sighash without any caching layers.
/// Uses incremental SHA256 - feeds data directly to the hasher, avoiding
/// the preimage buffer allocation and double memory pass.
///
/// Note: plain-ALL specialized nocache (+ bucket WILLNEED default-on) REVERT S10
/// 187.9 vs champ 197.9 (2026-07-31); keep unified path.
#[cfg(feature = "production")]
#[spec_locked("5.1.1", "CalculateSighash")]
#[inline]
pub fn compute_legacy_sighash_nocache(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    sighash_byte: u8,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let sighash_u32 = sighash_byte as u32;
    let base_type = sighash_u32 & 0x1f;
    let anyone_can_pay = (sighash_u32 & 0x80) != 0;
    let hash_none = base_type == 0x02;
    let hash_single = base_type == 0x03;

    if hash_single && input_index >= tx.outputs.len() {
        let mut result = [0u8; 32];
        result[0] = 1;
        return result;
    }

    let mut h = Sha256::new();
    h.update((tx.version as u32).to_le_bytes());

    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    update_varint(&mut h, n_inputs as u64);

    for i in 0..n_inputs {
        let actual_i = if anyone_can_pay { input_index } else { i };
        let input = &tx.inputs[actual_i];
        h.update(input.prevout.hash);
        h.update(input.prevout.index.to_le_bytes());

        if actual_i == input_index {
            update_varint(&mut h, script_code.len() as u64);
            h.update(script_code);
        } else {
            h.update([0u8]);
        }

        if actual_i != input_index && (hash_single || hash_none) {
            h.update(0u32.to_le_bytes());
        } else {
            h.update((input.sequence as u32).to_le_bytes());
        }
    }

    let n_outputs = if hash_none {
        0
    } else if hash_single {
        input_index + 1
    } else {
        tx.outputs.len()
    };
    update_varint(&mut h, n_outputs as u64);

    for i in 0..n_outputs {
        if hash_single && i != input_index {
            h.update((-1i64).to_le_bytes());
            h.update([0u8]);
        } else {
            let output = &tx.outputs[i];
            h.update(output.value.to_le_bytes());
            update_varint(&mut h, output.script_pubkey.len() as u64);
            h.update(output.script_pubkey.as_slice());
        }
    }

    h.update((tx.lock_time as u32).to_le_bytes());
    h.update(sighash_u32.to_le_bytes());

    let first_hash = h.finalize();
    let second_hash = Sha256::digest(first_hash);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second_hash);
    result
}

/// Helper: write varint directly to a sha2::Sha256 hasher (no intermediate buffer).
#[cfg(feature = "production")]
#[inline]
fn update_varint(hasher: &mut sha2::Sha256, value: u64) {
    use sha2::Digest;
    if value < 0xfd {
        hasher.update([value as u8]);
    } else if value <= 0xffff {
        hasher.update([0xfd]);
        hasher.update((value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        hasher.update([0xfe]);
        hasher.update((value as u32).to_le_bytes());
    } else {
        hasher.update([0xff]);
        hasher.update(value.to_le_bytes());
    }
}

/// Write varint to a byte buffer.
#[cfg(feature = "production")]
#[inline]
fn push_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Compute legacy sighash by pre-serializing the full preimage into a thread-local buffer,
/// then hashing in one pass. Reduces function call overhead vs streaming h.update() calls.
#[cfg(feature = "production")]
#[spec_locked("5.1.1", "CalculateSighash")]
#[inline]
pub fn compute_legacy_sighash_buffered(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    sighash_byte: u8,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let sighash_u32 = sighash_byte as u32;
    let base_type = sighash_u32 & 0x1f;
    let anyone_can_pay = (sighash_u32 & 0x80) != 0;
    let hash_none = base_type == 0x02;
    let hash_single = base_type == 0x03;

    if hash_single && input_index >= tx.outputs.len() {
        let mut result = [0u8; 32];
        result[0] = 1;
        return result;
    }

    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(4096));
    }

    BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();

        buf.extend_from_slice(&(tx.version as u32).to_le_bytes());

        let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
        push_varint(&mut buf, n_inputs as u64);

        for i in 0..n_inputs {
            let actual_i = if anyone_can_pay { input_index } else { i };
            let input = &tx.inputs[actual_i];
            buf.extend_from_slice(&input.prevout.hash);
            buf.extend_from_slice(&input.prevout.index.to_le_bytes());

            if actual_i == input_index {
                push_varint(&mut buf, script_code.len() as u64);
                buf.extend_from_slice(script_code);
            } else {
                buf.push(0u8);
            }

            if actual_i != input_index && (hash_single || hash_none) {
                buf.extend_from_slice(&0u32.to_le_bytes());
            } else {
                buf.extend_from_slice(&(input.sequence as u32).to_le_bytes());
            }
        }

        let n_outputs = if hash_none {
            0
        } else if hash_single {
            input_index + 1
        } else {
            tx.outputs.len()
        };
        push_varint(&mut buf, n_outputs as u64);

        for i in 0..n_outputs {
            if hash_single && i != input_index {
                buf.extend_from_slice(&(-1i64).to_le_bytes());
                buf.push(0u8);
            } else {
                let output = &tx.outputs[i];
                buf.extend_from_slice(&output.value.to_le_bytes());
                push_varint(&mut buf, output.script_pubkey.len() as u64);
                buf.extend_from_slice(&output.script_pubkey);
            }
        }

        buf.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
        buf.extend_from_slice(&sighash_u32.to_le_bytes());

        let first_hash = Sha256::digest(buf.as_slice());
        let second_hash = Sha256::digest(first_hash);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second_hash);
        result
    })
}

/// Batch-compute legacy sighashes for all inputs of a single transaction using
/// SHA256 forward midstate caching. For SIGHASH_ALL (most common), the SHA256 state
/// after processing inputs 0..i-1 with blank scripts is reused for input i,
/// cutting the O(N²) hashing work roughly in half.
///
/// Falls back to per-input compute for ANYONECANPAY/SINGLE/NONE hash types.
#[cfg(feature = "production")]
#[spec_locked("5.1.1", "CalculateSighash")]
pub fn compute_sighashes_batch(
    tx: &Transaction,
    script_codes: &[&[u8]],
    sighash_bytes: &[u8],
) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let n = tx.inputs.len();
    debug_assert_eq!(script_codes.len(), n);
    debug_assert_eq!(sighash_bytes.len(), n);

    let mut results = Vec::with_capacity(n);

    // Plain SIGHASH_ALL: base 0x01 *or* legacy 0x00 (same blanking; raw byte in trailer).
    let all_sighash_all = sighash_bytes.iter().all(|&b| {
        let base = (b as u32) & 0x1f;
        let acp = (b as u32) & 0x80;
        acp == 0 && (base == 0x01 || base == 0x00)
    });

    if !all_sighash_all || n <= 1 {
        for i in 0..n {
            results.push(compute_legacy_sighash_nocache(
                tx,
                i,
                script_codes[i],
                sighash_bytes[i],
            ));
        }
        return results;
    }

    // Pre-serialize outputs + locktime into reusable buffer
    let mut outputs_buf: Vec<u8> = Vec::with_capacity(tx.outputs.len() * 40 + 16);
    write_varint_to_vec(&mut outputs_buf, tx.outputs.len() as u64);
    for output in tx.outputs.iter() {
        outputs_buf.extend_from_slice(&output.value.to_le_bytes());
        write_varint_to_vec(&mut outputs_buf, output.script_pubkey.len() as u64);
        outputs_buf.extend_from_slice(&output.script_pubkey);
    }
    outputs_buf.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());

    // N8: single-pass forward midstate — one `Sha256::clone` per input (no Vec + second clone).
    // `running` = state after version + varint(n) + blank_input_0 + ... + blank_input_{i-1}.
    let mut running = Sha256::new();
    running.update((tx.version as u32).to_le_bytes());
    update_varint(&mut running, n as u64);

    for i in 0..n {
        let mut h = running.clone();

        // Input i with script_code
        h.update(tx.inputs[i].prevout.hash);
        h.update(tx.inputs[i].prevout.index.to_le_bytes());
        update_varint(&mut h, script_codes[i].len() as u64);
        h.update(script_codes[i]);
        h.update((tx.inputs[i].sequence as u32).to_le_bytes());

        // Remaining blank inputs i+1..N-1
        for j in (i + 1)..n {
            h.update(tx.inputs[j].prevout.hash);
            h.update(tx.inputs[j].prevout.index.to_le_bytes());
            h.update([0u8]);
            h.update((tx.inputs[j].sequence as u32).to_le_bytes());
        }

        // Outputs + locktime + per-input sighash byte (0x00 or 0x01)
        h.update(outputs_buf.as_slice());
        h.update((sighash_bytes[i] as u32).to_le_bytes());

        let first_hash = h.finalize();
        let second_hash = Sha256::digest(first_hash);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second_hash);
        results.push(result);

        // Advance shared prefix past blank input i for the next midstate.
        running.update(tx.inputs[i].prevout.hash);
        running.update(tx.inputs[i].prevout.index.to_le_bytes());
        running.update([0u8]);
        running.update((tx.inputs[i].sequence as u32).to_le_bytes());
    }

    results
}

/// Calculate transaction sighash for signature verification
///
/// This implements the Bitcoin transaction hash algorithm used for ECDSA signatures.
/// The sighash determines which parts of the transaction are signed.
///
/// Checks for precomputed templates
/// before computing sighash from scratch.
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input being signed
/// * `prevouts` - Previous transaction outputs (for input validation)
/// * `sighash_type` - Type of sighash to calculate
/// * `script_code` - Optional script code to use instead of scriptPubKey (for P2SH redeem script)
///
/// # Returns
/// 32-byte hash to be signed with ECDSA
#[spec_locked("5.1.1", "CalculateSighash")]
pub fn calculate_transaction_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TransactionOutput],
    sighash_type: SighashType,
) -> Result<Hash> {
    // Convert prevouts to parallel slices for the optimized API
    let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
    let prevout_script_pubkeys: Vec<&[u8]> =
        prevouts.iter().map(|p| p.script_pubkey.as_ref()).collect();
    // Validate prevouts match inputs
    if prevout_values.len() != tx.inputs.len() || prevout_script_pubkeys.len() != tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidPrevoutsCount(
            prevout_values.len(),
            tx.inputs.len(),
        ));
    }
    calculate_transaction_sighash_with_script_code(
        tx,
        input_index,
        &prevout_values,
        &prevout_script_pubkeys,
        sighash_type,
        None,
        #[cfg(feature = "production")]
        None,
    )
}

/// Calculate sighash for a single input without requiring full prevout arrays.
/// Takes only (script_for_signing, prevout_value) for the current input. Non-signing inputs
/// use empty script internally. Eliminates need for workers to build full refs per tx.
/// script_for_signing is the script that goes into the preimage (scriptPubKey or redeem script).
#[spec_locked("5.1.1", "CalculateSighash")]
pub fn calculate_transaction_sighash_single_input(
    tx: &Transaction,
    input_index: usize,
    script_for_signing: &[u8],
    prevout_value: i64,
    sighash_type: SighashType,
    #[cfg(feature = "production")] sighash_cache: Option<&SighashMidstateCache>,
) -> Result<Hash> {
    if input_index >= tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidInputIndex(input_index));
    }
    // Pass script_code=Some directly — avoids building SmallVec of N refs and Vec of N
    // prevout_values. Legacy sighash doesn't use prevout_values, and the fast-path helpers
    // + build_preimage_and_hash only access script_code for the signing input.
    #[cfg(feature = "production")]
    return calculate_transaction_sighash_with_script_code(
        tx,
        input_index,
        &[],
        &[],
        sighash_type,
        Some(script_for_signing),
        sighash_cache,
    );
    #[cfg(not(feature = "production"))]
    {
        let mut prevout_values = vec![0i64; tx.inputs.len()];
        prevout_values[input_index] = prevout_value;
        let prevout_script_pubkeys: Vec<&[u8]> = (0..tx.inputs.len())
            .map(|i| {
                if i == input_index {
                    script_for_signing
                } else {
                    &[]
                }
            })
            .collect();
        calculate_transaction_sighash_with_script_code(
            tx,
            input_index,
            &prevout_values,
            &prevout_script_pubkeys,
            sighash_type,
            Some(script_for_signing),
        )
    }
}

/// Calculate transaction sighash with optional script code override
///
/// For P2SH transactions, script_code should be the redeem script (not the scriptPubKey).
/// For non-P2SH, script_code should be None (uses scriptPubKey from prevout).
/// When sighash_cache is provided (parallel script-check path), caches (scriptCode, sighash_byte) -> hash for multisig reuse.
#[spec_locked("5.1.1", "CalculateSighash")]
pub fn calculate_transaction_sighash_with_script_code(
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    sighash_type: SighashType,
    script_code: Option<&[u8]>,
    #[cfg(feature = "production")] sighash_cache: Option<&SighashMidstateCache>,
) -> Result<Hash> {
    #[cfg(all(feature = "production", feature = "profile"))]
    let _t0 = std::time::Instant::now();

    // Validate input index
    if input_index >= tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidInputIndex(input_index));
    }

    // When script_code is provided, prevout_script_pubkeys/prevout_values aren't needed
    // for legacy sighash (only the signing input's scriptCode matters, and prevout_values
    // aren't part of the legacy preimage). Skip validation to allow empty slices.
    if script_code.is_none()
        && (prevout_values.len() != tx.inputs.len()
            || prevout_script_pubkeys.len() != tx.inputs.len())
    {
        return Err(crate::error::ConsensusError::InvalidPrevoutsCount(
            prevout_values.len(),
            tx.inputs.len(),
        ));
    }

    let sighash_byte = sighash_type.as_u32();
    let base_type = sighash_byte & 0x1f;
    let anyone_can_pay = (sighash_byte & 0x80) != 0;
    let hash_none = base_type == 0x02; // SIGHASH_NONE
    let hash_single = base_type == 0x03; // SIGHASH_SINGLE

    // SIGHASH_SINGLE special case: if input_index >= outputs count,
    // consensus returns the hash 0x0000...0001 (a historical quirk)
    if hash_single && input_index >= tx.outputs.len() {
        let mut result = [0u8; 32];
        result[0] = 1; // Little-endian 1
        return Ok(result);
    }

    // Midstate cache: (prevout, scriptCode, sighash_byte) -> hash. Key must include prevout.
    // When sighash_cache is None, use thread-local (avoids Mutex contention across workers).
    #[cfg(feature = "production")]
    {
        let prevout = &tx.inputs[input_index].prevout;
        let code = script_code.unwrap_or_else(|| prevout_script_pubkeys[input_index]);
        let sighash_byte_u8 = sighash_byte as u8;
        let hash = sighash_cache_hash(prevout, code, sighash_byte_u8);
        let lookup_key = SighashCacheKey {
            prevout: *prevout,
            code_hash: hash,
            sighash_byte: sighash_byte_u8,
        };
        let cached = if let Some(cache) = sighash_cache {
            cache
                .lock()
                .ok()
                .and_then(|guard| guard.get(&lookup_key).copied())
        } else {
            SIGHASH_MIDSTATE_CACHE.with(|cell| cell.borrow_mut().get(&lookup_key).copied())
        };
        if let Some(cached) = cached {
            return Ok(cached);
        }
    }

    // Fast path: 1-in-1-out SIGHASH_ALL (common P2PKH pattern). Avoids loop overhead and branches.
    #[cfg(feature = "production")]
    if tx.inputs.len() == 1 && input_index == 0 && !anyone_can_pay && !hash_none && !hash_single {
        let base_type = sighash_byte & 0x1f;
        if base_type == 0x01 || base_type == 0x00 {
            let n_out = tx.outputs.len();
            if n_out == 1 {
                if let Ok(h) = build_preimage_1in1out_sighash_all(
                    tx,
                    prevout_values,
                    prevout_script_pubkeys,
                    script_code,
                    sighash_byte,
                ) {
                    #[cfg(all(feature = "production", feature = "profile"))]
                    crate::script_profile::add_sighash_ns(_t0.elapsed().as_nanos() as u64);
                    #[cfg(feature = "production")]
                    insert_midstate_cache(
                        sighash_cache,
                        tx.inputs[0].prevout,
                        script_code.unwrap_or_else(|| prevout_script_pubkeys[0]),
                        sighash_byte as u8,
                        h,
                    );
                    return Ok(h);
                }
            } else if (2..=16).contains(&n_out) {
                if let Ok(h) = build_preimage_1in_nout_sighash_all(
                    tx,
                    prevout_script_pubkeys,
                    script_code,
                    sighash_byte,
                ) {
                    #[cfg(all(feature = "production", feature = "profile"))]
                    crate::script_profile::add_sighash_ns(_t0.elapsed().as_nanos() as u64);
                    #[cfg(feature = "production")]
                    insert_midstate_cache(
                        sighash_cache,
                        tx.inputs[0].prevout,
                        script_code.unwrap_or_else(|| prevout_script_pubkeys[0]),
                        sighash_byte as u8,
                        h,
                    );
                    return Ok(h);
                }
            }
        }
    }

    // Fast path: 2-in-1-out and 2-in-2-out SIGHASH_ALL (common batched/swap patterns).
    #[cfg(feature = "production")]
    if tx.inputs.len() == 2 && input_index < 2 && !anyone_can_pay && !hash_none && !hash_single {
        let base_type = sighash_byte & 0x1f;
        if base_type == 0x01 || base_type == 0x00 {
            let n_out = tx.outputs.len();
            if n_out == 1 {
                if let Ok(h) = build_preimage_2in1out_sighash_all(
                    tx,
                    input_index,
                    prevout_values,
                    prevout_script_pubkeys,
                    script_code,
                    sighash_byte,
                ) {
                    #[cfg(all(feature = "production", feature = "profile"))]
                    crate::script_profile::add_sighash_ns(_t0.elapsed().as_nanos() as u64);
                    #[cfg(feature = "production")]
                    insert_midstate_cache(
                        sighash_cache,
                        tx.inputs[input_index].prevout,
                        script_code.unwrap_or_else(|| prevout_script_pubkeys[input_index]),
                        sighash_byte as u8,
                        h,
                    );
                    return Ok(h);
                }
            } else if n_out == 2 {
                if let Ok(h) = build_preimage_2in2out_sighash_all(
                    tx,
                    input_index,
                    prevout_script_pubkeys,
                    script_code,
                    sighash_byte,
                ) {
                    #[cfg(all(feature = "production", feature = "profile"))]
                    crate::script_profile::add_sighash_ns(_t0.elapsed().as_nanos() as u64);
                    #[cfg(feature = "production")]
                    insert_midstate_cache(
                        sighash_cache,
                        tx.inputs[input_index].prevout,
                        script_code.unwrap_or_else(|| prevout_script_pubkeys[input_index]),
                        sighash_byte as u8,
                        h,
                    );
                    return Ok(h);
                }
            }
        }
    }

    // Build sighash preimage matching consensus's CTransactionSignatureSerializer
    let estimated_size = 4 + 2 + (tx.inputs.len() * 50) + 2 + (tx.outputs.len() * 30) + 4 + 4;
    let capacity = estimated_size.min(4096);

    #[cfg(feature = "production")]
    let (result, preimage_vec) = SIGHASH_PREIMAGE_BUF.with(|buf_cell| {
        let mut preimage = buf_cell.borrow_mut();
        preimage.clear();
        if preimage.capacity() < capacity {
            preimage.reserve(capacity);
        }
        build_preimage_and_hash(
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            script_code,
            sighash_byte,
            anyone_can_pay,
            hash_none,
            hash_single,
            &mut preimage,
        )
    });

    #[cfg(not(feature = "production"))]
    let (result, preimage_vec) = {
        let mut preimage = Vec::with_capacity(capacity);
        build_preimage_and_hash(
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            script_code,
            sighash_byte,
            anyone_can_pay,
            hash_none,
            hash_single,
            &mut preimage,
        )
    };

    #[cfg(all(feature = "production", feature = "profile"))]
    crate::script_profile::add_sighash_ns(_t0.elapsed().as_nanos() as u64);

    #[cfg(feature = "production")]
    if let Ok(ref h) = result {
        insert_midstate_cache(
            sighash_cache,
            tx.inputs[input_index].prevout,
            script_code.unwrap_or_else(|| prevout_script_pubkeys[input_index]),
            sighash_byte as u8,
            *h,
        );
    }
    result
}

/// Fast path for 1-in-1-out SIGHASH_ALL (common P2PKH). Unrolled serialization, no loop overhead.
#[cfg(feature = "production")]
#[inline]
fn build_preimage_1in1out_sighash_all(
    tx: &crate::types::Transaction,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    script_code: Option<&[u8]>,
    sighash_byte: u32,
) -> Result<Hash> {
    let input = &tx.inputs[0];
    let output = &tx.outputs[0];
    let code = script_code.unwrap_or_else(|| prevout_script_pubkeys[0]);

    let capacity = 4 + 2 + 36 + 2 + code.len() + 4 + 2 + 8 + 2 + output.script_pubkey.len() + 4 + 4;
    let (result, _) = SIGHASH_PREIMAGE_BUF.with(|buf_cell| {
        let mut preimage = buf_cell.borrow_mut();
        preimage.clear();
        if preimage.capacity() < capacity {
            preimage.reserve(capacity);
        }
        preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());
        preimage.push(1); // n_inputs
        preimage.extend_from_slice(&input.prevout.hash);
        preimage.extend_from_slice(&input.prevout.index.to_le_bytes());
        write_script_code_for_sighash(&mut preimage, code);
        preimage.extend_from_slice(&(input.sequence as u32).to_le_bytes());
        preimage.push(1); // n_outputs
        preimage.extend_from_slice(&output.value.to_le_bytes());
        write_varint_to_vec(&mut preimage, output.script_pubkey.len() as u64);
        preimage.extend_from_slice(&output.script_pubkey);
        preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
        preimage.extend_from_slice(&sighash_byte.to_le_bytes());
        let r = sighash_with_cache(&preimage);
        (Ok(r), ())
    });
    result
}

/// Fast path for 1-in-N-out SIGHASH_ALL (N=2..16, spend+change). Same structure as 1-in-1-out, small output loop.
#[cfg(feature = "production")]
#[inline]
fn build_preimage_1in_nout_sighash_all(
    tx: &crate::types::Transaction,
    prevout_script_pubkeys: &[&[u8]],
    script_code: Option<&[u8]>,
    sighash_byte: u32,
) -> Result<Hash> {
    let input = &tx.inputs[0];
    let code = script_code.unwrap_or_else(|| prevout_script_pubkeys[0]);
    let mut capacity = 4 + 2 + 36 + 2 + code.len() + 4 + 2; // version, n_in, input, n_out
    for out in &tx.outputs {
        capacity += 8 + 2 + out.script_pubkey.len();
    }
    capacity += 4 + 4; // lock_time, sighash_type

    let (result, _) = SIGHASH_PREIMAGE_BUF.with(|buf_cell| {
        let mut preimage = buf_cell.borrow_mut();
        preimage.clear();
        if preimage.capacity() < capacity {
            preimage.reserve(capacity);
        }
        preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());
        preimage.push(1); // n_inputs
        preimage.extend_from_slice(&input.prevout.hash);
        preimage.extend_from_slice(&input.prevout.index.to_le_bytes());
        write_script_code_for_sighash(&mut preimage, code);
        preimage.extend_from_slice(&(input.sequence as u32).to_le_bytes());
        write_varint_to_vec(&mut preimage, tx.outputs.len() as u64);
        for output in &tx.outputs {
            preimage.extend_from_slice(&output.value.to_le_bytes());
            write_varint_to_vec(&mut preimage, output.script_pubkey.len() as u64);
            preimage.extend_from_slice(&output.script_pubkey);
        }
        preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
        preimage.extend_from_slice(&sighash_byte.to_le_bytes());
        let r = sighash_with_cache(&preimage);
        (Ok(r), ())
    });
    result
}

/// Fast path for 2-in-1-out SIGHASH_ALL (consolidation, batched). Unrolled, no loop.
/// Non-signing inputs MUST use empty script (0x00) per consensus.
#[cfg(feature = "production")]
#[inline]
fn build_preimage_2in1out_sighash_all(
    tx: &crate::types::Transaction,
    input_index: usize,
    _prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    script_code: Option<&[u8]>,
    sighash_byte: u32,
) -> Result<Hash> {
    let output = &tx.outputs[0];
    let code_len = script_code
        .map(|s| s.len())
        .unwrap_or_else(|| prevout_script_pubkeys[input_index].len());
    let capacity =
        4 + 2 + 36 + 2 + code_len + 4 + 36 + 2 + 4 + 8 + 2 + output.script_pubkey.len() + 4 + 4;

    let (result, _) = SIGHASH_PREIMAGE_BUF.with(|buf_cell| {
        let mut preimage = buf_cell.borrow_mut();
        preimage.clear();
        if preimage.capacity() < capacity {
            preimage.reserve(capacity);
        }
        preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());
        preimage.push(2);
        for (i, inp) in tx.inputs.iter().enumerate().take(2) {
            let (script_len, script_slice): (usize, &[u8]) = if i == input_index {
                let c = script_code.unwrap_or_else(|| prevout_script_pubkeys[i]);
                (c.len(), c)
            } else {
                (0, &[][..]) // Non-signing input: empty script per consensus
            };
            preimage.extend_from_slice(&inp.prevout.hash);
            preimage.extend_from_slice(&inp.prevout.index.to_le_bytes());
            write_varint_to_vec(&mut preimage, script_len as u64);
            preimage.extend_from_slice(script_slice);
            preimage.extend_from_slice(&(inp.sequence as u32).to_le_bytes());
        }
        preimage.push(1);
        preimage.extend_from_slice(&output.value.to_le_bytes());
        write_varint_to_vec(&mut preimage, output.script_pubkey.len() as u64);
        preimage.extend_from_slice(&output.script_pubkey);
        preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
        preimage.extend_from_slice(&sighash_byte.to_le_bytes());
        let r = sighash_with_cache(&preimage);
        (Ok(r), ())
    });
    result
}

/// Fast path for 2-in-2-out SIGHASH_ALL (swap, batched). Unrolled, no loop.
/// Non-signing inputs MUST use empty script (0x00) per consensus.
#[cfg(feature = "production")]
#[inline]
fn build_preimage_2in2out_sighash_all(
    tx: &crate::types::Transaction,
    input_index: usize,
    prevout_script_pubkeys: &[&[u8]],
    script_code: Option<&[u8]>,
    sighash_byte: u32,
) -> Result<Hash> {
    let code_len = script_code
        .map(|s| s.len())
        .unwrap_or_else(|| prevout_script_pubkeys[input_index].len());
    let mut capacity = 4 + 2 + 36 + 2 + code_len + 4 + 36 + 2 + 4;
    for out in &tx.outputs {
        capacity += 8 + 2 + out.script_pubkey.len();
    }
    capacity += 4 + 4;

    let (result, _) = SIGHASH_PREIMAGE_BUF.with(|buf_cell| {
        let mut preimage = buf_cell.borrow_mut();
        preimage.clear();
        if preimage.capacity() < capacity {
            preimage.reserve(capacity);
        }
        preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());
        preimage.push(2);
        for (i, inp) in tx.inputs.iter().enumerate().take(2) {
            let (script_len, script_slice): (usize, &[u8]) = if i == input_index {
                let c = script_code.unwrap_or_else(|| prevout_script_pubkeys[i]);
                (c.len(), c)
            } else {
                (0, &[][..])
            };
            preimage.extend_from_slice(&inp.prevout.hash);
            preimage.extend_from_slice(&inp.prevout.index.to_le_bytes());
            write_varint_to_vec(&mut preimage, script_len as u64);
            preimage.extend_from_slice(script_slice);
            preimage.extend_from_slice(&(inp.sequence as u32).to_le_bytes());
        }
        write_varint_to_vec(&mut preimage, 2);
        for output in &tx.outputs {
            preimage.extend_from_slice(&output.value.to_le_bytes());
            write_varint_to_vec(&mut preimage, output.script_pubkey.len() as u64);
            preimage.extend_from_slice(&output.script_pubkey);
        }
        preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
        preimage.extend_from_slice(&sighash_byte.to_le_bytes());
        let r = sighash_with_cache(&preimage);
        (Ok(r), ())
    });
    result
}

#[inline]
fn build_preimage_and_hash(
    tx: &crate::types::Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    script_code: Option<&[u8]>,
    sighash_byte: u32,
    anyone_can_pay: bool,
    hash_none: bool,
    hash_single: bool,
    preimage: &mut Vec<u8>,
) -> (Result<Hash>, ()) {
    // 1. Transaction version (4 bytes LE)
    preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());

    // 2. Input count: ANYONECANPAY → 1, otherwise all inputs
    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    write_varint_to_vec(preimage, n_inputs as u64);

    // 3. Inputs
    for i in 0..n_inputs {
        // ANYONECANPAY remaps input index to the signing input
        let actual_i = if anyone_can_pay { input_index } else { i };
        let input = &tx.inputs[actual_i];

        // Prevout (always serialized)
        preimage.extend_from_slice(&input.prevout.hash);
        preimage.extend_from_slice(&input.prevout.index.to_le_bytes());

        // Script: signing input gets script_code/scriptPubKey, others get empty
        if actual_i == input_index {
            let code = match script_code {
                Some(s) => s,
                None => prevout_script_pubkeys[actual_i],
            };
            write_script_code_for_sighash(preimage, code);
        } else {
            preimage.push(0); // empty script
        }

        // Sequence: for SIGHASH_NONE/SINGLE, non-signing inputs get sequence 0
        if actual_i != input_index && (hash_single || hash_none) {
            preimage.extend_from_slice(&0u32.to_le_bytes());
        } else {
            preimage.extend_from_slice(&(input.sequence as u32).to_le_bytes());
        }
    }

    // 4. Output count: NONE → 0, SINGLE → input_index+1, ALL → all
    let n_outputs = if hash_none {
        0
    } else if hash_single {
        input_index + 1
    } else {
        tx.outputs.len()
    };
    write_varint_to_vec(preimage, n_outputs as u64);

    // 5. Outputs
    for i in 0..n_outputs {
        if hash_single && i != input_index {
            // SIGHASH_SINGLE: non-matching outputs are CTxOut() (value=-1, empty script)
            preimage.extend_from_slice(&(-1i64).to_le_bytes()); // -1 as i64 = 0xffffffffffffffff
            preimage.push(0); // empty script
        } else {
            let output = &tx.outputs[i];
            preimage.extend_from_slice(&output.value.to_le_bytes());
            write_varint_to_vec(preimage, output.script_pubkey.len() as u64);
            preimage.extend_from_slice(&output.script_pubkey);
        }
    }

    // 6. Lock time (4 bytes LE)
    preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());

    // 7. SIGHASH type (4 bytes LE) - use the raw sighash byte value
    preimage.extend_from_slice(&sighash_byte.to_le_bytes());

    // Double SHA256; in production use cache (first_hash as key) to save one SHA256 on hit
    #[cfg(feature = "production")]
    let result = sighash_with_cache(preimage);
    #[cfg(not(feature = "production"))]
    let result = {
        let hasher = OptimizedSha256::new();
        let first_hash = hasher.hash(&preimage);
        let second_hash = hasher.hash(&first_hash);
        let mut r = [0u8; 32];
        r.copy_from_slice(&second_hash);
        r
    };
    (Ok(result), ())
}

/// Batch compute sighashes for all inputs of a transaction
///
/// This function computes sighashes for all inputs at once, which is useful when
/// validating transactions with many inputs. The sighashes are computed in parallel
/// when the production feature is enabled.
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `prevouts` - Previous transaction outputs (for input validation)
/// * `sighash_type` - Type of sighash to calculate (must be the same for all inputs)
///
/// # Returns
/// Vector of 32-byte hashes, one per input (in same order)
#[spec_locked("5.1.1", "CalculateSighash")]
pub fn batch_compute_sighashes(
    tx: &Transaction,
    prevouts: &[TransactionOutput],
    sighash_type: SighashType,
) -> Result<Vec<Hash>> {
    // Validate prevouts match inputs
    if prevouts.len() != tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidPrevoutsCount(
            prevouts.len(),
            tx.inputs.len(),
        ));
    }

    // Convert prevouts to parallel slices for the optimized API
    let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
    let prevout_script_pubkeys: Vec<&[u8]> =
        prevouts.iter().map(|p| p.script_pubkey.as_ref()).collect();

    #[cfg(feature = "production")]
    {
        // Use correct legacy sighash preimage (build_legacy_sighash_preimage_into)
        // via batch_compute_legacy_sighashes. Fixes ANYONECANPAY/NONE/SINGLE handling.
        let sighash_byte = sighash_type.as_u32() as u8;
        let specs: Vec<(usize, u8, &[u8])> = (0..tx.inputs.len())
            .map(|i| (i, sighash_byte, prevout_script_pubkeys[i]))
            .collect();
        let hashes =
            batch_compute_legacy_sighashes(tx, &prevout_values, &prevout_script_pubkeys, &specs)?;
        Ok(hashes)
    }

    #[cfg(not(feature = "production"))]
    {
        // Sequential fallback for non-production builds
        let mut results = Vec::with_capacity(tx.inputs.len());
        for i in 0..tx.inputs.len() {
            results.push(calculate_transaction_sighash_with_script_code(
                tx,
                i,
                &prevout_values,
                &prevout_script_pubkeys,
                sighash_type,
                None,
            )?);
        }
        Ok(results)
    }
}

/// Build legacy sighash preimage into a reusable buffer (zero alloc).
#[cfg(feature = "production")]
fn build_legacy_sighash_preimage_into(
    preimage: &mut Vec<u8>,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    script_code: &[u8],
    sighash_byte: u32,
) {
    let anyone_can_pay = (sighash_byte & 0x80) != 0;
    let hash_none = (sighash_byte & 0x1f) == 0x02;
    let hash_single = (sighash_byte & 0x1f) == 0x03;
    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    let n_outputs = if hash_none {
        0
    } else if hash_single {
        input_index + 1
    } else {
        tx.outputs.len()
    };
    preimage.clear();
    preimage.reserve(512);
    preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());
    write_varint_to_vec(preimage, n_inputs as u64);
    for i in 0..n_inputs {
        let actual_i = if anyone_can_pay { input_index } else { i };
        let input = &tx.inputs[actual_i];
        preimage.extend_from_slice(&input.prevout.hash);
        preimage.extend_from_slice(&input.prevout.index.to_le_bytes());
        if actual_i == input_index {
            write_script_code_for_sighash(preimage, script_code);
        } else {
            preimage.push(0);
        }
        if actual_i != input_index && (hash_single || hash_none) {
            preimage.extend_from_slice(&0u32.to_le_bytes());
        } else {
            preimage.extend_from_slice(&(input.sequence as u32).to_le_bytes());
        }
    }
    write_varint_to_vec(preimage, n_outputs as u64);
    for i in 0..n_outputs {
        // SIGHASH_SINGLE: non-matching outputs, or input_index >= outputs.len() (invalid but must not panic)
        let use_missing_output =
            hash_single && (i != input_index || input_index >= tx.outputs.len());
        if use_missing_output {
            preimage.extend_from_slice(&(-1i64).to_le_bytes());
            preimage.push(0);
        } else {
            let output = &tx.outputs[i];
            preimage.extend_from_slice(&output.value.to_le_bytes());
            write_varint_to_vec(preimage, output.script_pubkey.len() as u64);
            preimage.extend_from_slice(&output.script_pubkey);
        }
    }
    preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
    preimage.extend_from_slice(&sighash_byte.to_le_bytes());
}

/// Batch compute legacy sighashes for specified inputs.
/// Roadmap #12: Precompute before script execution for P2PKH-heavy blocks (100k band).
/// Each spec is (input_index, sighash_byte, script_code). Returns hashes in spec order.
/// Uses thread-local reusable buffers; no per-spec Vec allocs.
#[cfg(feature = "production")]
#[spec_locked("5.1.1", "CalculateSighash")]
pub fn batch_compute_legacy_sighashes(
    tx: &Transaction,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    specs: &[(usize, u8, &[u8])],
) -> Result<Vec<[u8; 32]>> {
    if prevout_values.len() != tx.inputs.len() || prevout_script_pubkeys.len() != tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidPrevoutsCount(
            prevout_values.len(),
            tx.inputs.len(),
        ));
    }
    // SIGHASH_SINGLE with input_index >= outputs.len(): consensus hash is 0x0000...0001
    const SIGHASH_SINGLE_INVALID: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 1;
        h
    };

    LEGACY_BATCH_PREIMAGES.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.resize_with(specs.len(), || Vec::with_capacity(512));
        let mut fixed_indices: Vec<usize> = Vec::new();
        for (i, &(input_index, sighash_byte, script_code)) in specs.iter().enumerate() {
            let hash_single = (sighash_byte & 0x1f) == 0x03;
            if hash_single && input_index >= tx.outputs.len() {
                fixed_indices.push(i);
                continue;
            }
            build_legacy_sighash_preimage_into(
                &mut storage[i],
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                script_code,
                sighash_byte as u32,
            );
        }
        // Batch hash only preimages we built; fixed_indices get SIGHASH_SINGLE_INVALID
        let preimage_refs: Vec<&[u8]> = storage
            .iter()
            .enumerate()
            .filter(|(i, _)| !fixed_indices.contains(i))
            .map(|(_, v)| v.as_slice())
            .collect();
        let batch_hashes =
            crate::optimizations::simd_vectorization::batch_double_sha256(&preimage_refs);
        // Merge: fill result in spec order
        let mut result = vec![[0u8; 32]; specs.len()];
        let mut batch_idx = 0;
        for (i, slot) in result.iter_mut().enumerate() {
            if fixed_indices.contains(&i) {
                *slot = SIGHASH_SINGLE_INVALID;
            } else {
                *slot = batch_hashes[batch_idx];
                batch_idx += 1;
            }
        }
        Ok(result)
    })
}

/// Clear sighash cache. Useful for benchmarking to ensure consistent results.
/// Clears the thread-local SIGHASH_CACHE on the current thread.
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub fn clear_sighash_templates() {
    SIGHASH_CACHE.with(|cell| {
        cell.borrow_mut().clear();
    });
}

// =============================================================================
// BIP143: Segregated Witness Sighash Algorithm
// =============================================================================
//
// BIP143 defines a new transaction sighash algorithm for SegWit transactions.
// Key optimization: hashPrevouts, hashSequence, and hashOutputs are computed
// ONCE for all inputs, instead of once per input like legacy sighash.
//
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

/// Precomputed hash components for BIP143 sighash.
/// These are computed once per transaction and reused for all inputs.
#[derive(Clone, Debug)]
pub struct Bip143PrecomputedHashes {
    /// SHA256(SHA256(all input prevouts)) - 0 if ANYONECANPAY
    pub hash_prevouts: [u8; 32],
    /// SHA256(SHA256(all input sequences)) - 0 if ANYONECANPAY/NONE/SINGLE  
    pub hash_sequence: [u8; 32],
    /// SHA256(SHA256(all outputs)) - varies by sighash type
    pub hash_outputs: [u8; 32],
}

impl Bip143PrecomputedHashes {
    /// Compute precomputed hashes for a transaction.
    /// This is the expensive part - compute once, reuse for all inputs.
    /// Production: uses thread-local buffer to avoid 3 Vec allocs per SegWit tx.
    #[inline]
    pub fn compute(
        tx: &Transaction,
        _prevout_values: &[i64],
        _prevout_script_pubkeys: &[&[u8]],
    ) -> Self {
        #[cfg(feature = "production")]
        {
            let hash_prevouts = BIP143_SERIALIZE_BUF.with(|cell| {
                let mut data = cell.borrow_mut();
                data.clear();
                data.reserve(tx.inputs.len() * 36);
                for input in tx.inputs.iter() {
                    data.extend_from_slice(&input.prevout.hash);
                    data.extend_from_slice(&input.prevout.index.to_le_bytes());
                }
                double_sha256(&data)
            });

            let hash_sequence = BIP143_SERIALIZE_BUF.with(|cell| {
                let mut data = cell.borrow_mut();
                data.clear();
                data.reserve(tx.inputs.len() * 4);
                for input in tx.inputs.iter() {
                    data.extend_from_slice(&(input.sequence as u32).to_le_bytes());
                }
                double_sha256(&data)
            });

            let hash_outputs = BIP143_SERIALIZE_BUF.with(|cell| {
                let mut data = cell.borrow_mut();
                data.clear();
                let cap = tx
                    .outputs
                    .iter()
                    .map(|o| 8 + 5 + o.script_pubkey.len())
                    .sum::<usize>();
                data.reserve(cap);
                for output in tx.outputs.iter() {
                    data.extend_from_slice(&output.value.to_le_bytes());
                    write_varint_to_vec(&mut data, output.script_pubkey.len() as u64);
                    data.extend_from_slice(&output.script_pubkey);
                }
                double_sha256(&data)
            });

            Self {
                hash_prevouts,
                hash_sequence,
                hash_outputs,
            }
        }

        #[cfg(not(feature = "production"))]
        {
            // hashPrevouts = SHA256(SHA256(all outpoints))
            let hash_prevouts = {
                let mut data = Vec::with_capacity(tx.inputs.len() * 36);
                for input in tx.inputs.iter() {
                    data.extend_from_slice(&input.prevout.hash);
                    data.extend_from_slice(&input.prevout.index.to_le_bytes());
                }
                double_sha256(&data)
            };

            let hash_sequence = {
                let mut data = Vec::with_capacity(tx.inputs.len() * 4);
                for input in tx.inputs.iter() {
                    data.extend_from_slice(&(input.sequence as u32).to_le_bytes());
                }
                double_sha256(&data)
            };

            let hash_outputs = {
                let mut data = Vec::with_capacity(tx.outputs.len() * 34);
                for output in tx.outputs.iter() {
                    data.extend_from_slice(&output.value.to_le_bytes());
                    write_varint_to_vec(&mut data, output.script_pubkey.len() as u64);
                    data.extend_from_slice(&output.script_pubkey);
                }
                double_sha256(&data)
            };

            Self {
                hash_prevouts,
                hash_sequence,
                hash_outputs,
            }
        }
    }
}

/// Double SHA256 helper. Uses OptimizedSha256 (SHA-NI when available).
#[inline(always)]
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hasher = OptimizedSha256::new();
    hasher.hash256(data)
}

/// Calculate BIP143 sighash for SegWit transactions.
///
/// This is significantly faster than legacy sighash for transactions with
/// multiple inputs because hashPrevouts, hashSequence, and hashOutputs are
/// computed once and reused.
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input being signed
/// * `script_code` - The scriptCode for this input (P2WPKH: pubkeyhash script, P2WSH: witness script)
/// * `amount` - Value of the UTXO being spent (in satoshis)
/// * `sighash_type` - Sighash type byte
/// * `precomputed` - Optional precomputed hashes (compute once, pass to all inputs)
///
/// # Returns
/// 32-byte sighash for signature verification
#[spec_locked("11.1.9", "ComputeWitnessSignatureHash")]
pub fn calculate_bip143_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount: i64,
    sighash_type: u8,
    precomputed: Option<&Bip143PrecomputedHashes>,
) -> Result<Hash> {
    if input_index >= tx.inputs.len() {
        return Err(crate::error::ConsensusError::InvalidInputIndex(input_index));
    }

    // Parse sighash flags
    let anyone_can_pay = (sighash_type & 0x80) != 0;
    let base_type = sighash_type & 0x1f;
    let is_none = base_type == 0x02;
    let is_single = base_type == 0x03;

    // Use precomputed hashes or compute them
    let computed;
    let hashes = match precomputed {
        Some(h) => h,
        None => {
            computed = Bip143PrecomputedHashes::compute(tx, &[], &[]);
            &computed
        }
    };

    // Build sighash preimage according to BIP143
    // Estimated size: 4+32+32+36+var+8+4+32+4+4 = ~160 bytes + script_code
    #[cfg(feature = "production")]
    let preimage_result = BIP143_PREIMAGE_BUF.with(|buf_cell| {
        let mut preimage = buf_cell.borrow_mut();
        preimage.clear();
        let cap = 160 + script_code.len();
        if preimage.capacity() < cap {
            preimage.reserve(cap);
        }
        build_bip143_preimage(
            tx,
            input_index,
            script_code,
            amount,
            sighash_type,
            anyone_can_pay,
            is_none,
            is_single,
            hashes,
            &mut preimage,
        )
    });
    #[cfg(not(feature = "production"))]
    let preimage_result = {
        let mut preimage = Vec::with_capacity(160 + script_code.len());
        build_bip143_preimage(
            tx,
            input_index,
            script_code,
            amount,
            sighash_type,
            anyone_can_pay,
            is_none,
            is_single,
            hashes,
            &mut preimage,
        )
    };
    preimage_result
}

#[inline]
fn build_bip143_preimage(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount: i64,
    sighash_type: u8,
    anyone_can_pay: bool,
    is_none: bool,
    is_single: bool,
    hashes: &Bip143PrecomputedHashes,
    preimage: &mut Vec<u8>,
) -> Result<Hash> {
    // 1. nVersion (4 bytes LE)
    preimage.extend_from_slice(&(tx.version as u32).to_le_bytes());

    // 2. hashPrevouts (32 bytes) - 0 if ANYONECANPAY
    if anyone_can_pay {
        preimage.extend_from_slice(&[0u8; 32]);
    } else {
        preimage.extend_from_slice(&hashes.hash_prevouts);
    }

    // 3. hashSequence (32 bytes) - 0 if ANYONECANPAY/NONE/SINGLE
    if anyone_can_pay || is_none || is_single {
        preimage.extend_from_slice(&[0u8; 32]);
    } else {
        preimage.extend_from_slice(&hashes.hash_sequence);
    }

    // 4. outpoint (36 bytes: 32 hash + 4 index)
    let input = &tx.inputs[input_index];
    preimage.extend_from_slice(&input.prevout.hash);
    preimage.extend_from_slice(&input.prevout.index.to_le_bytes());

    // 5. scriptCode (varint + script)
    write_varint_to_vec(preimage, script_code.len() as u64);
    preimage.extend_from_slice(script_code);

    // 6. amount (8 bytes LE) - value of the UTXO being spent
    preimage.extend_from_slice(&amount.to_le_bytes());

    // 7. nSequence (4 bytes LE)
    preimage.extend_from_slice(&(input.sequence as u32).to_le_bytes());

    // 8. hashOutputs (32 bytes) - varies by sighash type
    if is_none {
        preimage.extend_from_slice(&[0u8; 32]);
    } else if is_single {
        if input_index < tx.outputs.len() {
            // Hash only the output at same index (reuse buffer to avoid per-input alloc)
            let output = &tx.outputs[input_index];
            #[cfg(feature = "production")]
            let hash_outputs = BIP143_SINGLE_OUTPUT_BUF.with(|buf_cell| {
                let mut output_data = buf_cell.borrow_mut();
                output_data.clear();
                let cap = 8 + 9 + output.script_pubkey.len(); // value + varint + script
                if output_data.capacity() < cap {
                    output_data.reserve(cap);
                }
                output_data.extend_from_slice(&output.value.to_le_bytes());
                write_varint_to_vec(&mut output_data, output.script_pubkey.len() as u64);
                output_data.extend_from_slice(&output.script_pubkey);
                double_sha256(&output_data)
            });
            #[cfg(not(feature = "production"))]
            let hash_outputs = {
                let mut output_data = Vec::with_capacity(8 + 9 + output.script_pubkey.len());
                output_data.extend_from_slice(&output.value.to_le_bytes());
                write_varint_to_vec(&mut output_data, output.script_pubkey.len() as u64);
                output_data.extend_from_slice(&output.script_pubkey);
                double_sha256(&output_data)
            };
            preimage.extend_from_slice(&hash_outputs);
        } else {
            // SIGHASH_SINGLE with no corresponding output
            preimage.extend_from_slice(&[0u8; 32]);
        }
    } else {
        preimage.extend_from_slice(&hashes.hash_outputs);
    }

    // 9. nLockTime (4 bytes LE)
    preimage.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());

    // 10. sighash type (4 bytes LE)
    preimage.extend_from_slice(&(sighash_type as u32).to_le_bytes());

    // Double SHA256 the preimage
    Ok(double_sha256(preimage))
}

/// Batch compute BIP143 sighashes for all inputs.
/// This is the optimal way to verify a SegWit transaction - compute precomputed
/// hashes once, then calculate sighash for each input.
///
/// N7: when `sighash_type` is plain SIGHASH_ALL and `n ≥ 2`, share a SHA256 midstate after
/// `version‖hashPrevouts‖hashSequence` (mirrors legacy `compute_sighashes_batch`).
#[spec_locked("11.1.9", "ComputeWitnessSignatureHash")]
pub fn batch_compute_bip143_sighashes(
    tx: &Transaction,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    script_codes: &[&[u8]],
    sighash_type: u8,
) -> Result<Vec<Hash>> {
    if prevout_values.len() != tx.inputs.len()
        || prevout_script_pubkeys.len() != tx.inputs.len()
        || script_codes.len() != tx.inputs.len()
    {
        return Err(crate::error::ConsensusError::InvalidPrevoutsCount(
            prevout_values.len(),
            tx.inputs.len(),
        ));
    }

    // Compute precomputed hashes ONCE
    let precomputed = Bip143PrecomputedHashes::compute(tx, prevout_values, prevout_script_pubkeys);

    let base = sighash_type & 0x1f;
    let acp = sighash_type & 0x80;
    if base == 0x01 && acp == 0 && tx.inputs.len() >= 2 {
        return Ok(batch_bip143_sighash_all_midstate(
            tx,
            prevout_values,
            script_codes,
            &precomputed,
        ));
    }

    // Calculate sighash for each input using precomputed hashes
    let mut results = Vec::with_capacity(tx.inputs.len());
    for (i, (value, script_code)) in prevout_values.iter().zip(script_codes.iter()).enumerate() {
        let sighash =
            calculate_bip143_sighash(tx, i, script_code, *value, sighash_type, Some(&precomputed))?;
        results.push(sighash);
    }
    Ok(results)
}

/// N7: BIP143 SIGHASH_ALL midstate — clone SHA after common prefix, diverge per input.
fn batch_bip143_sighash_all_midstate(
    tx: &Transaction,
    prevout_values: &[i64],
    script_codes: &[&[u8]],
    hashes: &Bip143PrecomputedHashes,
) -> Vec<Hash> {
    use sha2::{Digest, Sha256};
    let n = tx.inputs.len();
    let mut prefix = Sha256::new();
    prefix.update((tx.version as u32).to_le_bytes());
    prefix.update(hashes.hash_prevouts);
    prefix.update(hashes.hash_sequence);

    let mut suffix = [0u8; 40];
    suffix[..32].copy_from_slice(&hashes.hash_outputs);
    suffix[32..36].copy_from_slice(&(tx.lock_time as u32).to_le_bytes());
    suffix[36..40].copy_from_slice(&0x01u32.to_le_bytes());

    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = prefix.clone();
        let input = &tx.inputs[i];
        h.update(input.prevout.hash);
        h.update(input.prevout.index.to_le_bytes());
        update_varint(&mut h, script_codes[i].len() as u64);
        h.update(script_codes[i]);
        h.update(prevout_values[i].to_le_bytes());
        h.update((input.sequence as u32).to_le_bytes());
        h.update(suffix);
        let first = h.finalize();
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        results.push(out);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::*;

    #[test]
    fn test_sighash_type_parsing() {
        // Standard types
        assert_eq!(SighashType::from_byte(0x01), SighashType::ALL);
        assert_eq!(SighashType::from_byte(0x02), SighashType::NONE);
        assert_eq!(SighashType::from_byte(0x03), SighashType::SINGLE);
        assert_eq!(SighashType::from_byte(0x00), SighashType::ALL_LEGACY);
        assert_eq!(SighashType::from_byte(0x81), SighashType::ALL_ANYONECANPAY);
        assert_eq!(SighashType::from_byte(0x82), SighashType::NONE_ANYONECANPAY);
        assert_eq!(
            SighashType::from_byte(0x83),
            SighashType::SINGLE_ANYONECANPAY
        );
        // Verify the byte values are preserved correctly for sighash preimage
        assert_eq!(SighashType::ALL_ANYONECANPAY.as_u32(), 0x81);
        assert_eq!(SighashType::NONE_ANYONECANPAY.as_u32(), 0x82);
        assert_eq!(SighashType::SINGLE_ANYONECANPAY.as_u32(), 0x83);
        // Non-standard types are accepted (pre-STRICTENC) with raw byte preserved
        let st = SighashType::from_byte(0x04);
        assert!(st.is_all()); // base_type 0x04 acts as ALL
        assert_eq!(st.as_u32(), 0x04); // raw byte preserved in preimage
        let st84 = SighashType::from_byte(0x84);
        assert!(st84.is_all());
        assert!(st84.is_anyonecanpay());
        assert_eq!(st84.as_u32(), 0x84);
    }

    #[test]
    fn test_varint_encoding() {
        use crate::serialization::varint::encode_varint;
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(252), vec![252]);
        assert_eq!(encode_varint(253), vec![0xfd, 253, 0]);
        assert_eq!(encode_varint(65535), vec![0xfd, 255, 255]);
        assert_eq!(encode_varint(65536), vec![0xfe, 0, 0, 1, 0]);
    }

    #[test]
    fn test_sighash_calculation() {
        // Create a simple transaction for testing
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [1u8; 32],
                    index: 0,
                },
                script_sig: vec![OP_1],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![
                    OP_DUP,
                    OP_HASH160,
                    PUSH_20_BYTES,
                    0x89,
                    0xab,
                    0xcd,
                    0xef,
                    0x12,
                    0x34,
                    0x56,
                    0x78,
                    0x9a,
                    0xbc,
                    0xde,
                    0xf0,
                    0x12,
                    0x34,
                    0x56,
                    0x78,
                    0x9a,
                    OP_EQUALVERIFY,
                    OP_CHECKSIG,
                ], // P2PKH
            }]
            .into(),
            lock_time: 0,
        };

        let prevouts = vec![TransactionOutput {
            value: 10000000000,
            script_pubkey: vec![
                OP_DUP,
                OP_HASH160,
                PUSH_20_BYTES,
                0x89,
                0xab,
                0xcd,
                0xef,
                0x12,
                0x34,
                0x56,
                0x78,
                0x9a,
                0xbc,
                0xde,
                0xf0,
                0x12,
                0x34,
                0x56,
                0x78,
                0x9a,
                OP_EQUALVERIFY,
                OP_CHECKSIG,
            ],
        }];

        // Test SIGHASH_ALL
        let sighash = calculate_transaction_sighash(&tx, 0, &prevouts, SighashType::ALL).unwrap();
        assert_eq!(sighash.len(), 32);

        // Test SIGHASH_NONE
        let sighash_none =
            calculate_transaction_sighash(&tx, 0, &prevouts, SighashType::NONE).unwrap();
        assert_ne!(sighash, sighash_none);

        // Test SIGHASH_SINGLE
        let sighash_single =
            calculate_transaction_sighash(&tx, 0, &prevouts, SighashType::SINGLE).unwrap();
        assert_ne!(sighash, sighash_single);
    }

    #[test]
    fn test_sighash_invalid_input_index() {
        let tx = Transaction {
            version: 1,
            inputs: vec![].into(),
            outputs: vec![].into(),
            lock_time: 0,
        };

        let result = calculate_transaction_sighash(&tx, 0, &[], SighashType::ALL);
        assert!(result.is_err());
    }

    #[test]
    fn test_bip143_sighash() {
        // Create a SegWit transaction for testing
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint {
                        hash: [1u8; 32],
                        index: 0,
                    },
                    script_sig: vec![], // Empty for SegWit
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint {
                        hash: [2u8; 32],
                        index: 1,
                    },
                    script_sig: vec![],
                    sequence: 0xfffffffe,
                },
            ]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![
                    OP_0,
                    PUSH_20_BYTES,
                    0x89,
                    0xab,
                    0xcd,
                    0xef,
                    0x12,
                    0x34,
                    0x56,
                    0x78,
                    0x9a,
                    0xbc,
                    0xde,
                    0xf0,
                    0x12,
                    0x34,
                    0x56,
                    0x78,
                    0x9a,
                    0xbc,
                    0xde,
                    0xf0,
                ],
            }]
            .into(),
            lock_time: 0,
        };

        let prevouts = [
            TransactionOutput {
                value: 10000000000,
                script_pubkey: vec![
                    OP_0,
                    PUSH_20_BYTES,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                    0x55,
                    0x66,
                    0x77,
                    0x88,
                    0x99,
                    0xaa,
                    0xbb,
                    0xcc,
                    0xdd,
                    0xee,
                    0xff,
                    0x00,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                ],
            },
            TransactionOutput {
                value: 8000000000,
                script_pubkey: vec![
                    OP_0,
                    PUSH_20_BYTES,
                    0xaa,
                    0xbb,
                    0xcc,
                    0xdd,
                    0xee,
                    0xff,
                    0x00,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                    0x55,
                    0x66,
                    0x77,
                    0x88,
                    0x99,
                    0xaa,
                    0xbb,
                    0xcc,
                    0xdd,
                ],
            },
        ];

        // P2WPKH scriptCode is OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_code = vec![
            OP_DUP,
            OP_HASH160,
            PUSH_20_BYTES,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xaa,
            0xbb,
            0xcc,
            0xdd,
            0xee,
            0xff,
            0x00,
            0x11,
            0x22,
            0x33,
            OP_EQUALVERIFY,
            OP_CHECKSIG,
        ];

        // Test BIP143 sighash for first input
        let sighash0 =
            calculate_bip143_sighash(&tx, 0, &script_code, prevouts[0].value, 0x01, None).unwrap();
        assert_eq!(sighash0.len(), 32);

        // Test BIP143 sighash for second input (should be different)
        let sighash1 =
            calculate_bip143_sighash(&tx, 1, &script_code, prevouts[1].value, 0x01, None).unwrap();
        assert_ne!(sighash0, sighash1);

        // Test with precomputed hashes (should match)
        let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
        let prevout_script_pubkeys: Vec<&[u8]> =
            prevouts.iter().map(|p| p.script_pubkey.as_ref()).collect();
        let precomputed =
            Bip143PrecomputedHashes::compute(&tx, &prevout_values, &prevout_script_pubkeys);
        let sighash0_precomputed = calculate_bip143_sighash(
            &tx,
            0,
            &script_code,
            prevout_values[0],
            0x01,
            Some(&precomputed),
        )
        .unwrap();
        assert_eq!(sighash0, sighash0_precomputed);

        // N7: midstate batch == per-input BIP143 for SIGHASH_ALL.
        let script_codes = [script_code.as_slice(), script_code.as_slice()];
        let batched = batch_compute_bip143_sighashes(
            &tx,
            &prevout_values,
            &prevout_script_pubkeys,
            &script_codes,
            0x01,
        )
        .unwrap();
        assert_eq!(batched[0], sighash0);
        assert_eq!(batched[1], sighash1);
    }

    #[test]
    fn test_bip143_anyonecanpay() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [1u8; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![OP_0, PUSH_20_BYTES],
            }]
            .into(),
            lock_time: 0,
        };

        let script_code = {
            let mut s = vec![OP_DUP, OP_HASH160, PUSH_20_BYTES];
            s.extend_from_slice(&[0u8; 20]); // 20 zero bytes (pubkey hash)
            s.push(OP_EQUALVERIFY);
            s.push(OP_CHECKSIG);
            s // 25 bytes total
        };
        let amount = 10000000000i64;

        // SIGHASH_ALL
        let sighash_all =
            calculate_bip143_sighash(&tx, 0, &script_code, amount, 0x01, None).unwrap();

        // SIGHASH_ALL | ANYONECANPAY (0x81)
        let sighash_anyonecanpay =
            calculate_bip143_sighash(&tx, 0, &script_code, amount, 0x81, None).unwrap();

        // Should be different (ANYONECANPAY zeroes hashPrevouts and hashSequence)
        assert_ne!(sighash_all, sighash_anyonecanpay);
    }

    /// Regression: 2-input legacy sighash must use EMPTY script for non-signing input.
    /// Per consensus, only the signing input's scriptCode is included; others get 0x00.
    /// Bug: build_preimage_2in1out/2in2out used full scriptPubKey for non-signing input → wrong sighash → IBD failure.
    #[test]
    fn test_2input_legacy_sighash_non_signing_empty_script() {
        // 2-in-1-out tx: when signing input 0, input 1's script must be empty in preimage
        let script_a = vec![
            PUSH_33_BYTES,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            OP_CHECKSIG,
        ]; // P2PK 35 bytes
        let script_b = vec![
            PUSH_33_BYTES,
            0x03,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            OP_CHECKSIG,
        ]; // Different P2PK
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint {
                        hash: [1u8; 32],
                        index: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint {
                        hash: [2u8; 32],
                        index: 1,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![OP_DUP, OP_HASH160, PUSH_20_BYTES],
            }]
            .into(),
            lock_time: 0,
        };
        let pv: Vec<i64> = vec![10_000_000_000, 8_000_000_000];
        let psp_ab: Vec<&[u8]> = vec![script_a.as_slice(), script_b.as_slice()];
        let psp_aa: Vec<&[u8]> = vec![script_a.as_slice(), script_a.as_slice()];

        // Signing input 0: input 1's script must be empty. So (script_a, script_b) and (script_a, script_a)
        // must produce the SAME sighash for input 0 — because input 1 is empty in preimage.
        let sighash_ab = calculate_transaction_sighash_with_script_code(
            &tx,
            0,
            &pv,
            &psp_ab,
            SighashType::ALL,
            None,
            #[cfg(feature = "production")]
            None,
        )
        .unwrap();
        let sighash_aa = calculate_transaction_sighash_with_script_code(
            &tx,
            0,
            &pv,
            &psp_aa,
            SighashType::ALL,
            None,
            #[cfg(feature = "production")]
            None,
        )
        .unwrap();
        assert_eq!(
            sighash_ab, sighash_aa,
            "2-input legacy: signing input 0 — input 1 script must be empty; changing input 1 scriptPubKey must not change sighash"
        );
    }

    #[cfg(feature = "production")]
    #[test]
    fn test_batch_sighash_single_input_index_ge_outputs() {
        // 2 inputs, 1 output: SIGHASH_SINGLE for input_index=1 has no corresponding output.
        // Must not panic; must return consensus hash 0x0000...0001.
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint {
                        hash: [1u8; 32],
                        index: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint {
                        hash: [2u8; 32],
                        index: 1,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![OP_DUP, OP_HASH160, PUSH_20_BYTES],
            }]
            .into(),
            lock_time: 0,
        };
        let prevout_values = vec![10_000_000_000i64, 8_000_000_000i64];
        let script = vec![OP_DUP, OP_HASH160, PUSH_20_BYTES];
        let prevout_script_pubkeys: Vec<&[u8]> = vec![script.as_slice(), script.as_slice()];
        let specs = vec![(1usize, 0x03u8, script.as_slice() as &[u8])]; // SIGHASH_SINGLE, input 1
        let hashes = super::batch_compute_legacy_sighashes(
            &tx,
            &prevout_values,
            &prevout_script_pubkeys,
            &specs,
        )
        .unwrap();
        assert_eq!(hashes.len(), 1);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(
            hashes[0], expected,
            "SIGHASH_SINGLE with input_index>=outputs.len() must return 0x0000...0001"
        );
    }
}
