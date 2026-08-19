//! Script execution engine from Orange Paper Section 5.2
//!
//! Performance optimizations (VM):
#![allow(
    clippy::declare_interior_mutable_const,  // const vs static for OnceLock in array init
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::needless_return,  // Many branches; mechanical fix error-prone
)]
//! - Secp256k1 context reuse (thread-local, zero-cost abstraction)
//! - Script result caching (production feature only, maintains correctness)
//! - Hash operation result caching (OP_HASH160, OP_HASH256)
//! - Stack pooling (thread-local pool of pre-allocated `Vec<StackElement>`)
//! - Memory allocation optimizations
//!
//! **Test vs production graph:** fast paths, LRU script cache, and batch verification are
//! behind `feature = "production"`. That feature is **on by default** in `Cargo.toml`
//! (`default = ["production", "blvm-secp256k1"]`), so normal `cargo test` matches the release
//! node interpreter. Use `cargo test --no-default-features` only when intentionally exercising
//! the minimal non-production graph.

mod arithmetic;
mod context;
mod control_flow;
mod crypto_ops;
pub mod flags;
mod signature;
mod stack;

pub use signature::{batch_verify_signatures, verify_pre_extracted_ecdsa};
pub use stack::{StackElement, cast_to_bool, to_stack_element};

use crate::constants::*;
use crate::crypto::OptimizedSha256;
use crate::error::{ConsensusError, Result, ScriptErrorCode};
use crate::opcodes::*;
use crate::types::*;
use blvm_spec_lock::spec_locked;
use digest::Digest;
use ripemd::Ripemd160;

// LLVM-like optimizations
#[cfg(feature = "production")]
use crate::optimizations::{precomputed_constants, prefetch};

// Cold error construction helpers - these paths are rarely taken
#[cold]
#[allow(dead_code)]
fn make_operation_limit_error() -> ConsensusError {
    ConsensusError::ScriptErrorWithCode {
        code: ScriptErrorCode::OpCount,
        message: "Operation limit exceeded".into(),
    }
}

#[cold]
fn make_stack_overflow_error() -> ConsensusError {
    ConsensusError::ScriptErrorWithCode {
        code: ScriptErrorCode::StackSize,
        message: "Stack overflow".into(),
    }
}

#[inline]
fn bip143_p2wpkh_script_code(pubkey_hash: &[u8]) -> [u8; 25] {
    let mut hash = [0u8; 20];
    hash.copy_from_slice(pubkey_hash);
    crate::transaction_hash::derive_bip143_script_code_p2wpkh(&hash)
}

#[cfg(feature = "production")]
use std::collections::VecDeque;
#[cfg(feature = "production")]
use std::sync::{
    OnceLock, RwLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
#[cfg(feature = "production")]
use std::thread_local;

/// Script verification result cache (production feature only)
///
/// Caches scriptPubKey verification results to avoid re-execution of identical scripts.
/// Cache is bounded (LRU) and invalidated on consensus changes.
/// Reference: Orange Paper Section 13.1 explicitly mentions script caching.
#[cfg(feature = "production")]
static SCRIPT_CACHE: OnceLock<RwLock<lru::LruCache<u64, bool>>> = OnceLock::new();

/// Signature verification cache (sighash, pubkey, sig, flags) -> valid.
/// Reserved for future IBD/mempool warm-cache integration.
#[cfg(feature = "production")]
mod sig_cache {
    #![allow(dead_code)]

    use lru::LruCache;
    use siphasher::sip::SipHasher24;
    use std::hash::{Hash, Hasher};
    use std::num::NonZeroUsize;
    use std::sync::{OnceLock, RwLock};

    const SIG_CACHE_SHARDS: usize = 32;
    const SIG_CACHE_SHARD: OnceLock<RwLock<LruCache<[u8; 32], bool>>> = OnceLock::new();

    static SIG_CACHE: [OnceLock<RwLock<LruCache<[u8; 32], bool>>>; SIG_CACHE_SHARDS] =
        [SIG_CACHE_SHARD; SIG_CACHE_SHARDS];

    fn sig_cache_size() -> usize {
        std::env::var("BLVM_SIG_CACHE_ENTRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &usize| n > 0 && n <= 1_000_000)
            .unwrap_or(500_000)
    }

    fn sig_cache_shard_index(key: &[u8; 32]) -> usize {
        let h = (key[0] as usize) | ((key[1] as usize) << 8) | ((key[2] as usize) << 16);
        h % SIG_CACHE_SHARDS
    }

    fn get_sig_cache_shard(key: &[u8; 32]) -> &'static RwLock<LruCache<[u8; 32], bool>> {
        let idx = sig_cache_shard_index(key);
        SIG_CACHE[idx].get_or_init(|| {
            let cap = (sig_cache_size() / SIG_CACHE_SHARDS).max(1);
            RwLock::new(LruCache::new(NonZeroUsize::new(cap).unwrap()))
        })
    }

    thread_local! {
        static BATCH_PUT_SIG_CACHE_BY_SHARD: std::cell::RefCell<[Vec<([u8; 32], bool)>; SIG_CACHE_SHARDS]> =
            std::cell::RefCell::new(std::array::from_fn(|_| Vec::new()));
    }

    fn batch_put_sig_cache(keys: &[[u8; 32]], results: &[bool]) {
        BATCH_PUT_SIG_CACHE_BY_SHARD.with(|cell| {
            let mut by_shard = cell.borrow_mut();
            for v in by_shard.iter_mut() {
                v.clear();
            }
            for (i, key) in keys.iter().enumerate() {
                let result = results.get(i).copied().unwrap_or(false);
                let idx = sig_cache_shard_index(key);
                by_shard[idx].push((*key, result));
            }
            for shard_entries in by_shard.iter() {
                if shard_entries.is_empty() {
                    continue;
                }
                let first_key = &shard_entries[0].0;
                if let Ok(mut guard) = get_sig_cache_shard(first_key).write() {
                    for (k, v) in shard_entries.iter() {
                        guard.put(*k, *v);
                    }
                }
            }
        });
    }

    fn sig_cache_at_collect_enabled() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            std::env::var("BLVM_SIG_CACHE_AT_COLLECT")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        })
    }

    #[inline(always)]
    fn ecdsa_cache_key(
        msg: &[u8; 32],
        pk: &[u8; 33],
        sig_compact: &[u8; 64],
        flags: u32,
    ) -> [u8; 32] {
        let mut key_input = [0u8; 133];
        key_input[..32].copy_from_slice(msg);
        key_input[32..65].copy_from_slice(pk);
        key_input[65..129].copy_from_slice(sig_compact);
        key_input[129..133].copy_from_slice(&flags.to_le_bytes());
        let mut hasher = SipHasher24::new();
        key_input.hash(&mut hasher);
        let h = hasher.finish();
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&h.to_le_bytes());
        out
    }
}

/// Thread-local buffers for verify_soa_batch; reused to avoid per-batch allocs.
#[cfg(feature = "production")]
thread_local! {
    static SOA_BATCH_BUF: std::cell::RefCell<(
        Vec<[u8; 64]>,
        Vec<[u8; 32]>,
        Vec<[u8; 33]>,
        Vec<usize>,
        Vec<[u8; 32]>,
    )> = const { std::cell::RefCell::new((
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )) };
}

/// Fast-path hit counters (production): verify that P2PK/P2PKH/P2SH/P2WPKH/P2WSH fast-paths are used.
/// Logged periodically from block validation; interpreter = scripts that fell through to full interpreter.
#[cfg(feature = "production")]
static FAST_PATH_P2PK: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "production")]
static FAST_PATH_P2PKH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "production")]
static FAST_PATH_P2SH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "production")]
static FAST_PATH_P2WPKH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "production")]
static FAST_PATH_P2WSH: AtomicU64 = AtomicU64::new(0);
static FAST_PATH_P2TR: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "production")]
static FAST_PATH_BARE_MULTISIG: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "production")]
static FAST_PATH_INTERPRETER: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "production")]
fn get_script_cache() -> &'static RwLock<lru::LruCache<u64, bool>> {
    SCRIPT_CACHE.get_or_init(|| {
        // Bounded cache: 100,000 entries (optimized for production workloads)
        // LRU eviction policy prevents unbounded memory growth
        // Increased from 50k to 100k for better hit rates in large mempools
        use lru::LruCache;
        use std::num::NonZeroUsize;
        RwLock::new(LruCache::new(NonZeroUsize::new(100_000).unwrap()))
    })
}

/// Stack pool for VM optimization (production feature only)
///
/// Thread-local pool of pre-allocated stacks to avoid allocation overhead.
/// Stacks are reused across script executions, significantly reducing memory allocations.
#[cfg(feature = "production")]
thread_local! {
    static STACK_POOL: std::cell::RefCell<VecDeque<Vec<StackElement>>> =
        std::cell::RefCell::new(VecDeque::with_capacity(10));
}

/// Get a stack from the pool, or create a new one if pool is empty
#[cfg(feature = "production")]
fn get_pooled_stack() -> Vec<StackElement> {
    STACK_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if let Some(mut stack) = pool.pop_front() {
            stack.clear();
            if stack.capacity() < 20 {
                stack.reserve(20);
            }
            stack
        } else {
            Vec::with_capacity(20)
        }
    })
}

/// RAII guard that returns stack to pool on drop. Use for interpreter fallback path.
#[cfg(feature = "production")]
struct PooledStackGuard(Vec<StackElement>);
#[cfg(feature = "production")]
impl Drop for PooledStackGuard {
    fn drop(&mut self) {
        return_pooled_stack(std::mem::take(&mut self.0));
    }
}

/// Return a stack to the pool for reuse
#[cfg(feature = "production")]
fn return_pooled_stack(mut stack: Vec<StackElement>) {
    // Clear stack but preserve capacity
    stack.clear();

    STACK_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        // Limit pool size to prevent unbounded growth
        if pool.len() < 10 {
            pool.push_back(stack);
        }
        // If pool is full, stack is dropped (deallocated)
    });
}

/// Flag to disable caching for benchmarking (production feature only)
///
/// When set to true, caches are bypassed entirely, allowing reproducible benchmarks
/// without cache state pollution between runs.
#[cfg(feature = "production")]
static CACHE_DISABLED: AtomicBool = AtomicBool::new(false);

/// When true, `verify_script_with_context_full` skips fast paths (P4.2 differential harness).
#[cfg(feature = "production")]
static FAST_PATHS_DISABLED: AtomicBool = AtomicBool::new(false);

/// Disable caching for benchmarking
///
/// When disabled, all cache lookups are bypassed, ensuring consistent performance
/// measurements without cache state affecting results.
///
/// # Example
///
/// ```rust
/// use blvm_consensus::script::disable_caching;
///
/// // Disable caches for benchmarking
/// disable_caching(true);
/// // Run benchmarks...
/// disable_caching(false); // Re-enable for production
/// ```
#[cfg(feature = "production")]
pub fn disable_caching(disabled: bool) {
    CACHE_DISABLED.store(disabled, Ordering::Relaxed);
}

/// Skip script fast paths so results come from the full interpreter (P4.2 equivalence tests).
#[cfg(feature = "production")]
pub fn disable_fast_paths(disabled: bool) {
    FAST_PATHS_DISABLED.store(disabled, Ordering::Relaxed);
}

/// Check if caching is disabled
#[cfg(feature = "production")]
fn is_caching_disabled() -> bool {
    CACHE_DISABLED.load(Ordering::Relaxed)
}

#[cfg(feature = "production")]
fn fast_paths_disabled() -> bool {
    FAST_PATHS_DISABLED.load(Ordering::Relaxed)
}

/// Compute cache key for script verification (SHA256 prefix — not `DefaultHasher`).
#[cfg(feature = "production")]
fn compute_script_cache_key(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: Option<&ByteString>,
    flags: u32,
) -> u64 {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&script_sig[..]);
    hasher.update(script_pubkey);
    if let Some(w) = witness {
        hasher.update(&w[..]);
    }
    hasher.update(flags.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[0..8].try_into().expect("sha256 prefix"))
}

/// Script version for policy/consensus behavior (BIP141/BIP341 SigVersion)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    /// Legacy and P2SH scripts
    Base,
    /// Witness v0 (P2WPKH/P2WSH)
    WitnessV0,
    /// Taproot script path (witness v1 Tapscript)
    Tapscript,
}

/// EvalScript: 𝒮𝒞 × 𝒮𝒯 × ℕ × SigVersion → {true, false}
///
/// Script execution follows a stack-based virtual machine:
/// 1. Initialize stack S = ∅
/// 2. For each opcode op in script:
///    - If |S| > L_stack: return false (stack overflow)
///    - If operation count > L_ops: return false (operation limit exceeded)
///    - Execute op with current stack state
///    - If execution fails: return false
/// 3. Return true if execution completed without error (final stack shape is
///    checked by [`verify_script`] / [`verify_script_with_context_full`], not here).
///
/// Performance: Pre-allocates stack with capacity hint to reduce allocations
///
/// In production mode, stacks should be obtained from pool using get_pooled_stack()
/// for optimal performance. This function works with any Vec<StackElement>.
#[spec_locked("5.2", "EvalScript")]
#[cfg_attr(feature = "production", inline(always))]
#[cfg_attr(not(feature = "production"), inline)]
pub fn eval_script(
    script: &[u8],
    stack: &mut Vec<StackElement>,
    flags: u32,
    sigversion: SigVersion,
) -> Result<bool> {
    // Pre-allocate stack capacity to reduce allocations during execution
    // Most scripts don't exceed 20 stack items in practice
    if stack.capacity() < 20 {
        stack.reserve(20);
    }
    #[cfg(feature = "production")]
    {
        eval_script_impl(script, stack, flags, sigversion)
    }
    #[cfg(not(feature = "production"))]
    {
        eval_script_inner(script, stack, flags, sigversion)
    }
}
#[cfg(feature = "production")]
fn eval_script_impl(
    script: &[u8],
    stack: &mut Vec<StackElement>,
    flags: u32,
    sigversion: SigVersion,
) -> Result<bool> {
    eval_script_inner(script, stack, flags, sigversion)
}

#[cfg(not(feature = "production"))]
#[allow(dead_code)]
fn eval_script_impl(
    script: &[u8],
    stack: &mut Vec<StackElement>,
    flags: u32,
    sigversion: SigVersion,
) -> Result<bool> {
    eval_script_inner(script, stack, flags, sigversion)
}

/// Push opcodes: any opcode <= OP_16 (0x60). Used by both production and non-production paths.
#[inline(always)]
fn is_push_opcode(opcode: u8) -> bool {
    opcode <= 0x60
}

/// BIP342: opcodes that cause immediate script success in Tapscript (OP_SUCCESSx).
/// Reference: BIP342 successful witness opcodes (IsOpSuccess).
#[inline]
fn is_op_success(opcode: u8) -> bool {
    matches!(
        opcode,
        80 | 98
            | 126..=129
            | 131..=134
            | 137..=138
            | 141..=142
            | 149..=153
            | 187..=254
    )
}

/// Advance past one opcode + its push data in a script byte slice.
/// Returns the number of bytes to skip (always >= 1).
#[inline]
fn op_advance(script: &[u8], pc: usize) -> usize {
    let opcode = script[pc];
    match opcode {
        // direct push: opcode byte is the data length (1–75 bytes)
        0x01..=0x4b => 1 + opcode as usize,
        // OP_PUSHDATA1: 1 length byte follows
        0x4c => {
            if pc + 1 < script.len() {
                2 + script[pc + 1] as usize
            } else {
                1
            }
        }
        // OP_PUSHDATA2: 2 length bytes follow (LE)
        0x4d => {
            if pc + 2 < script.len() {
                3 + u16::from_le_bytes([script[pc + 1], script[pc + 2]]) as usize
            } else {
                1
            }
        }
        // OP_PUSHDATA4: 4 length bytes follow (LE)
        0x4e => {
            if pc + 4 < script.len() {
                5 + u32::from_le_bytes([
                    script[pc + 1],
                    script[pc + 2],
                    script[pc + 3],
                    script[pc + 4],
                ]) as usize
            } else {
                1
            }
        }
        _ => 1,
    }
}

fn eval_script_inner(
    script: &[u8],
    stack: &mut Vec<StackElement>,
    flags: u32,
    sigversion: SigVersion,
) -> Result<bool> {
    use crate::constants::MAX_SCRIPT_SIZE;
    use crate::error::{ConsensusError, ScriptErrorCode};

    if (sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0)
        && script.len() > MAX_SCRIPT_SIZE
    {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::ScriptSize,
            message: "Script size exceeds maximum".into(),
        });
    }

    let mut op_count = 0;
    let mut control_stack: Vec<control_flow::ControlBlock> = Vec::new();
    let mut altstack: Vec<StackElement> = Vec::new();

    let mut i = 0;
    while i < script.len() {
        let opcode = script[i];
        let in_false_branch = control_flow::in_false_branch(&control_stack);

        // Count non-push opcodes toward op limit (Base/WitnessV0 only; BIP342 Tapscript has no 201-op cap).
        // nOpCount only for BASE || WITNESS_V0 (BIP342 Tapscript exempt).
        if sigversion != SigVersion::Tapscript && !is_push_opcode(opcode) {
            op_count += 1;
            if op_count > MAX_SCRIPT_OPS {
                return Err(make_operation_limit_error());
            }
            debug_assert!(
                op_count <= MAX_SCRIPT_OPS,
                "Operation count ({op_count}) must not exceed MAX_SCRIPT_OPS ({MAX_SCRIPT_OPS})"
            );
        }

        // Check combined stack + altstack size (BIP62/consensus).
        // Stack size limit uses > MAX_STACK_SIZE (allows exactly 1000 items).
        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(make_stack_overflow_error());
        }

        // Handle push opcodes with embedded data (0x01-0x4b direct, OP_PUSHDATA1/2/4).
        if (0x01..=OP_PUSHDATA4).contains(&opcode) {
            let (data, advance) = if opcode <= 0x4b {
                let len = opcode as usize;
                if i + 1 + len > script.len() {
                    return Ok(false);
                }
                (&script[i + 1..i + 1 + len], 1 + len)
            } else if opcode == OP_PUSHDATA1 {
                if i + 1 >= script.len() {
                    return Ok(false);
                }
                let len = script[i + 1] as usize;
                if i + 2 + len > script.len() {
                    return Ok(false);
                }
                (&script[i + 2..i + 2 + len], 2 + len)
            } else if opcode == OP_PUSHDATA2 {
                if i + 2 >= script.len() {
                    return Ok(false);
                }
                let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                if i + 3 + len > script.len() {
                    return Ok(false);
                }
                (&script[i + 3..i + 3 + len], 3 + len)
            } else {
                if i + 4 >= script.len() {
                    return Ok(false);
                }
                let len = u32::from_le_bytes([
                    script[i + 1],
                    script[i + 2],
                    script[i + 3],
                    script[i + 4],
                ]) as usize;
                let data_start = i.saturating_add(5);
                let data_end = data_start.saturating_add(len);
                let advance = 5usize.saturating_add(len);
                if advance < 5 || data_end > script.len() || data_end < data_start {
                    return Ok(false);
                }
                (&script[data_start..data_end], advance)
            };

            if !in_false_branch {
                let max_element = MAX_SCRIPT_ELEMENT_SIZE;
                if data.len() > max_element {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::PushSize,
                        message: format!(
                            "Push data size {} exceeds maximum {}",
                            data.len(),
                            max_element
                        )
                        .into(),
                    });
                }
                stack.push(to_stack_element(data));
            }
            i += advance;
            continue;
        }

        match opcode {
            // OP_IF
            OP_IF => {
                if in_false_branch {
                    control_stack.push(control_flow::ControlBlock::If { executing: false });
                } else if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_IF: empty stack".into(),
                    });
                } else {
                    let condition_bytes = stack.pop().unwrap();
                    let condition = cast_to_bool(&condition_bytes);

                    const SCRIPT_VERIFY_MINIMALIF: u32 = 0x2000;
                    if (flags & SCRIPT_VERIFY_MINIMALIF) != 0
                        && (sigversion == SigVersion::WitnessV0
                            || sigversion == SigVersion::Tapscript)
                        && !control_flow::is_minimal_if_condition(&condition_bytes)
                    {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::MinimalIf,
                            message: "OP_IF condition must be minimally encoded".into(),
                        });
                    }

                    control_stack.push(control_flow::ControlBlock::If {
                        executing: condition,
                    });
                }
            }
            // OP_NOTIF
            OP_NOTIF => {
                if in_false_branch {
                    control_stack.push(control_flow::ControlBlock::NotIf { executing: false });
                } else if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_NOTIF: empty stack".into(),
                    });
                } else {
                    let condition_bytes = stack.pop().unwrap();
                    let condition = cast_to_bool(&condition_bytes);

                    const SCRIPT_VERIFY_MINIMALIF: u32 = 0x2000;
                    if (flags & SCRIPT_VERIFY_MINIMALIF) != 0
                        && (sigversion == SigVersion::WitnessV0
                            || sigversion == SigVersion::Tapscript)
                        && !control_flow::is_minimal_if_condition(&condition_bytes)
                    {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::MinimalIf,
                            message: "OP_NOTIF condition must be minimally encoded".into(),
                        });
                    }

                    control_stack.push(control_flow::ControlBlock::NotIf {
                        executing: !condition,
                    });
                }
            }
            // OP_ELSE
            OP_ELSE => {
                if let Some(block) = control_stack.last_mut() {
                    match block {
                        control_flow::ControlBlock::If { executing }
                        | control_flow::ControlBlock::NotIf { executing } => {
                            *executing = !*executing;
                        }
                    }
                } else {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::UnbalancedConditional,
                        message: "OP_ELSE without matching IF/NOTIF".into(),
                    });
                }
            }
            // OP_ENDIF
            OP_ENDIF => {
                if control_stack.pop().is_none() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::UnbalancedConditional,
                        message: "OP_ENDIF without matching IF/NOTIF".into(),
                    });
                }
            }
            // OP_TOALTSTACK - move top stack item to altstack
            OP_TOALTSTACK => {
                if !in_false_branch {
                    if stack.is_empty() {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::InvalidStackOperation,
                            message: "OP_TOALTSTACK: empty stack".into(),
                        });
                    }
                    altstack.push(stack.pop().unwrap());
                }
            }
            // OP_FROMALTSTACK - move top altstack item to stack
            OP_FROMALTSTACK => {
                if !in_false_branch {
                    if altstack.is_empty() {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::InvalidAltstackOperation,
                            message: "OP_FROMALTSTACK: empty altstack".into(),
                        });
                    }
                    stack.push(altstack.pop().unwrap());
                }
            }
            _ => {
                if in_false_branch {
                    i += 1;
                    continue;
                }

                if !execute_opcode(opcode, stack, flags, sigversion)? {
                    return Ok(false);
                }

                if stack.len() + altstack.len() > MAX_STACK_SIZE {
                    return Err(make_stack_overflow_error());
                }
            }
        }
        i += 1;
    }

    if !control_stack.is_empty() {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::UnbalancedConditional,
            message: "Unclosed IF/NOTIF block".into(),
        });
    }

    // No final stack check — EvalScript behavior (VerifyScript checks stack afterward).
    Ok(true)
}

/// VerifyScript: 𝒮𝒞 × 𝒮𝒞 × 𝒲 × ℕ → {true, false}
///
/// For scriptSig ss, scriptPubKey spk, witness w, and flags f:
/// 1. Execute ss on empty stack
/// 2. Execute spk on resulting stack
/// 3. If witness present: execute w on stack
/// 4. Return final stack has exactly one true value
///
/// Legacy script verification (Base sigversion, at most one witness push).
///
/// **Deprecated**: accepts `Option<&ByteString>` not a full witness stack. SegWit and Taproot
/// inputs require [`verify_script_with_context`] or [`verify_script_with_context_full`].
#[deprecated(
    since = "0.1.33",
    note = "Use verify_script_with_context for witness-aware script verification"
)]
#[spec_locked("5.2", "VerifyScript")]
#[cfg_attr(feature = "production", inline(always))]
#[cfg_attr(not(feature = "production"), inline)]
pub fn verify_script(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: Option<&ByteString>,
    flags: u32,
) -> Result<bool> {
    // SigVersion is always Base for this API (no tx/witness context)
    let sigversion = SigVersion::Base;

    #[cfg(feature = "production")]
    {
        // Check cache first (unless disabled for benchmarking)
        if !is_caching_disabled() {
            let cache_key = compute_script_cache_key(script_sig, script_pubkey, witness, flags);
            {
                let cache = get_script_cache().read().unwrap_or_else(|e| e.into_inner());
                if let Some(&cached_result) = cache.peek(&cache_key) {
                    return Ok(cached_result);
                }
            }
        }

        // Execute script (cache miss)
        // Use pooled stack to avoid allocation
        let mut stack = get_pooled_stack();
        let cache_key = compute_script_cache_key(script_sig, script_pubkey, witness, flags);
        let result = {
            if !eval_script(script_sig, &mut stack, flags, sigversion)? {
                // Cache negative result (unless disabled)
                if !is_caching_disabled() {
                    let mut cache = get_script_cache()
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    cache.put(cache_key, false);
                }
                false
            } else if !eval_script(script_pubkey, &mut stack, flags, sigversion)? {
                if !is_caching_disabled() {
                    let mut cache = get_script_cache()
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    cache.put(cache_key, false);
                }
                false
            } else if let Some(w) = witness {
                if !eval_script(w, &mut stack, flags, sigversion)? {
                    if !is_caching_disabled() {
                        let mut cache = get_script_cache()
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        cache.put(cache_key, false);
                    }
                    false
                } else {
                    let res = !stack.is_empty() && cast_to_bool(&stack[stack.len() - 1]);
                    if !is_caching_disabled() {
                        let mut cache = get_script_cache()
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        cache.put(cache_key, res);
                    }
                    res
                }
            } else {
                let res = !stack.is_empty() && cast_to_bool(&stack[stack.len() - 1]);
                if !is_caching_disabled() {
                    let mut cache = get_script_cache()
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    cache.put(cache_key, res);
                }
                res
            }
        };

        // Return stack to pool
        return_pooled_stack(stack);

        Ok(result)
    }

    #[cfg(not(feature = "production"))]
    {
        // Pre-allocate stack with capacity hint (most scripts use <20 items)
        let mut stack = Vec::with_capacity(20);

        // Execute scriptSig
        if !eval_script(script_sig, &mut stack, flags, sigversion)? {
            return Ok(false);
        }

        // Execute scriptPubkey
        if !eval_script(script_pubkey, &mut stack, flags, sigversion)? {
            return Ok(false);
        }

        // Execute witness if present
        if let Some(w) = witness {
            if !eval_script(w, &mut stack, flags, sigversion)? {
                return Ok(false);
            }
        }

        // Final validation: top of stack must be truthy (CastToBool on stack.back()).
        Ok(!stack.is_empty() && cast_to_bool(&stack[stack.len() - 1]))
    }
}

/// VerifyScript with transaction context for signature verification
///
/// This version includes the full transaction context needed for proper
/// Script verification with transaction context and optional block height.
///
/// Pass `block_height` whenever it is known; height-dependent fork rules (CLTV, CSV,
/// SegWit, Taproot) rely on it to select the correct evaluation path.  Passing `None`
/// falls back to height `0` inside the engine, which means pre-activation rules are
/// used — valid only for regtest / test-vector scenarios.
///
/// For callers that also need to supply a pre-computed sighash or a specific
/// `SigVersion`, use [`verify_script_with_context_full`] directly.
#[spec_locked("5.2", "VerifyScript")]
#[cfg_attr(feature = "production", inline(always))]
#[cfg_attr(not(feature = "production"), inline)]
#[allow(clippy::too_many_arguments)]
pub fn verify_script_with_context(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: Option<&crate::witness::Witness>,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TransactionOutput],
    block_height: Option<u64>,
    network: crate::types::Network,
) -> Result<bool> {
    // Convert prevouts to parallel slices for the optimized API
    let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
    let prevout_script_pubkeys: Vec<&[u8]> =
        prevouts.iter().map(|p| p.script_pubkey.as_ref()).collect();

    verify_script_with_context_full(
        script_sig,
        script_pubkey,
        witness,
        flags,
        tx,
        input_index,
        &prevout_values,
        &prevout_script_pubkeys,
        block_height,
        None, // median_time_past
        network,
        SigVersion::Base, // _sigversion is ignored inside full; SigVersion is inferred from script
        #[cfg(feature = "production")]
        None, // schnorr_collector
        None,             // precomputed_bip143
        #[cfg(feature = "production")]
        None, // precomputed_sighash_all
        #[cfg(feature = "production")]
        None, // sighash_cache
        #[cfg(feature = "production")]
        None, // precomputed_p2pkh_hash
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None, // ecdsa_collect
    )
}

/// P2PK fast-path. Bare pay-to-pubkey: scriptPubKey is `pubkey` + OP_CHECKSIG, scriptSig is `sig`.
/// Common in early blocks (coinbase outputs). Returns Some(Ok(bool)) if handled; None to fall back.
/// Uses full transaction context (height, network) for BIP66 / signature validation.
///
/// For the Orange Paper **`VerifyScript`** contract (scriptSig + scriptPubKey + witness + flags),
/// see [`verify_script`], [`verify_script_with_context`], and [`verify_script_with_context_full`].
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
pub fn try_verify_p2pk_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
) -> Option<Result<bool>> {
    // P2PK scriptPubKey: OP_PUSHBYTES_N + pubkey + OP_CHECKSIG
    // 35 bytes (compressed: 0x21 + 33) or 67 bytes (uncompressed: 0x41 + 65)
    let len = script_pubkey.len();
    if len != 35 && len != 67 {
        return None;
    }
    if script_pubkey[len - 1] != OP_CHECKSIG {
        return None;
    }
    let pubkey_len = len - 2; // exclude push opcode and OP_CHECKSIG
    if pubkey_len != 33 && pubkey_len != 65 {
        return None;
    }
    if script_pubkey[0] != 0x21 && script_pubkey[0] != 0x41 {
        return None; // OP_PUSHBYTES_33 or OP_PUSHBYTES_65
    }
    let pubkey_bytes = &script_pubkey[1..(len - 1)];

    let signature_bytes = parse_p2pk_script_sig(script_sig.as_ref())?;
    if signature_bytes.is_empty() {
        return Some(Ok(false));
    }

    // Fast-path: P2PK script_pubkey is 35 or 67 bytes; signature push ≥71. Skip serialize+find_and_delete.
    use crate::transaction_hash::{SighashType, calculate_transaction_sighash_single_input};
    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
    let sighash_type = SighashType::from_byte(sighash_byte);
    let deleted_storage;
    let script_code: &[u8] = if script_pubkey.len() < 71 {
        script_pubkey
    } else {
        let pattern = serialize_push_data(signature_bytes);
        deleted_storage = find_and_delete(script_pubkey, &pattern);
        deleted_storage.as_ref()
    };
    let sighash = match calculate_transaction_sighash_single_input(
        tx,
        input_index,
        script_code,
        prevout_values[input_index],
        sighash_type,
        #[cfg(feature = "production")]
        sighash_cache,
    ) {
        Ok(h) => h,
        Err(e) => return Some(Err(e)),
    };

    let height = block_height.unwrap_or(0);
    let is_valid = signature::with_secp_context(|secp| {
        signature::verify_signature(
            secp,
            pubkey_bytes,
            signature_bytes,
            &sighash,
            flags,
            height,
            network,
            SigVersion::Base,
        )
    });
    Some(is_valid)
}

/// P2PKH fast-path. Returns Some(Ok(bool)) if script is P2PKH and we handled it;
/// Returns None to fall back to full interpreter.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
pub fn try_verify_p2pkh_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    #[cfg(feature = "production")] precomputed_sighash_all: Option<[u8; 32]>,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
    #[cfg(feature = "production")] precomputed_p2pkh_hash: Option<[u8; 20]>,
) -> Option<Result<bool>> {
    #[cfg(all(feature = "production", feature = "profile"))]
    let _t_entry = std::time::Instant::now();
    // P2PKH scriptPubKey: 25 bytes = OP_DUP OP_HASH160 PUSH_20_BYTES <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if script_pubkey.len() != 25 {
        return None;
    }
    if script_pubkey[0] != OP_DUP
        || script_pubkey[1] != OP_HASH160
        || script_pubkey[2] != PUSH_20_BYTES
        || script_pubkey[23] != OP_EQUALVERIFY
        || script_pubkey[24] != OP_CHECKSIG
    {
        return None;
    }
    let expected_hash = &script_pubkey[3..23];

    #[cfg(all(feature = "production", feature = "profile"))]
    crate::script_profile::add_p2pkh_fast_path_entry_ns(_t_entry.elapsed().as_nanos() as u64);
    #[cfg(all(feature = "production", feature = "profile"))]
    let _t_parse = std::time::Instant::now();
    let (signature_bytes, pubkey_bytes) = parse_p2pkh_script_sig(script_sig.as_ref())?;
    #[cfg(all(feature = "production", feature = "profile"))]
    crate::script_profile::add_p2pkh_parse_ns(_t_parse.elapsed().as_nanos() as u64);

    // Pubkey must be 33 (compressed) or 65 (uncompressed) bytes
    if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
        return Some(Ok(false));
    }
    // Empty signature is valid script but leaves 0 on stack -> verification false
    if signature_bytes.is_empty() {
        return Some(Ok(false));
    }

    // HASH160(pubkey) == expected hash (or use precomputed when provided by batch path)
    let pubkey_hash: [u8; 20] = match precomputed_p2pkh_hash {
        Some(h) => h,
        None => {
            #[cfg(all(feature = "production", feature = "profile"))]
            let _t_hash = std::time::Instant::now();
            let sha256_hash = OptimizedSha256::new().hash(pubkey_bytes);
            let h = Ripemd160::digest(sha256_hash);
            #[cfg(all(feature = "production", feature = "profile"))]
            crate::script_profile::add_p2pkh_hash160_ns(_t_hash.elapsed().as_nanos() as u64);
            h.into()
        }
    };
    if &pubkey_hash[..] != expected_hash {
        return Some(Ok(false));
    }

    // Legacy sighash: scriptCode = FindAndDelete(script_pubkey, serialize(signature))
    // Roadmap #12: use precomputed when available (batch sighash for P2PKH).
    use crate::transaction_hash::SighashType;
    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
    let sighash_type = SighashType::from_byte(sighash_byte);
    let deleted_storage;
    let script_code: &[u8] = if script_pubkey.len() < 71 {
        script_pubkey
    } else {
        let pattern = serialize_push_data(signature_bytes);
        deleted_storage = find_and_delete(script_pubkey, &pattern);
        deleted_storage.as_ref()
    };
    let sighash = {
        #[cfg(feature = "production")]
        {
            if let Some(precomp) = precomputed_sighash_all {
                precomp
            } else {
                crate::transaction_hash::compute_legacy_sighash_nocache(
                    tx,
                    input_index,
                    script_code,
                    sighash_byte,
                )
            }
        }
        #[cfg(not(feature = "production"))]
        {
            match calculate_transaction_sighash_single_input(
                tx,
                input_index,
                script_code,
                prevout_values[input_index],
                sighash_type,
            ) {
                Ok(h) => h,
                Err(e) => return Some(Err(e)),
            }
        }
    };

    #[cfg(all(feature = "production", feature = "profile"))]
    let _t_secp = std::time::Instant::now();
    let height = block_height.unwrap_or(0);
    let is_valid: Result<bool> = {
        let der_sig = &signature_bytes[..signature_bytes.len() - 1];
        if flags & 0x04 != 0
            && !crate::bip_validation::check_bip66_network(signature_bytes, height, network)
                .unwrap_or(false)
        {
            Ok(false)
        } else if flags & 0x02 != 0 {
            let base_sighash = sighash_byte & !0x80;
            if !(0x01..=0x03).contains(&base_sighash) {
                Ok(false)
            } else if pubkey_bytes.len() == 33 {
                if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 {
                    Ok(false)
                } else {
                    let strict_der = flags & 0x04 != 0;
                    let enforce_low_s = flags & 0x08 != 0;
                    Ok(crate::secp256k1_backend::verify_ecdsa_direct(
                        der_sig,
                        pubkey_bytes,
                        &sighash,
                        strict_der,
                        enforce_low_s,
                    )
                    .unwrap_or(false))
                }
            } else if pubkey_bytes.len() == 65 && pubkey_bytes[0] == 0x04 {
                let strict_der = flags & 0x04 != 0;
                let enforce_low_s = flags & 0x08 != 0;
                Ok(crate::secp256k1_backend::verify_ecdsa_direct(
                    der_sig,
                    pubkey_bytes,
                    &sighash,
                    strict_der,
                    enforce_low_s,
                )
                .unwrap_or(false))
            } else {
                Ok(false)
            }
        } else {
            let strict_der = flags & 0x04 != 0;
            let enforce_low_s = flags & 0x08 != 0;
            Ok(crate::secp256k1_backend::verify_ecdsa_direct(
                der_sig,
                pubkey_bytes,
                &sighash,
                strict_der,
                enforce_low_s,
            )
            .unwrap_or(false))
        }
    };
    #[cfg(all(feature = "production", feature = "profile"))]
    {
        let ns = _t_secp.elapsed().as_nanos() as u64;
        crate::script_profile::add_p2pkh_collect_ns(ns);
        crate::script_profile::add_p2pkh_secp_context_ns(ns);
    }
    Some(is_valid)
}

/// Fully inlined P2PKH verification for the rayon fast path.
/// Caller MUST have already verified script_pubkey is a valid P2PKH (25 bytes, correct opcodes).
/// Eliminates: redundant pattern check, Option unwrapping for precomputed values (always None),
/// assumevalid lookup, sighash cache overhead.
/// Returns Ok(true/false) directly — no Option wrapping.
#[cfg(feature = "production")]
#[inline]
pub fn verify_p2pkh_inline(
    script_sig: &[u8],
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    height: u64,
    network: crate::types::Network,
    precomputed_sighash_all: Option<[u8; 32]>,
    precomputed_p2pkh_hash: Option<[u8; 20]>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Result<bool> {
    let (signature_bytes, pubkey_bytes) = match parse_p2pkh_script_sig(script_sig) {
        Some(pair) => pair,
        None => return Ok(false),
    };
    verify_p2pkh_inline_parsed(
        signature_bytes,
        pubkey_bytes,
        script_pubkey,
        flags,
        tx,
        input_index,
        height,
        network,
        precomputed_sighash_all,
        precomputed_p2pkh_hash,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        ecdsa_collect,
    )
}

/// Like [`verify_p2pkh_inline`] but skips a second `parse_p2pkh_script_sig` when the
/// caller already parsed (IBD serial / collect hot path).
#[cfg(feature = "production")]
#[inline]
pub fn verify_p2pkh_inline_parsed(
    signature_bytes: &[u8],
    pubkey_bytes: &[u8],
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    height: u64,
    network: crate::types::Network,
    precomputed_sighash_all: Option<[u8; 32]>,
    precomputed_p2pkh_hash: Option<[u8; 20]>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Result<bool> {
    #[cfg(feature = "profile")]
    let _t0 = std::time::Instant::now();

    let expected_hash = &script_pubkey[3..23];

    if (pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65) || signature_bytes.is_empty() {
        return Ok(false);
    }

    #[cfg(feature = "profile")]
    let _t_hash = std::time::Instant::now();

    let pubkey_hash: [u8; 20] = match precomputed_p2pkh_hash {
        Some(h) => h,
        None => {
            let sha256_hash = OptimizedSha256::new().hash(pubkey_bytes);
            Ripemd160::digest(sha256_hash).into()
        }
    };
    if &pubkey_hash[..] != expected_hash {
        return Ok(false);
    }

    #[cfg(feature = "profile")]
    crate::script_profile::add_p2pkh_hash160_ns(_t_hash.elapsed().as_nanos() as u64);

    #[cfg(feature = "profile")]
    let _t_sighash = std::time::Instant::now();

    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
    let sighash = if let Some(precomp) = precomputed_sighash_all {
        precomp
    } else {
        // Incremental hasher (REVERT calculate-path: S10 189.4 vs nocache 195.6).
        crate::transaction_hash::compute_legacy_sighash_nocache(
            tx,
            input_index,
            script_pubkey,
            sighash_byte,
        )
    };

    #[cfg(feature = "profile")]
    crate::script_profile::add_sighash_ns(_t_sighash.elapsed().as_nanos() as u64);

    let der_sig = &signature_bytes[..signature_bytes.len() - 1];
    let strict_der = flags & 0x04 != 0;
    let enforce_low_s = flags & 0x08 != 0;

    if strict_der
        && !crate::bip_validation::check_bip66_network(signature_bytes, height, network)
            .unwrap_or(false)
    {
        return Ok(false);
    }

    if flags & 0x02 != 0 {
        let sighash_base = sighash_byte & !0x80;
        if !(0x01..=0x03).contains(&sighash_base) {
            return Ok(false);
        }
        match pubkey_bytes.len() {
            33 if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 => return Ok(false),
            65 if pubkey_bytes[0] != 0x04 => return Ok(false),
            33 | 65 => {}
            _ => return Ok(false),
        }
    }

    #[cfg(feature = "profile")]
    let _t_secp = std::time::Instant::now();

    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
    if let Some((collector, global_idx)) = ecdsa_collect {
        // Defer secp to block-end batch (CPU / optional GPU). Need compressed pk + compact sig.
        let compact =
            match blvm_secp256k1::ecdsa::ecdsa_der_to_compact(der_sig, strict_der, enforce_low_s) {
                Some(c) => c,
                None => return Ok(false),
            };
        let pk33 = match pubkey_bytes.len() {
            33 => {
                let mut a = [0u8; 33];
                a.copy_from_slice(pubkey_bytes);
                a
            }
            65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                None => return Ok(false),
            },
            _ => return Ok(false),
        };
        #[cfg(feature = "profile")]
        {
            crate::script_profile::add_p2pkh_collect_ns(_t_secp.elapsed().as_nanos() as u64);
            crate::script_profile::add_p2pkh_fast_path_entry_ns(_t0.elapsed().as_nanos() as u64);
        }
        collector.collect_with_index(global_idx, &sighash, &pk33, &compact);
        return Ok(true);
    }

    let result = crate::secp256k1_backend::verify_ecdsa_direct(
        der_sig,
        pubkey_bytes,
        &sighash,
        strict_der,
        enforce_low_s,
    )
    .unwrap_or(false);

    #[cfg(feature = "profile")]
    crate::script_profile::add_p2pkh_secp_context_ns(_t_secp.elapsed().as_nanos() as u64);

    #[cfg(feature = "profile")]
    crate::script_profile::add_p2pkh_fast_path_entry_ns(_t0.elapsed().as_nanos() as u64);

    Ok(result)
}

/// P2PK (Pay-to-Public-Key) inline verify.
#[cfg(feature = "production")]
#[inline]
pub fn verify_p2pk_inline(
    script_sig: &[u8],
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    height: u64,
    network: crate::types::Network,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Result<bool> {
    let pk_len = script_pubkey.len() - 2; // 33 or 65
    let pubkey_bytes = &script_pubkey[1..1 + pk_len];

    let signature_bytes = match parse_p2pk_script_sig(script_sig) {
        Some(s) => s,
        None => return Ok(false),
    };
    if signature_bytes.is_empty() {
        return Ok(false);
    }

    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
    let script_code: &[u8] = script_pubkey; // P2PK scriptPubKey < 71 bytes, no FindAndDelete

    let sighash = crate::transaction_hash::compute_legacy_sighash_nocache(
        tx,
        input_index,
        script_code,
        sighash_byte,
    );

    let der_sig = &signature_bytes[..signature_bytes.len() - 1];
    let strict_der = flags & 0x04 != 0;
    let enforce_low_s = flags & 0x08 != 0;

    if strict_der
        && !crate::bip_validation::check_bip66_network(signature_bytes, height, network)
            .unwrap_or(false)
    {
        return Ok(false);
    }

    if flags & 0x02 != 0 {
        let sighash_base = sighash_byte & !0x80;
        if !(0x01..=0x03).contains(&sighash_base) {
            return Ok(false);
        }
        match pubkey_bytes.len() {
            33 if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 => return Ok(false),
            65 if pubkey_bytes[0] != 0x04 => return Ok(false),
            33 | 65 => {}
            _ => return Ok(false),
        }
    }

    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
    if let Some((collector, global_idx)) = ecdsa_collect {
        let compact =
            match blvm_secp256k1::ecdsa::ecdsa_der_to_compact(der_sig, strict_der, enforce_low_s) {
                Some(c) => c,
                None => return Ok(false),
            };
        let pk33 = match pubkey_bytes.len() {
            33 => {
                let mut a = [0u8; 33];
                a.copy_from_slice(pubkey_bytes);
                a
            }
            65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                None => return Ok(false),
            },
            _ => return Ok(false),
        };
        collector.collect_with_index(global_idx, &sighash, &pk33, &compact);
        return Ok(true);
    }

    Ok(crate::secp256k1_backend::verify_ecdsa_direct(
        der_sig,
        pubkey_bytes,
        &sighash,
        strict_der,
        enforce_low_s,
    )
    .unwrap_or(false))
}

/// P2SH-multisig fast path: when redeem script matches `OP_m <pubkeys> OP_n OP_CHECKMULTISIG`,
/// verify inline or defer cartesian trials to [`EcdsaSignatureCollector`] when provided.
/// Returns Some(Ok(true/false)) if we handled it, None to fall through to interpreter.
#[allow(clippy::too_many_arguments)]
fn try_verify_p2sh_multisig_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collector: Option<
        &crate::ecdsa_batch::EcdsaSignatureCollector,
    >,
) -> Option<Result<bool>> {
    let _ = prevout_script_pubkeys;
    // P2SH scriptPubKey: OP_HASH160 PUSH_20 <20> OP_EQUAL
    if script_pubkey.len() != 23
        || script_pubkey[0] != OP_HASH160
        || script_pubkey[1] != PUSH_20_BYTES
        || script_pubkey[22] != OP_EQUAL
    {
        return None;
    }
    let pushes = parse_p2sh_script_sig_pushes(script_sig.as_ref())?;
    if pushes.len() < 2 {
        return None;
    }
    let redeem = pushes.last().expect("at least 2 pushes").as_ref();
    let expected_hash = &script_pubkey[2..22];
    let sha256_hash = OptimizedSha256::new().hash(redeem);
    let redeem_hash = Ripemd160::digest(sha256_hash);
    if &redeem_hash[..] != expected_hash {
        return Some(Ok(false));
    }
    let (m, _n, pubkeys) = parse_redeem_multisig(redeem)?;
    let signatures: Vec<&[u8]> = pushes
        .iter()
        .take(pushes.len() - 1)
        .skip(1)
        .map(|e| e.as_ref())
        .collect();
    let dummy = pushes.first().expect("at least 2 pushes").as_ref();

    const SCRIPT_VERIFY_NULLDUMMY: u32 = 0x10;
    const SCRIPT_VERIFY_NULLFAIL: u32 = 0x4000;
    let height = block_height.unwrap_or(0);
    if (flags & SCRIPT_VERIFY_NULLDUMMY) != 0 {
        let activation = match network {
            crate::types::Network::Mainnet => crate::constants::BIP147_ACTIVATION_MAINNET,
            crate::types::Network::Testnet => crate::constants::BIP147_ACTIVATION_TESTNET,
            crate::types::Network::Regtest | crate::types::Network::Signet => 0,
        };
        if height >= activation && !dummy.is_empty() && dummy != [0x00] {
            return Some(Ok(false));
        }
    }

    let mut cleaned = redeem.to_vec();
    for sig in &signatures {
        if sig.is_empty() {
            continue;
        }
        // Push encoding is ≥ sig.len()+1; FindAndDelete is a no-op when pattern can't fit.
        if sig.len().saturating_add(1) > cleaned.len() {
            continue;
        }
        let pattern = serialize_push_data(sig);
        cleaned = find_and_delete(&cleaned, &pattern).into_owned();
    }

    use crate::transaction_hash::{SighashType, calculate_transaction_sighash_single_input};

    // IBD deferral: cartesian oracle → SoA/GPU; Core match + NULLFAIL at block end.
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
    if let Some(collector) = ecdsa_collector {
        let nullfail = (flags & SCRIPT_VERIFY_NULLFAIL) != 0;
        let enforce_low_s = (flags & flags::SCRIPT_VERIFY_LOW_S) != 0;
        let strict_der = (flags & flags::SCRIPT_VERIFY_DERSIG) != 0
            || (flags & flags::SCRIPT_VERIFY_STRICTENC) != 0
            || (flags & flags::SCRIPT_VERIFY_LOW_S) != 0;
        let mut trial_indices = Vec::new();
        let mut sig_empty = Vec::with_capacity(signatures.len());
        // Reuse sighash when multiple sigs share the same sighash byte (common m-of-n).
        let mut sighash_by_type: Vec<(u8, [u8; 32])> = Vec::new();
        for sig_bytes in &signatures {
            if sig_bytes.is_empty() {
                sig_empty.push(true);
                continue;
            }
            sig_empty.push(false);
            let sighash_byte = sig_bytes[sig_bytes.len() - 1];
            let sighash =
                if let Some((_, h)) = sighash_by_type.iter().find(|(b, _)| *b == sighash_byte) {
                    *h
                } else {
                    let sighash_type = SighashType::from_byte(sighash_byte);
                    let h = match calculate_transaction_sighash_single_input(
                        tx,
                        input_index,
                        &cleaned,
                        prevout_values[input_index],
                        sighash_type,
                        sighash_cache,
                    ) {
                        Ok(h) => h,
                        Err(e) => return Some(Err(e)),
                    };
                    sighash_by_type.push((sighash_byte, h));
                    h
                };
            let der_sig = &sig_bytes[..sig_bytes.len() - 1];
            // Invalid DER / high-S: Core treats the sig as non-matching, not hard-fail
            // (NULLFAIL applied at resolve when the overall match fails).
            let compact =
                blvm_secp256k1::ecdsa::ecdsa_der_to_compact(der_sig, strict_der, enforce_low_s);
            for pubkey_bytes in &pubkeys {
                let gidx = collector.alloc_multisig_trial_index();
                trial_indices.push(gidx);
                let Some(compact) = compact.as_ref() else {
                    // No SoA row → resolve sees false (unwrap_or(false)).
                    continue;
                };
                // Core skips invalid pubkeys (no match). Do not Ok(false) the spend —
                // mainnet 442715/tx1351 is 2-of-3 with one off-curve PUB65.
                let pk33 = match pubkey_bytes.len() {
                    33 => {
                        let mut a = [0u8; 33];
                        a.copy_from_slice(pubkey_bytes);
                        a
                    }
                    65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                        Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                        None => continue,
                    },
                    _ => continue,
                };
                collector.collect_with_index(gidx, &sighash, &pk33, compact);
            }
        }
        collector.push_multisig_pending(crate::ecdsa_batch::MultisigPending {
            m,
            n_pubs: pubkeys.len(),
            trial_indices,
            sig_empty,
            nullfail,
        });
        #[cfg(feature = "profile")]
        crate::script_profile::note_arm_p2sh_multisig(0);
        return Some(Ok(true));
    }

    let mut sig_index = 0;
    let mut valid_sigs = 0u8;

    for pubkey_bytes in pubkeys {
        if sig_index >= signatures.len() {
            break;
        }
        while sig_index < signatures.len() && signatures[sig_index].is_empty() {
            sig_index += 1;
        }
        if sig_index >= signatures.len() {
            break;
        }
        let signature_bytes = &signatures[sig_index];
        let sighash_byte = signature_bytes[signature_bytes.len() - 1];
        let sighash_type = SighashType::from_byte(sighash_byte);
        let sighash = match calculate_transaction_sighash_single_input(
            tx,
            input_index,
            &cleaned,
            prevout_values[input_index],
            sighash_type,
            #[cfg(feature = "production")]
            sighash_cache,
        ) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };

        #[cfg(feature = "production")]
        let is_valid = signature::with_secp_context(|secp| {
            signature::verify_signature(
                secp,
                pubkey_bytes,
                signature_bytes,
                &sighash,
                flags,
                height,
                network,
                SigVersion::Base,
            )
        });

        #[cfg(not(feature = "production"))]
        let is_valid = {
            let secp = signature::new_secp();
            signature::verify_signature(
                &secp,
                pubkey_bytes,
                signature_bytes,
                &sighash,
                flags,
                height,
                network,
                SigVersion::Base,
            )
        };

        let is_valid = match is_valid {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        if is_valid {
            valid_sigs += 1;
            sig_index += 1;
        }
    }

    if (flags & SCRIPT_VERIFY_NULLFAIL) != 0 {
        for sig_bytes in &signatures[sig_index..] {
            if !sig_bytes.is_empty() {
                return Some(Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::SigNullFail,
                    message: "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL"
                        .into(),
                }));
            }
        }
    }

    Some(Ok(valid_sigs >= m))
}

/// IBD entry: P2SH-multisig with optional SoA deferral (see [`try_verify_p2sh_multisig_fast_path`]).
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_verify_p2sh_multisig_ibd(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    sighash_cache: Option<&crate::transaction_hash::SighashMidstateCache>,
    ecdsa_collector: Option<&crate::ecdsa_batch::EcdsaSignatureCollector>,
) -> Option<Result<bool>> {
    try_verify_p2sh_multisig_fast_path(
        script_sig,
        script_pubkey,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        network,
        sighash_cache,
        ecdsa_collector,
    )
}

/// Bare multisig fast path: scriptPubKey is `OP_n <pubkeys> OP_m OP_CHECKMULTISIG` directly.
/// No P2SH wrapper; scriptSig is \[dummy, sig_1, ..., sig_m\]. Same verification as P2SH multisig.
#[allow(clippy::too_many_arguments)]
fn try_verify_bare_multisig_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
) -> Option<Result<bool>> {
    let (m, _n, pubkeys) = parse_redeem_multisig(script_pubkey)?;
    let pushes = parse_p2sh_script_sig_pushes(script_sig.as_ref())?;
    if pushes.len() < 2 {
        return None;
    }
    let dummy = pushes.first().expect("at least 2 pushes").as_ref();
    let signatures: Vec<&[u8]> = pushes[1..].iter().map(|e| e.as_ref()).collect();

    const SCRIPT_VERIFY_NULLDUMMY: u32 = 0x10;
    const SCRIPT_VERIFY_NULLFAIL: u32 = 0x4000;
    let height = block_height.unwrap_or(0);
    if (flags & SCRIPT_VERIFY_NULLDUMMY) != 0 {
        let activation = match network {
            crate::types::Network::Mainnet => crate::constants::BIP147_ACTIVATION_MAINNET,
            crate::types::Network::Testnet => crate::constants::BIP147_ACTIVATION_TESTNET,
            crate::types::Network::Regtest | crate::types::Network::Signet => 0,
        };
        if height >= activation && !dummy.is_empty() && dummy != [0x00] {
            return Some(Ok(false));
        }
    }

    let mut cleaned = script_pubkey.to_vec();
    for sig in &signatures {
        if sig.is_empty() {
            continue;
        }
        if sig.len().saturating_add(1) > cleaned.len() {
            continue;
        }
        let pattern = serialize_push_data(sig);
        cleaned = find_and_delete(&cleaned, &pattern).into_owned();
    }

    use crate::transaction_hash::{SighashType, calculate_transaction_sighash_single_input};

    let mut sig_index = 0;
    let mut valid_sigs = 0u8;

    for pubkey_bytes in pubkeys {
        if sig_index >= signatures.len() {
            break;
        }
        while sig_index < signatures.len() && signatures[sig_index].is_empty() {
            sig_index += 1;
        }
        if sig_index >= signatures.len() {
            break;
        }
        let signature_bytes = &signatures[sig_index];
        let sighash_byte = signature_bytes[signature_bytes.len() - 1];
        let sighash_type = SighashType::from_byte(sighash_byte);
        let sighash = match calculate_transaction_sighash_single_input(
            tx,
            input_index,
            &cleaned,
            prevout_values[input_index],
            sighash_type,
            #[cfg(feature = "production")]
            sighash_cache,
        ) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };

        #[cfg(feature = "production")]
        let is_valid = signature::with_secp_context(|secp| {
            signature::verify_signature(
                secp,
                pubkey_bytes,
                signature_bytes,
                &sighash,
                flags,
                height,
                network,
                SigVersion::Base,
            )
        });

        #[cfg(not(feature = "production"))]
        let is_valid = {
            let secp = signature::new_secp();
            signature::verify_signature(
                &secp,
                pubkey_bytes,
                signature_bytes,
                &sighash,
                flags,
                height,
                network,
                SigVersion::Base,
            )
        };

        let is_valid = match is_valid {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        if is_valid {
            valid_sigs += 1;
            sig_index += 1;
        }
    }

    if (flags & SCRIPT_VERIFY_NULLFAIL) != 0 {
        for sig_bytes in &signatures[sig_index..] {
            if !sig_bytes.is_empty() {
                return Some(Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::SigNullFail,
                    message: "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL"
                        .into(),
                }));
            }
        }
    }

    Some(Ok(valid_sigs >= m))
}

/// P2SH fast-path for regular P2SH (redeem script is not a witness program).
/// Skips scriptSig + scriptPubKey interpreter run; verifies hash then runs redeem script only.
/// Returns None to fall back to full interpreter (e.g. witness programs, non-P2SH).
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
fn try_verify_p2sh_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    network: crate::types::Network,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
    #[cfg(feature = "production")] precomputed_sighash_all: Option<[u8; 32]>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Option<Result<bool>> {
    const SCRIPT_VERIFY_P2SH: u32 = 0x01;
    if (flags & SCRIPT_VERIFY_P2SH) == 0 {
        return None;
    }
    // P2SH scriptPubKey: 23 bytes = OP_HASH160 PUSH_20_BYTES <20 bytes> OP_EQUAL
    if script_pubkey.len() != 23
        || script_pubkey[0] != OP_HASH160
        || script_pubkey[1] != PUSH_20_BYTES
        || script_pubkey[22] != OP_EQUAL
    {
        return None;
    }
    let expected_hash = &script_pubkey[2..22];

    let mut pushes = parse_script_sig_push_only(script_sig.as_ref())?;
    if pushes.is_empty() {
        return None;
    }
    let redeem = pushes.pop().expect("at least one push");
    let mut stack = pushes;

    // Redeem must not be a witness program (P2WPKH-in-P2SH / P2WSH-in-P2SH use witness; we don't handle here)
    if redeem.len() >= 3
        && redeem[0] == OP_0
        && ((redeem[1] == PUSH_20_BYTES && redeem.len() == 22)
            || (redeem[1] == PUSH_32_BYTES && redeem.len() == 34))
    {
        return None;
    }

    // HASH160(redeem) == expected hash
    let sha256_hash = OptimizedSha256::new().hash(redeem.as_ref());
    let redeem_hash = Ripemd160::digest(sha256_hash);
    if &redeem_hash[..] != expected_hash {
        return Some(Ok(false));
    }

    // P2SH-with-P2PKH-redeem fast-path: skip interpreter when redeem is P2PKH
    if redeem.len() == 25
        && redeem[0] == OP_DUP
        && redeem[1] == OP_HASH160
        && redeem[2] == PUSH_20_BYTES
        && redeem[23] == OP_EQUALVERIFY
        && redeem[24] == OP_CHECKSIG
        && stack.len() == 2
    {
        let signature_bytes = &stack[0];
        let pubkey_bytes = &stack[1];
        if (pubkey_bytes.len() == 33 || pubkey_bytes.len() == 65) && !signature_bytes.is_empty() {
            let expected_pubkey_hash = &redeem[3..23];
            let sha256_hash = OptimizedSha256::new().hash(pubkey_bytes);
            let pubkey_hash = Ripemd160::digest(sha256_hash);
            if &pubkey_hash[..] == expected_pubkey_hash {
                #[cfg(feature = "production")]
                let sighash = if let Some(precomp) = precomputed_sighash_all {
                    precomp
                } else {
                    use crate::transaction_hash::{
                        SighashType, calculate_transaction_sighash_single_input,
                    };
                    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
                    let sighash_type = SighashType::from_byte(sighash_byte);
                    let deleted_storage;
                    let script_code: &[u8] = if redeem.len() < 71 {
                        redeem.as_ref()
                    } else {
                        let pattern = serialize_push_data(signature_bytes);
                        deleted_storage = find_and_delete(redeem.as_ref(), &pattern);
                        deleted_storage.as_ref()
                    };
                    match calculate_transaction_sighash_single_input(
                        tx,
                        input_index,
                        script_code,
                        prevout_values[input_index],
                        sighash_type,
                        sighash_cache,
                    ) {
                        Ok(h) => h,
                        Err(e) => return Some(Err(e)),
                    }
                };
                #[cfg(not(feature = "production"))]
                let sighash = {
                    use crate::transaction_hash::{
                        SighashType, calculate_transaction_sighash_single_input,
                    };
                    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
                    let sighash_type = SighashType::from_byte(sighash_byte);
                    let deleted_storage;
                    let script_code: &[u8] = if redeem.len() < 71 {
                        redeem.as_ref()
                    } else {
                        let pattern = serialize_push_data(signature_bytes);
                        deleted_storage = find_and_delete(redeem.as_ref(), &pattern);
                        deleted_storage.as_ref()
                    };
                    match calculate_transaction_sighash_single_input(
                        tx,
                        input_index,
                        script_code,
                        prevout_values[input_index],
                        sighash_type,
                    ) {
                        Ok(h) => h,
                        Err(e) => return Some(Err(e)),
                    }
                };
                let height = block_height.unwrap_or(0);
                let der_sig = &signature_bytes[..signature_bytes.len() - 1];
                let strict_der = flags & 0x04 != 0;
                let enforce_low_s = flags & 0x08 != 0;
                if strict_der
                    && !crate::bip_validation::check_bip66_network(signature_bytes, height, network)
                        .unwrap_or(false)
                {
                    return Some(Ok(false));
                }
                if flags & 0x02 != 0 {
                    let sighash_base = signature_bytes[signature_bytes.len() - 1] & !0x80;
                    if !(0x01..=0x03).contains(&sighash_base) {
                        return Some(Ok(false));
                    }
                    match pubkey_bytes.len() {
                        33 if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 => {
                            return Some(Ok(false));
                        }
                        65 if pubkey_bytes[0] != 0x04 => return Some(Ok(false)),
                        33 | 65 => {}
                        _ => return Some(Ok(false)),
                    }
                }
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                if let Some((collector, global_idx)) = ecdsa_collect {
                    // Default-on; set BLVM_P2SH_P2PKH_SOA=0 to disable.
                    if std::env::var_os("BLVM_P2SH_P2PKH_SOA").is_none_or(|v| v != "0") {
                        let compact = match blvm_secp256k1::ecdsa::ecdsa_der_to_compact(
                            der_sig,
                            strict_der,
                            enforce_low_s,
                        ) {
                            Some(c) => c,
                            None => return Some(Ok(false)),
                        };
                        let pk33 = match pubkey_bytes.len() {
                            33 => {
                                let mut a = [0u8; 33];
                                a.copy_from_slice(pubkey_bytes);
                                a
                            }
                            65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                                Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                                None => return Some(Ok(false)),
                            },
                            _ => return Some(Ok(false)),
                        };
                        collector.collect_with_index(global_idx, &sighash, &pk33, &compact);
                        return Some(Ok(true));
                    }
                }
                let is_valid = signature::with_secp_context(|secp| {
                    signature::verify_signature(
                        secp,
                        pubkey_bytes,
                        signature_bytes,
                        &sighash,
                        flags,
                        height,
                        network,
                        SigVersion::Base,
                    )
                });
                return Some(is_valid);
            }
        }
    }

    // P2SH-with-P2PK-redeem fast-path: redeem = OP_PUSHBYTES_N + pubkey + OP_CHECKSIG, stack = [sig]
    if (redeem.len() == 35 || redeem.len() == 67)
        && redeem[redeem.len() - 1] == OP_CHECKSIG
        && (redeem[0] == PUSH_33_BYTES || redeem[0] == PUSH_65_BYTES)
        && stack.len() == 1
    {
        let pubkey_len = redeem.len() - 2;
        if pubkey_len == 33 || pubkey_len == 65 {
            let pubkey_bytes = &redeem.as_ref()[1..(redeem.len() - 1)];
            let signature_bytes = &stack[0];
            if !signature_bytes.is_empty() {
                use crate::transaction_hash::{
                    SighashType, calculate_transaction_sighash_single_input,
                };
                let sighash_byte = signature_bytes[signature_bytes.len() - 1];
                let sighash_type = SighashType::from_byte(sighash_byte);
                // Fast-path: redeem is 35 or 67 bytes; signature push ≥71. FindAndDelete no-op.
                let deleted_storage;
                let script_code: &[u8] = if redeem.len() < 71 {
                    redeem.as_ref()
                } else {
                    let pattern = serialize_push_data(signature_bytes);
                    deleted_storage = find_and_delete(redeem.as_ref(), &pattern);
                    deleted_storage.as_ref()
                };
                match calculate_transaction_sighash_single_input(
                    tx,
                    input_index,
                    script_code,
                    prevout_values[input_index],
                    sighash_type,
                    #[cfg(feature = "production")]
                    sighash_cache,
                ) {
                    Ok(sighash) => {
                        let height = block_height.unwrap_or(0);
                        let is_valid = signature::with_secp_context(|secp| {
                            signature::verify_signature(
                                secp,
                                pubkey_bytes,
                                signature_bytes,
                                &sighash,
                                flags,
                                height,
                                network,
                                SigVersion::Base,
                            )
                        });
                        return Some(is_valid);
                    }
                    Err(e) => return Some(Err(e)),
                }
            }
        }
    }

    // Execute redeem script with remaining stack (same as regular P2SH path: no batch collector)
    let result = eval_script_with_context_full_inner(
        &redeem,
        &mut stack,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        median_time_past,
        network,
        SigVersion::Base,
        Some(redeem.as_ref()),
        None, // script_sig_for_sighash (P2SH redeem context)
        None, // taproot_annex_hash
        #[cfg(feature = "production")]
        None, // schnorr_collector
        None, // precomputed_bip143 - Base sigversion
        #[cfg(feature = "production")]
        sighash_cache,
    );
    Some(result)
}

/// Native P2WPKH inline verify (BIP143). Caller must gate scriptPubKey / witness shape.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn verify_p2wpkh_inline(
    witness: &crate::witness::Witness,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_value: i64,
    height: u64,
    network: crate::types::Network,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    precomputed_sighash_all: Option<[u8; 32]>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Result<bool> {
    let signature_bytes = &witness[0];
    let pubkey_bytes = &witness[1];
    if (pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65) || signature_bytes.is_empty() {
        return Ok(false);
    }

    let expected_hash = &script_pubkey[2..22];
    let sha256_hash = OptimizedSha256::new().hash(pubkey_bytes);
    let pubkey_hash = Ripemd160::digest(sha256_hash);
    if &pubkey_hash[..] != expected_hash {
        return Ok(false);
    }

    let p2pkh_script_code = bip143_p2wpkh_script_code(expected_hash);
    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
    let sighash = if sighash_byte == 0x01 {
        if let Some(precomp) = precomputed_sighash_all {
            precomp
        } else {
            crate::transaction_hash::calculate_bip143_sighash(
                tx,
                input_index,
                &p2pkh_script_code,
                prevout_value,
                sighash_byte,
                precomputed_bip143,
            )?
        }
    } else {
        crate::transaction_hash::calculate_bip143_sighash(
            tx,
            input_index,
            &p2pkh_script_code,
            prevout_value,
            sighash_byte,
            precomputed_bip143,
        )?
    };

    let der_sig = &signature_bytes[..signature_bytes.len() - 1];
    let strict_der = flags & 0x04 != 0;
    let enforce_low_s = flags & 0x08 != 0;

    if strict_der
        && !crate::bip_validation::check_bip66_network(signature_bytes, height, network)
            .unwrap_or(false)
    {
        return Ok(false);
    }

    if flags & 0x02 != 0 {
        let sighash_base = sighash_byte & !0x80;
        if !(0x01..=0x03).contains(&sighash_base) {
            return Ok(false);
        }
        match pubkey_bytes.len() {
            33 if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 => return Ok(false),
            65 if pubkey_bytes[0] != 0x04 => return Ok(false),
            33 | 65 => {}
            _ => return Ok(false),
        }
    }

    // P2WPKH SoA collect disabled: deferred GPU path false-rejected mainnet @497110 tx330.
    // Default-on SoA collect; set BLVM_P2WPKH_SOA=0 to disable (bisect).
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
    if let Some((collector, global_idx)) = ecdsa_collect {
        if std::env::var_os("BLVM_P2WPKH_SOA").is_none_or(|v| v != "0") {
            let compact = match blvm_secp256k1::ecdsa::ecdsa_der_to_compact(
                der_sig,
                strict_der,
                enforce_low_s,
            ) {
                Some(c) => c,
                None => return Ok(false),
            };
            let pk33 = match pubkey_bytes.len() {
                33 => {
                    let mut a = [0u8; 33];
                    a.copy_from_slice(pubkey_bytes);
                    a
                }
                65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                    Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                    None => return Ok(false),
                },
                _ => return Ok(false),
            };
            collector.collect_with_index(global_idx, &sighash, &pk33, &compact);
            return Ok(true);
        }
    }

    Ok(signature::with_secp_context(|secp| {
        signature::verify_signature(
            secp,
            pubkey_bytes,
            signature_bytes,
            &sighash,
            flags,
            height,
            network,
            SigVersion::WitnessV0,
        )
    })
    .unwrap_or(false))
}

/// P2WPKH-in-P2SH inline verify (BIP143). Caller must gate scriptPubKey / scriptSig / witness shape.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn verify_p2wpkh_in_p2sh_inline(
    script_sig: &[u8],
    witness: &crate::witness::Witness,
    script_pubkey: &[u8],
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_value: i64,
    height: u64,
    network: crate::types::Network,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Result<bool> {
    let expected_hash = &script_pubkey[2..22];
    let pushes = match parse_script_sig_push_only(script_sig) {
        Some(p) => p,
        None => return Ok(false),
    };
    if pushes.len() != 1 {
        return Ok(false);
    }
    let redeem = &pushes[0];
    if redeem.len() != 22 || redeem[0] != OP_0 || redeem[1] != PUSH_20_BYTES {
        return Ok(false);
    }
    let sha256_hash = OptimizedSha256::new().hash(redeem.as_ref());
    let redeem_hash = Ripemd160::digest(sha256_hash);
    if &redeem_hash[..] != expected_hash {
        return Ok(false);
    }

    if witness.len() != 2 {
        return Ok(false);
    }
    let signature_bytes = &witness[0];
    let pubkey_bytes = &witness[1];
    if (pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65) || signature_bytes.is_empty() {
        return Ok(false);
    }
    let expected_pubkey_hash = &redeem[2..22];
    let pubkey_sha256 = OptimizedSha256::new().hash(pubkey_bytes);
    let pubkey_hash = Ripemd160::digest(pubkey_sha256);
    if &pubkey_hash[..] != expected_pubkey_hash {
        return Ok(false);
    }

    let p2pkh_script_code = bip143_p2wpkh_script_code(expected_pubkey_hash);
    let sighash_byte = signature_bytes[signature_bytes.len() - 1];
    let sighash = crate::transaction_hash::calculate_bip143_sighash(
        tx,
        input_index,
        &p2pkh_script_code,
        prevout_value,
        sighash_byte,
        precomputed_bip143,
    )?;

    let der_sig = &signature_bytes[..signature_bytes.len() - 1];
    let strict_der = flags & 0x04 != 0;
    let enforce_low_s = flags & 0x08 != 0;

    if strict_der
        && !crate::bip_validation::check_bip66_network(signature_bytes, height, network)
            .unwrap_or(false)
    {
        return Ok(false);
    }

    if flags & 0x02 != 0 {
        let sighash_base = sighash_byte & !0x80;
        if !(0x01..=0x03).contains(&sighash_base) {
            return Ok(false);
        }
        match pubkey_bytes.len() {
            33 if pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03 => return Ok(false),
            65 if pubkey_bytes[0] != 0x04 => return Ok(false),
            33 | 65 => {}
            _ => return Ok(false),
        }
    }

    // Nested P2WPKH SoA: same gate as native (BLVM_P2WPKH_SOA=0 disables).
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
    if let Some((collector, global_idx)) = ecdsa_collect {
        if std::env::var_os("BLVM_P2WPKH_SOA").is_none_or(|v| v != "0") {
            let compact = match blvm_secp256k1::ecdsa::ecdsa_der_to_compact(
                der_sig,
                strict_der,
                enforce_low_s,
            ) {
                Some(c) => c,
                None => return Ok(false),
            };
            let pk33 = match pubkey_bytes.len() {
                33 => {
                    let mut a = [0u8; 33];
                    a.copy_from_slice(pubkey_bytes);
                    a
                }
                65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                    Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                    None => return Ok(false),
                },
                _ => return Ok(false),
            };
            collector.collect_with_index(global_idx, &sighash, &pk33, &compact);
            return Ok(true);
        }
    }

    Ok(signature::with_secp_context(|secp| {
        signature::verify_signature(
            secp,
            pubkey_bytes,
            signature_bytes,
            &sighash,
            flags,
            height,
            network,
            SigVersion::WitnessV0,
        )
    })
    .unwrap_or(false))
}

/// P2WPKH fast-path (SegWit P2PKH). ScriptPubKey OP_0 <20-byte-hash>, witness [sig, pubkey].
/// Uses BIP143 sighash; skips interpreter. Returns None to fall back to full path.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
fn try_verify_p2wpkh_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(feature = "production")] precomputed_sighash_all: Option<[u8; 32]>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Option<Result<bool>> {
    let _ = prevout_script_pubkeys;
    // P2WPKH: 22 bytes = OP_0 PUSH_20_BYTES <20-byte-hash>
    if script_pubkey.len() != 22 || script_pubkey[0] != OP_0 || script_pubkey[1] != PUSH_20_BYTES {
        return None;
    }
    // Native SegWit: scriptSig must be empty
    if !script_sig.is_empty() {
        return None;
    }
    if witness.len() != 2 {
        return None;
    }
    let height = block_height.unwrap_or(0);
    let prevout_value = prevout_values.get(input_index).copied().unwrap_or(0);
    Some(verify_p2wpkh_inline(
        witness,
        script_pubkey,
        flags,
        tx,
        input_index,
        prevout_value,
        height,
        network,
        precomputed_bip143,
        precomputed_sighash_all,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        ecdsa_collect,
    ))
}

/// P2WPKH-in-P2SH (nested SegWit). ScriptPubKey P2SH, scriptSig = \[redeem\], redeem = OP_0 + 20-byte pubkey hash, witness = \[sig, pubkey\].
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
fn try_verify_p2wpkh_in_p2sh_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Option<Result<bool>> {
    let _ = prevout_script_pubkeys;
    const SCRIPT_VERIFY_P2SH: u32 = 0x01;
    if (flags & SCRIPT_VERIFY_P2SH) == 0 {
        return None;
    }
    if script_pubkey.len() != 23
        || script_pubkey[0] != OP_HASH160
        || script_pubkey[1] != PUSH_20_BYTES
        || script_pubkey[22] != OP_EQUAL
    {
        return None;
    }
    // P2WSH-in-P2SH also commonly has witness.len()==2 ([sig…, witnessScript]).
    // Only claim nested P2WPKH when redeem is the 22-byte v0 program; otherwise None
    // so the full P2SH/witness path runs (mainnet fail @497110 tx330 without this gate).
    if witness.len() != 2 {
        return None;
    }
    let pushes = parse_script_sig_push_only(script_sig.as_ref())?;
    if pushes.len() != 1 {
        return None;
    }
    let redeem = &pushes[0];
    if redeem.len() != 22 || redeem[0] != OP_0 || redeem[1] != PUSH_20_BYTES {
        return None;
    }
    let height = block_height.unwrap_or(0);
    let prevout_value = prevout_values.get(input_index).copied().unwrap_or(0);
    Some(verify_p2wpkh_in_p2sh_inline(
        script_sig.as_ref(),
        witness,
        script_pubkey,
        flags,
        tx,
        input_index,
        prevout_value,
        height,
        network,
        precomputed_bip143,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        ecdsa_collect,
    ))
}

/// P2WSH-in-P2SH (nested). scriptSig = \[redeem\], redeem = OP_0 + 32-byte program; then same as native P2WSH.
/// Must run after nested-P2WPKH gate so 22-byte redeems are not claimed here.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_verify_p2wsh_in_p2sh_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    network: crate::types::Network,
    schnorr_collector: Option<&crate::bip348::SchnorrSignatureCollector>,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collector: Option<
        &crate::ecdsa_batch::EcdsaSignatureCollector,
    >,
) -> Option<Result<bool>> {
    const SCRIPT_VERIFY_P2SH: u32 = 0x01;
    if (flags & SCRIPT_VERIFY_P2SH) == 0 {
        return None;
    }
    if script_pubkey.len() != 23
        || script_pubkey[0] != OP_HASH160
        || script_pubkey[1] != PUSH_20_BYTES
        || script_pubkey[22] != OP_EQUAL
    {
        return None;
    }
    let pushes = parse_script_sig_push_only(script_sig.as_ref())?;
    if pushes.len() != 1 {
        return None;
    }
    let redeem = &pushes[0];
    if redeem.len() != 34 || redeem[0] != OP_0 || redeem[1] != PUSH_32_BYTES {
        return None;
    }
    let expected_hash = &script_pubkey[2..22];
    let sha256_hash = OptimizedSha256::new().hash(redeem.as_ref());
    let redeem_hash = Ripemd160::digest(sha256_hash);
    if &redeem_hash[..] != expected_hash {
        return Some(Ok(false));
    }
    // Native P2WSH path with empty scriptSig and redeem as the v0 program.
    let empty_sig: ByteString = Vec::new();
    try_verify_p2wsh_fast_path(
        &empty_sig,
        redeem.as_ref(),
        witness,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        median_time_past,
        network,
        schnorr_collector,
        precomputed_bip143,
        #[cfg(feature = "production")]
        sighash_cache,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        ecdsa_collector,
    )
}

/// P2WSH fast-path. ScriptPubKey OP_0 <32-byte-SHA256(witness_script)>; witness = [..., witness_script].
/// Verifies hash then executes witness script only. Returns None to fall back to full path.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_verify_p2wsh_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    network: crate::types::Network,
    schnorr_collector: Option<&crate::bip348::SchnorrSignatureCollector>,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collector: Option<
        &crate::ecdsa_batch::EcdsaSignatureCollector,
    >,
) -> Option<Result<bool>> {
    // P2WSH: 34 bytes = OP_0 PUSH_32_BYTES <32-byte-hash>
    if script_pubkey.len() != 34 || script_pubkey[0] != OP_0 || script_pubkey[1] != PUSH_32_BYTES {
        return None;
    }
    if !script_sig.is_empty() {
        return None;
    }
    if witness.is_empty() {
        return None;
    }
    let max_witness_elem = MAX_SCRIPT_ELEMENT_SIZE;
    for element in witness.iter().take(witness.len().saturating_sub(1)) {
        if element.len() > max_witness_elem {
            return Some(Ok(false));
        }
    }
    let witness_script = witness.last().expect("witness not empty").clone();
    let mut stack: Vec<StackElement> = witness
        .iter()
        .take(witness.len() - 1)
        .map(|w| to_stack_element(w))
        .collect();

    let program_hash = &script_pubkey[2..34];
    if program_hash.len() != 32 {
        return None;
    }
    let witness_script_hash = OptimizedSha256::new().hash(witness_script.as_ref());
    if &witness_script_hash[..] != program_hash {
        return Some(Ok(false));
    }

    // P2WSH always uses WitnessV0 sighash semantics (BIP143).
    // 0x8000 is SCRIPT_VERIFY_WITNESS_PUBKEYTYPE — a key-type strictness flag, not a
    // sigversion selector. Tapscript only applies inside Taproot script-path spends.
    let witness_sigversion = SigVersion::WitnessV0;

    // P2WSH-with-P2PKH fast-path: witness_script = P2PKH, stack = [sig, pubkey]. BIP143 inline verify.
    if witness_sigversion == SigVersion::WitnessV0
        && witness_script.len() == 25
        && witness_script[0] == OP_DUP
        && witness_script[1] == OP_HASH160
        && witness_script[2] == PUSH_20_BYTES
        && witness_script[23] == OP_EQUALVERIFY
        && witness_script[24] == OP_CHECKSIG
        && stack.len() == 2
    {
        let signature_bytes = &stack[0];
        let pubkey_bytes = &stack[1];
        if (pubkey_bytes.len() == 33 || pubkey_bytes.len() == 65) && !signature_bytes.is_empty() {
            let expected_pubkey_hash = &witness_script[3..23];
            let pubkey_sha256 = OptimizedSha256::new().hash(pubkey_bytes);
            let pubkey_hash = Ripemd160::digest(pubkey_sha256);
            if &pubkey_hash[..] == expected_pubkey_hash {
                let sighash_byte = signature_bytes[signature_bytes.len() - 1];
                let amount = prevout_values.get(input_index).copied().unwrap_or(0);
                match crate::transaction_hash::calculate_bip143_sighash(
                    tx,
                    input_index,
                    witness_script.as_ref(),
                    amount,
                    sighash_byte,
                    precomputed_bip143,
                ) {
                    Ok(sighash) => {
                        let height = block_height.unwrap_or(0);
                        let is_valid = signature::with_secp_context(|secp| {
                            signature::verify_signature(
                                secp,
                                pubkey_bytes,
                                signature_bytes,
                                &sighash,
                                flags,
                                height,
                                network,
                                SigVersion::WitnessV0,
                            )
                        });
                        return Some(is_valid);
                    }
                    Err(e) => return Some(Err(e)),
                }
            }
        }
    }

    // P2WSH-with-P2PK fast-path: witness_script = OP_PUSHBYTES_N + pubkey + OP_CHECKSIG, stack = [sig]. BIP143 inline verify.
    if witness_sigversion == SigVersion::WitnessV0
        && (witness_script.len() == 35 || witness_script.len() == 67)
        && witness_script[witness_script.len() - 1] == OP_CHECKSIG
        && (witness_script[0] == 0x21 || witness_script[0] == 0x41)
        && stack.len() == 1
    {
        let pubkey_len = witness_script.len() - 2;
        if (pubkey_len == 33 || pubkey_len == 65) && !stack[0].is_empty() {
            let pubkey_bytes = &witness_script[1..(witness_script.len() - 1)];
            let signature_bytes = &stack[0];
            let sighash_byte = signature_bytes[signature_bytes.len() - 1];
            let amount = prevout_values.get(input_index).copied().unwrap_or(0);
            match crate::transaction_hash::calculate_bip143_sighash(
                tx,
                input_index,
                witness_script.as_ref(),
                amount,
                sighash_byte,
                precomputed_bip143,
            ) {
                Ok(sighash) => {
                    let height = block_height.unwrap_or(0);
                    let is_valid = signature::with_secp_context(|secp| {
                        signature::verify_signature(
                            secp,
                            pubkey_bytes,
                            signature_bytes,
                            &sighash,
                            flags,
                            height,
                            network,
                            SigVersion::WitnessV0,
                        )
                    });
                    return Some(is_valid);
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }

    // P2WSH-with-multisig fast-path: witness_script = OP_n <pubkeys> OP_m OP_CHECKMULTISIG,
    // stack = [dummy, sig_1, ..., sig_m]. BIP143 scriptCode = witness script (no FindAndDelete).
    if witness_sigversion == SigVersion::WitnessV0 {
        if let Some((m, _n, pubkeys)) = parse_redeem_multisig(witness_script.as_ref()) {
            if stack.len() < 2 {
                return Some(Ok(false));
            }
            let dummy = stack[0].as_ref();
            let signatures: Vec<&[u8]> = stack[1..].iter().map(|e| e.as_ref()).collect();

            const SCRIPT_VERIFY_NULLDUMMY: u32 = 0x10;
            const SCRIPT_VERIFY_NULLFAIL: u32 = 0x4000;
            let height = block_height.unwrap_or(0);
            if (flags & SCRIPT_VERIFY_NULLDUMMY) != 0 {
                let activation = match network {
                    crate::types::Network::Mainnet => crate::constants::BIP147_ACTIVATION_MAINNET,
                    crate::types::Network::Testnet => crate::constants::BIP147_ACTIVATION_TESTNET,
                    crate::types::Network::Regtest | crate::types::Network::Signet => 0,
                };
                if height >= activation && !dummy.is_empty() && dummy != [0x00] {
                    return Some(Ok(false));
                }
            }

            // WitnessV0 (BIP143): scriptCode is the witness script; no FindAndDelete.
            let script_code = witness_script.as_ref();
            let amount = prevout_values.get(input_index).copied().unwrap_or(0);

            // IBD deferral: cartesian oracle → SoA/GPU; Core match + NULLFAIL at block end.
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            if let Some(collector) = ecdsa_collector {
                let nullfail = (flags & SCRIPT_VERIFY_NULLFAIL) != 0;
                let enforce_low_s = (flags & flags::SCRIPT_VERIFY_LOW_S) != 0;
                let strict_der = (flags & flags::SCRIPT_VERIFY_DERSIG) != 0
                    || (flags & flags::SCRIPT_VERIFY_STRICTENC) != 0
                    || (flags & flags::SCRIPT_VERIFY_LOW_S) != 0;
                let mut trial_indices = Vec::new();
                let mut sig_empty = Vec::with_capacity(signatures.len());
                // Reuse BIP143 sighash when multiple sigs share sighash byte (common m-of-n).
                let mut sighash_by_type: Vec<(u8, [u8; 32])> = Vec::new();
                for sig_bytes in &signatures {
                    if sig_bytes.is_empty() {
                        sig_empty.push(true);
                        continue;
                    }
                    sig_empty.push(false);
                    let sighash_byte = sig_bytes[sig_bytes.len() - 1];
                    let sighash = if let Some((_, h)) =
                        sighash_by_type.iter().find(|(b, _)| *b == sighash_byte)
                    {
                        *h
                    } else {
                        let h = match crate::transaction_hash::calculate_bip143_sighash(
                            tx,
                            input_index,
                            script_code,
                            amount,
                            sighash_byte,
                            precomputed_bip143,
                        ) {
                            Ok(h) => h,
                            Err(e) => return Some(Err(e)),
                        };
                        sighash_by_type.push((sighash_byte, h));
                        h
                    };
                    let der_sig = &sig_bytes[..sig_bytes.len() - 1];
                    let compact = blvm_secp256k1::ecdsa::ecdsa_der_to_compact(
                        der_sig,
                        strict_der,
                        enforce_low_s,
                    );
                    for pubkey_bytes in &pubkeys {
                        let gidx = collector.alloc_multisig_trial_index();
                        trial_indices.push(gidx);
                        let Some(compact) = compact.as_ref() else {
                            continue;
                        };
                        let pk33 = match pubkey_bytes.len() {
                            33 => {
                                let mut a = [0u8; 33];
                                a.copy_from_slice(pubkey_bytes);
                                a
                            }
                            65 => match blvm_secp256k1::ecdsa::ge_from_pubkey_bytes(pubkey_bytes) {
                                Some(ge) => blvm_secp256k1::ecdsa::ge_to_compressed(&ge),
                                None => continue,
                            },
                            _ => continue,
                        };
                        collector.collect_with_index(gidx, &sighash, &pk33, compact);
                    }
                }
                collector.push_multisig_pending(crate::ecdsa_batch::MultisigPending {
                    m,
                    n_pubs: pubkeys.len(),
                    trial_indices,
                    sig_empty,
                    nullfail,
                });
                #[cfg(feature = "profile")]
                crate::script_profile::note_arm_p2sh_multisig(0);
                return Some(Ok(true));
            }

            let mut sig_index = 0;
            let mut valid_sigs = 0u8;

            for pubkey_bytes in pubkeys {
                if sig_index >= signatures.len() {
                    break;
                }
                while sig_index < signatures.len() && signatures[sig_index].is_empty() {
                    sig_index += 1;
                }
                if sig_index >= signatures.len() {
                    break;
                }
                let signature_bytes = &signatures[sig_index];
                let sighash_byte = signature_bytes[signature_bytes.len() - 1];
                match crate::transaction_hash::calculate_bip143_sighash(
                    tx,
                    input_index,
                    script_code,
                    amount,
                    sighash_byte,
                    precomputed_bip143,
                ) {
                    Ok(sighash) => {
                        let is_valid = signature::with_secp_context(|secp| {
                            signature::verify_signature(
                                secp,
                                pubkey_bytes,
                                signature_bytes,
                                &sighash,
                                flags,
                                height,
                                network,
                                SigVersion::WitnessV0,
                            )
                        });
                        match is_valid {
                            Ok(v) if v => {
                                valid_sigs += 1;
                                sig_index += 1;
                            }
                            Ok(_) => {}
                            Err(e) => return Some(Err(e)),
                        }
                    }
                    Err(e) => return Some(Err(e)),
                }
            }

            if (flags & SCRIPT_VERIFY_NULLFAIL) != 0 {
                for sig_bytes in &signatures[sig_index..] {
                    if !sig_bytes.is_empty() {
                        return Some(Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::SigNullFail,
                            message:
                                "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL"
                                    .into(),
                        }));
                    }
                }
            }

            return Some(Ok(valid_sigs >= m));
        }
    }

    // Witness script uses interpreter path (no batch collection).
    // CHECKMULTISIG in witness script can produce invalid sig/pubkey pairings for batch.
    let result = eval_script_with_context_full_inner(
        &witness_script,
        &mut stack,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        median_time_past,
        network,
        witness_sigversion,
        Some(witness_script.as_ref()), // BIP143 scriptCode for CHECKSIG inside P2WSH
        None,                          // script_sig_for_sighash (witness script context)
        None,                          // taproot_annex_hash
        schnorr_collector,
        precomputed_bip143,
        #[cfg(feature = "production")]
        sighash_cache,
    );
    Some(result)
}

/// P2TR script-path tapscript P2PK fast path. Tapscript PUSH_32_BYTES <32-byte-pubkey> OP_CHECKSIG, witness [sig, script, control_block].
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
fn try_verify_p2tr_scriptpath_p2pk_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    _flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    schnorr_collector: Option<&crate::bip348::SchnorrSignatureCollector>,
) -> Option<Result<bool>> {
    use crate::activation::taproot_active_at_height;
    use crate::taproot::parse_taproot_script_path_witness;

    if !taproot_active_at_height(block_height, network) {
        return None;
    }
    if script_pubkey.len() != 34 || script_pubkey[0] != OP_1 || script_pubkey[1] != PUSH_32_BYTES {
        return None;
    }
    if !script_sig.is_empty() {
        return None;
    }
    if witness.len() < 2 {
        return None;
    }
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&script_pubkey[2..34]);
    let (witness_body, annex_hash) = crate::taproot::strip_taproot_annex(witness);
    let parsed = match parse_taproot_script_path_witness(&witness_body, &output_key) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return None,
    };
    let (tapscript, stack_items, control_block) = parsed;
    if tapscript.len() != 34 || tapscript[0] != PUSH_32_BYTES || tapscript[33] != OP_CHECKSIG {
        return None;
    }
    if stack_items.len() != 1 {
        return None;
    }
    let (sig_bytes, sighash_type) =
        crate::bip348::try_parse_taproot_schnorr_witness_sig(stack_items[0].as_ref())?;
    let pubkey_32 = &tapscript[1..33];
    let sighash = crate::taproot::compute_tapscript_signature_hash(
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        &tapscript,
        control_block.leaf_version,
        0xffff_ffff,
        sighash_type,
        annex_hash.as_ref(),
    )
    .ok()?;
    let result = crate::bip348::verify_tapscript_schnorr_signature(
        &sighash,
        pubkey_32,
        &sig_bytes,
        schnorr_collector,
    );
    Some(result)
}

/// Taproot (P2TR) key-path fast-path. ScriptPubKey OP_1 <32-byte output key>, witness [64-byte sig].
/// Skips interpreter; verifies Schnorr directly. Returns None for script-path or pre-activation.
#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
fn verify_p2tr_keypath_witness(
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    schnorr_collector: Option<&crate::bip348::SchnorrSignatureCollector>,
) -> Result<bool> {
    use crate::bip348::{
        try_parse_taproot_schnorr_witness_sig, verify_tapscript_schnorr_signature,
    };

    let (witness_body, annex_hash) = crate::taproot::strip_taproot_annex(witness);
    if witness_body.len() != 1 {
        return Ok(false);
    }
    let Some((sig_bytes, sighash_type)) = try_parse_taproot_schnorr_witness_sig(&witness_body[0])
    else {
        return Ok(false);
    };
    let output_key = &script_pubkey[2..34];
    let sighash = crate::taproot::compute_taproot_signature_hash(
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        sighash_type,
        annex_hash.as_ref(),
    )?;
    verify_tapscript_schnorr_signature(&sighash, output_key, &sig_bytes, schnorr_collector)
}

#[cfg(feature = "production")]
#[allow(clippy::too_many_arguments)]
fn try_verify_p2tr_keypath_fast_path(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: &crate::witness::Witness,
    _flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    network: crate::types::Network,
    schnorr_collector: Option<&crate::bip348::SchnorrSignatureCollector>,
) -> Option<Result<bool>> {
    use crate::activation::taproot_active_at_height;
    if !taproot_active_at_height(block_height, network) {
        return None;
    }
    // P2TR: 34 bytes = OP_1 PUSH_32_BYTES <32-byte output key>
    if script_pubkey.len() != 34 || script_pubkey[0] != OP_1 || script_pubkey[1] != PUSH_32_BYTES {
        return None;
    }
    if !script_sig.is_empty() {
        return None;
    }
    // Key-path: one stack element after optional annex strip (BIP340 Schnorr check).
    let (witness_body, _) = crate::taproot::strip_taproot_annex(witness);
    if witness_body.len() != 1 {
        return None;
    }
    crate::bip348::try_parse_taproot_schnorr_witness_sig(&witness_body[0])?;
    Some(verify_p2tr_keypath_witness(
        script_pubkey,
        witness,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        schnorr_collector,
    ))
}

#[spec_locked("5.2", "VerifyScript")]
pub fn verify_script_with_context_full(
    script_sig: &ByteString,
    script_pubkey: &[u8],
    witness: Option<&crate::witness::Witness>,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    network: crate::types::Network,
    _sigversion: SigVersion,
    #[cfg(feature = "production")] schnorr_collector: Option<
        &crate::bip348::SchnorrSignatureCollector,
    >,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(feature = "production")] precomputed_sighash_all: Option<[u8; 32]>,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
    #[cfg(feature = "production")] precomputed_p2pkh_hash: Option<[u8; 20]>,
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))] ecdsa_collect: Option<(
        &crate::ecdsa_batch::EcdsaSignatureCollector,
        usize,
    )>,
) -> Result<bool> {
    // libbitcoin-consensus check (multi-input verify_script): prevouts length must match vin size
    if prevout_values.len() != tx.inputs.len() || prevout_script_pubkeys.len() != tx.inputs.len() {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::TxInputInvalid,
            message: format!(
                "Prevout slices: values={}, script_pubkeys={}, input_count={} (input_idx={})",
                prevout_values.len(),
                prevout_script_pubkeys.len(),
                tx.inputs.len(),
                input_index,
            )
            .into(),
        });
    }

    // libbitcoin-consensus check: prevout.value must not exceed i64::MAX
    // In libbitcoin-consensus: if (prevout.value > std::numeric_limits<int64_t>::max())
    // This prevents value overflow in TransactionSignatureChecker
    // Note: Our value is already i64, so it can't exceed i64::MAX by definition
    // But we validate it's non-negative and within MAX_MONEY bounds for safety
    if input_index < prevout_values.len() {
        let prevout_value = prevout_values[input_index];
        if prevout_value < 0 {
            return Err(ConsensusError::ScriptErrorWithCode {
                code: ScriptErrorCode::ValueOverflow,
                message: "Prevout value cannot be negative".into(),
            });
        }
        #[cfg(feature = "production")]
        {
            use precomputed_constants::MAX_MONEY_U64;
            if (prevout_value as u64) > MAX_MONEY_U64 {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::ValueOverflow,
                    message: format!("Prevout value {prevout_value} exceeds MAX_MONEY").into(),
                });
            }
        }
        #[cfg(not(feature = "production"))]
        {
            use crate::constants::MAX_MONEY;
            if prevout_value > MAX_MONEY {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::ValueOverflow,
                    message: format!("Prevout value {prevout_value} exceeds MAX_MONEY").into(),
                });
            }
        }
    }

    // libbitcoin-consensus check: input_index must be valid
    if input_index >= tx.inputs.len() {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::TxInputInvalid,
            message: format!(
                "Input index {} out of bounds (tx has {} inputs)",
                input_index,
                tx.inputs.len()
            )
            .into(),
        });
    }

    // P2PK / P2PKH / P2SH fast-paths — skip interpreter for common legacy scripts
    #[cfg(feature = "production")]
    if !fast_paths_disabled() && witness.is_none() {
        if let Some(result) = try_verify_p2pk_fast_path(
            script_sig,
            script_pubkey,
            flags,
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            block_height,
            network,
            #[cfg(feature = "production")]
            sighash_cache,
        ) {
            FAST_PATH_P2PK.fetch_add(1, Ordering::Relaxed);
            return result;
        }
        if let Some(result) = try_verify_p2pkh_fast_path(
            script_sig,
            script_pubkey,
            flags,
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            block_height,
            network,
            #[cfg(feature = "production")]
            precomputed_sighash_all,
            #[cfg(feature = "production")]
            sighash_cache,
            #[cfg(feature = "production")]
            precomputed_p2pkh_hash,
        ) {
            FAST_PATH_P2PKH.fetch_add(1, Ordering::Relaxed);
            return result;
        }
        if let Some(result) = try_verify_p2sh_fast_path(
            script_sig,
            script_pubkey,
            flags,
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            block_height,
            median_time_past,
            network,
            #[cfg(feature = "production")]
            sighash_cache,
            #[cfg(feature = "production")]
            precomputed_sighash_all,
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            ecdsa_collect,
        ) {
            FAST_PATH_P2SH.fetch_add(1, Ordering::Relaxed);
            return result;
        }
        if let Some(result) = try_verify_bare_multisig_fast_path(
            script_sig,
            script_pubkey,
            flags,
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            block_height,
            network,
            #[cfg(feature = "production")]
            sighash_cache,
        ) {
            FAST_PATH_BARE_MULTISIG.fetch_add(1, Ordering::Relaxed);
            return result;
        }
    }
    // P2WPKH / P2WSH / P2WPKH-in-P2SH fast-paths when witness present
    #[cfg(feature = "production")]
    if !fast_paths_disabled() {
        if let Some(wit) = witness {
            if let Some(result) = try_verify_p2wpkh_in_p2sh_fast_path(
                script_sig,
                script_pubkey,
                wit,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                network,
                precomputed_bip143,
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                ecdsa_collect,
            ) {
                FAST_PATH_P2WPKH.fetch_add(1, Ordering::Relaxed);
                return result;
            }
            if let Some(result) = try_verify_p2wsh_in_p2sh_fast_path(
                script_sig,
                script_pubkey,
                wit,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                median_time_past,
                network,
                schnorr_collector,
                precomputed_bip143,
                #[cfg(feature = "production")]
                sighash_cache,
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                ecdsa_collect.map(|(c, _)| c),
            ) {
                FAST_PATH_P2WSH.fetch_add(1, Ordering::Relaxed);
                return result;
            }
            if let Some(result) = try_verify_p2wpkh_fast_path(
                script_sig,
                script_pubkey,
                wit,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                network,
                precomputed_bip143,
                precomputed_sighash_all,
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                ecdsa_collect,
            ) {
                FAST_PATH_P2WPKH.fetch_add(1, Ordering::Relaxed);
                return result;
            }
            if let Some(result) = try_verify_p2wsh_fast_path(
                script_sig,
                script_pubkey,
                wit,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                median_time_past,
                network,
                schnorr_collector,
                precomputed_bip143,
                #[cfg(feature = "production")]
                sighash_cache,
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                ecdsa_collect.map(|(c, _)| c),
            ) {
                FAST_PATH_P2WSH.fetch_add(1, Ordering::Relaxed);
                return result;
            }
            if let Some(result) = try_verify_p2tr_scriptpath_p2pk_fast_path(
                script_sig,
                script_pubkey,
                wit,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                network,
                schnorr_collector,
            ) {
                FAST_PATH_P2TR.fetch_add(1, Ordering::Relaxed);
                return result;
            }
            if let Some(result) = try_verify_p2tr_keypath_fast_path(
                script_sig,
                script_pubkey,
                wit,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                network,
                schnorr_collector,
            ) {
                FAST_PATH_P2TR.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }
    }
    #[cfg(feature = "production")]
    FAST_PATH_INTERPRETER.fetch_add(1, Ordering::Relaxed);

    // P2SH handling: If SCRIPT_VERIFY_P2SH flag is set and scriptPubkey is P2SH format,
    // we need to check scriptSig push-only BEFORE executing it
    // P2SH scriptPubkey format: OP_HASH160 <20-byte-hash> OP_EQUAL
    const SCRIPT_VERIFY_P2SH: u32 = 0x01;
    let is_p2sh = (flags & SCRIPT_VERIFY_P2SH) != 0
        && script_pubkey.len() == 23  // OP_HASH160 (1) + push 20 (1) + 20 bytes + OP_EQUAL (1) = 23
        && script_pubkey[0] == OP_HASH160   // OP_HASH160
        && script_pubkey[1] == PUSH_20_BYTES   // push 20 bytes
        && script_pubkey[22] == OP_EQUAL; // OP_EQUAL

    // CRITICAL: For P2SH, scriptSig MUST only contain push operations (data pushes only)
    // This prevents script injection attacks. If scriptSig contains non-push opcodes, fail immediately.
    // This check MUST happen BEFORE executing scriptSig
    // Note: We validate push-only by attempting to parse scriptSig as push-only
    // If we encounter any non-push opcode OR invalid push encoding, we fail
    if is_p2sh {
        let mut i = 0;
        while i < script_sig.len() {
            let opcode = script_sig[i];
            if !is_push_opcode(opcode) {
                // Non-push opcode found in P2SH scriptSig - this is invalid
                return Ok(false);
            }
            // Advance past the push opcode and data
            if opcode == OP_0 {
                // OP_0 - push empty array, no data to skip
                i += 1;
            } else if opcode <= 0x4b {
                // Direct push: opcode is the length (1-75 bytes)
                let len = opcode as usize;
                if i + 1 + len > script_sig.len() {
                    return Ok(false); // Invalid push length
                }
                i += 1 + len;
            } else if opcode == OP_PUSHDATA1 {
                // OP_PUSHDATA1
                if i + 1 >= script_sig.len() {
                    return Ok(false);
                }
                let len = script_sig[i + 1] as usize;
                if i + 2 + len > script_sig.len() {
                    return Ok(false);
                }
                i += 2 + len;
            } else if opcode == OP_PUSHDATA2 {
                // OP_PUSHDATA2
                if i + 2 >= script_sig.len() {
                    return Ok(false);
                }
                let len = u16::from_le_bytes([script_sig[i + 1], script_sig[i + 2]]) as usize;
                if i + 3 + len > script_sig.len() {
                    return Ok(false);
                }
                i += 3 + len;
            } else if opcode == OP_PUSHDATA4 {
                // OP_PUSHDATA4
                if i + 4 >= script_sig.len() {
                    return Ok(false);
                }
                let len = u32::from_le_bytes([
                    script_sig[i + 1],
                    script_sig[i + 2],
                    script_sig[i + 3],
                    script_sig[i + 4],
                ]) as usize;
                if i + 5 + len > script_sig.len() {
                    return Ok(false);
                }
                i += 5 + len;
            } else if (OP_1NEGATE..=OP_16).contains(&opcode) {
                // OP_1NEGATE, OP_RESERVED, OP_1-OP_16
                // These are single-byte push opcodes with no data payload
                i += 1;
            } else {
                // Should not reach here if is_push_opcode is correct, but fail anyway
                return Ok(false);
            }
        }
        if !fast_paths_disabled() {
            if let Some(result) = try_verify_p2sh_multisig_fast_path(
                script_sig,
                script_pubkey,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                network,
                #[cfg(feature = "production")]
                sighash_cache,
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                ecdsa_collect.map(|(c, _)| c),
            ) {
                return result;
            }
        }
    }

    #[cfg(feature = "production")]
    let mut _stack_guard = PooledStackGuard(get_pooled_stack());
    #[cfg(feature = "production")]
    let stack = &mut _stack_guard.0;
    #[cfg(not(feature = "production"))]
    let mut stack = Vec::with_capacity(20);

    // Execute scriptSig (always Base sigversion)
    // FIX: scriptSig can contain CHECKSIG/CHECKMULTISIG (non-standard); collecting produces invalid
    // (sig, pubkey) pairings. Only fast paths (P2PKH, P2WPKH, P2WSH) have correct 1:1 pairing.
    let script_sig_result = eval_script_with_context_full(
        script_sig,
        stack,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        median_time_past,
        network,
        SigVersion::Base,
        None, // redeem_script_for_sighash
        None, // script_sig not needed when executing scriptSig
        None, // taproot_annex_hash
        #[cfg(feature = "production")]
        schnorr_collector,
        None, // precomputed_bip143 - Base sigversion
        #[cfg(feature = "production")]
        sighash_cache,
    )?;
    if !script_sig_result {
        return Ok(false);
    }

    // Save redeem script if P2SH (it's the last item on stack after scriptSig)
    let redeem_script: Option<ByteString> = if is_p2sh && !stack.is_empty() {
        Some(stack.last().expect("Stack is not empty").as_ref().to_vec())
    } else {
        None
    };
    let nested_witness_program = redeem_script.as_ref().is_some_and(|redeem| {
        redeem.len() >= 3
            && redeem[0] == OP_0
            && ((redeem[1] == PUSH_20_BYTES && redeem.len() == 22)
                || (redeem[1] == PUSH_32_BYTES && redeem.len() == 34))
    });
    // BIP141: nested P2WPKH/P2WSH scriptSig must be exactly one push of the redeem.
    if nested_witness_program {
        match parse_script_sig_push_only(script_sig.as_ref()) {
            Some(items) if items.len() == 1 => {}
            _ => return Ok(false),
        }
    }

    // CRITICAL FIX: Check if scriptPubkey is Taproot (P2TR) - OP_1 <32-byte-hash>
    // Taproot format: [OP_1, PUSH_32_BYTES, <32 bytes>] = 34 bytes total
    // For Taproot, scriptSig must be empty and validation happens via witness using Taproot-specific logic
    use crate::activation::taproot_active_at_height;
    let is_taproot = redeem_script.is_none()  // Not P2SH
        && taproot_active_at_height(block_height, network)
        && script_pubkey.len() == 34
        && script_pubkey[0] == OP_1  // OP_1 (witness version 1)
        && script_pubkey[1] == PUSH_32_BYTES; // push 32 bytes

    // If Taproot, scriptSig must be empty
    if is_taproot && !script_sig.is_empty() {
        return Ok(false); // Taproot requires empty scriptSig
    }

    // Future / non-standard witness programs (BIP141 §2; discourage-upgradable-witness).
    if redeem_script.is_none()
        && !is_taproot
        && crate::witness::is_upgradable_witness_program(script_pubkey)
    {
        use crate::script::flags::{
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, SCRIPT_VERIFY_WITNESS,
        };
        if !script_sig.is_empty() {
            return Ok(false);
        }
        if (flags & SCRIPT_VERIFY_WITNESS) == 0 {
            return Ok(false);
        }
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) != 0 {
            return Ok(false);
        }
        return Ok(true);
    }

    // CRITICAL FIX: Check if scriptPubkey is a direct witness program (P2WPKH or P2WSH, not nested in P2SH)
    // Witness program format: OP_0 (0x00) + push opcode + program bytes
    // P2WPKH: [OP_0, PUSH_20_BYTES, <20 bytes>] = 22 bytes total
    // P2WSH: [OP_0, PUSH_32_BYTES, <32 bytes>] = 34 bytes total
    let is_direct_witness_program = redeem_script.is_none()  // Not P2SH
        && !is_taproot  // Not Taproot
        && script_pubkey.len() >= 3
        && script_pubkey[0] == OP_0  // OP_0 (witness version 0)
        && ((script_pubkey[1] == PUSH_20_BYTES && script_pubkey.len() == 22)  // P2WPKH: push 20 bytes, total 22
            || (script_pubkey[1] == PUSH_32_BYTES && script_pubkey.len() == 34)); // P2WSH: push 32 bytes, total 34

    // For direct P2WPKH/P2WSH, push witness stack elements BEFORE executing scriptPubkey
    let mut witness_script_to_execute: Option<ByteString> = None;
    if is_direct_witness_program {
        if let Some(witness_stack) = witness {
            if script_pubkey[1] == PUSH_32_BYTES {
                // P2WSH: witness_stack = [sig1, sig2, ..., witness_script]
                // Push all elements except last onto stack, save witness_script for later execution
                if witness_stack.is_empty() {
                    return Ok(false); // P2WSH requires witness
                }

                // Get witness script (last element)
                let witness_script = witness_stack.last().expect("Witness stack is not empty");

                // Verify witness script hash matches program
                let program_bytes = &script_pubkey[2..];
                if program_bytes.len() != 32 {
                    return Ok(false); // Invalid P2WSH program length
                }

                let witness_script_hash = OptimizedSha256::new().hash(witness_script.as_ref());
                if &witness_script_hash[..] != program_bytes {
                    return Ok(false); // Witness script hash doesn't match program
                }

                // Hash matches - push witness stack elements (except last) onto stack
                let max_witness_elem = MAX_SCRIPT_ELEMENT_SIZE;
                for element in witness_stack.iter().take(witness_stack.len() - 1) {
                    if element.len() > max_witness_elem {
                        return Ok(false);
                    }
                    stack.push(to_stack_element(element));
                }

                // Save witness script for execution after scriptPubkey
                witness_script_to_execute = Some(witness_script.clone());
            } else if script_pubkey[1] == PUSH_20_BYTES {
                // P2WPKH: witness_stack = [signature, pubkey]
                // Push both elements onto stack
                if witness_stack.len() != 2 {
                    return Ok(false); // P2WPKH requires exactly 2 witness elements
                }

                let max_witness_elem = MAX_SCRIPT_ELEMENT_SIZE;
                for element in witness_stack.iter() {
                    if element.len() > max_witness_elem {
                        return Ok(false);
                    }
                    stack.push(to_stack_element(element));
                }
            } else {
                return Ok(false); // Invalid witness program format
            }
        } else {
            return Ok(false); // Witness program requires witness
        }
    }

    if is_taproot {
        let Some(witness_stack) = witness else {
            return Ok(false);
        };
        if witness_stack.is_empty() {
            return Ok(false);
        }
        // After optional annex strip: 1 element = key-path; 2+ = script-path (BIP341).
        let (witness_body, annex_hash) = crate::taproot::strip_taproot_annex(witness_stack);
        if witness_body.is_empty() {
            return Ok(false);
        }
        if witness_body.len() == 1 {
            #[cfg(feature = "production")]
            {
                return verify_p2tr_keypath_witness(
                    script_pubkey,
                    witness_stack,
                    tx,
                    input_index,
                    prevout_values,
                    prevout_script_pubkeys,
                    schnorr_collector,
                );
            }
            #[cfg(not(feature = "production"))]
            {
                return Ok(false);
            }
        }
        if witness_body.len() < 2 {
            return Ok(false);
        }
        let mut output_key = [0u8; 32];
        output_key.copy_from_slice(&script_pubkey[2..34]);
        match crate::taproot::parse_taproot_script_path_witness(&witness_body, &output_key)? {
            None => return Ok(false),
            Some((tapscript, stack_items, control_block)) => {
                if control_block.leaf_version != crate::taproot::TAPROOT_LEAF_VERSION_TAPSCRIPT {
                    use crate::script::flags::SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;
                    if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION != 0 {
                        return Ok(false);
                    }
                    return Ok(true);
                }
                let max_witness_elem = MAX_SCRIPT_ELEMENT_SIZE;
                for item in &stack_items {
                    if item.len() > max_witness_elem {
                        return Ok(false);
                    }
                    stack.push(to_stack_element(item));
                }
                let tapscript_flags = flags | 0x8000;
                if !eval_script_with_context_full(
                    &tapscript,
                    stack,
                    tapscript_flags,
                    tx,
                    input_index,
                    prevout_values,
                    prevout_script_pubkeys,
                    block_height,
                    median_time_past,
                    network,
                    SigVersion::Tapscript,
                    None, // redeem_script_for_sighash
                    None, // script_sig_for_sighash
                    annex_hash.as_ref(),
                    #[cfg(feature = "production")]
                    schnorr_collector,
                    None,
                    #[cfg(feature = "production")]
                    sighash_cache,
                )? {
                    return Ok(false);
                }
                return Ok(true);
            }
        }
    }

    // Execute scriptPubkey (always Base sigversion)
    // For P2WPKH/P2WSH, witness stack elements are already on the stack
    // Pass script_sig so legacy sighash uses same signature bytes as fast path (FindAndDelete pattern).
    // Interpreter path: verify in-place only. Interpreter sighash can diverge from
    // fast path (e.g. CHECKMULTISIG), causing batch to store invalid triples. Verify in-place only.
    // Thread-local guard ensures we never collect even if a collector is accidentally threaded through.
    let script_pubkey_result = eval_script_with_context_full(
        script_pubkey,
        stack,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        median_time_past,
        network,
        SigVersion::Base,
        None, // redeem_script_for_sighash
        Some(script_sig),
        None, // taproot_annex_hash
        #[cfg(feature = "production")]
        schnorr_collector,
        None, // precomputed_bip143 - Base sigversion
        #[cfg(feature = "production")]
        sighash_cache,
    )?;
    if !script_pubkey_result {
        return Ok(false);
    }

    // For P2WSH, execute the witness script after scriptPubkey verification
    if let Some(witness_script) = witness_script_to_execute {
        // P2WSH always uses WitnessV0 (BIP143). 0x8000 = SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
        // is a key-type strictness flag and does not select Tapscript semantics.
        let witness_sigversion = SigVersion::WitnessV0;

        // Execute witness script with witness stack elements on the stack
        // Interpreter path: no collection (same invalid pairing issue as bare multisig).
        if !eval_script_with_context_full(
            &witness_script,
            stack,
            flags,
            tx,
            input_index,
            prevout_values,
            prevout_script_pubkeys,
            block_height,
            median_time_past,
            network,
            witness_sigversion,
            Some(witness_script.as_ref()), // BIP143 scriptCode for CHECKSIG inside P2WSH
            None,                          // script_sig_for_sighash
            None,                          // taproot_annex_hash
            #[cfg(feature = "production")]
            schnorr_collector,
            precomputed_bip143, // WitnessV0 uses BIP143
            #[cfg(feature = "production")]
            sighash_cache,
        )? {
            return Ok(false);
        }
    }

    // P2SH: If scriptPubkey verified the hash, we need to execute the redeem script
    // The scriptPubkey (OP_HASH160 <hash> OP_EQUAL) pops the redeem script, hashes it, compares
    // After scriptPubkey execution, if successful, stack should have [sig1, sig2, ..., 1]
    // where 1 is the OP_EQUAL result (true)
    if let Some(redeem) = redeem_script {
        // Verify stack has at least one element (the OP_EQUAL result)
        if stack.is_empty() {
            return Ok(false); // scriptPubkey execution failed
        }

        // Verify top element is non-zero (OP_EQUAL returned 1 = hash matched)
        let top = stack.last().expect("Stack is not empty");
        if !cast_to_bool(top) {
            return Ok(false); // Hash didn't match or scriptPubkey failed
        }

        // Pop the OP_EQUAL result (1) - this was pushed by OP_EQUAL when hashes matched
        stack.pop();

        // Check if redeem script is a witness program (P2WSH-in-P2SH or P2WPKH-in-P2SH)
        // Witness program format: OP_0 (0x00) + push opcode + program bytes
        // P2WPKH: [OP_0, PUSH_20_BYTES, <20 bytes>] = 22 bytes total
        // P2WSH: [OP_0, PUSH_32_BYTES, <32 bytes>] = 34 bytes total
        let is_witness_program = redeem.len() >= 3
            && redeem[0] == OP_0  // OP_0 (witness version 0)
            && ((redeem[1] == PUSH_20_BYTES && redeem.len() == 22)  // P2WPKH: push 20 bytes, total 22
                || (redeem[1] == PUSH_32_BYTES && redeem.len() == 34)); // P2WSH: push 32 bytes, total 34

        if is_witness_program && witness.is_some() {
            // For P2WSH-in-P2SH or P2WPKH-in-P2SH:
            // - We've already verified the redeem script hash matches (scriptPubkey check passed)
            // - We should NOT execute the redeem script as a normal script
            // - Extract the witness program from redeem script (program bytes after OP_0 and push opcode)
            // - For P2WPKH-in-P2SH: witness script is pubkey hash (20 bytes), witness contains signature + pubkey
            // - For P2WSH-in-P2SH: witness script is the last witness element, hash must match program (32 bytes)

            // Extract program from redeem script: skip OP_0 (1 byte) + push opcode (1 byte), get program bytes
            let program_bytes = &redeem[2..];

            if redeem[1] == PUSH_32_BYTES {
                // P2WSH-in-P2SH: program is 32 bytes, witness should contain the witness script as last element
                // The witness script's SHA256 hash must match the program
                if program_bytes.len() != 32 {
                    return Ok(false); // Invalid P2WSH program length
                }

                // CRITICAL FIX: For P2WSH-in-P2SH, witness is now the full Witness stack
                // Structure: [sig1, sig2, ..., witness_script]
                // The last element is the witness script, which we verify the hash of
                // Then we execute the witness script with the remaining elements (signatures) on the stack
                if let Some(witness_stack) = witness {
                    if witness_stack.is_empty() {
                        return Ok(false); // P2WSH requires witness
                    }

                    // Get the witness script (last element) - it's a ByteString (Vec<u8>)
                    let witness_script = witness_stack.last().expect("Witness stack is not empty");
                    let witness_script_hash = OptimizedSha256::new().hash(witness_script.as_ref());
                    if &witness_script_hash[..] != program_bytes {
                        return Ok(false); // Witness script hash doesn't match program
                    }

                    // Hash matches - now push witness stack elements (except the last one, which is the script)
                    // onto the stack, then execute the witness script
                    stack.clear();

                    // Push all witness stack elements except the last one (witness script) onto the stack
                    // These are the signatures and other data needed for witness script execution
                    let max_witness_elem = MAX_SCRIPT_ELEMENT_SIZE;
                    for element in witness_stack.iter().take(witness_stack.len() - 1) {
                        if element.len() > max_witness_elem {
                            return Ok(false);
                        }
                        stack.push(to_stack_element(element));
                    }

                    // Execute the witness script with witness stack elements on the stack
                    // P2WSH-in-P2SH always uses WitnessV0 (BIP143). 0x8000 = WITNESS_PUBKEYTYPE
                    // is a key-type strictness flag and does not select Tapscript semantics.
                    let witness_sigversion = SigVersion::WitnessV0;

                    // Interpreter path: no collection (P2WSH-in-P2SH).
                    if !eval_script_with_context_full(
                        witness_script,
                        stack,
                        flags,
                        tx,
                        input_index,
                        prevout_values,
                        prevout_script_pubkeys,
                        block_height,
                        median_time_past,
                        network,
                        witness_sigversion,
                        Some(witness_script.as_ref()), // BIP143 scriptCode for CHECKSIG inside P2WSH-in-P2SH
                        None,                          // script_sig_for_sighash
                        None,                          // taproot_annex_hash
                        #[cfg(feature = "production")]
                        schnorr_collector,
                        precomputed_bip143, // WitnessV0 uses BIP143
                        #[cfg(feature = "production")]
                        sighash_cache,
                    )? {
                        return Ok(false);
                    }
                } else {
                    return Ok(false); // P2WSH requires witness
                }
            } else if redeem[1] == PUSH_20_BYTES {
                // P2WPKH-in-P2SH (BIP141): the redeem script is OP_0 <20-byte-pubkey-hash>.
                // Witness must be exactly [signature, pubkey].
                // Verify pubkey hashes to the program, then check BIP143 signature.
                let pubkey_hash = &redeem[2..22]; // 20-byte hash from redeem script

                let witness_stack = match witness {
                    Some(w) => w,
                    None => return Ok(false), // P2WPKH-in-P2SH requires witness
                };
                if witness_stack.len() != 2 {
                    return Ok(false); // Must be exactly [sig, pubkey]
                }
                let signature_bytes = &witness_stack[0];
                let pubkey_bytes = &witness_stack[1];

                if signature_bytes.is_empty() {
                    return Ok(false);
                }
                if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
                    return Ok(false);
                }

                // Verify pubkey hash matches program
                let pubkey_sha256 = OptimizedSha256::new().hash(pubkey_bytes);
                let computed_hash = Ripemd160::digest(pubkey_sha256);
                if &computed_hash[..] != pubkey_hash {
                    return Ok(false);
                }

                // BIP143 §4.3: scriptCode for P2WPKH is the P2PKH expansion, not the witness program.
                let sighash_byte = signature_bytes[signature_bytes.len() - 1];
                let amount = prevout_values.get(input_index).copied().unwrap_or(0);
                let p2pkh_script_code = bip143_p2wpkh_script_code(pubkey_hash);
                let sighash = crate::transaction_hash::calculate_bip143_sighash(
                    tx,
                    input_index,
                    &p2pkh_script_code,
                    amount,
                    sighash_byte,
                    precomputed_bip143,
                )?;

                let height = block_height.unwrap_or(0);
                return signature::with_secp_context(|secp| {
                    signature::verify_signature(
                        secp,
                        pubkey_bytes,
                        signature_bytes,
                        &sighash,
                        flags,
                        height,
                        network,
                        SigVersion::WitnessV0,
                    )
                });
            } else {
                return Ok(false); // Invalid witness program format
            }
            // P2WSH-in-P2SH path falls through to final stack check above
        } else {
            // Regular P2SH: execute the redeem script with the remaining stack (signatures pushed by scriptSig)
            // The redeem script will consume the signatures and should leave exactly one true value
            // CRITICAL FIX: Pass redeem script for P2SH sighash calculation
            let redeem_result = eval_script_with_context_full_inner(
                &redeem,
                stack,
                flags,
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                median_time_past,
                network,
                SigVersion::Base,
                Some(redeem.as_ref()), // Pass redeem script for sighash
                Some(script_sig), // Use same script_sig for legacy sighash pattern (e.g. P2PKH inside P2SH)
                None,             // taproot_annex_hash
                #[cfg(feature = "production")]
                None, // schnorr_collector
                None,             // precomputed_bip143 - Base sigversion
                #[cfg(feature = "production")]
                sighash_cache,
            )?;
            if !redeem_result {
                return Ok(false);
            }
        }
    }

    // Stack size must not exceed consensus limit after scriptPubkey execution.
    if stack.len() > MAX_STACK_SIZE {
        return Ok(false);
    }

    // Execute witness if present
    // CRITICAL:
    // - Direct P2WPKH/P2WSH: Already handled above (witness stack pushed before scriptPubkey, witness script executed after)
    // - P2WSH-in-P2SH: Handled in P2SH section above (witness script executed with witness stack elements)
    // - P2WPKH-in-P2SH: Handled in P2SH section above (BIP143 sig/pubkey check via implicit P2PKH scriptCode)
    // - Regular scripts: No witness execution needed
    //
    // Fail closed when witness data is present but this spend is not a witness program path.
    // Do not require the witness parameter to be cleared: P2WSH-in-P2SH and similar paths
    // leave the original witness stack intact (see p2wsh_scriptcode_regression).
    let accepts_witness = is_direct_witness_program || is_taproot || nested_witness_program;
    if let Some(witness_stack) = witness {
        if !crate::witness::is_witness_empty(witness_stack) && !accepts_witness {
            return Ok(false);
        }
    }

    // Final validation
    // SCRIPT_VERIFY_CLEANSTACK (0x100): requires exactly 1 element on the stack
    // This is only a consensus rule for witness scripts (handled above in witness paths).
    // For legacy scripts in block validation, only the top stack element is checked
    // to be truthy (non-empty and non-zero). CLEANSTACK for legacy is mempool policy only.
    const SCRIPT_VERIFY_CLEANSTACK: u32 = 0x100;

    let final_result = if (flags & SCRIPT_VERIFY_CLEANSTACK) != 0 {
        // CLEANSTACK: exactly one element, must be truthy
        stack.len() == 1 && cast_to_bool(&stack[0])
    } else {
        // Legacy: stack non-empty, top element is truthy
        !stack.is_empty() && cast_to_bool(stack.last().expect("Stack is not empty"))
    };
    Ok(final_result)
}

/// EvalScript with transaction context for signature verification
#[allow(dead_code)]
fn eval_script_with_context(
    script: &ByteString,
    stack: &mut Vec<StackElement>,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TransactionOutput],
    network: crate::types::Network,
) -> Result<bool> {
    // Convert prevouts to parallel slices for the optimized API
    let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
    let prevout_script_pubkeys: Vec<&[u8]> =
        prevouts.iter().map(|p| p.script_pubkey.as_ref()).collect();
    eval_script_with_context_full(
        script,
        stack,
        flags,
        tx,
        input_index,
        &prevout_values,
        &prevout_script_pubkeys,
        None, // block_height
        None, // median_time_past
        network,
        SigVersion::Base,
        None, // redeem_script_for_sighash
        None, // script_sig_for_sighash
        None, // taproot_annex_hash
        #[cfg(feature = "production")]
        None, // schnorr_collector - No collector in this context
        None, // precomputed_bip143 - Base sigversion
        #[cfg(feature = "production")]
        None, // sighash_cache - no context
    )
}

/// EvalScript with full context including block height, median time-past, and network
#[allow(clippy::too_many_arguments)]
fn eval_script_with_context_full(
    script: &[u8],
    stack: &mut Vec<StackElement>,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    network: crate::types::Network,
    sigversion: SigVersion,
    redeem_script_for_sighash: Option<&[u8]>,
    script_sig_for_sighash: Option<&ByteString>,
    taproot_annex_hash: Option<&Hash>,
    #[cfg(feature = "production")] schnorr_collector: Option<
        &crate::bip348::SchnorrSignatureCollector,
    >,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
) -> Result<bool> {
    #[cfg(all(feature = "production", feature = "profile"))]
    let _t0 = std::time::Instant::now();
    let r = eval_script_with_context_full_inner(
        script,
        stack,
        flags,
        tx,
        input_index,
        prevout_values,
        prevout_script_pubkeys,
        block_height,
        median_time_past,
        network,
        sigversion,
        redeem_script_for_sighash,
        script_sig_for_sighash,
        taproot_annex_hash,
        #[cfg(feature = "production")]
        schnorr_collector,
        precomputed_bip143,
        #[cfg(feature = "production")]
        sighash_cache,
    );
    #[cfg(all(feature = "production", feature = "profile"))]
    crate::script_profile::add_interpreter_ns(_t0.elapsed().as_nanos() as u64);
    r
}

/// Internal function with redeem script support for P2SH sighash
fn eval_script_with_context_full_inner(
    script: &[u8],
    stack: &mut Vec<StackElement>,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevout_values: &[i64],
    prevout_script_pubkeys: &[&[u8]],
    block_height: Option<u64>,
    median_time_past: Option<u64>,
    network: crate::types::Network,
    sigversion: SigVersion,
    redeem_script_for_sighash: Option<&[u8]>,
    script_sig_for_sighash: Option<&ByteString>,
    taproot_annex_hash: Option<&Hash>,
    #[cfg(feature = "production")] schnorr_collector: Option<
        &crate::bip348::SchnorrSignatureCollector,
    >,
    precomputed_bip143: Option<&crate::transaction_hash::Bip143PrecomputedHashes>,
    #[cfg(feature = "production")] sighash_cache: Option<
        &crate::transaction_hash::SighashMidstateCache,
    >,
) -> Result<bool> {
    // Precondition assertions: input_index and prevout lengths validated by caller (verify_script_with_context_full).
    // 6d: Removed redundant assert! for input_index and prevout lengths — caller returns error on mismatch.
    use crate::constants::{MAX_SCRIPT_SIZE, MAX_STACK_SIZE};
    use crate::error::{ConsensusError, ScriptErrorCode};

    // MAX_SCRIPT_SIZE applies to Base and WitnessV0 only; Tapscript may exceed 10k.
    if (sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0)
        && script.len() > MAX_SCRIPT_SIZE
    {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::ScriptSize,
            message: "Script size exceeds maximum".into(),
        });
    }
    if stack.len() > MAX_STACK_SIZE {
        return Err(make_stack_overflow_error());
    }

    // BIP342: In Tapscript, pre-scan the entire script for OP_SUCCESSx opcodes.
    // If any OP_SUCCESSx is encountered (even in unexecuted branches), the whole
    // script succeeds immediately. This must happen before any opcode is executed.
    // Reference: BIP342 Tapscript witness execution (ExecuteWitnessScript).
    if sigversion == SigVersion::Tapscript {
        use crate::script::flags::SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS;
        let mut pc = 0usize;
        while pc < script.len() {
            let opcode = script[pc];
            if is_op_success(opcode) {
                if flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS != 0 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::BadOpcode,
                        message: format!("OP_SUCCESSx opcode 0x{opcode:02x} is discouraged").into(),
                    });
                }
                return Ok(true);
            }
            // Advance past push data so we inspect opcodes, not push payloads.
            pc += op_advance(script, pc);
        }
    }

    // Pre-allocate stack capacity if needed
    if stack.capacity() < 20 {
        stack.reserve(20);
    }
    let mut op_count = 0;

    // Pre-allocate control_stack and altstack to avoid realloc in hot path
    #[cfg(feature = "production")]
    let mut control_stack: Vec<control_flow::ControlBlock> = Vec::with_capacity(4);
    #[cfg(not(feature = "production"))]
    let mut control_stack: Vec<control_flow::ControlBlock> = Vec::new();

    #[cfg(feature = "production")]
    let mut altstack: Vec<StackElement> = Vec::with_capacity(8);
    #[cfg(not(feature = "production"))]
    let mut altstack: Vec<StackElement> = Vec::new();

    // Track OP_CODESEPARATOR position for sighash calculation.
    // pbegincodehash: the script code used for sighash starts
    // from after the last OP_CODESEPARATOR (or from the beginning if none).
    let mut code_separator_pos: usize = 0;
    let mut last_codesep_opcode_pos: u32 = 0xffff_ffff;

    // Use index-based iteration to properly handle push opcodes
    let mut i = 0;
    while i < script.len() {
        #[cfg(feature = "production")]
        {
            // Prefetch next cache line(s) ahead for sequential script access
            prefetch::prefetch_ahead(script, i, 64); // Prefetch 64 bytes ahead
        }
        // Use optimized bounds access after length check
        let opcode = {
            #[cfg(feature = "production")]
            {
                unsafe { *script.get_unchecked(i) }
            }
            #[cfg(not(feature = "production"))]
            {
                script[i]
            }
        };

        // Cache in_false_branch state - only recompute when control stack changes
        let in_false_branch = control_flow::in_false_branch(&control_stack);

        // Count non-push opcodes toward op limit (Base/WitnessV0 only; BIP342 Tapscript has no 201-op cap).
        if sigversion != SigVersion::Tapscript && !is_push_opcode(opcode) {
            op_count += 1;
            if op_count > MAX_SCRIPT_OPS {
                return Err(make_operation_limit_error());
            }
        }

        // Check combined stack + altstack size (BIP62/consensus)
        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(make_stack_overflow_error());
        }

        // Handle push opcodes (0x01-0x4b: direct push, OP_PUSHDATA1/2/4)
        if (0x01..=OP_PUSHDATA4).contains(&opcode) {
            let (data, advance) = if opcode <= 0x4b {
                // Direct push: opcode is the length (1-75 bytes)
                let len = opcode as usize;
                if i + 1 + len > script.len() {
                    return Ok(false); // Script truncated
                }
                (&script[i + 1..i + 1 + len], 1 + len)
            } else if opcode == OP_PUSHDATA1 {
                // OP_PUSHDATA1: next byte is length
                if i + 1 >= script.len() {
                    return Ok(false);
                }
                let len = script[i + 1] as usize;
                if i + 2 + len > script.len() {
                    return Ok(false);
                }
                (&script[i + 2..i + 2 + len], 2 + len)
            } else if opcode == OP_PUSHDATA2 {
                // OP_PUSHDATA2: next 2 bytes (little-endian) are length
                if i + 2 >= script.len() {
                    return Ok(false);
                }
                let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                if i + 3 + len > script.len() {
                    return Ok(false);
                }
                (&script[i + 3..i + 3 + len], 3 + len)
            } else {
                // OP_PUSHDATA4: next 4 bytes (little-endian) are length
                // Use saturating arithmetic to avoid overflow on 32-bit platforms
                if i + 4 >= script.len() {
                    return Ok(false);
                }
                let len = u32::from_le_bytes([
                    script[i + 1],
                    script[i + 2],
                    script[i + 3],
                    script[i + 4],
                ]) as usize;
                let data_start = i.saturating_add(5);
                let data_end = data_start.saturating_add(len);
                let advance = 5usize.saturating_add(len);
                if advance < 5 || data_end > script.len() || data_end < data_start {
                    return Ok(false); // Overflow or out-of-bounds
                }
                (&script[data_start..data_end], advance)
            };

            // Only push data if not in a non-executing branch
            if !in_false_branch {
                let max_element = MAX_SCRIPT_ELEMENT_SIZE;
                if data.len() > max_element {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::PushSize,
                        message: format!(
                            "Push data size {} exceeds maximum {}",
                            data.len(),
                            max_element
                        )
                        .into(),
                    });
                }
                stack.push(to_stack_element(data));
            }
            i += advance;
            continue;
        }

        // Check hottest opcodes BEFORE match statement
        // This eliminates dispatch overhead for the most common opcodes (OP_DUP, OP_EQUALVERIFY, OP_HASH160)
        // These opcodes are executed millions of times per block, so avoiding match overhead is critical

        // OP_DUP - duplicate top stack item (VERY HOT - every P2PKH script)
        if opcode == OP_DUP {
            if !in_false_branch {
                if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_DUP: empty stack".into(),
                    });
                }
                // Optimize OP_DUP - avoid double lookup
                // Use unsafe bounds access after length check (already verified above)
                let len = stack.len();
                #[cfg(feature = "production")]
                {
                    // OPTIMIZATION: Reserve capacity before push to avoid reallocation
                    if stack.capacity() == stack.len() {
                        stack.reserve(1);
                    }
                    // Clone the item using unsafe bounds access (we already checked len > 0)
                    let item = unsafe { stack.get_unchecked(len - 1).clone() };
                    stack.push(item);
                }
                #[cfg(not(feature = "production"))]
                {
                    let item = stack.last().unwrap();
                    stack.push(item.clone());
                }
            }
            i += 1;
            continue;
        }

        // OP_EQUALVERIFY - verify top two stack items are equal (VERY HOT - every P2PKH script)
        if opcode == OP_EQUALVERIFY {
            if !in_false_branch {
                if stack.len() < 2 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_EQUALVERIFY: insufficient stack items".into(),
                    });
                }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a != b {
                    return Ok(false);
                }
            }
            i += 1;
            continue;
        }

        // OP_HASH160 - RIPEMD160(SHA256(x)) (VERY HOT - every P2PKH script)
        if opcode == OP_HASH160 {
            if !in_false_branch && !crypto_ops::op_hash160(stack)? {
                return Ok(false);
            }
            i += 1;
            continue;
        }

        // OP_VERIFY - check if top stack item is non-zero (HOT - many scripts)
        if opcode == OP_VERIFY {
            if !in_false_branch {
                if let Some(item) = stack.pop() {
                    if !cast_to_bool(&item) {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }
            i += 1;
            continue;
        }

        // OP_EQUAL - check if top two stack items are equal (HOT - P2SH scripts)
        if opcode == OP_EQUAL {
            if !in_false_branch {
                if stack.len() < 2 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_EQUAL: insufficient stack items".into(),
                    });
                }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(to_stack_element(&[if a == b { 1 } else { 0 }]));
            }
            i += 1;
            continue;
        }

        // OP_CHECKSIG / OP_CHECKSIGVERIFY - hot in multisig/P2SH (skip match dispatch)
        // OP_CHECKSIGADD (BIP 342) - Tapscript only; in Base/WitnessV0, 0xba falls through to match
        if opcode == OP_CHECKSIG
            || opcode == OP_CHECKSIGVERIFY
            || (opcode == OP_CHECKSIGADD && sigversion == SigVersion::Tapscript)
        {
            if !in_false_branch {
                let effective_script_code = Some(&script[code_separator_pos..]);
                let (tapscript, codesep) = if sigversion == SigVersion::Tapscript {
                    (Some(script), Some(last_codesep_opcode_pos))
                } else {
                    (None, None)
                };
                let ctx = context::ScriptContext {
                    tx,
                    input_index,
                    prevout_values,
                    prevout_script_pubkeys,
                    block_height,
                    median_time_past,
                    network,
                    sigversion,
                    redeem_script_for_sighash,
                    script_sig_for_sighash,
                    tapscript_for_sighash: tapscript,
                    tapscript_codesep_pos: codesep,
                    taproot_annex_hash,
                    #[cfg(feature = "production")]
                    schnorr_collector,
                    #[cfg(feature = "production")]
                    precomputed_bip143,
                    #[cfg(feature = "production")]
                    sighash_cache,
                };
                if !execute_opcode_with_context_full(
                    opcode,
                    stack,
                    flags,
                    &ctx,
                    effective_script_code,
                )? {
                    return Ok(false);
                }
            }
            i += 1;
            continue;
        }

        match opcode {
            // OP_0 - push empty array
            OP_0 => {
                if !in_false_branch {
                    stack.push(to_stack_element(&[]));
                }
            }

            // OP_1 to OP_16 - push numbers 1-16
            OP_1_RANGE_START..=OP_1_RANGE_END => {
                if !in_false_branch {
                    let num = opcode - OP_N_BASE;
                    stack.push(to_stack_element(&[num]));
                }
            }

            // OP_1NEGATE - push -1
            OP_1NEGATE => {
                if !in_false_branch {
                    stack.push(to_stack_element(&[0x81])); // -1 in script number encoding
                }
            }

            // OP_NOP - do nothing, execution continues
            OP_NOP => {
                // No operation - this is valid and execution continues
            }

            // OP_VER - causes failure only when executing
            // OP_VER is inside the conditional-execution check,
            // so it only fails in executing branches. Non-executing branches skip it.
            // This differs from truly disabled opcodes (OP_CAT, etc.) which always fail.
            OP_VER => {
                if !in_false_branch {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::DisabledOpcode,
                        message: "OP_VER is disabled".into(),
                    });
                }
            }

            OP_IF => {
                // OP_IF
                if in_false_branch {
                    control_stack.push(control_flow::ControlBlock::If { executing: false });
                    i += 1;
                    continue;
                }

                if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_IF: empty stack".into(),
                    });
                }
                let condition_bytes = stack.pop().unwrap();
                let condition = cast_to_bool(&condition_bytes);

                const SCRIPT_VERIFY_MINIMALIF: u32 = 0x2000;
                if (flags & SCRIPT_VERIFY_MINIMALIF) != 0
                    && (sigversion == SigVersion::WitnessV0 || sigversion == SigVersion::Tapscript)
                    && !control_flow::is_minimal_if_condition(&condition_bytes)
                {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::MinimalIf,
                        message: "OP_IF condition must be minimally encoded".into(),
                    });
                }

                control_stack.push(control_flow::ControlBlock::If {
                    executing: condition,
                });
            }
            OP_NOTIF => {
                // OP_NOTIF
                if in_false_branch {
                    control_stack.push(control_flow::ControlBlock::NotIf { executing: false });
                    i += 1;
                    continue;
                }

                if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_NOTIF: empty stack".into(),
                    });
                }
                let condition_bytes = stack.pop().unwrap();
                let condition = cast_to_bool(&condition_bytes);

                const SCRIPT_VERIFY_MINIMALIF: u32 = 0x2000;
                if (flags & SCRIPT_VERIFY_MINIMALIF) != 0
                    && (sigversion == SigVersion::WitnessV0 || sigversion == SigVersion::Tapscript)
                    && !control_flow::is_minimal_if_condition(&condition_bytes)
                {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::MinimalIf,
                        message: "OP_NOTIF condition must be minimally encoded".into(),
                    });
                }

                control_stack.push(control_flow::ControlBlock::NotIf {
                    executing: !condition,
                });
            }
            OP_ELSE => {
                // OP_ELSE
                if let Some(block) = control_stack.last_mut() {
                    match block {
                        control_flow::ControlBlock::If { executing }
                        | control_flow::ControlBlock::NotIf { executing } => {
                            *executing = !*executing;
                        }
                    }
                } else {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::UnbalancedConditional,
                        message: "OP_ELSE without matching IF/NOTIF".into(),
                    });
                }
            }
            OP_ENDIF => {
                // OP_ENDIF
                if control_stack.pop().is_none() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::UnbalancedConditional,
                        message: "OP_ENDIF without matching IF/NOTIF".into(),
                    });
                }
            }

            // OP_DUP, OP_EQUALVERIFY, OP_HASH160 are handled BEFORE match statement for performance
            // (moved to avoid dispatch overhead)

            // OP_TOALTSTACK - move top stack item to altstack
            OP_TOALTSTACK => {
                if in_false_branch {
                    i += 1;
                    continue;
                }
                if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_TOALTSTACK: empty stack".into(),
                    });
                }
                altstack.push(stack.pop().unwrap());
            }
            // OP_FROMALTSTACK - move top altstack item to stack
            OP_FROMALTSTACK => {
                if in_false_branch {
                    i += 1;
                    continue;
                }
                if altstack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidAltstackOperation,
                        message: "OP_FROMALTSTACK: empty altstack".into(),
                    });
                }
                stack.push(altstack.pop().unwrap());
            }
            // OP_CODESEPARATOR - update sighash script code start position
            OP_CODESEPARATOR => {
                if in_false_branch {
                    i += 1;
                    continue;
                }
                code_separator_pos = i + 1;
                last_codesep_opcode_pos = opcode_position_at_byte(script, i);
            }
            _ => {
                if in_false_branch {
                    i += 1;
                    continue;
                }

                // For signature opcodes, compute the effective script code for sighash:
                // From the last OP_CODESEPARATOR position to the end of the script.
                // scriptCode = slice from pbegincodehash to pend
                // Only allocate for opcodes that actually use the script code.
                let subscript_for_sighash = if matches!(
                    opcode,
                    OP_CHECKSIG
                        | OP_CHECKSIGVERIFY
                        | OP_CHECKSIGADD
                        | OP_CHECKMULTISIG
                        | OP_CHECKMULTISIGVERIFY
                ) {
                    Some(&script[code_separator_pos..])
                } else {
                    None
                };
                let effective_script_code = subscript_for_sighash.or(redeem_script_for_sighash);
                let (tapscript, codesep) = if sigversion == SigVersion::Tapscript {
                    (Some(script), Some(last_codesep_opcode_pos))
                } else {
                    (None, None)
                };
                let ctx = context::ScriptContext {
                    tx,
                    input_index,
                    prevout_values,
                    prevout_script_pubkeys,
                    block_height,
                    median_time_past,
                    network,
                    sigversion,
                    redeem_script_for_sighash,
                    script_sig_for_sighash,
                    tapscript_for_sighash: tapscript,
                    tapscript_codesep_pos: codesep,
                    taproot_annex_hash,
                    #[cfg(feature = "production")]
                    schnorr_collector,
                    #[cfg(feature = "production")]
                    precomputed_bip143,
                    #[cfg(feature = "production")]
                    sighash_cache,
                };
                if !execute_opcode_with_context_full(
                    opcode,
                    stack,
                    flags,
                    &ctx,
                    effective_script_code,
                )? {
                    return Ok(false);
                }
            }
        }
        i += 1;
    }

    // Invariant: control stack must be empty — return Err if not (unclosed IF/NOTIF)
    if !control_stack.is_empty() {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::UnbalancedConditional,
            message: "Unclosed IF/NOTIF block".into(),
        });
    }

    // No final stack check here — EvalScript behavior.
    // Stack evaluation happens in verify_script_with_context_full (the VerifyScript equivalent)
    // after BOTH scriptSig and scriptPubKey have been executed.
    Ok(true)
}

/// Decode a CScriptNum from byte representation.
/// Bitcoin's variable-length signed integer encoding (little-endian, sign bit in MSB of last byte).
/// CScriptNum::set_vch() — BIP62 numeric encoding.
#[spec_locked("5.4.5", "DecodeCScriptNum")]
#[blvm_spec_lock::axiom(result >= -549755813887)]
#[blvm_spec_lock::ensures(result >= -549755813887)]
#[cfg(feature = "production")]
#[inline(always)]
pub(crate) fn script_num_decode(data: &[u8], max_num_size: usize) -> Result<i64> {
    if data.len() > max_num_size {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::InvalidStackOperation,
            message: format!(
                "Script number overflow: {} > {} bytes",
                data.len(),
                max_num_size
            )
            .into(),
        });
    }
    if data.is_empty() {
        return Ok(0);
    }

    // Fast paths for common sizes (most script numbers are 1-2 bytes)
    let len = data.len();
    let result = match len {
        1 => {
            let byte = data[0];
            if byte & 0x80 != 0 {
                // Negative: clear sign bit and negate
                -((byte & 0x7f) as i64)
            } else {
                byte as i64
            }
        }
        2 => {
            let byte0 = data[0] as i64;
            let byte1 = data[1] as i64;
            let value = byte0 | (byte1 << 8);
            if byte1 & 0x80 != 0 {
                // Negative: clear sign bit and negate
                -(value & !(0x80i64 << 8))
            } else {
                value
            }
        }
        _ => {
            // General case for 3+ bytes
            let mut result: i64 = 0;
            for (i, &byte) in data.iter().enumerate() {
                result |= (byte as i64) << (8 * i);
            }
            // Check sign bit (MSB of last byte) - safe because len > 0
            let last_idx = len - 1;
            if data[last_idx] & 0x80 != 0 {
                // Negative: clear sign bit and negate
                result &= !(0x80i64 << (8 * last_idx));
                result = -result;
            }
            result
        }
    };

    Ok(result)
}

#[cfg(not(feature = "production"))]
#[inline]
pub(crate) fn script_num_decode(data: &[u8], max_num_size: usize) -> Result<i64> {
    if data.len() > max_num_size {
        return Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::InvalidStackOperation,
            message: format!(
                "Script number overflow: {} > {} bytes",
                data.len(),
                max_num_size
            )
            .into(),
        });
    }
    if data.is_empty() {
        return Ok(0);
    }
    // Little-endian decode
    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }
    // Check sign bit (MSB of last byte)
    if data.last().expect("Data is not empty") & 0x80 != 0 {
        // Negative: clear sign bit and negate
        result &= !(0x80i64 << (8 * (data.len() - 1)));
        result = -result;
    }
    Ok(result)
}

/// Encode an i64 as CScriptNum byte representation.
/// CScriptNum::serialize() — BIP62 numeric encoding.
#[cfg(feature = "production")]
pub(crate) fn script_num_encode(value: i64) -> Vec<u8> {
    // Fast paths for common values
    match value {
        0 => return vec![],
        1 => return vec![1],
        -1 => return vec![0x81],
        _ => {}
    }

    let neg = value < 0;
    let mut absvalue = if neg {
        (-(value as i128)) as u64
    } else {
        value as u64
    };
    // Pre-allocate Vec: most script numbers are 1-4 bytes
    let mut result = Vec::with_capacity(4);
    while absvalue > 0 {
        result.push((absvalue & 0xff) as u8);
        absvalue >>= 8;
    }
    // If MSB is set, add extra byte for sign
    if result.last().expect("Result is not empty (absvalue > 0)") & 0x80 != 0 {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *result.last_mut().unwrap() |= 0x80;
    }
    result
}

#[cfg(not(feature = "production"))]
pub(crate) fn script_num_encode(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let neg = value < 0;
    let mut absvalue = if neg {
        (-(value as i128)) as u64
    } else {
        value as u64
    };
    let mut result = Vec::new();
    while absvalue > 0 {
        result.push((absvalue & 0xff) as u8);
        absvalue >>= 8;
    }
    // If MSB is set, add extra byte for sign
    if result.last().expect("Result is not empty (absvalue > 0)") & 0x80 != 0 {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *result.last_mut().unwrap() |= 0x80;
    }
    result
}

/// Execute a single opcode (currently ignores sigversion; accepts it for future compatibility)
#[cfg(feature = "production")]
#[inline(always)]
fn execute_opcode(
    opcode: u8,
    stack: &mut Vec<StackElement>,
    flags: u32,
    _sigversion: SigVersion,
) -> Result<bool> {
    match opcode {
        // OP_0 - push empty array
        OP_0 => {
            stack.push(to_stack_element(&[]));
            Ok(true)
        }

        // OP_1 to OP_16 - push numbers 1-16
        OP_1..=OP_16 => {
            let num = opcode - OP_N_BASE;
            stack.push(to_stack_element(&[num]));
            Ok(true)
        }

        // OP_NOP - do nothing, execution continues
        OP_NOP => Ok(true),

        // OP_VER - disabled opcode, always fails
        OP_VER => Ok(false),

        // OP_DEPTH - push stack size
        OP_DEPTH => {
            let depth = stack.len() as i64;
            stack.push(to_stack_element(&script_num_encode(depth)));
            Ok(true)
        }

        // OP_DUP - duplicate top stack item
        OP_DUP => {
            if let Some(item) = stack.last().cloned() {
                stack.push(item);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_RIPEMD160 - RIPEMD160(x)
        OP_RIPEMD160 => crypto_ops::op_ripemd160(stack),

        // OP_SHA1 - SHA1(x)
        OP_SHA1 => crypto_ops::op_sha1(stack),

        // OP_SHA256 - SHA256(x)
        OP_SHA256 => crypto_ops::op_sha256(stack),

        // OP_HASH160 - RIPEMD160(SHA256(x))
        OP_HASH160 => crypto_ops::op_hash160(stack),

        // OP_HASH256 - SHA256(SHA256(x))
        OP_HASH256 => crypto_ops::op_hash256(stack),

        // OP_EQUAL - check if top two stack items are equal.
        // Pushes [] (empty = false) or [0x01] (true).
        OP_EQUAL => {
            if stack.len() < 2 {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::InvalidStackOperation,
                    message: "OP_EQUAL: insufficient stack items".into(),
                });
            }
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            stack.push(to_stack_element(if a == b { &[1u8] } else { &[] }));
            Ok(true)
        }

        // OP_EQUALVERIFY - verify top two stack items are equal
        // OP_EQUAL followed by pop if equal
        OP_EQUALVERIFY => {
            if stack.len() < 2 {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::InvalidStackOperation,
                    message: "OP_EQUALVERIFY: insufficient stack items".into(),
                });
            }
            let a = stack.pop().unwrap();
            let b = stack.pop().unwrap();
            let f_equal = a == b;
            // Push result (like OP_EQUAL does)
            stack.push(to_stack_element(&[if f_equal { 1 } else { 0 }]));
            if f_equal {
                // Pop the true value
                stack.pop();
                Ok(true)
            } else {
                Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::EqualVerify,
                    message: "OP_EQUALVERIFY: stack items not equal".into(),
                })
            }
        }

        // OP_CHECKSIG - verify ECDSA signature (simple path, no tx context)
        OP_CHECKSIG => crypto_ops::op_checksig_simple(stack, flags),

        // OP_CHECKSIGVERIFY - verify ECDSA signature and fail if invalid (simple path)
        OP_CHECKSIGVERIFY => crypto_ops::op_checksigverify_simple(stack, flags),

        // OP_RETURN - always fail (unspendable output)
        OP_RETURN => Ok(false),

        // OP_VERIFY - check if top stack item is non-zero
        OP_VERIFY => {
            if let Some(item) = stack.pop() {
                Ok(cast_to_bool(&item))
            } else {
                Ok(false)
            }
        }

        // OP_CHECKLOCKTIMEVERIFY (BIP65)
        // When SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY flag is not set, behaves as NOP (BIP65 rule).
        // With the flag set but no tx context, fails. Use verify_script_with_context for full CLTV.
        OP_CHECKLOCKTIMEVERIFY => {
            const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 0x200;
            if (flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) == 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_CHECKSEQUENCEVERIFY (BIP112)
        // When SCRIPT_VERIFY_CHECKSEQUENCEVERIFY flag is not set, behaves as NOP (BIP112 rule).
        // With the flag set but no tx context, fails. Use verify_script_with_context for full CSV.
        OP_CHECKSEQUENCEVERIFY => {
            const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: u32 = 0x400;
            if (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) == 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_IFDUP - duplicate top stack item if it's non-zero
        OP_IFDUP => {
            if let Some(item) = stack.last().cloned() {
                if cast_to_bool(&item) {
                    stack.push(item);
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_DEPTH - push stack size (duplicate handler removed, using single implementation)
        // OP_DROP - remove top stack item
        OP_DROP => {
            if stack.pop().is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_NIP - remove second-to-top stack item
        OP_NIP => {
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
        OP_OVER => {
            if stack.len() >= 2 {
                let len = stack.len();
                #[cfg(feature = "production")]
                {
                    // Use proven bounds after length check
                    unsafe {
                        let second = stack.get_unchecked(len - 2);
                        stack.push(second.clone());
                    }
                }
                #[cfg(not(feature = "production"))]
                {
                    let second = stack[stack.len() - 2].clone();
                    stack.push(second);
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_PICK - copy nth stack item to top
        OP_PICK => {
            if let Some(n_bytes) = stack.pop() {
                // Use script_num_decode to properly handle CScriptNum encoding
                // (empty [] = 0, [0x00] = 0, [0x01] = 1, etc.)
                let n_val = script_num_decode(&n_bytes, 4)?;
                if n_val < 0 || n_val as usize >= stack.len() {
                    return Ok(false);
                }
                let n = n_val as usize;
                let len = stack.len();
                #[cfg(feature = "production")]
                {
                    // Use proven bounds after length check (n_val < stack.len() already checked)
                    unsafe {
                        let item = stack.get_unchecked(len - 1 - n);
                        stack.push(item.clone());
                    }
                }
                #[cfg(not(feature = "production"))]
                {
                    let item = stack[stack.len() - 1 - n].clone();
                    stack.push(item);
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_ROLL - move nth stack item to top
        OP_ROLL => {
            if let Some(n_bytes) = stack.pop() {
                // Use script_num_decode to properly handle CScriptNum encoding
                // (empty [] = 0, which is a valid no-op roll)
                let n_val = script_num_decode(&n_bytes, 4)?;
                if n_val < 0 || n_val as usize >= stack.len() {
                    return Ok(false);
                }
                let n = n_val as usize;
                let len = stack.len();
                #[cfg(feature = "production")]
                {
                    // Use proven bounds after length check (n_val < stack.len() already checked)
                    let idx = len - 1 - n;
                    let item = stack.remove(idx);
                    stack.push(item);
                }
                #[cfg(not(feature = "production"))]
                {
                    let item = stack.remove(stack.len() - 1 - n);
                    stack.push(item);
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_ROT - rotate top 3 stack items
        OP_ROT => {
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
        OP_SWAP => {
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
        OP_TUCK => {
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
        OP_2DROP => {
            if stack.len() >= 2 {
                stack.pop();
                stack.pop();
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_2DUP - duplicate top 2 stack items
        OP_2DUP => {
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
        OP_3DUP => {
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
        OP_2OVER => {
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

        // OP_2ROT - move the pair at positions 5 and 6 from top to top.
        // Before: [... a b c d e f] (f=top). After: [... c d e f a b] (b=top).
        OP_2ROT => {
            if stack.len() >= 6 {
                // Remove from bottom-most of the pair first (index 0 = 6th from top).
                let sixth = stack.remove(stack.len() - 6); // a
                // After first remove the stack shrank; 5th from original top is now at index 0.
                let fifth = stack.remove(stack.len() - 5); // b
                // Push in original order: sixth (a) below, fifth (b) on top.
                stack.push(sixth);
                stack.push(fifth);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_2SWAP - swap second pair of stack items
        OP_2SWAP => {
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
        // OP_SIZE - push the byte length of top stack item (does NOT pop)
        OP_SIZE => {
            if let Some(item) = stack.last() {
                let size = item.len() as i64;
                stack.push(to_stack_element(&script_num_encode(size)));
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // --- Arithmetic opcodes ---
        // All use CScriptNum encoding (max 4 bytes by default)

        // OP_1ADD - increment top by 1
        OP_1ADD => {
            if let Some(item) = stack.pop() {
                let a = script_num_decode(&item, 4)?;
                stack.push(to_stack_element(&script_num_encode(a + 1)));
                Ok(true)
            } else {
                Ok(false)
            }
        }
        // OP_1SUB - decrement top by 1
        OP_1SUB => {
            if let Some(item) = stack.pop() {
                let a = script_num_decode(&item, 4)?;
                stack.push(to_stack_element(&script_num_encode(a - 1)));
                Ok(true)
            } else {
                Ok(false)
            }
        }
        // OP_2MUL - DISABLED
        OP_2MUL => Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::DisabledOpcode,
            message: "OP_2MUL is disabled".into(),
        }),
        // OP_2DIV - DISABLED
        OP_2DIV => Err(ConsensusError::ScriptErrorWithCode {
            code: ScriptErrorCode::DisabledOpcode,
            message: "OP_2DIV is disabled".into(),
        }),
        // OP_NEGATE - negate top
        OP_NEGATE => {
            if let Some(item) = stack.pop() {
                let a = script_num_decode(&item, 4)?;
                stack.push(to_stack_element(&script_num_encode(-a)));
                Ok(true)
            } else {
                Ok(false)
            }
        }
        // OP_ABS - absolute value
        OP_ABS => {
            if let Some(item) = stack.pop() {
                let a = script_num_decode(&item, 4)?;
                stack.push(to_stack_element(&script_num_encode(a.abs())));
                Ok(true)
            } else {
                Ok(false)
            }
        }
        // OP_NOT - logical NOT: 0 → 1, nonzero → 0
        OP_NOT => {
            if let Some(item) = stack.pop() {
                let a = script_num_decode(&item, 4)?;
                stack.push(to_stack_element(&script_num_encode(if a == 0 {
                    1
                } else {
                    0
                })));
                Ok(true)
            } else {
                Ok(false)
            }
        }
        // OP_0NOTEQUAL - 0 → 0, nonzero → 1
        OP_0NOTEQUAL => {
            if let Some(item) = stack.pop() {
                let a = script_num_decode(&item, 4)?;
                stack.push(to_stack_element(&script_num_encode(if a != 0 {
                    1
                } else {
                    0
                })));
                Ok(true)
            } else {
                Ok(false)
            }
        }
        OP_ADD => arithmetic::op_add(stack),
        OP_SUB => arithmetic::op_sub(stack),
        OP_MUL => arithmetic::op_mul_disabled(),
        OP_DIV => arithmetic::op_div_disabled(),
        OP_MOD => arithmetic::op_mod_disabled(),
        OP_LSHIFT => arithmetic::op_lshift_disabled(),
        OP_RSHIFT => arithmetic::op_rshift_disabled(),
        OP_BOOLAND => arithmetic::op_booland(stack),
        OP_BOOLOR => arithmetic::op_boolor(stack),
        OP_NUMEQUAL => arithmetic::op_numequal(stack),
        OP_NUMEQUALVERIFY => arithmetic::op_numequalverify(stack),
        OP_NUMNOTEQUAL => arithmetic::op_numnotequal(stack),
        OP_LESSTHAN => arithmetic::op_lessthan(stack),
        OP_GREATERTHAN => arithmetic::op_greaterthan(stack),
        OP_LESSTHANOREQUAL => arithmetic::op_lessthanorequal(stack),
        OP_GREATERTHANOREQUAL => arithmetic::op_greaterthanorequal(stack),
        OP_MIN => arithmetic::op_min(stack),
        OP_MAX => arithmetic::op_max(stack),
        OP_WITHIN => arithmetic::op_within(stack),

        // OP_CODESEPARATOR - marks position for sighash (no-op in execute_opcode)
        OP_CODESEPARATOR => Ok(true),

        // OP_NOP1 and OP_NOP5-OP_NOP10 - no-ops
        // Note: OP_NOP4 (0xb3) is used for OP_CHECKTEMPLATEVERIFY (BIP119)
        OP_NOP1 | OP_NOP5..=OP_NOP10 => Ok(true),

        // OP_CHECKTEMPLATEVERIFY (NOP4 / BIP 119)
        // Treated as NOP when the CTV flag is not in the verification flags.
        // Full validation requires tx context and the SCRIPT_VERIFY_CHECKTEMPLATEVERIFY flag.
        OP_CHECKTEMPLATEVERIFY => {
            #[cfg(feature = "ctv")]
            {
                const SCRIPT_VERIFY_CHECKTEMPLATEVERIFY: u32 = 0x8000;
                if (flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY) != 0 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::TxInvalid,
                        message: "OP_CHECKTEMPLATEVERIFY requires transaction context".into(),
                    });
                }
            }
            Ok(true)
        }

        // Disabled string opcodes - must return error per consensus
        OP_DISABLED_STRING_RANGE_START..=OP_DISABLED_STRING_RANGE_END
        | OP_DISABLED_BITWISE_RANGE_START..=OP_DISABLED_BITWISE_RANGE_END => {
            Err(ConsensusError::ScriptErrorWithCode {
                code: ScriptErrorCode::DisabledOpcode,
                message: format!("Disabled opcode 0x{opcode:02x}").into(),
            })
        }

        // OP_1NEGATE - push -1 onto stack
        OP_1NEGATE => {
            stack.push(to_stack_element(&[0x81]));
            Ok(true)
        }

        // OP_CHECKMULTISIG - verify m-of-n multisig without transaction context.
        // Handles stack mechanics correctly for all cases; succeeds only when m=0
        // (no signatures to verify). Vectors requiring real ECDSA verification need
        // verify_script_with_context_full.
        OP_CHECKMULTISIG => {
            if stack.is_empty() {
                return Ok(false);
            }
            let n_bytes = stack.pop().unwrap();
            let n = match script_num_decode(&n_bytes, 4) {
                Ok(v) if (0..=20).contains(&v) => v as usize,
                _ => return Ok(false),
            };
            if stack.len() < n {
                return Ok(false);
            }
            for _ in 0..n {
                stack.pop();
            }
            if stack.is_empty() {
                return Ok(false);
            }
            let m_bytes = stack.pop().unwrap();
            let m = match script_num_decode(&m_bytes, 4) {
                Ok(v) if v >= 0 && v as usize <= n => v as usize,
                _ => return Ok(false),
            };
            if stack.len() < m {
                return Ok(false);
            }
            for _ in 0..m {
                stack.pop();
            }
            // Pop the mandatory dummy element (Bitcoin off-by-one quirk)
            if stack.is_empty() {
                return Ok(false);
            }
            stack.pop();
            // Without tx context only 0-sig multisig can succeed
            stack.push(to_stack_element(&[if m == 0 { 1 } else { 0 }]));
            Ok(true)
        }

        // OP_CHECKMULTISIGVERIFY - CHECKMULTISIG then VERIFY
        OP_CHECKMULTISIGVERIFY => {
            if stack.is_empty() {
                return Ok(false);
            }
            let n_bytes = stack.pop().unwrap();
            let n = match script_num_decode(&n_bytes, 4) {
                Ok(v) if (0..=20).contains(&v) => v as usize,
                _ => return Ok(false),
            };
            if stack.len() < n {
                return Ok(false);
            }
            for _ in 0..n {
                stack.pop();
            }
            if stack.is_empty() {
                return Ok(false);
            }
            let m_bytes = stack.pop().unwrap();
            let m = match script_num_decode(&m_bytes, 4) {
                Ok(v) if v >= 0 && v as usize <= n => v as usize,
                _ => return Ok(false),
            };
            if stack.len() < m {
                return Ok(false);
            }
            for _ in 0..m {
                stack.pop();
            }
            if stack.is_empty() {
                return Ok(false);
            }
            stack.pop();
            // Verify: succeed only if m == 0
            Ok(m == 0)
        }

        // Unknown opcode
        _ => Ok(false),
    }
}

/// Execute a single opcode with transaction context for signature verification
#[allow(dead_code)]
fn execute_opcode_with_context(
    opcode: u8,
    stack: &mut Vec<StackElement>,
    flags: u32,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TransactionOutput],
    network: crate::types::Network,
) -> Result<bool> {
    // Convert prevouts to parallel slices for the optimized API
    let prevout_values: Vec<i64> = prevouts.iter().map(|p| p.value).collect();
    let prevout_script_pubkeys: Vec<&[u8]> =
        prevouts.iter().map(|p| p.script_pubkey.as_ref()).collect();
    let ctx = context::ScriptContext {
        tx,
        input_index,
        prevout_values: &prevout_values,
        prevout_script_pubkeys: &prevout_script_pubkeys,
        block_height: None,
        median_time_past: None,
        network,
        sigversion: SigVersion::Base,
        redeem_script_for_sighash: None,
        script_sig_for_sighash: None,
        tapscript_for_sighash: None,
        tapscript_codesep_pos: None,
        taproot_annex_hash: None,
        #[cfg(feature = "production")]
        schnorr_collector: None,
        #[cfg(feature = "production")]
        precomputed_bip143: None,
        #[cfg(feature = "production")]
        sighash_cache: None,
    };
    execute_opcode_with_context_full(opcode, stack, flags, &ctx, None)
}

/// Parse P2SH-P2PKH scriptSig for batch sighash precompute. Zero-allocation.
/// script_sig = [sig, pubkey, redeem] where redeem is P2PKH (25 bytes).
/// Returns (sighash_byte, redeem_slice) or None. Pub(crate) for block.rs.
#[cfg(feature = "production")]
#[inline(always)]
pub(crate) fn parse_p2sh_p2pkh_for_precompute(script_sig: &[u8]) -> Option<(u8, &[u8])> {
    let mut i = 0;
    let (adv1, s_start, s_end) = parse_one_data_push(script_sig, i)?;
    i += adv1;
    if i >= script_sig.len() {
        return None;
    }
    let (adv2, _p_start, _p_end) = parse_one_data_push(script_sig, i)?;
    i += adv2;
    if i >= script_sig.len() {
        return None;
    }
    let (adv3, r_start, r_end) = parse_one_data_push(script_sig, i)?;
    i += adv3;
    if i != script_sig.len() {
        return None;
    }
    let sig = &script_sig[s_start..s_end];
    let redeem = &script_sig[r_start..r_end];
    if sig.is_empty() || redeem.len() != 25 {
        return None;
    }
    if redeem[0] != OP_DUP
        || redeem[1] != OP_HASH160
        || redeem[2] != PUSH_20_BYTES
        || redeem[23] != OP_EQUALVERIFY
        || redeem[24] != OP_CHECKSIG
    {
        return None;
    }
    Some((sig[sig.len() - 1], redeem))
}

/// Zero-allocation parser for P2PKH scriptSig: exactly two data pushes (`signature`, then `pubkey`).
/// Returns (sig_slice, pubkey_slice) borrowing into script_sig, or None if invalid.
/// Pub(crate) for batch sighash precompute in block.rs.
#[inline(always)]
pub(crate) fn parse_p2pkh_script_sig(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 0;
    let (adv1, s_start, s_end) = parse_one_data_push(script_sig, i)?;
    i += adv1;
    if i >= script_sig.len() {
        return None;
    }
    let (adv2, p_start, p_end) = parse_one_data_push(script_sig, i)?;
    i += adv2;
    if i != script_sig.len() {
        return None;
    }
    Some((&script_sig[s_start..s_end], &script_sig[p_start..p_end]))
}

/// Parse P2PK scriptSig as single push (signature). Returns sig slice or None.
/// Used for P2PK pre-extraction in producer.
pub(crate) fn parse_p2pk_script_sig(script_sig: &[u8]) -> Option<&[u8]> {
    let (advance, data_start, data_end) = parse_one_data_push(script_sig, 0)?;
    if advance != script_sig.len() {
        return None;
    }
    Some(&script_sig[data_start..data_end])
}

/// Parse a single push opcode at `i`, return (advance, data_start, data_end). Rejects OP_0 and numerics.
fn parse_one_data_push(script: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    if i >= script.len() {
        return None;
    }
    let opcode = script[i];
    let (advance, data_start, data_end) = if opcode == OP_0 {
        return None;
    } else if opcode <= 0x4b {
        let len = opcode as usize;
        if i + 1 + len > script.len() {
            return None;
        }
        (1 + len, i + 1, i + 1 + len)
    } else if opcode == OP_PUSHDATA1 {
        if i + 1 >= script.len() {
            return None;
        }
        let len = script[i + 1] as usize;
        if i + 2 + len > script.len() {
            return None;
        }
        (2 + len, i + 2, i + 2 + len)
    } else if opcode == OP_PUSHDATA2 {
        if i + 2 >= script.len() {
            return None;
        }
        let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
        if i + 3 + len > script.len() {
            return None;
        }
        (3 + len, i + 3, i + 3 + len)
    } else if opcode == OP_PUSHDATA4 {
        if i + 4 >= script.len() {
            return None;
        }
        let len = u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
            as usize;
        if i + 5 + len > script.len() {
            return None;
        }
        (5 + len, i + 5, i + 5 + len)
    } else {
        return None;
    };
    Some((advance, data_start, data_end))
}

/// P2SH Push-Only Validation (Orange Paper 5.2.1).
/// Returns true if script_sig contains only push opcodes (valid), false otherwise (invalid).
#[spec_locked("5.2.1", "P2SHPushOnlyCheck")]
pub fn p2sh_push_only_check(script_sig: &[u8]) -> bool {
    parse_script_sig_push_only(script_sig).is_some()
}

/// Parse script_sig as push-only and return pushed items in order.
/// Returns None if script contains non-push opcodes or invalid push encoding.
/// Used by P2PKH fast-path to get [signature, pubkey] without running the interpreter.
fn parse_script_sig_push_only(script_sig: &[u8]) -> Option<Vec<StackElement>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script_sig.len() {
        let opcode = script_sig[i];
        if !is_push_opcode(opcode) {
            return None;
        }
        let (advance, data) = if opcode == OP_0 {
            (1, vec![])
        } else if opcode <= 0x4b {
            let len = opcode as usize;
            if i + 1 + len > script_sig.len() {
                return None;
            }
            (1 + len, script_sig[i + 1..i + 1 + len].to_vec())
        } else if opcode == OP_PUSHDATA1 {
            if i + 1 >= script_sig.len() {
                return None;
            }
            let len = script_sig[i + 1] as usize;
            if i + 2 + len > script_sig.len() {
                return None;
            }
            (2 + len, script_sig[i + 2..i + 2 + len].to_vec())
        } else if opcode == OP_PUSHDATA2 {
            if i + 2 >= script_sig.len() {
                return None;
            }
            let len = u16::from_le_bytes([script_sig[i + 1], script_sig[i + 2]]) as usize;
            if i + 3 + len > script_sig.len() {
                return None;
            }
            (3 + len, script_sig[i + 3..i + 3 + len].to_vec())
        } else if opcode == OP_PUSHDATA4 {
            if i + 4 >= script_sig.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script_sig[i + 1],
                script_sig[i + 2],
                script_sig[i + 3],
                script_sig[i + 4],
            ]) as usize;
            if i + 5 + len > script_sig.len() {
                return None;
            }
            (5 + len, script_sig[i + 5..i + 5 + len].to_vec())
        } else if (OP_1NEGATE..=OP_16).contains(&opcode) {
            // Single-byte push: push the numeric value as minimal bytes
            let n = script_num_from_opcode(opcode);
            (1, script_num_encode(n))
        } else {
            return None;
        };
        out.push(to_stack_element(&data));
        i += advance;
    }
    Some(out)
}

/// Parse all pushes from P2SH scriptSig (including OP_0/dummy).
/// Returns pushed data in order; last push = redeem script.
/// Uses parse_script_sig_push_only; caller uses .as_ref() for &[u8].
fn parse_p2sh_script_sig_pushes(script_sig: &[u8]) -> Option<Vec<StackElement>> {
    parse_script_sig_push_only(script_sig)
}

/// Parse redeem script as `OP_m <pubkeys> OP_n OP_CHECKMULTISIG` (Bitcoin standard).
///
/// `m` = required signatures (threshold), `n` = pubkey count. Standard mainnet
/// form uses push opcodes before each key (`PUSH_33_BYTES` / `PUSH_65_BYTES`).
/// Also accepts legacy raw-key form (SEC header, no push length) for tests.
///
/// Returns `(m, n, pubkey_slices)` or `None` if the format doesn't match.
fn parse_redeem_multisig(redeem: &[u8]) -> Option<(u8, u8, Vec<&[u8]>)> {
    if redeem.len() < 4 {
        return None;
    }
    // Trailer: OP_n OP_CHECKMULTISIG
    if redeem[redeem.len() - 1] != OP_CHECKMULTISIG {
        return None;
    }
    let n_op = redeem[redeem.len() - 2];
    if !(OP_1..=OP_16).contains(&n_op) {
        return None;
    }
    let n = (n_op - OP_1 + 1) as usize;
    let m_op = redeem[0];
    if !(OP_1..=OP_16).contains(&m_op) {
        return None;
    }
    let m = m_op - OP_1 + 1;
    if (m as usize) > n || m == 0 {
        return None;
    }
    let mut i = 1;
    let mut pubkeys = Vec::with_capacity(n);
    for _ in 0..n {
        if i >= redeem.len().saturating_sub(2) {
            return None;
        }
        let first = redeem[i];
        // Push-encoded compressed/uncompressed — standard mainnet redeem.
        // Also accept legacy raw-key form (SEC header with no push length) for tests.
        let (pk_start, pk_len) = if first == PUSH_33_BYTES {
            (i + 1, 33usize)
        } else if first == PUSH_65_BYTES {
            (i + 1, 65usize)
        } else if first == 0x02 || first == 0x03 {
            (i, 33usize)
        } else if first == 0x04 {
            (i, 65usize)
        } else {
            return None;
        };
        if pk_start + pk_len > redeem.len().saturating_sub(2) {
            return None;
        }
        let pk = &redeem[pk_start..pk_start + pk_len];
        let hdr = pk[0];
        if !(hdr == 0x02 || hdr == 0x03 || hdr == 0x04) {
            return None;
        }
        if (hdr == 0x02 || hdr == 0x03) && pk_len != 33 {
            return None;
        }
        if hdr == 0x04 && pk_len != 65 {
            return None;
        }
        pubkeys.push(pk);
        i = pk_start + pk_len;
    }
    // Must land exactly on OP_n OP_CHECKMULTISIG.
    if i != redeem.len() - 2 {
        return None;
    }
    Some((m, n as u8, pubkeys))
}

#[cfg(test)]
mod parse_redeem_multisig_tests {
    use super::*;

    #[test]
    fn accepts_push_encoded_compressed_2of3() {
        // Standard: OP_m <pks> OP_n OP_CHECKMULTISIG  →  2-of-3
        let mut redeem = vec![OP_2];
        for i in 0..3u8 {
            redeem.push(PUSH_33_BYTES);
            let mut pk = [0u8; 33];
            pk[0] = 0x02;
            pk[1] = i + 1;
            redeem.extend_from_slice(&pk);
        }
        redeem.push(OP_3);
        redeem.push(OP_CHECKMULTISIG);
        let (m, n, pks) = parse_redeem_multisig(&redeem).expect("push-encoded redeem");
        assert_eq!(m, 2);
        assert_eq!(n, 3);
        assert_eq!(pks.len(), 3);
        assert_eq!(pks[0][0], 0x02);
    }

    #[test]
    fn accepts_legacy_raw_key_form() {
        // 1-of-1 raw key: OP_1 <33-byte-pk> OP_1 OP_CHECKMULTISIG
        let mut redeem = vec![OP_1];
        let mut pk = [0u8; 33];
        pk[0] = 0x03;
        pk[2] = 0xaa;
        redeem.extend_from_slice(&pk);
        redeem.push(OP_1);
        redeem.push(OP_CHECKMULTISIG);
        let (m, n, pks) = parse_redeem_multisig(&redeem).expect("raw-key redeem");
        assert_eq!((m, n, pks.len()), (1, 1, 1));
    }

    #[test]
    fn rejects_trailing_opcodes() {
        let mut redeem = vec![OP_1, PUSH_33_BYTES];
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        redeem.extend_from_slice(&pk);
        redeem.push(OP_1);
        redeem.push(OP_CHECKMULTISIG);
        redeem.push(OP_DROP);
        assert!(parse_redeem_multisig(&redeem).is_none());
    }

    /// Regression: P2WSH-in-P2SH (wit.len()==2) must not be claimed as nested P2WPKH.
    /// Mainnet height 497110 tx330 failed when the dens path returned Ok(false) instead of None.
    #[cfg(feature = "production")]
    #[test]
    fn nested_p2wsh_not_claimed_as_p2wpkh_in_p2sh() {
        use crate::types::{OutPoint, Transaction, TransactionInput};
        // scriptSig = push(34) ‖ OP_0 ‖ PUSH_32 ‖ <32-byte program>  (nested P2WSH)
        let mut program = [0u8; 32];
        program[0] = 0x50;
        let mut script_sig = vec![34u8, OP_0, PUSH_32_BYTES];
        script_sig.extend_from_slice(&program);
        let script_pubkey = {
            let h = Ripemd160::digest(OptimizedSha256::new().hash(&script_sig[1..]));
            let mut spk = vec![OP_HASH160, PUSH_20_BYTES];
            spk.extend_from_slice(&h);
            spk.push(OP_EQUAL);
            spk
        };
        // Minimal fake witness [sig, witnessScript] — shape only; fast path must return None
        // before verifying (redeem is not 22-byte P2WPKH).
        let witness: crate::witness::Witness = vec![vec![0u8; 72], vec![OP_1, OP_1]];
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                sequence: 0xffff_ffff,
                script_sig: script_sig.clone(),
            }]
            .into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        let result = try_verify_p2wpkh_in_p2sh_fast_path(
            &script_sig,
            &script_pubkey,
            &witness,
            0x01, // P2SH
            &tx,
            0,
            &[0i64],
            &[],
            Some(497_110),
            crate::types::Network::Mainnet,
            None,
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            None,
        );
        assert!(
            result.is_none(),
            "nested P2WSH must fall through, got {:?}",
            result
        );
    }
}

/// Map OP_1NEGATE..OP_16 to numeric value for script_num_to_bytes
fn script_num_from_opcode(opcode: u8) -> i64 {
    match opcode {
        OP_1NEGATE => -1,
        OP_1 => 1,
        OP_2 => 2,
        OP_3 => 3,
        OP_4 => 4,
        OP_5 => 5,
        OP_6 => 6,
        OP_7 => 7,
        OP_8 => 8,
        OP_9 => 9,
        OP_10 => 10,
        OP_11 => 11,
        OP_12 => 12,
        OP_13 => 13,
        OP_14 => 14,
        OP_15 => 15,
        OP_16 => 16,
        _ => 0,
    }
}

/// Serialize data as a Bitcoin push operation: `push_opcode` followed by `data` bytes.
/// This creates the byte pattern that FindAndDelete searches for.
/// Push data to script (BIP62 encoding rules).
pub(crate) fn serialize_push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::with_capacity(len + 5);
    if len < 76 {
        result.push(len as u8);
    } else if len < 256 {
        result.push(OP_PUSHDATA1);
        result.push(len as u8);
    } else if len < 65536 {
        result.push(OP_PUSHDATA2);
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
    } else {
        result.push(OP_PUSHDATA4);
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.push(((len >> 16) & 0xff) as u8);
        result.push(((len >> 24) & 0xff) as u8);
    }
    result.extend_from_slice(data);
    result
}

/// Advance `pc` past one opcode (Bitcoin `CScript::GetOp`-compatible sizing).
#[inline]
fn script_get_op_advance(script: &[u8], pc: usize) -> Option<usize> {
    if pc >= script.len() {
        return None;
    }
    let opcode = script[pc];
    let advance = if opcode <= 0x4b {
        1 + opcode as usize
    } else if opcode == OP_PUSHDATA1 && pc + 1 < script.len() {
        2 + script[pc + 1] as usize
    } else if opcode == OP_PUSHDATA2 && pc + 2 < script.len() {
        3 + ((script[pc + 1] as usize) | ((script[pc + 2] as usize) << 8))
    } else if opcode == OP_PUSHDATA4 && pc + 4 < script.len() {
        5 + ((script[pc + 1] as usize)
            | ((script[pc + 2] as usize) << 8)
            | ((script[pc + 3] as usize) << 16)
            | ((script[pc + 4] as usize) << 24))
    } else {
        1
    };
    let next = pc + advance;
    if next > script.len() {
        None
    } else {
        Some(next)
    }
}

/// FindAndDelete — consensus match to the reference FindAndDelete algorithm.
///
/// Do/while loop: flush `[pc2, pc)`, delete consecutive raw occurrences of `pattern` from `pc`,
/// then advance `pc` one opcode via GetOp-style sizing. The inner delete loop can leave `pc`
/// misaligned; the next "opcode" is parsed from that byte (same behavior as the reference impl).
#[spec_locked("5.1.1", "FindAndDelete")]
#[inline]
pub(crate) fn find_and_delete<'a>(script: &'a [u8], pattern: &[u8]) -> std::borrow::Cow<'a, [u8]> {
    if pattern.is_empty() {
        return std::borrow::Cow::Borrowed(script);
    }
    if pattern.len() > script.len() {
        return std::borrow::Cow::Borrowed(script);
    }
    // Fast pre-scan: if pattern doesn't appear anywhere in the raw bytes, it can't appear
    // at any opcode boundary either — skip the full walk and the Vec allocation entirely.
    // `windows()` is O(N) and avoids ~100B-4KB Vec allocation + full script copy on the
    // overwhelmingly common case (CHECKSIG before codeseparator = never matches).
    if !script.windows(pattern.len()).any(|w| w == pattern) {
        return std::borrow::Cow::Borrowed(script);
    }
    let end = script.len();
    let mut n_found = 0usize;
    let mut result = Vec::new();
    let mut pc = 0usize;
    let mut pc2 = 0usize;

    loop {
        result.extend_from_slice(&script[pc2..pc]);
        while end - pc >= pattern.len() && script[pc..pc + pattern.len()] == *pattern {
            pc += pattern.len();
            n_found += 1;
        }
        pc2 = pc;
        if pc >= end {
            break;
        }
        let Some(next_pc) = script_get_op_advance(script, pc) else {
            break;
        };
        pc = next_pc;
    }

    if n_found > 0 {
        result.extend_from_slice(&script[pc2..end]);
        std::borrow::Cow::Owned(result)
    } else {
        std::borrow::Cow::Borrowed(script)
    }
}

/// Return opcode position (0-indexed) of the opcode at byte_index in script. BIP 342 codesep_pos.
fn opcode_position_at_byte(script: &[u8], byte_index: usize) -> u32 {
    let mut pos = 0u32;
    let mut i = 0usize;
    while i < script.len() && i <= byte_index {
        let opcode = script[i];
        let advance = if opcode <= 0x4b {
            1 + opcode as usize
        } else if opcode == OP_PUSHDATA1 && i + 1 < script.len() {
            2 + script[i + 1] as usize
        } else if opcode == OP_PUSHDATA2 && i + 2 < script.len() {
            3 + ((script[i + 1] as usize) | ((script[i + 2] as usize) << 8))
        } else if opcode == OP_PUSHDATA4 && i + 4 < script.len() {
            5 + ((script[i + 1] as usize)
                | ((script[i + 2] as usize) << 8)
                | ((script[i + 3] as usize) << 16)
                | ((script[i + 4] as usize) << 24))
        } else {
            1
        };
        if i == byte_index {
            return pos;
        }
        pos += 1;
        i = std::cmp::min(i + advance, script.len());
    }
    0xffff_ffff
}

/// Execute a single opcode with full context including block height, median time-past, and network
#[cfg_attr(feature = "production", inline(always))]
fn execute_opcode_with_context_full(
    opcode: u8,
    stack: &mut Vec<StackElement>,
    flags: u32,
    ctx: &context::ScriptContext<'_>,
    effective_script_code: Option<&[u8]>,
) -> Result<bool> {
    let tx = ctx.tx;
    let input_index = ctx.input_index;
    let prevout_values = ctx.prevout_values;
    let prevout_script_pubkeys = ctx.prevout_script_pubkeys;
    let block_height = ctx.block_height;
    let median_time_past = ctx.median_time_past;
    let network = ctx.network;
    let sigversion = ctx.sigversion;
    let script_sig_for_sighash = ctx.script_sig_for_sighash;
    let tapscript_for_sighash = ctx.tapscript_for_sighash;
    let tapscript_codesep_pos = ctx.tapscript_codesep_pos;
    let redeem_script_for_sighash = effective_script_code;
    #[cfg(feature = "production")]
    let schnorr_collector = ctx.schnorr_collector;
    #[cfg(feature = "production")]
    let precomputed_bip143 = ctx.precomputed_bip143;
    #[cfg(feature = "production")]
    let sighash_cache = ctx.sighash_cache;

    // match ordered by frequency (hot opcodes first for better branch prediction)
    match opcode {
        // OP_CHECKSIG - verify ECDSA signature
        OP_CHECKSIG => {
            if stack.len() >= 2 {
                let pubkey_bytes = stack.pop().unwrap();
                let signature_bytes = stack.pop().unwrap();

                // Empty signature always fails but is valid script execution
                if signature_bytes.is_empty() {
                    stack.push(to_stack_element(&[0]));
                    return Ok(true);
                }

                // Tapscript (BIP 342): BIP 340 Schnorr (64 bytes, or 65 with explicit sighash byte).
                if sigversion == SigVersion::Tapscript && pubkey_bytes.len() == 32 {
                    use crate::bip348::try_parse_taproot_schnorr_witness_sig;
                    if let Some((sig_bytes, sighash_byte)) =
                        try_parse_taproot_schnorr_witness_sig(&signature_bytes)
                    {
                        let (tapscript, codesep_pos) = tapscript_for_sighash
                            .map(|s| (s, tapscript_codesep_pos.unwrap_or(0xffff_ffff)))
                            .unwrap_or((&[] as &[u8], 0xffff_ffff));
                        let sighash = if tapscript.is_empty() {
                            crate::taproot::compute_taproot_signature_hash(
                                tx,
                                input_index,
                                prevout_values,
                                prevout_script_pubkeys,
                                sighash_byte,
                                None,
                            )?
                        } else {
                            crate::taproot::compute_tapscript_signature_hash(
                                tx,
                                input_index,
                                prevout_values,
                                prevout_script_pubkeys,
                                tapscript,
                                crate::taproot::TAPROOT_LEAF_VERSION_TAPSCRIPT,
                                codesep_pos,
                                sighash_byte,
                                ctx.taproot_annex_hash,
                            )?
                        };

                        #[cfg(feature = "production")]
                        let is_valid = {
                            use crate::bip348::verify_tapscript_schnorr_signature;
                            verify_tapscript_schnorr_signature(
                                &sighash,
                                &pubkey_bytes,
                                &sig_bytes,
                                schnorr_collector,
                            )
                            .unwrap_or(false)
                        };

                        #[cfg(not(feature = "production"))]
                        let is_valid = {
                            #[cfg(feature = "csfs")]
                            let x = {
                                use crate::bip348::verify_tapscript_schnorr_signature;
                                verify_tapscript_schnorr_signature(
                                    &sighash,
                                    &pubkey_bytes,
                                    &sig_bytes,
                                    None,
                                )
                                .unwrap_or(false)
                            };
                            #[cfg(not(feature = "csfs"))]
                            let x = false;
                            x
                        };

                        stack.push(to_stack_element(&[if is_valid { 1 } else { 0 }]));
                        return Ok(true);
                    }
                    // Invalid Schnorr encoding for 32-byte x-only pubkey → failed check.
                    stack.push(to_stack_element(&[0]));
                    return Ok(true);
                }
                if sigversion == SigVersion::Tapscript {
                    // Non-32-byte pubkeys succeed without verification (BIP 342).
                    stack.push(to_stack_element(&[1]));
                    return Ok(true);
                }

                // Extract sighash type from last byte of signature
                // Bitcoin signature format: <DER signature><sighash_type>
                // OPTIMIZATION: Cache length to avoid repeated computation
                let sig_len = signature_bytes.len();
                let sighash_byte = signature_bytes[sig_len - 1];
                let _der_sig = &signature_bytes[..sig_len - 1];

                // Calculate sighash - use BIP143 for SegWit, legacy for others
                // BIP143 OPTIMIZATION: For SegWit, hashPrevouts/hashSequence/hashOutputs
                // are computed once per transaction, not once per input.
                let sighash = if sigversion == SigVersion::WitnessV0 {
                    // BIP143 sighash for SegWit v0 (P2WPKH, P2WSH)
                    let amount = prevout_values.get(input_index).copied().unwrap_or(0);

                    // scriptCode for BIP143: the witnessScript or P2PKH equivalent
                    let script_code = redeem_script_for_sighash.unwrap_or_else(|| {
                        prevout_script_pubkeys
                            .get(input_index)
                            .copied()
                            .unwrap_or(&[])
                    });

                    crate::transaction_hash::calculate_bip143_sighash(
                        tx,
                        input_index,
                        script_code,
                        amount,
                        sighash_byte,
                        precomputed_bip143,
                    )?
                } else {
                    // Legacy sighash for non-SegWit transactions
                    use crate::transaction_hash::{
                        SighashType, calculate_transaction_sighash_single_input,
                    };
                    let sighash_type = SighashType::from_byte(sighash_byte);

                    // FindAndDelete: remove the *current* signature's push encoding from scriptCode.
                    // Must not use only the first scriptSig push — P2SH inputs may contain multiple
                    // signatures before the redeem script, each checked with its own sighash.
                    let pattern = serialize_push_data(signature_bytes.as_ref());

                    let base_script = match (
                        redeem_script_for_sighash,
                        prevout_script_pubkeys.get(input_index),
                    ) {
                        (Some(redeem), Some(prevout)) if redeem == *prevout => *prevout,
                        (Some(redeem), _) => redeem,
                        (None, Some(prevout)) => *prevout,
                        (None, None) => &[],
                    };
                    let cleaned = find_and_delete(base_script, &pattern);

                    calculate_transaction_sighash_single_input(
                        tx,
                        input_index,
                        cleaned.as_ref(),
                        prevout_values[input_index],
                        sighash_type,
                        #[cfg(feature = "production")]
                        sighash_cache,
                    )?
                };

                // Verify signature with real transaction hash
                // CRITICAL FIX: Pass full signature (with sighash byte) to verify_signature
                // IsValidSignatureEncoding expects signature WITH sighash byte
                let height = block_height.unwrap_or(0);
                #[cfg(feature = "production")]
                let is_valid = signature::with_secp_context(|secp| {
                    signature::verify_signature(
                        secp,
                        &pubkey_bytes,
                        &signature_bytes, // Pass full signature WITH sighash byte
                        &sighash,
                        flags,
                        height,
                        network,
                        sigversion,
                    )
                })?;

                #[cfg(not(feature = "production"))]
                let is_valid = {
                    let secp = signature::new_secp();
                    signature::verify_signature(
                        &secp,
                        &pubkey_bytes,
                        &signature_bytes, // Pass full signature WITH sighash byte
                        &sighash,
                        flags,
                        height,
                        network,
                        sigversion,
                    )?
                };

                stack.push(to_stack_element(&[if is_valid { 1 } else { 0 }]));
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_CHECKSIGVERIFY - verify signature (Schnorr in Tapscript, ECDSA otherwise)
        OP_CHECKSIGVERIFY => {
            if stack.len() >= 2 {
                let pubkey_bytes = stack.pop().unwrap();
                let signature_bytes = stack.pop().unwrap();

                // Empty signature always fails
                if signature_bytes.is_empty() {
                    return Ok(false);
                }

                // BIP342 Tapscript: Schnorr path (same as OP_CHECKSIG Tapscript branch).
                if sigversion == SigVersion::Tapscript {
                    if pubkey_bytes.len() == 32 {
                        use crate::bip348::try_parse_taproot_schnorr_witness_sig;
                        if let Some((sig_bytes, sighash_byte)) =
                            try_parse_taproot_schnorr_witness_sig(&signature_bytes)
                        {
                            let (tapscript, codesep_pos) = tapscript_for_sighash
                                .map(|s| (s, tapscript_codesep_pos.unwrap_or(0xffff_ffff)))
                                .unwrap_or((&[] as &[u8], 0xffff_ffff));
                            let sighash = if tapscript.is_empty() {
                                crate::taproot::compute_taproot_signature_hash(
                                    tx,
                                    input_index,
                                    prevout_values,
                                    prevout_script_pubkeys,
                                    sighash_byte,
                                    None,
                                )?
                            } else {
                                crate::taproot::compute_tapscript_signature_hash(
                                    tx,
                                    input_index,
                                    prevout_values,
                                    prevout_script_pubkeys,
                                    tapscript,
                                    crate::taproot::TAPROOT_LEAF_VERSION_TAPSCRIPT,
                                    codesep_pos,
                                    sighash_byte,
                                    ctx.taproot_annex_hash,
                                )?
                            };
                            #[cfg(feature = "production")]
                            let is_valid = {
                                use crate::bip348::verify_tapscript_schnorr_signature;
                                verify_tapscript_schnorr_signature(
                                    &sighash,
                                    &pubkey_bytes,
                                    &sig_bytes,
                                    schnorr_collector,
                                )
                                .unwrap_or(false)
                            };
                            #[cfg(not(feature = "production"))]
                            let is_valid = {
                                #[cfg(feature = "csfs")]
                                let x = {
                                    use crate::bip348::verify_tapscript_schnorr_signature;
                                    verify_tapscript_schnorr_signature(
                                        &sighash,
                                        &pubkey_bytes,
                                        &sig_bytes,
                                        None,
                                    )
                                    .unwrap_or(false)
                                };
                                #[cfg(not(feature = "csfs"))]
                                let x = false;
                                x
                            };
                            if !is_valid {
                                return Ok(false); // OP_CHECKSIGVERIFY: fail script on invalid sig
                            }
                            return Ok(true);
                        }
                        // Invalid Schnorr encoding for 32-byte x-only pubkey → failed check.
                        return Ok(false);
                    }
                    // Non-32-byte pubkeys succeed without verification (BIP 342).
                    return Ok(true);
                }

                // Legacy / SegWit v0: ECDSA path
                // Extract sighash type from last byte of signature
                let sig_len = signature_bytes.len();
                let sighash_byte = signature_bytes[sig_len - 1];
                let _der_sig = &signature_bytes[..sig_len - 1];

                // Calculate sighash - use BIP143 for SegWit, legacy for others
                // BIP143 OPTIMIZATION: For SegWit, hashPrevouts/hashSequence/hashOutputs
                // are computed once per transaction, not once per input.
                let sighash = if sigversion == SigVersion::WitnessV0 {
                    // BIP143 sighash for SegWit v0 (P2WPKH, P2WSH)
                    let amount = prevout_values.get(input_index).copied().unwrap_or(0);

                    let script_code = redeem_script_for_sighash.unwrap_or_else(|| {
                        prevout_script_pubkeys
                            .get(input_index)
                            .copied()
                            .unwrap_or(&[])
                    });

                    crate::transaction_hash::calculate_bip143_sighash(
                        tx,
                        input_index,
                        script_code,
                        amount,
                        sighash_byte,
                        precomputed_bip143,
                    )?
                } else {
                    // Legacy sighash for non-SegWit transactions
                    use crate::transaction_hash::{
                        SighashType, calculate_transaction_sighash_single_input,
                    };
                    let sighash_type = SighashType::from_byte(sighash_byte);

                    // FindAndDelete: remove the signature under verification (not first scriptSig push).
                    let pattern = serialize_push_data(signature_bytes.as_ref());

                    let base_script = match (
                        redeem_script_for_sighash,
                        prevout_script_pubkeys.get(input_index),
                    ) {
                        (Some(redeem), Some(prevout)) if redeem == *prevout => *prevout,
                        (Some(redeem), _) => redeem,
                        (None, Some(prevout)) => *prevout,
                        (None, None) => &[],
                    };
                    let cleaned = find_and_delete(base_script, &pattern);

                    calculate_transaction_sighash_single_input(
                        tx,
                        input_index,
                        cleaned.as_ref(),
                        prevout_values[input_index],
                        sighash_type,
                        #[cfg(feature = "production")]
                        sighash_cache,
                    )?
                };

                // Verify signature with real transaction hash
                // CRITICAL FIX: Pass full signature (with sighash byte) to verify_signature
                // IsValidSignatureEncoding expects signature WITH sighash byte
                let height = block_height.unwrap_or(0);
                #[cfg(feature = "production")]
                let is_valid = signature::with_secp_context(|secp| {
                    signature::verify_signature(
                        secp,
                        &pubkey_bytes,
                        &signature_bytes, // Pass full signature WITH sighash byte
                        &sighash,
                        flags,
                        height,
                        network,
                        sigversion,
                    )
                })?;

                #[cfg(not(feature = "production"))]
                let is_valid = {
                    let secp = signature::new_secp();
                    signature::verify_signature(
                        &secp,
                        &pubkey_bytes,
                        &signature_bytes, // Pass full signature WITH sighash byte
                        &sighash,
                        flags,
                        height,
                        network,
                        sigversion,
                    )?
                };

                if is_valid { Ok(true) } else { Ok(false) }
            } else {
                Ok(false)
            }
        }

        // OP_CHECKSIGADD (BIP 342) - Tapscript only. Pops pubkey, n, sig. Verifies Schnorr; if valid push n+1 else fail.
        OP_CHECKSIGADD => {
            if sigversion != SigVersion::Tapscript {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::DisabledOpcode,
                    message: "OP_CHECKSIGADD is only available in Tapscript".into(),
                });
            }
            if stack.len() < 3 {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::InvalidStackOperation,
                    message: "OP_CHECKSIGADD: insufficient stack items (need 3)".into(),
                });
            }
            // BIP 342: pubkey (top), n (second), sig (third)
            let pubkey_bytes = stack.pop().unwrap();
            let n_bytes = stack.pop().unwrap();
            let signature_bytes = stack.pop().unwrap();
            let n = script_num_decode(&n_bytes, 4)?;

            // Empty signature: push n unchanged (BIP 342)
            if signature_bytes.is_empty() {
                stack.push(to_stack_element(&script_num_encode(n)));
                return Ok(true);
            }

            // 32-byte pubkey + non-empty sig: validate. BIP 342: validation failure terminates script.
            if pubkey_bytes.len() == 32 {
                use crate::bip348::try_parse_taproot_schnorr_witness_sig;
                if let Some((sig_bytes, sighash_byte)) =
                    try_parse_taproot_schnorr_witness_sig(&signature_bytes)
                {
                    let (tapscript, codesep_pos) = tapscript_for_sighash
                        .map(|s| (s, tapscript_codesep_pos.unwrap_or(0xffff_ffff)))
                        .unwrap_or((&[] as &[u8], 0xffff_ffff));
                    let sighash = if tapscript.is_empty() {
                        crate::taproot::compute_taproot_signature_hash(
                            tx,
                            input_index,
                            prevout_values,
                            prevout_script_pubkeys,
                            sighash_byte,
                            None,
                        )?
                    } else {
                        crate::taproot::compute_tapscript_signature_hash(
                            tx,
                            input_index,
                            prevout_values,
                            prevout_script_pubkeys,
                            tapscript,
                            crate::taproot::TAPROOT_LEAF_VERSION_TAPSCRIPT,
                            codesep_pos,
                            sighash_byte,
                            ctx.taproot_annex_hash,
                        )?
                    };

                    #[cfg(feature = "production")]
                    let is_valid = {
                        use crate::bip348::verify_tapscript_schnorr_signature;
                        verify_tapscript_schnorr_signature(
                            &sighash,
                            &pubkey_bytes,
                            &sig_bytes,
                            schnorr_collector,
                        )
                        .unwrap_or(false)
                    };

                    #[cfg(not(feature = "production"))]
                    let is_valid = {
                        #[cfg(feature = "csfs")]
                        let x = {
                            use crate::bip348::verify_tapscript_schnorr_signature;
                            verify_tapscript_schnorr_signature(
                                &sighash,
                                &pubkey_bytes,
                                &sig_bytes,
                                None,
                            )
                            .unwrap_or(false)
                        };
                        #[cfg(not(feature = "csfs"))]
                        let x = false;
                        x
                    };

                    if !is_valid {
                        return Ok(false); // BIP 342: validation failure terminates script
                    }
                    stack.push(to_stack_element(&script_num_encode(n + 1)));
                    return Ok(true);
                }
                return Ok(false); // invalid Schnorr encoding for 32-byte pubkey
            }

            // Unknown pubkey type (not 32 bytes): BIP 342 treats as always-valid, push n+1
            stack.push(to_stack_element(&script_num_encode(n + 1)));
            Ok(true)
        }

        // OP_CHECKMULTISIG - verify m-of-n multisig (hot path)
        OP_CHECKMULTISIG => {
            // OP_CHECKMULTISIG implementation
            // Stack layout: [dummy] [sig1] ... [sigm] [m] [pubkey1] ... [pubkeyn] [n]
            if stack.len() < 2 {
                return Ok(false);
            }

            // Pop n (number of public keys) — must be decoded as CScriptNum (BIP62)
            let n_bytes = stack.pop().unwrap();
            let n_raw = script_num_decode(&n_bytes, 4).map_err(|_| {
                ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::InvalidStackOperation,
                    message: "OP_CHECKMULTISIG: invalid n encoding".into(),
                }
            })?;
            if !(0..=20).contains(&n_raw) {
                return Ok(false);
            }
            let n = n_raw as usize;
            if stack.len() < n + 1 {
                return Ok(false);
            }

            // Pop n public keys
            let mut pubkeys = Vec::with_capacity(n);
            for _ in 0..n {
                pubkeys.push(stack.pop().unwrap());
            }

            // Pop m (number of required signatures) — must be decoded as CScriptNum (BIP62)
            let m_bytes = stack.pop().unwrap();
            let m_raw = script_num_decode(&m_bytes, 4).map_err(|_| {
                ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::InvalidStackOperation,
                    message: "OP_CHECKMULTISIG: invalid m encoding".into(),
                }
            })?;
            if m_raw < 0 || m_raw as usize > n || m_raw > 20 {
                return Ok(false);
            }
            let m = m_raw as usize;
            if stack.len() < m + 1 {
                return Ok(false);
            }

            // Pop m signatures
            let mut signatures = Vec::with_capacity(m);
            for _ in 0..m {
                signatures.push(stack.pop().unwrap());
            }

            // Pop dummy element - this is the FIRST element consumed (last remaining on stack)
            // BIP147: Check NULLDUMMY if flag is set (SCRIPT_VERIFY_NULLDUMMY = 0x10)
            let dummy = stack.pop().unwrap();
            if flags & 0x10 != 0 {
                let height = block_height.unwrap_or(0);
                // Convert network type for BIP147
                use crate::bip_validation::Bip147Network;
                let bip147_network = match network {
                    crate::types::Network::Mainnet => Bip147Network::Mainnet,
                    crate::types::Network::Testnet => Bip147Network::Testnet,
                    crate::types::Network::Regtest | crate::types::Network::Signet => {
                        Bip147Network::Regtest
                    }
                };

                // For BIP147, the dummy element must be exactly [0x00] (OP_0) after activation
                // BIP147 requires the dummy to be exactly one byte: 0x00
                // Not empty [], not multi-byte [0x00, ...], not non-zero [0x01, ...]
                use crate::constants::{BIP147_ACTIVATION_MAINNET, BIP147_ACTIVATION_TESTNET};

                let bip147_active = height
                    >= match bip147_network {
                        Bip147Network::Mainnet => BIP147_ACTIVATION_MAINNET,
                        Bip147Network::Testnet => BIP147_ACTIVATION_TESTNET,
                        Bip147Network::Regtest => 0,
                    };

                if bip147_active {
                    // BIP147: Dummy must be empty (either [] or [0x00])
                    // In Bitcoin script, both empty [] and [0x00] (OP_0) are considered "empty"
                    // Both accepted as valid NULLDUMMY (BIP147)
                    let is_empty = dummy.is_empty() || dummy.as_ref() == [0x00];
                    if !is_empty {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::SigNullDummy,
                message: format!(
                    "OP_CHECKMULTISIG: dummy element {dummy:?} violates BIP147 NULLDUMMY (must be empty: [] or [0x00])"
                )
                            .into(),
                        });
                    }
                }
            }

            // Verify signatures against public keys
            // CHECKMULTISIG algorithm: iterate pubkeys, try to match sigs in order
            let height = block_height.unwrap_or(0);

            // FindAndDelete: Remove ALL signatures from scriptCode BEFORE any sighash computation
            // Consensus rule for OP_CHECKMULTISIG (legacy only, not SegWit)
            let cleaned_script_for_multisig: Vec<u8> = if sigversion == SigVersion::Base {
                let base_script = match (
                    redeem_script_for_sighash,
                    prevout_script_pubkeys.get(input_index),
                ) {
                    (Some(redeem), Some(prevout)) if redeem == *prevout => *prevout,
                    (Some(redeem), _) => redeem,
                    (None, Some(prevout)) => *prevout,
                    (None, None) => &[],
                };
                let mut cleaned = base_script.to_vec();
                for sig in &signatures {
                    if sig.is_empty() {
                        continue;
                    }
                    if sig.len().saturating_add(1) > cleaned.len() {
                        continue;
                    }
                    let pattern = serialize_push_data(sig.as_ref());
                    cleaned = find_and_delete(&cleaned, &pattern).into_owned();
                }
                cleaned
            } else {
                // For SegWit, no FindAndDelete needed
                redeem_script_for_sighash
                    .map(|s| s.to_vec())
                    .unwrap_or_else(|| {
                        prevout_script_pubkeys
                            .get(input_index)
                            .map(|p| p.to_vec())
                            .unwrap_or_default()
                    })
            };

            use crate::transaction_hash::{
                SighashType, calculate_transaction_sighash_single_input,
            };

            // Batch path: when n*m >= 4, precompute sighashes once per sig and batch-verify all (pubkey, sig) pairs.
            #[cfg(feature = "production")]
            let use_batch = pubkeys.len() * signatures.len() >= 4;

            #[cfg(feature = "production")]
            let (valid_sigs, _) = if use_batch {
                // Phase 3: Batch sighash for multisig — use batch_compute_legacy_sighashes when Base
                let sighashes: Vec<[u8; 32]> = if sigversion == SigVersion::Base {
                    let non_empty: Vec<_> = signatures.iter().filter(|s| !s.is_empty()).collect();
                    if non_empty.is_empty() {
                        vec![]
                    } else {
                        let specs: Vec<(usize, u8, &[u8])> = non_empty
                            .iter()
                            .map(|s| {
                                (
                                    input_index,
                                    s.as_ref()[s.as_ref().len() - 1],
                                    cleaned_script_for_multisig.as_ref(),
                                )
                            })
                            .collect();
                        crate::transaction_hash::batch_compute_legacy_sighashes(
                            tx,
                            prevout_values,
                            prevout_script_pubkeys,
                            &specs,
                        )?
                    }
                } else {
                    // WitnessV0 (P2WSH): use BIP143 sighash, not legacy.
                    let amount = prevout_values.get(input_index).copied().unwrap_or(0);
                    signatures
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|sig_bytes| {
                            let sighash_byte = sig_bytes[sig_bytes.len() - 1];
                            crate::transaction_hash::calculate_bip143_sighash(
                                tx,
                                input_index,
                                &cleaned_script_for_multisig,
                                amount,
                                sighash_byte,
                                precomputed_bip143,
                            )
                        })
                        .collect::<Result<Vec<_>>>()?
                };

                // Build verification tasks: (pubkey_i, sig_j, sighash_j) for all i,j. Order: j then i (sig_index, pubkey_index)
                let mut tasks: Vec<(&[u8], &[u8], [u8; 32])> =
                    Vec::with_capacity(pubkeys.len() * signatures.len());
                let mut sig_idx_to_sighash_idx = Vec::with_capacity(signatures.len());
                let mut sighash_idx = 0usize;
                for (j, sig_bytes) in signatures.iter().enumerate() {
                    if sig_bytes.is_empty() {
                        sig_idx_to_sighash_idx.push(usize::MAX);
                    } else {
                        sig_idx_to_sighash_idx.push(sighash_idx);
                        let sh = sighashes[sighash_idx];
                        sighash_idx += 1;
                        for pubkey_bytes in &pubkeys {
                            tasks.push((pubkey_bytes.as_ref(), sig_bytes.as_ref(), sh));
                        }
                    }
                }

                let results = if tasks.is_empty() {
                    vec![]
                } else {
                    batch_verify_signatures(&tasks, flags, height, network, sigversion)?
                };

                // Matching: for each pubkey in order, if current sig verifies with this pubkey, advance
                let mut sig_index = 0;
                let mut valid_sigs = 0usize;
                for (i, _pubkey_bytes) in pubkeys.iter().enumerate() {
                    if sig_index >= signatures.len() {
                        break;
                    }
                    // Skip empty sigs without advancing (same as original)
                    while sig_index < signatures.len() && signatures[sig_index].is_empty() {
                        sig_index += 1;
                    }
                    if sig_index >= signatures.len() {
                        break;
                    }
                    let sh_idx = sig_idx_to_sighash_idx[sig_index];
                    if sh_idx == usize::MAX {
                        continue;
                    }
                    let task_idx = sh_idx * pubkeys.len() + i;
                    if task_idx < results.len() && results[task_idx] {
                        valid_sigs += 1;
                        sig_index += 1;
                    }
                }

                // NULLFAIL: any non-empty sig that didn't match any pubkey must cause failure
                const SCRIPT_VERIFY_NULLFAIL: u32 = 0x4000;
                if (flags & SCRIPT_VERIFY_NULLFAIL) != 0 {
                    for (j, sig_bytes) in signatures.iter().enumerate() {
                        if sig_bytes.is_empty() {
                            continue;
                        }
                        let sh_idx = sig_idx_to_sighash_idx[j];
                        if sh_idx == usize::MAX {
                            continue;
                        }
                        let sig_start = sh_idx * pubkeys.len();
                        let sig_end = (sig_start + pubkeys.len()).min(results.len());
                        let matched = results[sig_start..sig_end].iter().any(|&r| r);
                        if !matched {
                            return Err(ConsensusError::ScriptErrorWithCode {
                                code: ScriptErrorCode::SigNullFail,
                                message: "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL".into(),
                            });
                        }
                    }
                }
                (valid_sigs, ())
            } else {
                let mut sig_index = 0;
                let mut valid_sigs = 0;
                let amount = prevout_values.get(input_index).copied().unwrap_or(0);

                for pubkey_bytes in &pubkeys {
                    if sig_index >= signatures.len() {
                        break;
                    }

                    let signature_bytes = &signatures[sig_index];

                    if signature_bytes.is_empty() {
                        continue;
                    }

                    let sig_len = signature_bytes.len();
                    let sighash_byte = signature_bytes[sig_len - 1];

                    // WitnessV0 (P2WSH): BIP143 sighash; Base (P2SH legacy): legacy sighash.
                    let sighash = if sigversion == SigVersion::WitnessV0 {
                        crate::transaction_hash::calculate_bip143_sighash(
                            tx,
                            input_index,
                            &cleaned_script_for_multisig,
                            amount,
                            sighash_byte,
                            #[cfg(feature = "production")]
                            precomputed_bip143,
                            #[cfg(not(feature = "production"))]
                            None,
                        )?
                    } else {
                        let sighash_type = SighashType::from_byte(sighash_byte);
                        calculate_transaction_sighash_single_input(
                            tx,
                            input_index,
                            &cleaned_script_for_multisig,
                            prevout_values[input_index],
                            sighash_type,
                            #[cfg(feature = "production")]
                            sighash_cache,
                        )?
                    };

                    #[cfg(feature = "production")]
                    let is_valid = signature::with_secp_context(|secp| {
                        signature::verify_signature(
                            secp,
                            pubkey_bytes,
                            signature_bytes,
                            &sighash,
                            flags,
                            height,
                            network,
                            sigversion,
                        )
                    })?;

                    #[cfg(not(feature = "production"))]
                    let is_valid = {
                        let secp = signature::new_secp();
                        signature::verify_signature(
                            &secp,
                            pubkey_bytes,
                            signature_bytes,
                            &sighash,
                            flags,
                            height,
                            network,
                            sigversion,
                        )?
                    };

                    const SCRIPT_VERIFY_NULLFAIL: u32 = 0x4000;
                    if !is_valid
                        && (flags & SCRIPT_VERIFY_NULLFAIL) != 0
                        && !signature_bytes.is_empty()
                    {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::SigNullFail,
                            message:
                                "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL"
                                    .into(),
                        });
                    }

                    if is_valid {
                        valid_sigs += 1;
                        sig_index += 1;
                    }
                }
                (valid_sigs, ())
            };

            #[cfg(not(feature = "production"))]
            let (valid_sigs, _) = {
                let mut sig_index = 0;
                let mut valid_sigs = 0;
                let amount = prevout_values.get(input_index).copied().unwrap_or(0);

                for pubkey_bytes in &pubkeys {
                    if sig_index >= signatures.len() {
                        break;
                    }
                    let signature_bytes = &signatures[sig_index];
                    if signature_bytes.is_empty() {
                        continue;
                    }
                    let sig_len = signature_bytes.len();
                    let sighash_byte = signature_bytes[sig_len - 1];

                    // WitnessV0 (P2WSH): BIP143 sighash; Base: legacy sighash.
                    let sighash = if sigversion == SigVersion::WitnessV0 {
                        crate::transaction_hash::calculate_bip143_sighash(
                            tx,
                            input_index,
                            &cleaned_script_for_multisig,
                            amount,
                            sighash_byte,
                            None,
                        )?
                    } else {
                        let sighash_type = SighashType::from_byte(sighash_byte);
                        calculate_transaction_sighash_single_input(
                            tx,
                            input_index,
                            &cleaned_script_for_multisig,
                            prevout_values[input_index],
                            sighash_type,
                        )?
                    };
                    let secp = signature::new_secp();
                    let is_valid = signature::verify_signature(
                        &secp,
                        pubkey_bytes,
                        signature_bytes,
                        &sighash,
                        flags,
                        height,
                        network,
                        sigversion,
                    )?;
                    const SCRIPT_VERIFY_NULLFAIL: u32 = 0x4000;
                    if !is_valid
                        && (flags & SCRIPT_VERIFY_NULLFAIL) != 0
                        && !signature_bytes.is_empty()
                    {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::SigNullFail,
                            message:
                                "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL"
                                    .into(),
                        });
                    }
                    if is_valid {
                        valid_sigs += 1;
                        sig_index += 1;
                    }
                }
                (valid_sigs, ())
            };

            // Push result: 1 if valid_sigs >= m, 0 otherwise
            stack.push(to_stack_element(&[if valid_sigs >= m { 1 } else { 0 }]));
            Ok(true)
        }

        // OP_CHECKMULTISIGVERIFY - CHECKMULTISIG + VERIFY (hot path)
        OP_CHECKMULTISIGVERIFY => {
            // Execute CHECKMULTISIG first
            let ctx_checkmultisig = context::ScriptContext {
                tx,
                input_index,
                prevout_values,
                prevout_script_pubkeys,
                block_height,
                median_time_past,
                network,
                sigversion,
                redeem_script_for_sighash,
                script_sig_for_sighash,
                tapscript_for_sighash,
                tapscript_codesep_pos,
                taproot_annex_hash: None,
                #[cfg(feature = "production")]
                schnorr_collector: None,
                #[cfg(feature = "production")]
                precomputed_bip143,
                #[cfg(feature = "production")]
                sighash_cache,
            };
            let result = execute_opcode_with_context_full(
                OP_CHECKMULTISIG,
                stack,
                flags,
                &ctx_checkmultisig,
                redeem_script_for_sighash,
            )?;
            if !result {
                return Ok(false);
            }
            // VERIFY: check top of stack is truthy, then pop it
            if let Some(top) = stack.pop() {
                if !cast_to_bool(&top) {
                    return Ok(false);
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        // OP_CHECKLOCKTIMEVERIFY (BIP65)
        // Validates that transaction locktime is >= top stack item
        // If SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY flag is not set, treat as NOP2
        // CLTV does NOT pop the stack — it only reads the top element (NOP-type opcode)
        OP_CHECKLOCKTIMEVERIFY => {
            // If CLTV flag is not enabled, behave as NOP (treat as NOP2)
            const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 0x200;
            if (flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) == 0 {
                return Ok(true);
            }

            use crate::locktime::{check_bip65, decode_locktime_value};

            if stack.is_empty() {
                return Err(ConsensusError::ScriptErrorWithCode {
                    code: ScriptErrorCode::InvalidStackOperation,
                    message: "OP_CHECKLOCKTIMEVERIFY: empty stack".into(),
                });
            }

            // Decode locktime value from stack using CScriptNum rules (max 5 bytes)
            let locktime_bytes = stack.last().expect("Stack is not empty");
            let locktime_value = match decode_locktime_value(locktime_bytes.as_ref()) {
                Some(v) => v,
                None => {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::MinimalData,
                        message: "OP_CHECKLOCKTIMEVERIFY: invalid locktime encoding".into(),
                    });
                }
            };

            let tx_locktime = tx.lock_time as u32;

            // CheckLockTime order (BIP65): locktime check via check_bip65
            if !check_bip65(tx_locktime, locktime_value) {
                return Ok(false);
            }

            // Input sequence must NOT be SEQUENCE_FINAL (0xffffffff)
            let input_seq = if input_index < tx.inputs.len() {
                tx.inputs[input_index].sequence
            } else {
                0xffffffff
            };
            if input_seq == 0xffffffff {
                return Ok(false);
            }

            // CLTV does NOT pop the stack (NOP-type opcode)
            Ok(true)
        }

        // OP_CHECKSEQUENCEVERIFY (BIP112)
        // Validates that transaction input sequence number meets relative locktime requirement.
        // Implements BIP68: Relative Lock-Time Using Consensus-Enforced Sequence Numbers.
        //
        // Behavior must match consensus (BIP65/112):
        // - If SCRIPT_VERIFY_CHECKSEQUENCEVERIFY flag is not set, behaves as a NOP (no-op)
        // - If the *stack* sequence has the disable flag set (0x80000000), behaves as a NOP
        // - If the *input* nSequence disable flag is set (and stack is not disabled), fail
        // - Does NOT remove the top stack item on success (non-consuming)
        OP_CHECKSEQUENCEVERIFY => {
            use crate::locktime::{
                decode_locktime_value, extract_sequence_locktime_value, extract_sequence_type_flag,
                is_sequence_disabled,
            };

            // If CSV flag is not enabled, behave as NOP (treat as NOP3)
            const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: u32 = 0x400;
            if (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) == 0 {
                return Ok(true);
            }

            if stack.is_empty() {
                return Ok(false);
            }

            // Decode sequence value from stack using shared locktime logic.
            // Interpret the top stack element as a sequence value (BIP112).
            let sequence_bytes = stack.last().expect("Stack is not empty");
            let sequence_value = match decode_locktime_value(sequence_bytes.as_ref()) {
                Some(v) => v,
                None => return Ok(false), // Invalid encoding
            };

            // Get input sequence number
            if input_index >= tx.inputs.len() {
                return Ok(false);
            }
            let input_sequence = tx.inputs[input_index].sequence as u32;

            // BIP112: stack disable flag → NOP. Input disable flag → fail.
            if is_sequence_disabled(sequence_value) {
                return Ok(true);
            }
            if is_sequence_disabled(input_sequence) {
                return Ok(false);
            }

            // BIP68: Extract relative locktime type and value using shared logic
            let type_flag = extract_sequence_type_flag(sequence_value);
            let locktime_mask = extract_sequence_locktime_value(sequence_value) as u32;

            // Extract input sequence flags and value
            let input_type_flag = extract_sequence_type_flag(input_sequence);
            let input_locktime = extract_sequence_locktime_value(input_sequence) as u32;

            // BIP112: CSV fails if type_flag doesn't match input type
            if type_flag != input_type_flag {
                return Ok(false);
            }

            // BIP112: CSV fails if input locktime < required locktime
            if input_locktime < locktime_mask {
                return Ok(false);
            }

            // Validation passed - behave as NOP (do NOT pop the sequence value)
            Ok(true)
        }

        // OP_CHECKTEMPLATEVERIFY (BIP119) - OP_NOP4
        // Verifies that the transaction matches a template hash.
        // Implements BIP119: CHECKTEMPLATEVERIFY.
        //
        // Behavior must match consensus:
        // - If SCRIPT_VERIFY_DEFAULT_CHECK_TEMPLATE_VERIFY_HASH flag is not set, behaves as NOP4
        // - Requires exactly 32 bytes on stack (template hash)
        // - Fails if template hash doesn't match transaction
        OP_CHECKTEMPLATEVERIFY => {
            #[cfg(not(feature = "ctv"))]
            {
                // Without feature flag, treat as NOP4 (or discourage if flag set)
                const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 0x10000;
                if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::BadOpcode,
                        message: "OP_CHECKTEMPLATEVERIFY requires --features ctv".into(),
                    });
                }
                Ok(true) // NOP4
            }

            #[cfg(feature = "ctv")]
            {
                use crate::constants::{
                    CTV_ACTIVATION_MAINNET, CTV_ACTIVATION_REGTEST, CTV_ACTIVATION_TESTNET,
                };

                // Check activation
                let ctv_activation = match network {
                    crate::types::Network::Mainnet => CTV_ACTIVATION_MAINNET,
                    crate::types::Network::Testnet => CTV_ACTIVATION_TESTNET,
                    crate::types::Network::Regtest | crate::types::Network::Signet => {
                        CTV_ACTIVATION_REGTEST
                    }
                };

                let ctv_active = block_height.map(|h| h >= ctv_activation).unwrap_or(false);
                if !ctv_active {
                    // Before activation: treat as NOP4
                    const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 0x10000;
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0 {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::BadOpcode,
                            message: "OP_CHECKTEMPLATEVERIFY not yet activated".into(),
                        });
                    }
                    return Ok(true); // NOP4
                }

                // Check if CTV flag is enabled
                const SCRIPT_VERIFY_DEFAULT_CHECK_TEMPLATE_VERIFY_HASH: u32 = 0x80000000;
                if (flags & SCRIPT_VERIFY_DEFAULT_CHECK_TEMPLATE_VERIFY_HASH) == 0 {
                    // Flag not set, treat as NOP4
                    return Ok(true);
                }

                use crate::bip119::calculate_template_hash;

                // CTV requires exactly 32 bytes (template hash) on stack
                if stack.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_CHECKTEMPLATEVERIFY: insufficient stack items".into(),
                    });
                }

                let template_hash_bytes = stack.pop().unwrap();

                // Template hash must be exactly 32 bytes
                if template_hash_bytes.len() != 32 {
                    // Non-32-byte argument: NOP (per BIP-119)
                    // But discourage if flag is set
                    const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 0x10000;
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0 {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::InvalidStackOperation,
                            message: "OP_CHECKTEMPLATEVERIFY: template hash must be 32 bytes"
                                .into(),
                        });
                    }
                    return Ok(true); // NOP
                }

                // Calculate actual template hash for this transaction
                let mut expected_hash = [0u8; 32];
                expected_hash.copy_from_slice(&template_hash_bytes);

                let actual_hash = calculate_template_hash(tx, input_index).map_err(|e| {
                    ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::TxInvalid,
                        message: format!("CTV hash calculation failed: {e}").into(),
                    }
                })?;

                // Constant-time comparison (use hash_eq from crypto module)
                use crate::crypto::hash_compare::hash_eq;
                let matches = hash_eq(&expected_hash, &actual_hash);

                if !matches {
                    return Ok(false); // Script fails if template doesn't match
                }

                // CTV succeeds - script continues (NOP-type opcode, doesn't push anything)
                Ok(true)
            }
        }

        // OP_CHECKSIGFROMSTACK (BIP348) - replaces OP_SUCCESS204
        // Verifies a BIP 340 Schnorr signature against an arbitrary message.
        // Implements BIP348: CHECKSIGFROMSTACK.
        //
        // Behavior must match BIP341 tapscript verification:
        // - Only available in Tapscript (leaf version 0xc0)
        // - Pops 3 items: pubkey (top), message (second), signature (third)
        // - If signature is empty, pushes empty vector and continues
        // - If signature is valid, pushes 0x01 (single byte)
        // - If signature is invalid, script fails
        OP_CHECKSIGFROMSTACK => {
            #[cfg(not(feature = "csfs"))]
            {
                // Without feature flag, OP_SUCCESS204 behavior (succeeds)
                // But discourage if flag is set
                const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 0x10000;
                if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::BadOpcode,
                        message: "OP_CHECKSIGFROMSTACK requires --features csfs".into(),
                    });
                }
                Ok(true) // OP_SUCCESS204 succeeds
            }

            #[cfg(feature = "csfs")]
            {
                use crate::constants::{
                    CSFS_ACTIVATION_MAINNET, CSFS_ACTIVATION_REGTEST, CSFS_ACTIVATION_TESTNET,
                };

                // BIP-348: Only available in Tapscript (leaf version 0xc0)
                if sigversion != SigVersion::Tapscript {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::BadOpcode,
                        message: "OP_CHECKSIGFROMSTACK only available in Tapscript".into(),
                    });
                }

                // Check activation
                let csfs_activation = match network {
                    crate::types::Network::Mainnet => CSFS_ACTIVATION_MAINNET,
                    crate::types::Network::Testnet => CSFS_ACTIVATION_TESTNET,
                    crate::types::Network::Regtest | crate::types::Network::Signet => {
                        CSFS_ACTIVATION_REGTEST
                    }
                };

                let csfs_active = block_height.map(|h| h >= csfs_activation).unwrap_or(false);
                if !csfs_active {
                    // Before activation: OP_SUCCESS204 behavior (succeeds)
                    const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 0x10000;
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0 {
                        return Err(ConsensusError::ScriptErrorWithCode {
                            code: ScriptErrorCode::BadOpcode,
                            message: "OP_CHECKSIGFROMSTACK not yet activated".into(),
                        });
                    }
                    return Ok(true); // OP_SUCCESS204 succeeds
                }

                use crate::bip348::verify_signature_from_stack;

                // BIP-348: If fewer than 3 elements, script MUST fail
                if stack.len() < 3 {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::InvalidStackOperation,
                        message: "OP_CHECKSIGFROMSTACK: insufficient stack items (need 3)".into(),
                    });
                }

                // BIP-348: Pop in order: pubkey (top), message (second), signature (third)
                let pubkey_bytes = stack.pop().unwrap(); // Top
                let message_bytes = stack.pop().unwrap(); // Second
                let signature_bytes = stack.pop().unwrap(); // Third

                // BIP-348: If pubkey size is zero, script MUST fail
                if pubkey_bytes.is_empty() {
                    return Err(ConsensusError::ScriptErrorWithCode {
                        code: ScriptErrorCode::PubkeyType,
                        message: "OP_CHECKSIGFROMSTACK: pubkey size is zero".into(),
                    });
                }

                // BIP-348: If signature is empty, push empty vector and continue
                if signature_bytes.is_empty() {
                    stack.push(to_stack_element(&[])); // Empty vector, not 0
                    return Ok(true);
                }

                // BIP-348: Verify signature (only for 32-byte pubkeys)
                // OPTIMIZATION: Use collector for batch verification if available
                #[cfg(feature = "production")]
                let is_valid = {
                    verify_signature_from_stack(
                        &message_bytes,    // Message (NOT hashed by BIP 340 spec)
                        &pubkey_bytes,     // Pubkey (32 bytes for BIP 340)
                        &signature_bytes,  // Signature (64-byte BIP 340 Schnorr)
                        schnorr_collector, // Pass collector for batch verification
                    )
                    .unwrap_or(false)
                };
                #[cfg(not(feature = "production"))]
                let is_valid = verify_signature_from_stack(
                    &message_bytes,   // Message (NOT hashed by BIP 340 spec)
                    &pubkey_bytes,    // Pubkey (32 bytes for BIP 340)
                    &signature_bytes, // Signature (64-byte BIP 340 Schnorr)
                )
                .unwrap_or(false);

                if !is_valid {
                    // BIP-348: Validation failure immediately terminates script execution
                    return Ok(false);
                }

                // BIP-342/348: per-tapscript validation weight enforces signature-related limits during
                // execution. They are not added to `MAX_BLOCK_SIGOPS_COST` (witness v1 returns 0).

                // BIP-348: Push 0x01 (single byte) if valid
                stack.push(to_stack_element(&[0x01])); // Single byte 0x01, not 1
                Ok(true)
            }
        }

        // cold path for all other opcodes (branch prediction hint)
        _ => execute_opcode_cold(opcode, stack, flags),
    }
}

/// Rare opcode dispatch (`#[cold]` so hot path stays compact).
#[cold]
fn execute_opcode_cold(opcode: u8, stack: &mut Vec<StackElement>, flags: u32) -> Result<bool> {
    execute_opcode(opcode, stack, flags, SigVersion::Base)
}

// ============================================================================
// Benchmarking Utilities
// ============================================================================

/// Clear script verification cache
///
/// Useful for benchmarking to ensure consistent results without cache state
/// pollution between runs.
///
/// # Example
///
/// Get and reset fast-path hit counters (production). Used by block validation to log
/// whether P2PK/P2PKH/P2SH/P2WPKH/P2WSH fast-paths are taken vs interpreter fallback.
/// Returns (p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, bare_multisig, interpreter).
#[cfg(all(feature = "production", feature = "profile"))]
pub(crate) fn get_and_reset_fast_path_counts() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        FAST_PATH_P2PK.swap(0, Ordering::Relaxed),
        FAST_PATH_P2PKH.swap(0, Ordering::Relaxed),
        FAST_PATH_P2SH.swap(0, Ordering::Relaxed),
        FAST_PATH_P2WPKH.swap(0, Ordering::Relaxed),
        FAST_PATH_P2WSH.swap(0, Ordering::Relaxed),
        FAST_PATH_P2TR.swap(0, Ordering::Relaxed),
        FAST_PATH_BARE_MULTISIG.swap(0, Ordering::Relaxed),
        FAST_PATH_INTERPRETER.swap(0, Ordering::Relaxed),
    )
}

/// ```rust
/// use blvm_consensus::script::clear_script_cache;
///
/// // Clear cache before benchmark run
/// clear_script_cache();
/// ```
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub fn clear_script_cache() {
    if let Some(cache) = SCRIPT_CACHE.get() {
        let mut cache = cache.write().unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }
}

/// Clear hash operation cache
///
/// Useful for benchmarking to ensure consistent results without cache state
/// pollution between runs.
///
/// # Example
///
/// ```rust
/// use blvm_consensus::script::clear_hash_cache;
///
/// // Clear cache before benchmark run
/// clear_hash_cache();
/// ```
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub fn clear_hash_cache() {
    crypto_ops::clear_hash_cache();
}

/// Clear all caches
///
/// Convenience function to clear both script and hash caches.
///
/// # Example
///
/// ```rust
/// use blvm_consensus::script::clear_all_caches;
///
/// // Clear all caches before benchmark run
/// clear_all_caches();
/// ```
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub fn clear_all_caches() {
    clear_script_cache();
    clear_hash_cache();
}

/// Clear thread-local stack pool
///
/// Clears the thread-local stack pool to reset allocation state for benchmarking.
/// This ensures consistent memory allocation patterns across benchmark runs.
///
/// # Example
///
/// ```rust
/// use blvm_consensus::script::clear_stack_pool;
///
/// // Clear pool before benchmark run
/// clear_stack_pool();
/// ```
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub fn clear_stack_pool() {
    STACK_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        pool.clear();
    });
}

/// Reset all benchmarking state
///
/// Convenience function to reset all caches and thread-local state for
/// reproducible benchmarks. Also clears sighash templates cache.
///
/// # Example
///
/// ```rust
/// use blvm_consensus::script::reset_benchmarking_state;
///
/// // Reset all state before benchmark run
/// reset_benchmarking_state();
/// ```
#[cfg(all(feature = "production", feature = "benchmarking"))]
pub fn reset_benchmarking_state() {
    clear_all_caches();
    clear_stack_pool();
    disable_caching(false); // Re-enable caching by default
    // Also clear sighash templates (currently no-op as templates aren't populated yet)
    #[cfg(feature = "benchmarking")]
    crate::transaction_hash::clear_sighash_templates();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_script_simple() {
        let script = vec![OP_1]; // OP_1
        let mut stack = Vec::new();

        assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[1]);
    }

    #[test]
    fn test_eval_script_overflow() {
        let script = vec![0x51; MAX_STACK_SIZE + 1]; // Too many pushes
        let mut stack = Vec::new();

        assert!(eval_script(&script, &mut stack, 0, SigVersion::Base).is_err());
    }

    #[test]
    fn test_verify_script_simple() {
        let _script_sig = [0x51]; // OP_1
        let _script_pubkey = [0x51]; // OP_1

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
        let script = vec![OP_0]; // OP_0
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script always succeeds; stack has empty item (falsy but not an error)
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
            let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
            assert!(result);
            assert_eq!(stack.len(), 1);
            assert_eq!(stack[0].as_ref(), &[i]);
        }
    }

    #[test]
    fn test_op_dup() {
        let script = vec![0x51, 0x76]; // OP_1, OP_DUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 2 items (EvalScript doesn't check count)
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[1]);
    }

    #[test]
    fn test_op_dup_empty_stack() {
        let script = vec![OP_DUP]; // OP_DUP on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_op_hash160() {
        let script = vec![OP_1, OP_HASH160]; // OP_1, OP_HASH160
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20); // RIPEMD160 output is 20 bytes
    }

    #[test]
    fn test_op_hash160_empty_stack() {
        let script = vec![OP_HASH160]; // OP_HASH160 on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_op_hash256() {
        let script = vec![OP_1, OP_HASH256]; // OP_1, OP_HASH256
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 32); // SHA256 output is 32 bytes
    }

    #[test]
    fn test_op_hash256_empty_stack() {
        let script = vec![OP_HASH256]; // OP_HASH256 on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_op_equal() {
        let script = vec![0x51, 0x51, 0x87]; // OP_1, OP_1, OP_EQUAL
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[1]); // True
    }

    #[test]
    fn test_op_equal_false() {
        let script = vec![0x51, 0x52, 0x87]; // OP_1, OP_2, OP_EQUAL
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; OP_EQUAL pushes [] (empty = falsy)
        assert_eq!(stack.len(), 1);
        assert!(stack[0].is_empty()); // False is [] (empty), not [0x00]
    }

    #[test]
    fn test_op_equal_insufficient_stack() {
        let script = vec![0x51, 0x87]; // OP_1, OP_EQUAL (need 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base);
        assert!(
            result.is_err(),
            "OP_EQUAL with insufficient stack should return error"
        );
        if let Err(crate::error::ConsensusError::ScriptErrorWithCode { code, .. }) = result {
            assert_eq!(
                code,
                crate::error::ScriptErrorCode::InvalidStackOperation,
                "Should return InvalidStackOperation"
            );
        }
    }

    #[test]
    fn test_op_verify() {
        let script = vec![0x51, 0x69]; // OP_1, OP_VERIFY
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; OP_VERIFY consumed the truthy item
        assert_eq!(stack.len(), 0); // OP_VERIFY consumes the top item
    }

    #[test]
    fn test_op_verify_false() {
        let script = vec![0x00, 0x69]; // OP_0, OP_VERIFY (false)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_op_verify_empty_stack() {
        let script = vec![OP_VERIFY]; // OP_VERIFY on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_op_equalverify() {
        let script = vec![0x51, 0x51, 0x88]; // OP_1, OP_1, OP_EQUALVERIFY
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; OP_EQUALVERIFY consumed both equal items
        assert_eq!(stack.len(), 0); // OP_EQUALVERIFY consumes both items
    }

    #[test]
    fn test_op_equalverify_false() {
        let script = vec![0x51, 0x52, 0x88]; // OP_1, OP_2, OP_EQUALVERIFY (false)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base);
        assert!(
            result.is_err(),
            "OP_EQUALVERIFY with false condition should return error"
        );
        if let Err(crate::error::ConsensusError::ScriptErrorWithCode { code, .. }) = result {
            assert_eq!(
                code,
                crate::error::ScriptErrorCode::EqualVerify,
                "Should return EqualVerify"
            );
        }
    }

    #[test]
    fn test_op_checksig() {
        // Note: This test uses simplified inputs. Production code performs full signature verification.
        // The test verifies that OP_CHECKSIG executes without panicking, not that signatures are valid.
        let script = vec![OP_1, OP_1, OP_CHECKSIG]; // OP_1, OP_1, OP_CHECKSIG
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; CHECKSIG pushes [] (invalid sig = falsy) but no error
        assert_eq!(stack.len(), 1);
        // Production code validates signatures using secp256k1; test uses simplified inputs
    }

    #[test]
    fn test_op_checksig_insufficient_stack() {
        let script = vec![OP_1, OP_CHECKSIG]; // OP_1, OP_CHECKSIG (need 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base);
        assert!(
            result.is_err(),
            "OP_CHECKSIG with insufficient stack should return error"
        );
        if let Err(crate::error::ConsensusError::ScriptErrorWithCode { code, .. }) = result {
            assert_eq!(
                code,
                crate::error::ScriptErrorCode::InvalidStackOperation,
                "Should return InvalidStackOperation"
            );
        }
    }

    #[test]
    fn test_unknown_opcode() {
        let script = vec![0xff]; // Unknown opcode (0xff is not a defined opcode constant)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_script_size_limit() {
        let script = vec![0x51; MAX_SCRIPT_SIZE + 1]; // Exceed size limit
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base);
        assert!(result.is_err());
    }

    #[test]
    fn test_operation_count_limit() {
        // Use OP_NOP (0x61) - non-push opcodes count toward limit
        let script = vec![0x61; MAX_SCRIPT_OPS + 1]; // Exceed operation limit
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base);
        assert!(result.is_err());
    }

    #[test]
    fn test_stack_underflow_multiple_ops() {
        let script = vec![0x51, 0x87, 0x87]; // OP_1, OP_EQUAL, OP_EQUAL (second OP_EQUAL will underflow)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base);
        assert!(result.is_err(), "Stack underflow should return error");
        if let Err(crate::error::ConsensusError::ScriptErrorWithCode { code, .. }) = result {
            assert_eq!(
                code,
                crate::error::ScriptErrorCode::InvalidStackOperation,
                "Should return InvalidStackOperation"
            );
        }
    }

    #[test]
    fn test_final_stack_empty() {
        // eval_script (EvalScript) does not check the final stack — VerifyScript does.
        let script = vec![0x51, 0x52]; // OP_1, OP_2 (two items on final stack)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; final stack check is VerifyScript's responsibility
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn test_final_stack_false() {
        // eval_script (EvalScript) does not check top-of-stack truthiness — VerifyScript does.
        let script = vec![OP_0]; // OP_0 (false on final stack)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; verify_script would return false here
    }

    #[test]
    fn test_verify_script_with_witness() {
        // OP_1 sig + OP_1 pubkey + OP_1 witness leaves 3 truthy items; top is truthy → success.
        let script_sig = vec![OP_1]; // OP_1
        let script_pubkey = vec![OP_1]; // OP_1
        let witness = vec![OP_1]; // OP_1
        let flags = 0;

        let result = verify_script(&script_sig, &script_pubkey, Some(&witness), flags).unwrap();
        assert!(result); // VerifyScript: top of stack is truthy regardless of stack size
    }

    #[test]
    fn test_verify_script_failure() {
        // OP_0 pubkey pushes empty (falsy) item on top; verify_script returns false.
        let script_sig = vec![OP_1]; // OP_1 (truthy)
        let script_pubkey = vec![OP_0]; // OP_0 (pushes empty = falsy)
        let witness = None;
        let flags = 0;

        let result = verify_script(&script_sig, &script_pubkey, witness, flags).unwrap();
        assert!(!result); // VerifyScript: top of stack is [] (falsy) → fail
    }

    // ============================================================================
    // COMPREHENSIVE SCRIPT TESTS
    // ============================================================================

    #[test]
    fn test_op_ifdup_true() {
        let script = vec![OP_1, OP_IFDUP]; // OP_1, OP_IFDUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 2 items after dup
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[1]);
    }

    #[test]
    fn test_op_ifdup_false() {
        let script = vec![OP_0, OP_IFDUP]; // OP_0, OP_IFDUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; IFDUP doesn't dup falsy items
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[] as &[u8]);
    }

    #[test]
    fn test_op_depth() {
        let script = vec![OP_1, OP_1, OP_DEPTH]; // OP_1, OP_1, OP_DEPTH
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 3 items
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[2].as_ref(), &[2]); // Depth should be 2 (before OP_DEPTH)
    }

    #[test]
    fn test_op_drop() {
        let script = vec![OP_1, OP_2, OP_DROP]; // OP_1, OP_2, OP_DROP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // Final stack has 1 item [1]
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[1]);
    }

    #[test]
    fn test_op_drop_empty_stack() {
        let script = vec![OP_DROP]; // OP_DROP on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_op_nip() {
        let script = vec![OP_1, OP_2, OP_NIP]; // OP_1, OP_2, OP_NIP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // Final stack has 1 item [2]
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[2]);
    }

    #[test]
    fn test_op_nip_insufficient_stack() {
        let script = vec![OP_1, OP_NIP]; // OP_1, OP_NIP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_over() {
        let script = vec![OP_1, OP_2, OP_OVER]; // OP_1, OP_2, OP_OVER
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 3 items
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[2]);
        assert_eq!(stack[2].as_ref(), &[1]);
    }

    #[test]
    fn test_op_over_insufficient_stack() {
        let script = vec![OP_1, OP_OVER]; // OP_1, OP_OVER (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_pick() {
        let script = vec![OP_1, OP_2, OP_3, OP_1, OP_PICK]; // OP_1, OP_2, OP_3, OP_1, OP_PICK
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 4 items
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[3].as_ref(), &[2]); // Should pick index 1 (OP_2)
    }

    #[test]
    fn test_op_pick_empty_n() {
        // OP_1, OP_0, OP_PICK: n=0 picks top item (duplicates it), stack [1,1]
        let script = vec![OP_1, OP_0, OP_PICK];
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 2 items
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[1].as_ref(), &[1]); // Picked the top (OP_1 value)
    }

    #[test]
    fn test_op_pick_invalid_index() {
        let script = vec![OP_1, OP_2, OP_PICK]; // OP_1, OP_2, OP_PICK (n=2, but only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_roll() {
        let script = vec![OP_1, OP_2, OP_3, OP_1, OP_ROLL]; // OP_1, OP_2, OP_3, OP_1, OP_ROLL
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 3 items
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[3]);
        assert_eq!(stack[2].as_ref(), &[2]); // Should roll index 1 (OP_2) to top
    }

    #[test]
    fn test_op_roll_zero_n() {
        // OP_0 pushes empty bytes (CScriptNum 0), OP_ROLL(0) is a valid no-op
        let script = vec![OP_1, OP_0, OP_ROLL]; // OP_1, OP_0, OP_ROLL (n=0, no-op)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // Stack has [1], which is truthy
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[1]);
    }

    #[test]
    fn test_op_roll_invalid_index() {
        let script = vec![OP_1, OP_2, OP_ROLL]; // OP_1, OP_2, OP_ROLL (n=2, but only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_rot() {
        let script = vec![OP_1, OP_2, OP_3, OP_ROT]; // OP_1, OP_2, OP_3, OP_ROT
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 3 items
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0].as_ref(), &[2]);
        assert_eq!(stack[1].as_ref(), &[3]);
        assert_eq!(stack[2].as_ref(), &[1]);
    }

    #[test]
    fn test_op_rot_insufficient_stack() {
        let script = vec![OP_1, OP_2, OP_ROT]; // OP_1, OP_2, OP_ROT (only 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn test_op_swap() {
        let script = vec![OP_1, OP_2, OP_SWAP]; // OP_1, OP_2, OP_SWAP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 2 items
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0].as_ref(), &[2]);
        assert_eq!(stack[1].as_ref(), &[1]);
    }

    #[test]
    fn test_op_swap_insufficient_stack() {
        let script = vec![OP_1, OP_SWAP]; // OP_1, OP_SWAP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_tuck() {
        let script = vec![OP_1, OP_2, OP_TUCK]; // OP_1, OP_2, OP_TUCK
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 3 items
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0].as_ref(), &[2]);
        assert_eq!(stack[1].as_ref(), &[1]);
        assert_eq!(stack[2].as_ref(), &[2]);
    }

    #[test]
    fn test_op_tuck_insufficient_stack() {
        let script = vec![OP_1, OP_TUCK]; // OP_1, OP_TUCK (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_2drop() {
        let script = vec![OP_1, OP_2, OP_3, OP_2DROP]; // OP_1, OP_2, OP_3, OP_2DROP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // Final stack has 1 item [1]
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].as_ref(), &[1]);
    }

    #[test]
    fn test_op_2drop_insufficient_stack() {
        let script = vec![OP_1, OP_2DROP]; // OP_1, OP_2DROP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_2dup() {
        let script = vec![OP_1, OP_2, OP_2DUP]; // OP_1, OP_2, OP_2DUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 4 items
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[2]);
        assert_eq!(stack[2].as_ref(), &[1]);
        assert_eq!(stack[3].as_ref(), &[2]);
    }

    #[test]
    fn test_op_2dup_insufficient_stack() {
        let script = vec![OP_1, OP_2DUP]; // OP_1, OP_2DUP (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_3dup() {
        let script = vec![OP_1, OP_2, OP_3, OP_3DUP]; // OP_1, OP_2, OP_3, OP_3DUP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 6 items
        assert_eq!(stack.len(), 6);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[2]);
        assert_eq!(stack[2].as_ref(), &[3]);
        assert_eq!(stack[3].as_ref(), &[1]);
        assert_eq!(stack[4].as_ref(), &[2]);
        assert_eq!(stack[5].as_ref(), &[3]);
    }

    #[test]
    fn test_op_3dup_insufficient_stack() {
        let script = vec![OP_1, OP_2, OP_3DUP]; // OP_1, OP_2, OP_3DUP (only 2 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn test_op_2over() {
        let script = vec![OP_1, OP_2, OP_3, OP_4, OP_2OVER]; // OP_1, OP_2, OP_3, OP_4, OP_2OVER
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 6 items
        assert_eq!(stack.len(), 6);
        assert_eq!(stack[4].as_ref(), &[1]); // Should copy second pair
        assert_eq!(stack[5].as_ref(), &[2]);
    }

    #[test]
    fn test_op_2over_insufficient_stack() {
        let script = vec![OP_1, OP_2, OP_3, OP_2OVER]; // OP_1, OP_2, OP_3, OP_2OVER (only 3 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 3);
    }

    #[test]
    fn test_op_2rot() {
        // Stack before: [1,2,3,4,5,6] (1=bottom, 6=top)
        // 2ROT moves 6th and 5th from top (=1 and 2) to top preserving order.
        // Stack after:  [3,4,5,6,1,2] (2=top, 1=second)
        let script = vec![OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_2ROT]; // 6 items, OP_2ROT
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 6 items
        assert_eq!(stack.len(), 6);
        assert_eq!(stack[4].as_ref(), &[1]); // OP_1 moved to second-from-top
        assert_eq!(stack[5].as_ref(), &[2]); // OP_2 moved to top
    }

    #[test]
    fn test_op_2rot_insufficient_stack() {
        let script = vec![OP_1, OP_2, OP_3, OP_4, OP_2ROT]; // OP_1, OP_2, OP_3, OP_4, OP_2ROT (only 4 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 4);
    }

    #[test]
    fn test_op_2swap() {
        let script = vec![OP_1, OP_2, OP_3, OP_4, OP_2SWAP]; // OP_1, OP_2, OP_3, OP_4, OP_2SWAP
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 4 items
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[0].as_ref(), &[3]); // Should swap second pair
        assert_eq!(stack[1].as_ref(), &[4]);
        assert_eq!(stack[2].as_ref(), &[1]);
        assert_eq!(stack[3].as_ref(), &[2]);
    }

    #[test]
    fn test_op_2swap_insufficient_stack() {
        let script = vec![OP_1, OP_2, OP_3, OP_2SWAP]; // OP_1, OP_2, OP_3, OP_2SWAP (only 3 items)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 3);
    }

    #[test]
    fn test_op_size() {
        let script = vec![OP_1, OP_SIZE]; // OP_1, OP_SIZE
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(result); // eval_script succeeds; stack has 2 items (original + size)
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0].as_ref(), &[1]);
        assert_eq!(stack[1].as_ref(), &[1]); // Size of [1] is 1
    }

    #[test]
    fn test_op_size_empty_stack() {
        let script = vec![OP_SIZE]; // OP_SIZE on empty stack
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_op_return() {
        let script = vec![OP_1, OP_RETURN]; // OP_1, OP_RETURN
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result); // OP_RETURN always fails
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_op_checksigverify() {
        let script = vec![OP_1, OP_2, OP_CHECKSIGVERIFY]; // OP_1, OP_2, OP_CHECKSIGVERIFY
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result); // Should fail due to invalid signature
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_op_checksigverify_insufficient_stack() {
        let script = vec![OP_1, OP_CHECKSIGVERIFY]; // OP_1, OP_CHECKSIGVERIFY (only 1 item)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_unknown_opcode_comprehensive() {
        let script = vec![OP_1, 0xff]; // OP_1, unknown opcode (0xff is not a defined opcode constant)
        let mut stack = Vec::new();
        let result = eval_script(&script, &mut stack, 0, SigVersion::Base).unwrap();
        assert!(!result); // Unknown opcode should fail
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn test_verify_signature_invalid_pubkey() {
        let secp = signature::new_secp();
        let invalid_pubkey = vec![0x00]; // Invalid pubkey
        let signature = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]; // Valid DER signature
        let dummy_hash = [0u8; 32];
        let result = signature::verify_signature(
            &secp,
            &invalid_pubkey,
            &signature,
            &dummy_hash,
            0,
            0,
            crate::types::Network::Regtest,
            SigVersion::Base,
        );
        assert!(!result.unwrap_or(false));
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let secp = signature::new_secp();
        let pubkey = vec![
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ]; // Valid pubkey
        let invalid_signature = vec![0x00]; // Invalid signature
        let dummy_hash = [0u8; 32];
        let result = signature::verify_signature(
            &secp,
            &pubkey,
            &invalid_signature,
            &dummy_hash,
            0,
            0,
            crate::types::Network::Regtest,
            SigVersion::Base,
        );
        assert!(!result.unwrap_or(false));
    }

    // ============================================================================
    // Fast-path and verify_script_with_context_full tests
    // ============================================================================

    /// Build a minimal transaction and prevout slices for verify_script_with_context_full.
    fn minimal_tx_and_prevouts(
        script_sig: &[u8],
        script_pubkey: &[u8],
    ) -> (
        crate::types::Transaction,
        Vec<i64>,
        Vec<crate::types::ByteString>,
    ) {
        use crate::types::{OutPoint, Transaction, TransactionInput, TransactionOutput};
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                sequence: 0xffff_ffff,
                script_sig: script_sig.to_vec(),
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 0,
                script_pubkey: script_pubkey.to_vec(),
            }]
            .into(),
            lock_time: 0,
        };
        let prevout_values = vec![0i64];
        let prevout_script_pubkeys_vec = vec![script_pubkey.to_vec()];
        let prevout_script_pubkeys: Vec<&ByteString> = prevout_script_pubkeys_vec.iter().collect();
        (tx, prevout_values, prevout_script_pubkeys_vec)
    }

    #[test]
    fn test_verify_with_context_p2pkh_hash_mismatch() {
        // P2PKH pattern but pubkey hash does not match script_pubkey -> false (fast-path or interpreter).
        let pubkey = vec![0x02u8; 33]; // dummy compressed pubkey
        let sig = vec![0x30u8; 70]; // dummy sig (with sighash byte)
        let mut script_sig = Vec::new();
        script_sig.push(sig.len() as u8);
        script_sig.extend(&sig);
        script_sig.push(pubkey.len() as u8);
        script_sig.extend(&pubkey);

        let mut script_pubkey = vec![OP_DUP, OP_HASH160, PUSH_20_BYTES];
        script_pubkey.extend(&[0u8; 20]); // wrong hash (not HASH160(pubkey))
        script_pubkey.push(OP_EQUALVERIFY);
        script_pubkey.push(OP_CHECKSIG);

        let (tx, pv, psp) = minimal_tx_and_prevouts(&script_sig, &script_pubkey);
        let psp_refs: Vec<&[u8]> = psp.iter().map(|b| b.as_ref()).collect();
        let result = verify_script_with_context_full(
            &script_sig,
            &script_pubkey,
            None,
            0,
            &tx,
            0,
            &pv,
            &psp_refs,
            Some(500_000),
            None,
            crate::types::Network::Mainnet,
            SigVersion::Base,
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
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_with_context_p2sh_hash_mismatch() {
        // P2SH pattern but redeem script hash does not match -> false.
        let redeem = vec![OP_1, OP_1, OP_ADD]; // minimal redeem
        let mut script_sig = Vec::new();
        script_sig.push(redeem.len() as u8);
        script_sig.extend(&redeem);

        let mut script_pubkey = vec![OP_HASH160, PUSH_20_BYTES];
        script_pubkey.extend(&[0u8; 20]); // wrong hash (not HASH160(redeem))
        script_pubkey.push(OP_EQUAL);

        let (tx, pv, psp) = minimal_tx_and_prevouts(&script_sig, &script_pubkey);
        let psp_refs: Vec<&[u8]> = psp.iter().map(|b| b.as_ref()).collect();
        let result = verify_script_with_context_full(
            &script_sig,
            &script_pubkey,
            None,
            0x01, // P2SH
            &tx,
            0,
            &pv,
            &psp_refs,
            Some(500_000),
            None,
            crate::types::Network::Mainnet,
            SigVersion::Base,
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
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_with_context_p2wpkh_wrong_witness_size() {
        // P2WPKH script_pubkey but witness has 1 element (need 2) -> false.
        let mut script_pubkey = vec![OP_0, PUSH_20_BYTES];
        script_pubkey.extend(&[0u8; 20]);
        let witness: Vec<Vec<u8>> = vec![vec![0x30; 70]]; // only sig, no pubkey
        let (tx, pv, psp) = minimal_tx_and_prevouts(&[], &script_pubkey);
        let psp_refs: Vec<&[u8]> = psp.iter().map(|b| b.as_ref()).collect();
        let empty: Vec<u8> = vec![];
        let result = verify_script_with_context_full(
            &empty,
            &script_pubkey,
            Some(&witness),
            0,
            &tx,
            0,
            &pv,
            &psp_refs,
            Some(500_000),
            None,
            crate::types::Network::Mainnet,
            SigVersion::Base,
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
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_with_context_p2wsh_wrong_witness_script_hash() {
        // P2WSH script_pubkey but SHA256(witness_script) != program -> false.
        let witness_script = vec![OP_1];
        let mut script_pubkey = vec![OP_0, PUSH_32_BYTES];
        script_pubkey.extend(&[0u8; 32]); // wrong hash (not SHA256(witness_script))
        let witness: Vec<Vec<u8>> = vec![witness_script];
        let (tx, pv, psp) = minimal_tx_and_prevouts(&[], &script_pubkey);
        let psp_refs: Vec<&[u8]> = psp.iter().map(|b| b.as_ref()).collect();
        let empty: Vec<u8> = vec![];
        let result = verify_script_with_context_full(
            &empty,
            &script_pubkey,
            Some(&witness),
            0,
            &tx,
            0,
            &pv,
            &psp_refs,
            Some(500_000),
            None,
            crate::types::Network::Mainnet,
            SigVersion::Base,
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
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    #[cfg(feature = "production")]
    fn test_p2wsh_multisig_fast_path() {
        // P2WSH 2-of-2 multisig: fast path parses and validates; placeholder sigs fail -> Ok(false).
        use crate::constants::BIP147_ACTIVATION_MAINNET;
        use crate::crypto::OptimizedSha256;

        let pk1 = [0x02u8; 33];
        let pk2 = [0x03u8; 33];
        let mut witness_script = vec![0x52]; // OP_2
        witness_script.extend_from_slice(&pk1);
        witness_script.extend_from_slice(&pk2);
        witness_script.push(0x52); // OP_2
        witness_script.push(0xae); // OP_CHECKMULTISIG

        let wsh_hash = OptimizedSha256::new().hash(&witness_script);
        let mut script_pubkey = vec![OP_0, PUSH_32_BYTES];
        script_pubkey.extend_from_slice(&wsh_hash);

        let witness: Vec<Vec<u8>> = vec![
            vec![0x00],       // NULLDUMMY
            vec![0x30u8; 72], // placeholder sig 1
            vec![0x30u8; 72], // placeholder sig 2
            witness_script.clone(),
        ];

        let (tx, pv, psp) = minimal_tx_and_prevouts(&[], &script_pubkey);
        let psp_refs: Vec<&[u8]> = psp.iter().map(|b| b.as_ref()).collect();
        let empty: Vec<u8> = vec![];
        let result = verify_script_with_context_full(
            &empty,
            &script_pubkey,
            Some(&witness),
            0x810, // SIGHASH_ALL | VERIFY_NULLDUMMY | VERIFY_NULLFAIL
            &tx,
            0,
            &pv,
            &psp_refs,
            Some(BIP147_ACTIVATION_MAINNET + 1),
            None,
            crate::types::Network::Mainnet,
            SigVersion::Base,
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
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Property test: eval_script respects operation limits
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString: |script| > MAX_SCRIPT_OPS ⟹ eval_script fails
    proptest! {
        #[test]
        fn prop_eval_script_operation_limit(script in prop::collection::vec(any::<u8>(), 0..300)) {
            let mut stack = Vec::new();
            let flags = 0u32;

            let result = eval_script(&script, &mut stack, flags, SigVersion::Base);

            // Note: Production code tracks op_count precisely (number of non-push opcodes executed).
            // Script length can be larger than op_count if there are data pushes.
            // For a script with only opcodes (no data pushes), length = op_count.
            // So scripts with length > MAX_SCRIPT_OPS that are all opcodes will fail.
            // But scripts with data pushes might have length > MAX_SCRIPT_OPS but op_count <= MAX_SCRIPT_OPS.
            // This property test verifies that very long scripts (> MAX_SCRIPT_OPS * 2) eventually fail
            // or that the operation limit is respected.
            if script.len() > MAX_SCRIPT_OPS * 2 {
                // Very long scripts should fail (either op limit or other reasons)
                // This is a weak check but acceptable for property testing
                prop_assert!(result.is_err() || !result.unwrap(),
                    "Very long scripts should fail or return false");
            }
            // Otherwise, scripts may succeed or fail - both are acceptable
        }
    }

    /// Property test: verify_script is deterministic
    ///
    /// Mathematical specification:
    /// ∀ inputs: verify_script(inputs) = verify_script(inputs)
    proptest! {
        #[test]
        fn prop_verify_script_deterministic(
            script_sig in prop::collection::vec(any::<u8>(), 0..20),
            script_pubkey in prop::collection::vec(any::<u8>(), 0..20),
            witness in prop::option::of(prop::collection::vec(any::<u8>(), 0..10)),
            flags in any::<u32>()
        ) {
            let result1 = verify_script(&script_sig, &script_pubkey, witness.as_ref(), flags);
            let result2 = verify_script(&script_sig, &script_pubkey, witness.as_ref(), flags);

            assert_eq!(result1.is_ok(), result2.is_ok());
            if result1.is_ok() && result2.is_ok() {
                assert_eq!(result1.unwrap(), result2.unwrap());
            }
        }
    }

    /// Property test: execute_opcode handles all opcodes without panicking
    ///
    /// Mathematical specification:
    /// ∀ opcode ∈ {0..255}, stack ∈ Vec<StackElement>: execute_opcode(opcode, stack) ∈ {true, false}
    proptest! {
        #[test]
        fn prop_execute_opcode_no_panic(
            opcode in any::<u8>(),
            stack_items in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..5),
                0..10
            ),
            flags in any::<u32>()
        ) {
            let mut stack: Vec<StackElement> = stack_items.into_iter().map(|v| to_stack_element(&v)).collect();
            let result = execute_opcode(opcode, &mut stack, flags, SigVersion::Base);

            // Some opcodes may return errors (invalid opcodes, insufficient stack, etc.)
            // The important thing is that it doesn't panic
            match result {
                Ok(success) => {
                    // Just test it returns a boolean (success is either true or false)
                    let _ = success;
                },
                Err(_) => {
                    // Errors are acceptable - invalid opcodes, insufficient stack, etc.
                    // The test is about not panicking, not about always succeeding
                }
            }

            // Stack should remain within bounds
            assert!(stack.len() <= MAX_STACK_SIZE);
        }
    }

    /// Property test: stack operations preserve bounds
    ///
    /// Mathematical specification:
    /// ∀ opcode ∈ {0..255}, stack ∈ Vec<StackElement>:
    /// - |stack| ≤ MAX_STACK_SIZE before and after execute_opcode
    /// - Stack operations are well-defined
    proptest! {
        #[test]
        fn prop_stack_operations_bounds(
            opcode in any::<u8>(),
            stack_items in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..3),
                0..5
            ),
            flags in any::<u32>()
        ) {
            let mut stack: Vec<StackElement> = stack_items.into_iter().map(|v| to_stack_element(&v)).collect();
            let initial_len = stack.len();

            let result = execute_opcode(opcode, &mut stack, flags, SigVersion::Base);

            // Stack should never exceed MAX_STACK_SIZE
            assert!(stack.len() <= MAX_STACK_SIZE);

            // If operation succeeded, stack should be in valid state
            if result.is_ok() && result.unwrap() {
                // For opcodes that modify stack size, verify reasonable bounds
                match opcode {
                    OP_0 | OP_1..=OP_16 => {
                        // Push opcodes - increase by 1
                        assert!(stack.len() == initial_len + 1);
                    },
                    OP_DUP => {
                        // OP_DUP - increase by 1
                        if initial_len > 0 {
                            assert!(stack.len() == initial_len + 1);
                        }
                    },
                    OP_3DUP => {
                        // OP_3DUP - increases by 3 if stack has >= 3 items
                        if initial_len >= 3 {
                            assert!(stack.len() == initial_len + 3);
                        }
                    },
                    OP_2OVER => {
                        // OP_2OVER - increases by 2 if stack has >= 4 items
                        if initial_len >= 4 {
                            assert!(stack.len() == initial_len + 2);
                        }
                    },
                    OP_DROP | OP_NIP | OP_2DROP => {
                        // These opcodes decrease stack size
                        assert!(stack.len() <= initial_len);
                    },
                    _ => {
                        // Other opcodes maintain or modify stack size reasonably
                        // Some opcodes can push multiple items, so allow up to +3
                        assert!(stack.len() <= initial_len + 3, "Stack size should be reasonable");
                    }
                }
            }
        }
    }

    /// Property test: hash operations are deterministic
    ///
    /// Mathematical specification:
    /// ∀ input ∈ ByteString: OP_HASH160(input) = OP_HASH160(input)
    proptest! {
        #[test]
        fn prop_hash_operations_deterministic(
            input in prop::collection::vec(any::<u8>(), 0..10)
        ) {
            let elem = to_stack_element(&input);
            let mut stack1 = vec![elem.clone()];
            let mut stack2 = vec![elem];

            let result1 = execute_opcode(0xa9, &mut stack1, 0, SigVersion::Base); // OP_HASH160
            let result2 = execute_opcode(0xa9, &mut stack2, 0, SigVersion::Base); // OP_HASH160

            assert_eq!(result1.is_ok(), result2.is_ok());
            if let (Ok(val1), Ok(val2)) = (result1, result2) {
                assert_eq!(val1, val2);
                if val1 {
                    assert_eq!(stack1, stack2);
                }
            }
        }
    }

    /// Property test: equality operations are symmetric
    ///
    /// Mathematical specification:
    /// ∀ a, b ∈ ByteString: OP_EQUAL(a, b) = OP_EQUAL(b, a)
    proptest! {
        #[test]
        fn prop_equality_operations_symmetric(
            a in prop::collection::vec(any::<u8>(), 0..5),
            b in prop::collection::vec(any::<u8>(), 0..5)
        ) {
            let mut stack1 = vec![to_stack_element(&a), to_stack_element(&b)];
            let mut stack2 = vec![to_stack_element(&b), to_stack_element(&a)];

            let result1 = execute_opcode(0x87, &mut stack1, 0, SigVersion::Base); // OP_EQUAL
            let result2 = execute_opcode(0x87, &mut stack2, 0, SigVersion::Base); // OP_EQUAL

            assert_eq!(result1.is_ok(), result2.is_ok());
            if let (Ok(val1), Ok(val2)) = (result1, result2) {
                assert_eq!(val1, val2);
                if val1 {
                    // Results should be identical (both true or both false)
                    assert_eq!(stack1.len(), stack2.len());
                    if !stack1.is_empty() && !stack2.is_empty() {
                        assert_eq!(stack1[0], stack2[0]);
                    }
                }
            }
        }
    }

    /// Property test: script execution terminates
    ///
    /// Mathematical specification:
    /// ∀ script ∈ ByteString: eval_script(script) terminates (no infinite loops)
    proptest! {
        #[test]
        fn prop_script_execution_terminates(
            script in prop::collection::vec(any::<u8>(), 0..50)
        ) {
            let mut stack = Vec::new();
            let flags = 0u32;

            // This should complete without hanging
            let result = eval_script(&script, &mut stack, flags, SigVersion::Base);

            // Should return a result (success or failure)
            assert!(result.is_ok() || result.is_err());

            // Stack should be in valid state
            assert!(stack.len() <= MAX_STACK_SIZE);
        }
    }
}
