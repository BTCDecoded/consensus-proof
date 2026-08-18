//! Script sub-timing for IBD profiling (sighash, interpreter, CHECKMULTISIG ECDSA, P2PKH).
//! Used by connect.rs to extend [PERF] when `production` + `profile` are enabled.
//!
//! Accumulators are **thread-local** so N validate workers do not steal each other's
//! buckets when `get_and_reset_*` runs at block end (process-global atomics corrupted
//! per-block ratios on ATTR 2026-07-29).

#![cfg(all(feature = "production", feature = "profile"))]

use std::cell::Cell;

macro_rules! tls_u64 {
    ($($name:ident),+ $(,)?) => {
        thread_local! {
            $( static $name: Cell<u64> = const { Cell::new(0) }; )+
        }
    };
}

tls_u64!(
    SCRIPT_SIGHASH_NS,
    SCRIPT_INTERPRETER_NS,
    SCRIPT_CHECKMULTISIG_ECDSA_NS,
    SCRIPT_P2PKH_PARSE_NS,
    SCRIPT_P2PKH_HASH160_NS,
    SCRIPT_P2PKH_COLLECT_NS,
    COLLECT_SLOT_NS,
    COLLECT_SHARD_LOCK_NS,
    COLLECT_COPY_NS,
    COLLECT_CHUNK_NS,
    WORKER_P2PKH_MAP_NS,
    WORKER_REFS_NS,
    WORKER_REFS_LOCK_NS,
    WORKER_RUN_CHECK_LOOP_NS,
    WORKER_RESULTS_EXTEND_NS,
    P2PKH_FAST_PATH_ENTRY_NS,
    P2PKH_BIP66_NS,
    P2PKH_SECP_CONTEXT_NS,
    BATCH_SOA_EXTRACT_NS,
    BATCH_SECP_VERIFY_NS,
    BATCH_CACHE_WRITE_NS,
    DRAIN_SHARD_COPY_NS,
    DRAIN_PARSE_NS,
    DRAIN_SECP_NS,
    ECDSA_CACHE_HITS,
    ECDSA_CACHE_MISSES,
    // process_check arm counts / ns (IBD dens attribution)
    ARM_P2PKH_N,
    ARM_P2PKH_NS,
    ARM_P2PK_N,
    ARM_P2PK_NS,
    ARM_P2SH_MULTISIG_N,
    ARM_P2SH_MULTISIG_NS,
    ARM_P2WPKH_N,
    ARM_P2WPKH_NS,
    ARM_P2WSH_N,
    ARM_P2WSH_NS,
    ARM_FALLBACK_N,
    ARM_FALLBACK_NS,
    // Fallback shape split (ATTR: what is the 88% arm-ms binder?)
    FB_NESTED_P2WSH_N,
    FB_NESTED_P2WSH_NS,
    FB_P2SH_OTHER_N,
    FB_P2SH_OTHER_NS,
    FB_NATIVE_WIT_N,
    FB_NATIVE_WIT_NS,
    FB_OTHER_N,
    FB_OTHER_NS,
);

#[inline(always)]
fn add(cell: &'static std::thread::LocalKey<Cell<u64>>, ns: u64) {
    cell.with(|c| c.set(c.get().saturating_add(ns)));
}

#[inline(always)]
fn take(cell: &'static std::thread::LocalKey<Cell<u64>>) -> u64 {
    cell.with(|c| c.replace(0))
}

#[inline(always)]
pub fn add_sighash_ns(ns: u64) {
    add(&SCRIPT_SIGHASH_NS, ns);
}

#[inline(always)]
pub fn add_interpreter_ns(ns: u64) {
    add(&SCRIPT_INTERPRETER_NS, ns);
}

/// Wall inside `batch_verify_signatures` (CHECKMULTISIG cartesian / serial ECDSA).
#[inline(always)]
pub fn add_multisig_ns(ns: u64) {
    add(&SCRIPT_CHECKMULTISIG_ECDSA_NS, ns);
}

#[inline(always)]
pub fn add_checkmultisig_ecdsa_ns(ns: u64) {
    add_multisig_ns(ns);
}

#[inline(always)]
pub fn add_p2pkh_parse_ns(ns: u64) {
    add(&SCRIPT_P2PKH_PARSE_NS, ns);
}

#[inline(always)]
pub fn add_p2pkh_hash160_ns(ns: u64) {
    add(&SCRIPT_P2PKH_HASH160_NS, ns);
}

#[inline(always)]
pub fn add_p2pkh_collect_ns(ns: u64) {
    add(&SCRIPT_P2PKH_COLLECT_NS, ns);
}

#[inline(always)]
pub fn add_collect_slot_ns(ns: u64) {
    add(&COLLECT_SLOT_NS, ns);
}

#[inline(always)]
pub fn add_collect_shard_lock_ns(ns: u64) {
    add(&COLLECT_SHARD_LOCK_NS, ns);
}

#[inline(always)]
pub fn add_collect_copy_ns(ns: u64) {
    add(&COLLECT_COPY_NS, ns);
}

#[inline(always)]
pub fn add_collect_chunk_ns(ns: u64) {
    add(&COLLECT_CHUNK_NS, ns);
}

#[inline(always)]
pub fn add_worker_p2pkh_map_ns(ns: u64) {
    add(&WORKER_P2PKH_MAP_NS, ns);
}

#[inline(always)]
pub fn add_worker_refs_ns(ns: u64) {
    add(&WORKER_REFS_NS, ns);
}

#[inline(always)]
pub fn add_worker_refs_lock_ns(ns: u64) {
    add(&WORKER_REFS_LOCK_NS, ns);
}

#[inline(always)]
pub fn add_worker_run_check_loop_ns(ns: u64) {
    add(&WORKER_RUN_CHECK_LOOP_NS, ns);
}

#[inline(always)]
pub fn add_worker_results_extend_ns(ns: u64) {
    add(&WORKER_RESULTS_EXTEND_NS, ns);
}

#[inline(always)]
pub fn add_p2pkh_fast_path_entry_ns(ns: u64) {
    add(&P2PKH_FAST_PATH_ENTRY_NS, ns);
}

#[inline(always)]
pub fn add_p2pkh_bip66_ns(ns: u64) {
    add(&P2PKH_BIP66_NS, ns);
}

#[inline(always)]
pub fn add_p2pkh_secp_context_ns(ns: u64) {
    add(&P2PKH_SECP_CONTEXT_NS, ns);
}

#[inline(always)]
pub fn add_batch_soa_extract_ns(ns: u64) {
    add(&BATCH_SOA_EXTRACT_NS, ns);
}

#[inline(always)]
pub fn add_batch_secp_verify_ns(ns: u64) {
    add(&BATCH_SECP_VERIFY_NS, ns);
}

#[inline(always)]
pub fn add_batch_cache_write_ns(ns: u64) {
    add(&BATCH_CACHE_WRITE_NS, ns);
}

#[inline(always)]
pub fn add_drain_shard_copy_ns(ns: u64) {
    add(&DRAIN_SHARD_COPY_NS, ns);
}

#[inline(always)]
pub fn add_drain_parse_ns(ns: u64) {
    add(&DRAIN_PARSE_NS, ns);
}

#[inline(always)]
pub fn add_drain_secp_ns(ns: u64) {
    add(&DRAIN_SECP_NS, ns);
}

#[inline(always)]
pub fn add_ecdsa_cache_hit() {
    add(&ECDSA_CACHE_HITS, 1);
}

#[inline(always)]
pub fn add_ecdsa_cache_miss() {
    add(&ECDSA_CACHE_MISSES, 1);
}

#[inline(always)]
pub fn note_arm_p2pkh(ns: u64) {
    add(&ARM_P2PKH_N, 1);
    add(&ARM_P2PKH_NS, ns);
}

#[inline(always)]
pub fn note_arm_p2pk(ns: u64) {
    add(&ARM_P2PK_N, 1);
    add(&ARM_P2PK_NS, ns);
}

#[inline(always)]
pub fn note_arm_p2sh_multisig(ns: u64) {
    add(&ARM_P2SH_MULTISIG_N, 1);
    add(&ARM_P2SH_MULTISIG_NS, ns);
}

#[inline(always)]
pub fn note_arm_p2wpkh(ns: u64) {
    add(&ARM_P2WPKH_N, 1);
    add(&ARM_P2WPKH_NS, ns);
}

#[inline(always)]
pub fn note_arm_p2wsh(ns: u64) {
    add(&ARM_P2WSH_N, 1);
    add(&ARM_P2WSH_NS, ns);
}

#[inline(always)]
pub fn note_arm_fallback(ns: u64) {
    add(&ARM_FALLBACK_N, 1);
    add(&ARM_FALLBACK_NS, ns);
}

/// Classify a fallback input by scriptPubKey / scriptSig / witness shape.
#[inline(always)]
pub fn note_fallback_shape(ns: u64, kind: FallbackShape) {
    note_arm_fallback(ns);
    match kind {
        FallbackShape::NestedP2wsh => {
            add(&FB_NESTED_P2WSH_N, 1);
            add(&FB_NESTED_P2WSH_NS, ns);
        }
        FallbackShape::P2shOther => {
            add(&FB_P2SH_OTHER_N, 1);
            add(&FB_P2SH_OTHER_NS, ns);
        }
        FallbackShape::NativeWit => {
            add(&FB_NATIVE_WIT_N, 1);
            add(&FB_NATIVE_WIT_NS, ns);
        }
        FallbackShape::Other => {
            add(&FB_OTHER_N, 1);
            add(&FB_OTHER_NS, ns);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FallbackShape {
    /// P2SH + redeem = OP_0 PUSH_32 (nested P2WSH)
    NestedP2wsh,
    /// Other P2SH (non-standard redeem / non-msig)
    P2shOther,
    /// Native witness program (P2WPKH/P2WSH/P2TR) that missed fast paths
    NativeWit,
    Other,
}

pub fn get_and_reset_fallback_shape_stats() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        take(&FB_NESTED_P2WSH_N),
        take(&FB_NESTED_P2WSH_NS),
        take(&FB_P2SH_OTHER_N),
        take(&FB_P2SH_OTHER_NS),
        take(&FB_NATIVE_WIT_N),
        take(&FB_NATIVE_WIT_NS),
        take(&FB_OTHER_N),
        take(&FB_OTHER_NS),
    )
}

pub fn get_and_reset_drain_timing() -> (u64, u64, u64) {
    (
        take(&DRAIN_SHARD_COPY_NS),
        take(&DRAIN_PARSE_NS),
        take(&DRAIN_SECP_NS),
    )
}

pub fn get_and_reset_ecdsa_cache_stats() -> (u64, u64) {
    (take(&ECDSA_CACHE_HITS), take(&ECDSA_CACHE_MISSES))
}

pub fn get_and_reset_script_sub_timing() -> (u64, u64, u64) {
    (
        take(&SCRIPT_SIGHASH_NS),
        take(&SCRIPT_INTERPRETER_NS),
        take(&SCRIPT_CHECKMULTISIG_ECDSA_NS),
    )
}

pub fn get_and_reset_p2pkh_timing() -> (u64, u64, u64, u64, u64, u64) {
    (
        take(&SCRIPT_P2PKH_PARSE_NS),
        take(&SCRIPT_P2PKH_HASH160_NS),
        take(&SCRIPT_P2PKH_COLLECT_NS),
        take(&P2PKH_FAST_PATH_ENTRY_NS),
        take(&P2PKH_BIP66_NS),
        take(&P2PKH_SECP_CONTEXT_NS),
    )
}

pub fn get_and_reset_collect_timing() -> (u64, u64, u64, u64) {
    (
        take(&COLLECT_SLOT_NS),
        take(&COLLECT_SHARD_LOCK_NS),
        take(&COLLECT_COPY_NS),
        take(&COLLECT_CHUNK_NS),
    )
}

pub fn get_and_reset_worker_timing() -> (u64, u64, u64, u64, u64) {
    (
        take(&WORKER_P2PKH_MAP_NS),
        take(&WORKER_REFS_NS),
        take(&WORKER_REFS_LOCK_NS),
        take(&WORKER_RUN_CHECK_LOOP_NS),
        take(&WORKER_RESULTS_EXTEND_NS),
    )
}

pub fn get_and_reset_batch_phase_timing() -> (u64, u64, u64) {
    (
        take(&BATCH_SOA_EXTRACT_NS),
        take(&BATCH_SECP_VERIFY_NS),
        take(&BATCH_CACHE_WRITE_NS),
    )
}

/// (p2pkh_n, p2pkh_ns, p2pk_n, p2pk_ns, p2sh_msig_n, p2sh_msig_ns, p2wpkh_n, p2wpkh_ns, p2wsh_n, p2wsh_ns, fallback_n, fallback_ns)
pub fn get_and_reset_arm_stats() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        take(&ARM_P2PKH_N),
        take(&ARM_P2PKH_NS),
        take(&ARM_P2PK_N),
        take(&ARM_P2PK_NS),
        take(&ARM_P2SH_MULTISIG_N),
        take(&ARM_P2SH_MULTISIG_NS),
        take(&ARM_P2WPKH_N),
        take(&ARM_P2WPKH_NS),
        take(&ARM_P2WSH_N),
        take(&ARM_P2WSH_NS),
        take(&ARM_FALLBACK_N),
        take(&ARM_FALLBACK_NS),
    )
}
