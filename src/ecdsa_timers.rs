//! Cheap ECDSA Phase-0 timers (opt-in `BLVM_ECDSA_TIMERS=1`).
//!
//! Separates script-check-loop wall from end-of-block `verify_batch` wall so
//! AV=0 @400k can branch GPU-overlap vs host-cut work.
//!
//! `collect_ms` is the entire `process_check` / script-check loop (not merely
//! SoA append). `batch_ms` is deferred ECDSA/Schnorr `verify_batch`.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        matches!(
            std::env::var("BLVM_ECDSA_TIMERS")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

static COLLECT_NS: AtomicU64 = AtomicU64::new(0);
static BATCH_NS: AtomicU64 = AtomicU64::new(0);
static BLOCKS: AtomicU64 = AtomicU64::new(0);
static LAST_LOG_BLOCKS: AtomicU64 = AtomicU64::new(0);

pub fn note_collect_ns(ns: u64) {
    if !enabled() {
        return;
    }
    COLLECT_NS.fetch_add(ns, Ordering::Relaxed);
}

pub fn note_batch_ns(ns: u64) {
    if !enabled() {
        return;
    }
    BATCH_NS.fetch_add(ns, Ordering::Relaxed);
}

pub fn note_block_done() {
    if !enabled() {
        return;
    }
    let b = BLOCKS.fetch_add(1, Ordering::Relaxed) + 1;
    let last = LAST_LOG_BLOCKS.load(Ordering::Relaxed);
    if (b == 1 || b.saturating_sub(last) >= 128)
        && LAST_LOG_BLOCKS
            .compare_exchange(last, b, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let c = COLLECT_NS.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let v = BATCH_NS.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let tot = c + v;
        let pct = if tot > 0.0 { 100.0 * v / tot } else { 0.0 };
        eprintln!(
            "[BLVM_ECDSA_TIMERS] blocks={b} collect_ms={c:.1} batch_ms={v:.1} \
             batch_share={pct:.1}% (batch/(script_check_loop+batch); \
             collect_ms=whole process_check loop)"
        );
    }
}

pub fn snapshot() -> (u64, u64, u64) {
    (
        BLOCKS.load(Ordering::Relaxed),
        COLLECT_NS.load(Ordering::Relaxed),
        BATCH_NS.load(Ordering::Relaxed),
    )
}

pub fn reset() {
    COLLECT_NS.store(0, Ordering::Relaxed);
    BATCH_NS.store(0, Ordering::Relaxed);
    BLOCKS.store(0, Ordering::Relaxed);
    LAST_LOG_BLOCKS.store(0, Ordering::Relaxed);
}

/// Narrow within-block collect pool size (`BLVM_ECDSA_COLLECT_THREADS`, default 0 = serial IBD).
/// Clamp 0..=8. Values ≥2 use a dedicated rayon pool (not global SCRIPT workers).
pub fn collect_threads() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("BLVM_ECDSA_COLLECT_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
            .min(8)
    })
}

/// Shared collect pool sized to **host CPU count** (not `COLLECT_THREADS`).
///
/// C3 lesson: a 2-thread pool + 20 validate workers → every block queues on 2 cores
/// (`val≈400ms`). Pool must cover concurrent in-flight blocks; callers should keep
/// `MAX_PARALLEL * COLLECT_THREADS ≤ nproc` (harness H1: 14×2 on 32-wide).
#[cfg(feature = "rayon")]
pub fn collect_pool() -> Option<&'static rayon::ThreadPool> {
    let per_block = collect_threads();
    if per_block < 2 {
        return None;
    }
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    Some(POOL.get_or_init(|| {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
            .clamp(2, 64);
        let max_par = std::env::var("BLVM_IBD_MAX_PARALLEL")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if max_par > 0 && max_par.saturating_mul(per_block) > cpus {
            eprintln!(
                "[BLVM_ECDSA_COLLECT] WARN MAX_PARALLEL={max_par}×COLLECT={per_block} \
                 > nproc={cpus} — expect oversub (C3-class REVERT)"
            );
        }
        eprintln!(
            "[BLVM_ECDSA_COLLECT] shared rayon pool threads={cpus} \
             per_block_width={per_block} (budget MAX_PARALLEL×COLLECT≤nproc)"
        );
        rayon::ThreadPoolBuilder::new()
            .num_threads(cpus)
            .thread_name(|i| format!("blvm-ecdsa-collect-{i}"))
            .build()
            .expect("ecdsa collect pool")
    }))
}

#[cfg(not(feature = "rayon"))]
pub fn collect_pool() -> Option<&'static ()> {
    None
}
