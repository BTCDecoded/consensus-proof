//! Script verification queue: dedicated N-1 worker threads plus master as Nth.
//!
//! Producer adds checks per-tx; workers pull batches and verify. Master joins until
//! queue empty. Batch size from ibd_tuning (default 128, env/config override).

#![cfg(all(feature = "production", feature = "rayon"))]

use crate::activation::{ForkActivationTable, IsForkActive};
use crate::error::{ConsensusError, Result};
use crate::script::verify_script_with_context_full;
use crate::types::{Block, ForkId, Natural, Network};
use crate::witness::Witness;
use crate::witness::is_witness_empty;
use crossbeam_queue::SegQueue;

use std::cell::RefCell;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

fn lock_poison_recovery<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn condvar_wait_poison_recovery<'a, T>(
    cv: &Condvar,
    guard: std::sync::MutexGuard<'a, T>,
) -> std::sync::MutexGuard<'a, T> {
    cv.wait(guard).unwrap_or_else(|e| e.into_inner())
}

/// Default batch size when not overridden.
const DEFAULT_BATCH_SIZE: usize = 128;

/// Thread-local HashMaps reused across batches to avoid per-batch allocations.
/// all_refs cannot be reused because it holds refs into buffer which is batch-scoped.
thread_local! {
    static PREVOUT_BUF: RefCell<Vec<i64>> = const { RefCell::new(Vec::new()) };
}

/// Script check with embedded per-input data. Workers use these directly without
/// HashMap grouping or shared-buffer indirection (self-contained script checks).
#[derive(Clone, Debug)]
pub struct ScriptCheck {
    pub tx_ctx_idx: usize,
    pub input_idx: usize,
    pub spk_offset: u32,
    pub spk_len: u32,
    pub prevout_value: i64,
    /// Per-input verify flags.
    pub flags: u32,
}

/// Per-tx context shared by all inputs of that tx.
/// prevout_script_pubkeys and prevout_values in block-level buffers;
/// context holds (start, count) ranges to avoid per-tx Vec allocations.
#[derive(Clone, Debug)]
pub struct TxScriptContext {
    pub tx_index: usize,
    /// (start, count) range into BlockSessionContext.prevout_values_buffer
    pub prevout_values_range: (usize, usize),
    /// (start, count) range into BlockSessionContext.script_pubkey_indices_buffer
    pub script_pubkey_indices_range: (usize, usize),
    pub flags: u32,
    #[cfg(feature = "production")]
    pub bip143: Option<crate::transaction_hash::Bip143PrecomputedHashes>,
    pub loop_idx: usize,
    pub fee: i64,
    pub ecdsa_index_base: usize,
    /// Roadmap: (scriptCode, nHashType) -> hash cache. Helps multisig.
    #[cfg(feature = "production")]
    pub sighash_midstate_cache: Option<crate::transaction_hash::SighashMidstateCache>,
}

/// Session context for one block; set at start_session, used by workers until complete.
/// When schnorr_collector is None, verify in-place (no batch collection).
/// TxScriptContext stored in Arc to avoid cloning full context per check (workers get Arc::clone).
/// Block-level buffers are immutable (Arc<Vec<...>>) — no locks during worker execution.
pub struct BlockSessionContext {
    pub block: Arc<Block>,
    /// Block-level buffer for all prevout values; TxScriptContext.prevout_values_range indexes into this.
    pub prevout_values_buffer: Arc<Vec<i64>>,
    /// Block-level buffer for (start, len) pairs into script_pubkey_buffer; TxScriptContext.script_pubkey_indices_range indexes into this.
    pub script_pubkey_indices_buffer: Arc<Vec<(usize, usize)>>,
    /// Block-level buffer for all prevout script_pubkeys; (start, len) from script_pubkey_indices_buffer index into this.
    pub script_pubkey_buffer: Arc<Vec<u8>>,
    /// Block-level witness data; workers index via `session.witness_buffer[ctx.tx_index][input_idx]`.
    pub witness_buffer: Arc<Vec<Vec<Witness>>>,
    pub tx_contexts: Arc<Vec<TxScriptContext>>,
    #[cfg(feature = "production")]
    pub ecdsa_sub_counters: Arc<Vec<AtomicUsize>>,
    #[cfg(feature = "production")]
    pub schnorr_collector: Option<Arc<crate::bip348::SchnorrSignatureCollector>>,
    /// When set, P2PKH fast path defers secp to block-end ECDSA batch (CPU / GPU).
    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
    pub ecdsa_collector: Option<Arc<crate::ecdsa_batch::EcdsaSignatureCollector>>,
    pub height: Natural,
    pub median_time_past: Option<u64>,
    pub network: Network,
    /// Fork heights for this validation session (same table as `BlockValidationContext::activation`).
    pub activation: ForkActivationTable,
    /// Lock-free: workers push batch_results; master drains at complete(). Reduces Mutex contention.
    pub results: Arc<SegQueue<Vec<(usize, bool)>>>,
    /// Precomputed sighashes for P2PKH inputs, indexed by ecdsa_index_base + input_idx.
    /// None = not precomputed (worker computes on demand).
    #[cfg(feature = "production")]
    pub precomputed_sighashes: Arc<Vec<Option<[u8; 32]>>>,
    /// Precomputed HASH160(pubkey) for P2PKH inputs, indexed same as precomputed_sighashes.
    #[cfg(feature = "production")]
    pub precomputed_p2pkh_hashes: Arc<Vec<Option<[u8; 20]>>>,
}

struct QueueState {
    checks: Vec<ScriptCheck>,
    n_todo: usize,
    n_total: usize,
    n_idle: usize,
    /// Total checks submitted in the current block session; used to pre-size the result Vec in `complete()`.
    n_submitted: usize,
    error_result: Option<ConsensusError>,
    request_stop: bool,
    session: Option<Arc<BlockSessionContext>>,
}

/// Script verification queue: N-1 dedicated workers + master joins.
pub struct ScriptCheckQueue {
    state: Arc<Mutex<QueueState>>,
    worker_cv: Arc<Condvar>,
    master_cv: Arc<Condvar>,
    control_mutex: Mutex<()>,
    _workers: Vec<JoinHandle<()>>,
    batch_size: usize,
}

impl ScriptCheckQueue {
    /// Create queue with `worker_count` dedicated threads (par-1; master joins for total par).
    /// `batch_size`: from ibd_tuning (default 128). Use `None` for default.
    pub fn new(worker_count: usize, batch_size: Option<usize>) -> Self {
        let batch_size = batch_size
            .filter(|&b| b > 0 && b <= 1024)
            .unwrap_or(DEFAULT_BATCH_SIZE);
        let state = Arc::new(Mutex::new(QueueState {
            checks: Vec::new(),
            n_todo: 0,
            n_total: 0,
            n_idle: 0,
            n_submitted: 0,
            error_result: None,
            request_stop: false,
            session: None,
        }));
        let worker_cv = Arc::new(Condvar::new());
        let master_cv = Arc::new(Condvar::new());

        let mut workers = Vec::with_capacity(worker_count);
        for n in 0..worker_count {
            let state_clone = Arc::clone(&state);
            let cv_clone = Arc::clone(&worker_cv);
            let master_clone = Arc::clone(&master_cv);
            let bs = batch_size;
            workers.push(
                thread::Builder::new()
                    .name(format!("scriptch.{n}"))
                    .spawn(move || {
                        Self::worker_loop(state_clone, &cv_clone, &master_clone, bs);
                    })
                    .expect("scriptch thread spawn"),
            );
        }

        Self {
            state,
            worker_cv,
            master_cv,
            control_mutex: Mutex::new(()),
            _workers: workers,
            batch_size,
        }
    }

    /// Run a single check with pre-built refs (used when refs are cached per tx_ctx).
    /// p2pkh_hash: when Some, P2PKH fast path skips HASH160 (batch path).
    /// When script_pubkey and prevout_values are Some, skips per-check lock acquisitions (batch path).
    pub fn run_check_with_refs(
        check: &ScriptCheck,
        session: &BlockSessionContext,
        ctx: &TxScriptContext,
        refs: &[&[u8]],
        buffer: &[u8],
        #[cfg(feature = "production")] p2pkh_hash: Option<[u8; 20]>,
        script_pubkey_prefetched: Option<&[u8]>,
        prevout_values_prefetched: Option<&[i64]>,
    ) -> std::result::Result<bool, ConsensusError> {
        let tx = &session.block.transactions[ctx.tx_index];
        let script_pubkey: &[u8] = match script_pubkey_prefetched {
            Some(s) => s,
            None => {
                let spi = session.script_pubkey_indices_buffer.as_slice();
                let (base, count) = ctx.script_pubkey_indices_range;
                let (start, len) = if check.input_idx < count {
                    spi[base + check.input_idx]
                } else {
                    (0, 0)
                };
                &buffer[start..start + len]
            }
        };
        let witness_for_script = if !session
            .activation
            .is_fork_active(ForkId::SegWit, session.height)
        {
            None
        } else {
            session
                .witness_buffer
                .get(ctx.tx_index)
                .and_then(|w| w.get(check.input_idx))
                .and_then(|w| if is_witness_empty(w) { None } else { Some(w) })
        };
        let ecdsa_global_idx = ctx.ecdsa_index_base + check.input_idx;

        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        let ecdsa_collect = session
            .ecdsa_collector
            .as_ref()
            .map(|col| (col.as_ref(), ecdsa_global_idx));

        #[cfg(feature = "production")]
        let sighash_cache = ctx.sighash_midstate_cache.as_ref();

        #[cfg(feature = "production")]
        let precomputed_sighash = session
            .precomputed_sighashes
            .get(ecdsa_global_idx)
            .and_then(|s| *s);
        #[cfg(feature = "production")]
        let precomputed_p2pkh = match p2pkh_hash {
            Some(h) => Some(h),
            None => session
                .precomputed_p2pkh_hashes
                .get(ecdsa_global_idx)
                .and_then(|h| *h),
        };

        let do_verify = |prevout_values: &[i64]| {
            verify_script_with_context_full(
                &tx.inputs[check.input_idx].script_sig,
                script_pubkey,
                witness_for_script,
                check.flags,
                tx,
                check.input_idx,
                prevout_values,
                refs,
                Some(session.height),
                session.median_time_past,
                session.network,
                crate::script::SigVersion::Base,
                #[cfg(feature = "production")]
                session.schnorr_collector.as_deref(),
                #[cfg(not(feature = "production"))]
                None,
                #[cfg(feature = "production")]
                ctx.bip143.as_ref(),
                #[cfg(not(feature = "production"))]
                None,
                #[cfg(feature = "production")]
                precomputed_sighash,
                #[cfg(feature = "production")]
                sighash_cache,
                #[cfg(feature = "production")]
                precomputed_p2pkh,
                #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                ecdsa_collect,
            )
            .map_err(|e| {
                ConsensusError::BlockValidation(
                    format!(
                        "Script verification failed at tx {} input {}: {}",
                        ctx.tx_index, check.input_idx, e
                    )
                    .into(),
                )
            })
        };

        match prevout_values_prefetched {
            Some(p) => do_verify(p),
            None => {
                let pv = session.prevout_values_buffer.as_slice();
                let (base, count) = ctx.prevout_values_range;
                let slice = &pv[base..][..count];
                PREVOUT_BUF.with(|cell| {
                    let mut v = cell.borrow_mut();
                    v.clear();
                    v.extend_from_slice(slice);
                    do_verify(&v)
                })
            }
        }
    }

    fn run_check<'a>(
        check: &ScriptCheck,
        session: &'a BlockSessionContext,
        refs_buf: &mut Vec<&'a [u8]>,
    ) -> std::result::Result<bool, ConsensusError> {
        let ctx = session
            .tx_contexts
            .get(check.tx_ctx_idx)
            .ok_or_else(|| ConsensusError::BlockValidation("tx_ctx_idx out of range".into()))?;
        let buffer = session.script_pubkey_buffer.as_slice();
        let spi = session.script_pubkey_indices_buffer.as_slice();
        let (base, count) = ctx.script_pubkey_indices_range;
        refs_buf.clear();
        refs_buf.extend((0..count).map(|j| {
            let (s, l) = spi[base + j];
            buffer[s..s + l].as_ref()
        }));
        Self::run_check_with_refs(
            check, session, ctx, refs_buf, buffer, None, // run_check has no batch context
            None, // script_pubkey_prefetched
            None, // prevout_values_prefetched
        )
    }

    fn worker_loop(
        state: Arc<Mutex<QueueState>>,
        worker_cv: &Condvar,
        master_cv: &Condvar,
        batch_size: usize,
    ) {
        let mut n_now: usize = 0;
        let mut local_error: Option<ConsensusError> = None;
        let mut batch_buf: Vec<ScriptCheck> = Vec::with_capacity(batch_size);

        loop {
            let (session_opt, _batch_len) = {
                let mut guard = lock_poison_recovery(state.as_ref());
                if n_now > 0 {
                    if let Some(ref err) = local_error {
                        if guard.error_result.is_none() {
                            guard.error_result = Some(err.clone());
                        }
                    }
                    guard.n_todo -= n_now;
                    if guard.n_todo == 0 {
                        master_cv.notify_one();
                    }
                    n_now = 0;
                    local_error = None;
                } else {
                    guard.n_total += 1;
                }

                loop {
                    if guard.request_stop {
                        return;
                    }
                    if guard.checks.is_empty() {
                        guard.n_idle += 1;
                        guard = condvar_wait_poison_recovery(worker_cv, guard);
                        guard.n_idle -= 1;
                        continue;
                    }
                    break;
                }

                let n_total = guard.n_total;
                let n_idle = guard.n_idle;
                let divisor = (n_total + n_idle + 1).max(1);
                n_now = (guard.checks.len() / divisor).clamp(1, batch_size);
                let drain_len = n_now.min(guard.checks.len());
                batch_buf.clear();
                let drain_start = guard.checks.len() - drain_len;
                batch_buf.extend(guard.checks.drain(drain_start..));
                let session = guard.session.clone();
                (session, ())
            };

            if batch_buf.is_empty() {
                continue;
            }

            let session = match session_opt.as_ref() {
                Some(s) => Arc::clone(s),
                None => continue,
            };

            let mut batch_results = Vec::with_capacity(batch_buf.len());
            #[cfg(all(feature = "production", feature = "profile"))]
            let t_run_check = std::time::Instant::now();
            {
                batch_buf.sort_unstable_by_key(|c| c.tx_ctx_idx);
                let buffer = session.script_pubkey_buffer.as_slice();
                let spi = session.script_pubkey_indices_buffer.as_slice();
                let pv = session.prevout_values_buffer.as_slice();
                let mut refs_buf: Vec<&[u8]> = Vec::with_capacity(64);
                let mut cached_ctx_idx: usize = usize::MAX;
                for c in batch_buf.iter() {
                    let ctx = match session.tx_contexts.get(c.tx_ctx_idx) {
                        Some(ctx) => ctx,
                        None => {
                            local_error = Some(ConsensusError::BlockValidation(
                                "tx_ctx_idx out of range".into(),
                            ));
                            break;
                        }
                    };
                    let s = c.spk_offset as usize;
                    let l = c.spk_len as usize;
                    let script_pubkey = if s + l <= buffer.len() {
                        &buffer[s..s + l]
                    } else {
                        &[]
                    };
                    let (pv_base, pv_count) = ctx.prevout_values_range;
                    let prevout_slice = &pv[pv_base..][..pv_count];
                    if c.tx_ctx_idx != cached_ctx_idx {
                        refs_buf.clear();
                        let (spi_base, spi_count) = ctx.script_pubkey_indices_range;
                        for j in 0..spi_count {
                            let (start, len) = spi[spi_base + j];
                            refs_buf.push(if start + len <= buffer.len() {
                                &buffer[start..start + len]
                            } else {
                                &[]
                            });
                        }
                        cached_ctx_idx = c.tx_ctx_idx;
                    }
                    match Self::run_check_with_refs(
                        c,
                        session.as_ref(),
                        ctx,
                        &refs_buf,
                        buffer,
                        None,
                        Some(script_pubkey),
                        Some(prevout_slice),
                    ) {
                        Ok(valid) => batch_results.push((c.tx_ctx_idx, valid)),
                        Err(e) => {
                            local_error = Some(e);
                            break;
                        }
                    }
                }
            }
            #[cfg(all(feature = "production", feature = "profile"))]
            crate::script_profile::add_worker_run_check_loop_ns(
                t_run_check.elapsed().as_nanos() as u64
            );
            if !batch_results.is_empty() {
                #[cfg(all(feature = "production", feature = "profile"))]
                let t_results = std::time::Instant::now();
                session.results.push(batch_results);
                #[cfg(all(feature = "production", feature = "profile"))]
                crate::script_profile::add_worker_results_extend_ns(
                    t_results.elapsed().as_nanos() as u64
                );
            }
        }
    }

    /// Start a block session. Must be called before any Add. Session holds shared context.
    pub fn start_session(&self, session: BlockSessionContext) {
        let mut guard = lock_poison_recovery(&self.state);
        guard.session = Some(Arc::new(session));
        guard.checks.clear();
        guard.n_todo = 0;
        guard.n_submitted = 0;
        guard.error_result = None;
    }

    /// Add checks to the queue; workers wake and process.
    pub fn add(&self, checks: Vec<ScriptCheck>) {
        let n = checks.len();
        if n == 0 {
            return;
        }
        {
            let mut guard = lock_poison_recovery(&self.state);
            guard.checks.extend(checks);
            guard.n_todo += n;
            guard.n_submitted += n;
        }
        if n == 1 {
            self.worker_cv.notify_one();
        } else {
            self.worker_cv.notify_all();
        }
    }

    /// Add checks from a slice without consuming. Used with block-level pre-allocated Vec (Q).
    pub fn add_from_slice(&self, checks: &[ScriptCheck]) {
        let n = checks.len();
        if n == 0 {
            return;
        }
        {
            let mut guard = lock_poison_recovery(&self.state);
            guard.checks.extend(checks.iter().cloned());
            guard.n_todo += n;
            guard.n_submitted += n;
        }
        if n == 1 {
            self.worker_cv.notify_one();
        } else {
            self.worker_cv.notify_all();
        }
    }

    /// Run checks sequentially on the current thread (fallback when parallel retry fails).
    pub fn run_checks_sequential(
        checks: &[ScriptCheck],
        session: &BlockSessionContext,
    ) -> Result<Vec<(usize, bool)>> {
        let mut results = Vec::with_capacity(checks.len());
        let mut refs_buf = Vec::with_capacity(256);
        for c in checks {
            let valid = Self::run_check(c, session, &mut refs_buf)?;
            results.push((c.tx_ctx_idx, valid));
        }
        Ok(results)
    }

    /// Master joins until queue empty; returns collected (tx_ctx_idx, valid) results.
    pub fn complete(&self) -> Result<Vec<(usize, bool)>> {
        let _control = lock_poison_recovery(&self.control_mutex);
        let state = Arc::clone(&self.state);
        let worker_cv = Arc::clone(&self.worker_cv);
        let master_cv = Arc::clone(&self.master_cv);
        let batch_size = self.batch_size;

        let mut n_now: usize = 0;
        let mut local_error: Option<ConsensusError> = None;
        let mut session_opt: Option<Arc<BlockSessionContext>> = None;
        let mut batch_buf: Vec<ScriptCheck> = Vec::with_capacity(batch_size);

        loop {
            let done = {
                let mut guard = lock_poison_recovery(state.as_ref());
                if n_now > 0 {
                    if let Some(ref err) = local_error {
                        if guard.error_result.is_none() {
                            guard.error_result = Some(err.clone());
                        }
                    }
                    guard.n_todo -= n_now;
                    n_now = 0;
                    local_error = None;
                } else {
                    guard.n_total += 1;
                }

                loop {
                    if guard.n_todo == 0 {
                        guard.n_total -= 1;
                        let n_expected = guard.n_submitted;
                        guard.n_submitted = 0;
                        let results = guard
                            .session
                            .as_ref()
                            .map(|s| {
                                let mut out = Vec::with_capacity(n_expected.max(64));
                                while let Some(batch) = s.results.pop() {
                                    out.extend(batch);
                                }
                                out
                            })
                            .unwrap_or_default();
                        guard.session = None;
                        if let Some(ref e) = guard.error_result {
                            return Err(e.clone());
                        }
                        return Ok(results);
                    }
                    if guard.checks.is_empty() {
                        guard.n_idle += 1;
                        guard = condvar_wait_poison_recovery(master_cv.as_ref(), guard);
                        guard.n_idle -= 1;
                        continue;
                    }
                    break;
                }

                let n_total = guard.n_total;
                let n_idle = guard.n_idle;
                let divisor = (n_total + n_idle + 1).max(1);
                n_now = (guard.checks.len() / divisor).clamp(1, batch_size);
                let drain_len = n_now.min(guard.checks.len());
                batch_buf.clear();
                let drain_start = guard.checks.len() - drain_len;
                batch_buf.extend(guard.checks.drain(drain_start..));
                session_opt = guard.session.clone();
                false
            };

            if batch_buf.is_empty() {
                continue;
            }

            let session = match session_opt.as_ref() {
                Some(s) => Arc::clone(s),
                None => continue,
            };

            let mut batch_results = Vec::with_capacity(batch_buf.len());
            #[cfg(all(feature = "production", feature = "profile"))]
            let t_run_check = std::time::Instant::now();
            {
                batch_buf.sort_unstable_by_key(|c| c.tx_ctx_idx);
                let buffer = session.script_pubkey_buffer.as_slice();
                let spi = session.script_pubkey_indices_buffer.as_slice();
                let pv = session.prevout_values_buffer.as_slice();
                let mut refs_buf: Vec<&[u8]> = Vec::with_capacity(64);
                let mut cached_ctx_idx: usize = usize::MAX;
                for c in batch_buf.iter() {
                    let ctx = match session.tx_contexts.get(c.tx_ctx_idx) {
                        Some(ctx) => ctx,
                        None => {
                            local_error = Some(ConsensusError::BlockValidation(
                                "tx_ctx_idx out of range".into(),
                            ));
                            break;
                        }
                    };
                    let s = c.spk_offset as usize;
                    let l = c.spk_len as usize;
                    let script_pubkey = if s + l <= buffer.len() {
                        &buffer[s..s + l]
                    } else {
                        &[]
                    };
                    let (pv_base, pv_count) = ctx.prevout_values_range;
                    let prevout_slice = &pv[pv_base..][..pv_count];
                    if c.tx_ctx_idx != cached_ctx_idx {
                        refs_buf.clear();
                        let (spi_base, spi_count) = ctx.script_pubkey_indices_range;
                        for j in 0..spi_count {
                            let (start, len) = spi[spi_base + j];
                            refs_buf.push(if start + len <= buffer.len() {
                                &buffer[start..start + len]
                            } else {
                                &[]
                            });
                        }
                        cached_ctx_idx = c.tx_ctx_idx;
                    }
                    match Self::run_check_with_refs(
                        c,
                        session.as_ref(),
                        ctx,
                        &refs_buf,
                        buffer,
                        None,
                        Some(script_pubkey),
                        Some(prevout_slice),
                    ) {
                        Ok(valid) => batch_results.push((c.tx_ctx_idx, valid)),
                        Err(e) => {
                            local_error = Some(e);
                            break;
                        }
                    }
                }
            }
            #[cfg(all(feature = "production", feature = "profile"))]
            crate::script_profile::add_worker_run_check_loop_ns(
                t_run_check.elapsed().as_nanos() as u64
            );
            if !batch_results.is_empty() {
                #[cfg(all(feature = "production", feature = "profile"))]
                let t_results = std::time::Instant::now();
                session.results.push(batch_results);
                #[cfg(all(feature = "production", feature = "profile"))]
                crate::script_profile::add_worker_results_extend_ns(
                    t_results.elapsed().as_nanos() as u64
                );
            }
        }
    }
}
