//! ECDSA signature collector for deferred batch verification (P2PKH / compact SoA).
//!
//! Mirrors [`crate::bip348::SchnorrSignatureCollector`]: workers collect compact
//! (msg32, pk33, sig64) rows; block end calls [`EcdsaSignatureCollector::verify_batch`]
//! which uses [`crate::secp256k1_backend::verify_ecdsa_batch`] (CPU batch + optional GPU).
//!
//! ## Opt-in accelerators
//! - Lock-free SoA writes when constructed with `serial_ibd=true` (IBD path).
//! - `BLVM_ECDSA_FLUSH_CHUNK=N` (N≥64): async mid-block verify enqueue; join before accept.
//!   Prefer `BLVM_SECP_GPU_SUBMITTERS=1` (GPU overlap when CUDA is linked).
//! - `BLVM_ECDSA_WAVE=1`: park SoA via [`take_owned_soa`] for orch two-phase wave.

#[cfg(feature = "production")]
use crate::error::{ConsensusError, Result};
#[cfg(feature = "production")]
use std::sync::atomic::{AtomicUsize, Ordering};

/// Owned compact SoA for wave / async submit.
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
#[derive(Clone)]
pub struct OwnedEcdsaSoA {
    pub indices: Vec<usize>,
    pub msgs: Vec<[u8; 32]>,
    pub pubkeys: Vec<[u8; 33]>,
    pub sigs: Vec<[u8; 64]>,
}

/// Deferred CHECKMULTISIG oracle: cartesian trial rows in SoA, resolved after batch.
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
#[derive(Clone, Debug)]
pub struct MultisigPending {
    pub m: u8,
    pub n_pubs: usize,
    /// Global indices of trials, row-major `sig_j` then `pubkey_i` (interpreter order).
    pub trial_indices: Vec<usize>,
    pub sig_empty: Vec<bool>,
    pub nullfail: bool,
}

/// High bit marks SoA rows that are CHECKMULTISIG trials (failed trials are not block failures).
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
pub const MULTISIG_TRIAL_INDEX_TAG: usize = 1usize << 40;

#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
#[inline]
pub fn is_multisig_trial_index(idx: usize) -> bool {
    idx >= MULTISIG_TRIAL_INDEX_TAG
}

/// SoA collector for compact ECDSA verification tasks.
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
pub struct EcdsaSignatureCollector {
    soa: Option<std::sync::Arc<EcdsaSoAStorage>>,
    next_idx: AtomicUsize,
    overflow: crossbeam_queue::SegQueue<(usize, [u8; 32], [u8; 33], [u8; 64])>,
    serial_ibd: bool,
    inflight: std::sync::Mutex<Vec<InflightChunk>>,
    flushed_upto: AtomicUsize,
    multisig_pending: std::sync::Mutex<Vec<MultisigPending>>,
}

#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
struct InflightChunk {
    indices: Vec<usize>,
    rx: std::sync::mpsc::Receiver<Result<Vec<bool>>>,
}

#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
struct EcdsaSoAStorage {
    inner: std::sync::Mutex<EcdsaSoAInner>,
    serial_data: std::cell::UnsafeCell<EcdsaSoAInner>,
    next_slot: AtomicUsize,
}

// SAFETY: `serial_data` is only written when `serial_ibd=true` on a single thread.
#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
unsafe impl Sync for EcdsaSoAStorage {}

#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
struct EcdsaSoAInner {
    indices: Vec<usize>,
    msgs: Vec<[u8; 32]>,
    pubkeys: Vec<[u8; 33]>,
    sigs: Vec<[u8; 64]>,
}

#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
fn flush_chunk_env() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("BLVM_ECDSA_FLUSH_CHUNK")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
    })
}

#[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
impl EcdsaSignatureCollector {
    pub fn new_with_capacity(cap: usize) -> Self {
        Self::new_with_capacity_mode(cap, false)
    }

    /// `serial_ibd=true`: lock-free SoA writes (IBD validate worker owns collector).
    pub fn new_with_capacity_mode(cap: usize, serial_ibd: bool) -> Self {
        let soa = if cap == 0 {
            None
        } else {
            let mk = || EcdsaSoAInner {
                indices: vec![0; cap],
                msgs: vec![[0u8; 32]; cap],
                pubkeys: vec![[0u8; 33]; cap],
                sigs: vec![[0u8; 64]; cap],
            };
            // Serial IBD only touches `serial_data`; skip Mutex twin (~halve SoA RAM).
            let mutex_inner = if serial_ibd {
                EcdsaSoAInner {
                    indices: Vec::new(),
                    msgs: Vec::new(),
                    pubkeys: Vec::new(),
                    sigs: Vec::new(),
                }
            } else {
                mk()
            };
            Some(std::sync::Arc::new(EcdsaSoAStorage {
                inner: std::sync::Mutex::new(mutex_inner),
                serial_data: std::cell::UnsafeCell::new(mk()),
                next_slot: AtomicUsize::new(0),
            }))
        };
        Self {
            soa,
            next_idx: AtomicUsize::new(0),
            overflow: crossbeam_queue::SegQueue::new(),
            serial_ibd,
            inflight: std::sync::Mutex::new(Vec::new()),
            flushed_upto: AtomicUsize::new(0),
            multisig_pending: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        let soa_n = self
            .soa
            .as_ref()
            .map(|s| s.next_slot.load(Ordering::Relaxed))
            .unwrap_or(0);
        let flushed = self.flushed_upto.load(Ordering::Relaxed);
        let inflight_empty = self.inflight.lock().map(|g| g.is_empty()).unwrap_or(true);
        let pending_empty = self
            .multisig_pending
            .lock()
            .map(|g| g.is_empty())
            .unwrap_or(true);
        soa_n == flushed && inflight_empty && self.overflow.is_empty() && pending_empty
    }

    /// Allocate a unique global index for a CHECKMULTISIG trial row.
    pub fn alloc_multisig_trial_index(&self) -> usize {
        MULTISIG_TRIAL_INDEX_TAG | self.next_idx.fetch_add(1, Ordering::Relaxed)
    }

    pub fn push_multisig_pending(&self, pending: MultisigPending) {
        if let Ok(mut g) = self.multisig_pending.lock() {
            g.push(pending);
        }
    }

    /// After batch verify: Core match + NULLFAIL for each deferred CHECKMULTISIG.
    pub fn resolve_multisig_pending(
        &self,
        results: &std::collections::HashMap<usize, bool>,
    ) -> Result<()> {
        let pending = self
            .multisig_pending
            .lock()
            .map_err(|_| ConsensusError::BlockValidation("ECDSA multisig pending lock".into()))?;
        for p in pending.iter() {
            let n_pubs = p.n_pubs;
            if n_pubs == 0 {
                return Err(ConsensusError::BlockValidation(
                    "CHECKMULTISIG deferred: n_pubs=0".into(),
                ));
            }
            let n_nonempty = p.sig_empty.iter().filter(|e| !**e).count();
            if p.trial_indices.len() != n_nonempty.saturating_mul(n_pubs) {
                return Err(ConsensusError::BlockValidation(
                    "CHECKMULTISIG deferred: trial_indices length mismatch".into(),
                ));
            }
            // Match: for each pubkey in order, try current sig; on success advance sig.
            let mut sig_cursor = 0usize;
            let mut valid_sigs = 0u8;
            for i in 0..n_pubs {
                while sig_cursor < p.sig_empty.len() && p.sig_empty[sig_cursor] {
                    sig_cursor += 1;
                }
                if sig_cursor >= p.sig_empty.len() {
                    break;
                }
                let sh_ord = p.sig_empty[..sig_cursor].iter().filter(|e| !**e).count();
                let gidx = p.trial_indices[sh_ord * n_pubs + i];
                if results.get(&gidx).copied().unwrap_or(false) {
                    valid_sigs = valid_sigs.saturating_add(1);
                    sig_cursor += 1;
                }
            }
            // Core NULLFAIL (EvalCheckMultisig cleanup): only when the multisig fails
            // overall, require every signature in the sig region to be empty.
            let success = valid_sigs >= p.m;
            if p.nullfail && !success {
                for &empty in &p.sig_empty {
                    if !empty {
                        return Err(ConsensusError::BlockValidation(
                            "OP_CHECKMULTISIG: non-null signature must not fail under NULLFAIL"
                                .into(),
                        ));
                    }
                }
            }
            if !success {
                return Err(ConsensusError::BlockValidation(
                    "Invalid CHECKMULTISIG (deferred batch) in block".into(),
                ));
            }
        }
        Ok(())
    }

    /// Collect compact ECDSA triple at a deterministic global index.
    pub fn collect_with_index(
        &self,
        global_index: usize,
        msg: &[u8; 32],
        pubkey33: &[u8; 33],
        sig64: &[u8; 64],
    ) {
        if let Some(ref soa) = self.soa {
            let slot = soa.next_slot.fetch_add(1, Ordering::Relaxed);
            if self.serial_ibd {
                // SAFETY: serial_ibd collectors are single-writer (IBD validate thread).
                unsafe {
                    let inner = &mut *soa.serial_data.get();
                    if slot < inner.msgs.len() {
                        inner.indices[slot] = global_index;
                        inner.msgs[slot] = *msg;
                        inner.pubkeys[slot] = *pubkey33;
                        inner.sigs[slot] = *sig64;
                        self.maybe_flush_async();
                        return;
                    }
                }
            } else if let Ok(mut inner) = soa.inner.lock() {
                if slot < inner.msgs.len() {
                    inner.indices[slot] = global_index;
                    inner.msgs[slot] = *msg;
                    inner.pubkeys[slot] = *pubkey33;
                    inner.sigs[slot] = *sig64;
                    drop(inner);
                    self.maybe_flush_async();
                    return;
                }
            }
        }
        self.overflow.push((global_index, *msg, *pubkey33, *sig64));
        let _ = self.next_idx.fetch_add(1, Ordering::Relaxed);
    }

    fn maybe_flush_async(&self) {
        let chunk = flush_chunk_env();
        if chunk < 64 {
            return;
        }
        let Some(ref soa) = self.soa else {
            return;
        };
        let end = soa.next_slot.load(Ordering::Relaxed);
        let start = self.flushed_upto.load(Ordering::Relaxed);
        if end.saturating_sub(start) < chunk {
            return;
        }
        if self
            .flushed_upto
            .compare_exchange(start, start + chunk, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let end_chunk = start + chunk;
        let (indices, msgs, pks, sigs) = if self.serial_ibd {
            unsafe {
                let inner = &*soa.serial_data.get();
                let n = end_chunk.min(inner.msgs.len());
                if start >= n {
                    return;
                }
                (
                    inner.indices[start..n].to_vec(),
                    inner.msgs[start..n].to_vec(),
                    inner.pubkeys[start..n].to_vec(),
                    inner.sigs[start..n].to_vec(),
                )
            }
        } else if let Ok(inner) = soa.inner.lock() {
            let n = end_chunk.min(inner.msgs.len());
            if start >= n {
                return;
            }
            (
                inner.indices[start..n].to_vec(),
                inner.msgs[start..n].to_vec(),
                inner.pubkeys[start..n].to_vec(),
                inner.sigs[start..n].to_vec(),
            )
        } else {
            return;
        };

        let (rtx, rrx) = std::sync::mpsc::sync_channel(1);
        if let Some(gpu_rx) =
            blvm_secp256k1::gpu::enqueue_ecdsa_job(msgs.clone(), pks.clone(), sigs.clone())
        {
            std::thread::spawn(move || {
                let out = match gpu_rx.recv() {
                    Ok(Some(v)) => Ok(v),
                    Ok(None) | Err(_) => {
                        crate::secp256k1_backend::verify_ecdsa_batch(&sigs, &msgs, &pks)
                    }
                };
                let _ = rtx.send(out);
            });
            if let Ok(mut g) = self.inflight.lock() {
                g.push(InflightChunk { indices, rx: rrx });
            }
            return;
        }
        std::thread::spawn(move || {
            let out = crate::secp256k1_backend::verify_ecdsa_batch(&sigs, &msgs, &pks);
            let _ = rtx.send(out);
        });
        if let Ok(mut g) = self.inflight.lock() {
            g.push(InflightChunk { indices, rx: rrx });
        }
    }

    /// Drain unflushed + overflow SoA for wave submit (does not join inflight).
    pub fn take_owned_soa(&self) -> Option<OwnedEcdsaSoA> {
        let mut indices = Vec::new();
        let mut msgs = Vec::new();
        let mut pubkeys = Vec::new();
        let mut sigs = Vec::new();

        if let Some(ref soa) = self.soa {
            let count = soa.next_slot.load(Ordering::Relaxed);
            let start = self.flushed_upto.load(Ordering::Relaxed);
            if count > start {
                if self.serial_ibd {
                    unsafe {
                        let inner = &*soa.serial_data.get();
                        let n = count.min(inner.msgs.len());
                        if start < n {
                            indices.extend_from_slice(&inner.indices[start..n]);
                            msgs.extend_from_slice(&inner.msgs[start..n]);
                            pubkeys.extend_from_slice(&inner.pubkeys[start..n]);
                            sigs.extend_from_slice(&inner.sigs[start..n]);
                        }
                    }
                } else if let Ok(inner) = soa.inner.lock() {
                    let n = count.min(inner.msgs.len());
                    if start < n {
                        indices.extend_from_slice(&inner.indices[start..n]);
                        msgs.extend_from_slice(&inner.msgs[start..n]);
                        pubkeys.extend_from_slice(&inner.pubkeys[start..n]);
                        sigs.extend_from_slice(&inner.sigs[start..n]);
                    }
                }
            }
            soa.next_slot.store(0, Ordering::Relaxed);
            self.flushed_upto.store(0, Ordering::Relaxed);
        }

        let mut overflow: Vec<_> = std::iter::from_fn(|| self.overflow.pop()).collect();
        if !overflow.is_empty() {
            overflow.sort_by_key(|t| t.0);
            for (i, m, p, s) in overflow {
                indices.push(i);
                msgs.push(m);
                pubkeys.push(p);
                sigs.push(s);
            }
        }

        if msgs.is_empty() {
            None
        } else {
            Some(OwnedEcdsaSoA {
                indices,
                msgs,
                pubkeys,
                sigs,
            })
        }
    }

    /// Join mid-block inflight chunks into merged (index, bool) pairs.
    pub fn join_inflight(&self) -> Result<Vec<(usize, bool)>> {
        let mut merged = Vec::new();
        if let Ok(mut inflight) = self.inflight.lock() {
            for chunk in inflight.drain(..) {
                let results = chunk.rx.recv().map_err(|_| {
                    ConsensusError::BlockValidation("ECDSA async chunk recv failed".into())
                })??;
                if results.len() != chunk.indices.len() {
                    return Err(ConsensusError::BlockValidation(
                        "ECDSA async chunk result length mismatch".into(),
                    ));
                }
                merged.extend(chunk.indices.into_iter().zip(results));
            }
        }
        Ok(merged)
    }

    /// Verify all collected signatures; returns `(global_index, ok)` pairs.
    pub fn verify_batch_indexed(&self) -> Result<Vec<(usize, bool)>> {
        let t0 = std::time::Instant::now();
        let mut merged = self.join_inflight()?;

        if let Some(ref soa) = self.soa {
            let count = soa.next_slot.load(Ordering::Relaxed);
            let start = self.flushed_upto.load(Ordering::Relaxed);
            if count > start {
                if self.serial_ibd {
                    unsafe {
                        let inner = &*soa.serial_data.get();
                        let n = count.min(inner.msgs.len());
                        if start < n {
                            let results = crate::secp256k1_backend::verify_ecdsa_batch(
                                &inner.sigs[start..n],
                                &inner.msgs[start..n],
                                &inner.pubkeys[start..n],
                            )?;
                            merged
                                .extend((start..n).map(|i| (inner.indices[i], results[i - start])));
                        }
                    }
                } else {
                    let inner = soa.inner.lock().map_err(|_| {
                        ConsensusError::BlockValidation("ECDSA SoA lock poisoned".into())
                    })?;
                    let n = count.min(inner.msgs.len());
                    if start < n {
                        let results = crate::secp256k1_backend::verify_ecdsa_batch(
                            &inner.sigs[start..n],
                            &inner.msgs[start..n],
                            &inner.pubkeys[start..n],
                        )?;
                        merged.extend((start..n).map(|i| (inner.indices[i], results[i - start])));
                    }
                }
            }
        }

        let mut overflow: Vec<_> = std::iter::from_fn(|| self.overflow.pop()).collect();
        if !overflow.is_empty() {
            overflow.sort_by_key(|t| t.0);
            let indices: Vec<usize> = overflow.iter().map(|t| t.0).collect();
            let msgs: Vec<[u8; 32]> = overflow.iter().map(|t| t.1).collect();
            let pks: Vec<[u8; 33]> = overflow.iter().map(|t| t.2).collect();
            let sigs: Vec<[u8; 64]> = overflow.iter().map(|t| t.3).collect();
            let results = crate::secp256k1_backend::verify_ecdsa_batch(&sigs, &msgs, &pks)?;
            merged.extend(indices.into_iter().zip(results));
        }

        merged.sort_by_key(|(i, _)| *i);
        crate::ecdsa_timers::note_batch_ns(t0.elapsed().as_nanos() as u64);
        Ok(merged)
    }

    /// Verify SoA + resolve deferred CHECKMULTISIG; P2PKH rows must all succeed.
    pub fn verify_batch(&self) -> Result<Vec<bool>> {
        let merged = self.verify_batch_indexed()?;
        let map: std::collections::HashMap<usize, bool> = merged.iter().copied().collect();
        self.resolve_multisig_pending(&map)?;
        for &(idx, ok) in &merged {
            if !is_multisig_trial_index(idx) && !ok {
                return Err(ConsensusError::BlockValidation(
                    "Invalid ECDSA signature in block".into(),
                ));
            }
        }
        Ok(merged.into_iter().map(|(_, v)| v).collect())
    }
}

#[cfg(all(test, feature = "production", feature = "blvm-secp256k1"))]
mod multisig_resolve_tests {
    use super::*;
    use std::collections::HashMap;

    fn tag(i: usize) -> usize {
        MULTISIG_TRIAL_INDEX_TAG | i
    }

    #[test]
    fn off_curve_pubkey_trials_missing_are_false_not_hard_fail() {
        // 2-of-3: sig0 matches pub0; pub2 trials absent (off-curve → no SoA row).
        let c = EcdsaSignatureCollector::new_with_capacity(0);
        let trials = vec![tag(0), tag(1), tag(2), tag(3), tag(4), tag(5)];
        c.push_multisig_pending(MultisigPending {
            m: 2,
            n_pubs: 3,
            trial_indices: trials.clone(),
            sig_empty: vec![false, false],
            nullfail: false,
        });
        let mut map = HashMap::new();
        // Core match: pub0×sig0 ok, pub1×sig0 no, pub2×sig0 missing; advance;
        // pub1×sig1 ok (index 1*3+1=4).
        map.insert(tag(0), true);
        map.insert(tag(1), false);
        // tag(2) absent
        map.insert(tag(3), false);
        map.insert(tag(4), true);
        // tag(5) absent
        c.resolve_multisig_pending(&map)
            .expect("2-of-3 with off-curve pub");
    }

    #[test]
    fn nullfail_only_when_multisig_fails() {
        let c = EcdsaSignatureCollector::new_with_capacity(0);
        c.push_multisig_pending(MultisigPending {
            m: 1,
            n_pubs: 1,
            trial_indices: vec![tag(0)],
            sig_empty: vec![false],
            nullfail: true,
        });
        let mut map = HashMap::new();
        map.insert(tag(0), true);
        c.resolve_multisig_pending(&map)
            .expect("success must not NULLFAIL");

        let c2 = EcdsaSignatureCollector::new_with_capacity(0);
        c2.push_multisig_pending(MultisigPending {
            m: 1,
            n_pubs: 1,
            trial_indices: vec![tag(1)],
            sig_empty: vec![false],
            nullfail: true,
        });
        let map2 = HashMap::new(); // trial false
        assert!(c2.resolve_multisig_pending(&map2).is_err());
    }
}
