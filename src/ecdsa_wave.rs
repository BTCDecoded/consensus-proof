//! Cross-block ECDSA wave hub (opt-in `BLVM_ECDSA_WAVE=1`).
//!
//! Collectors park owned SoA after structure+collect; orch submits to this hub.
//! The hub can merge pending jobs briefly before GPU/CPU verify, then completes
//! per-job oneshots. Validation workers may take another collect job while a
//! prior wave verify runs (two-phase).

#![cfg(all(feature = "production", feature = "blvm-secp256k1"))]

use crate::ecdsa_batch::OwnedEcdsaSoA;
use crate::error::{ConsensusError, Result};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

fn wave_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        matches!(
            std::env::var("BLVM_ECDSA_WAVE")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

fn wave_max_sigs() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("BLVM_ECDSA_WAVE_MAX_SIGS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8192)
            .max(64)
    })
}

fn wave_wait_ms() -> u64 {
    static N: OnceLock<u64> = OnceLock::new();
    *N.get_or_init(|| {
        // Default 0: flush each job immediately (coalesce wait caused VALRES HOL hangs
        // when orch depth=1 and worker blocked on next job while wave coalesced).
        std::env::var("BLVM_ECDSA_WAVE_WAIT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    })
}

thread_local! {
    static PARKED: std::cell::RefCell<Option<OwnedEcdsaSoA>> = const { std::cell::RefCell::new(None) };
}

/// Park SoA on this thread for orch pickup (connect defer path).
pub fn park_pending(soa: OwnedEcdsaSoA) {
    PARKED.with(|c| {
        *c.borrow_mut() = Some(soa);
    });
}

/// Take parked SoA after connect returns (validation worker).
pub fn take_parked() -> Option<OwnedEcdsaSoA> {
    PARKED.with(|c| c.borrow_mut().take())
}

pub fn is_enabled() -> bool {
    wave_enabled()
}

struct WaveJob {
    height: u64,
    soa: OwnedEcdsaSoA,
    reply: mpsc::SyncSender<Result<()>>,
}

struct WaveHub {
    tx: mpsc::Sender<WaveJob>,
}

fn hub() -> &'static WaveHub {
    static HUB: OnceLock<WaveHub> = OnceLock::new();
    HUB.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<WaveJob>();
        std::thread::Builder::new()
            .name("blvm-ecdsa-wave".into())
            .spawn(move || wave_loop(rx))
            .expect("spawn ecdsa wave thread");
        eprintln!(
            "[BLVM_ECDSA_WAVE] hub started max_sigs={} wait_ms={}",
            wave_max_sigs(),
            wave_wait_ms()
        );
        WaveHub { tx }
    })
}

fn wave_loop(rx: mpsc::Receiver<WaveJob>) {
    let mut batch: Vec<WaveJob> = Vec::new();
    let mut batch_sigs = 0usize;
    let mut deadline: Option<Instant> = None;

    loop {
        let job = if batch.is_empty() {
            match rx.recv() {
                Ok(j) => j,
                Err(_) => break,
            }
        } else {
            let wait = deadline
                .map(|d| d.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_millis(wave_wait_ms()));
            match rx.recv_timeout(wait) {
                Ok(j) => j,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    flush_batch(&mut batch, &mut batch_sigs, &mut deadline);
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    flush_batch(&mut batch, &mut batch_sigs, &mut deadline);
                    break;
                }
            }
        };

        batch_sigs += job.soa.sigs.len();
        let wait = wave_wait_ms();
        if wait == 0 {
            batch.push(job);
            flush_batch(&mut batch, &mut batch_sigs, &mut deadline);
            continue;
        }
        if deadline.is_none() {
            deadline = Some(Instant::now() + Duration::from_millis(wait));
        }
        batch.push(job);
        if batch_sigs >= wave_max_sigs() {
            flush_batch(&mut batch, &mut batch_sigs, &mut deadline);
        }
    }
}

fn flush_batch(batch: &mut Vec<WaveJob>, batch_sigs: &mut usize, deadline: &mut Option<Instant>) {
    if batch.is_empty() {
        *deadline = None;
        return;
    }
    let jobs = std::mem::take(batch);
    *batch_sigs = 0;
    *deadline = None;

    let mut all_msgs = Vec::new();
    let mut all_pks = Vec::new();
    let mut all_sigs = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for job in &jobs {
        let start = all_sigs.len();
        let n = job.soa.sigs.len();
        all_msgs.extend_from_slice(&job.soa.msgs);
        all_pks.extend_from_slice(&job.soa.pubkeys);
        all_sigs.extend_from_slice(&job.soa.sigs);
        spans.push((start, n));
    }

    let mega = crate::secp256k1_backend::verify_ecdsa_batch(&all_sigs, &all_msgs, &all_pks);
    match mega {
        Ok(results) => {
            for (job, (start, n)) in jobs.into_iter().zip(spans) {
                let slice = &results[start..start + n];
                let ok = slice.iter().all(|&v| v);
                let reply = if ok {
                    Ok(())
                } else {
                    Err(ConsensusError::BlockValidation(
                        format!(
                            "Invalid ECDSA signature in wave height={}",
                            job.height
                        )
                        .into(),
                    ))
                };
                let _ = job.reply.send(reply);
            }
        }
        Err(e) => {
            for job in jobs {
                let _ = job.reply.send(Err(ConsensusError::BlockValidation(
                    format!(
                        "ECDSA wave verify failed height={}: {e:?}",
                        job.height
                    )
                    .into(),
                )));
            }
        }
    }
}

/// Submit owned SoA for wave verify. Returns a receiver completed when sigs are checked.
pub fn submit(height: u64, soa: OwnedEcdsaSoA) -> mpsc::Receiver<Result<()>> {
    let (rtx, rrx) = mpsc::sync_channel(1);
    if soa.sigs.is_empty() {
        let _ = rtx.send(Ok(()));
        return rrx;
    }
    if !wave_enabled() {
        let n = soa.sigs.len();
        let out = crate::secp256k1_backend::verify_ecdsa_batch(&soa.sigs, &soa.msgs, &soa.pubkeys);
        let reply = match out {
            Ok(v) if v.len() == n && v.iter().all(|&x| x) => Ok(()),
            Ok(_) => Err(ConsensusError::BlockValidation(
                "Invalid ECDSA signature in block".into(),
            )),
            Err(e) => Err(e),
        };
        let _ = rtx.send(reply);
        return rrx;
    }
    let _ = hub().tx.send(WaveJob {
        height,
        soa,
        reply: rtx,
    });
    rrx
}
