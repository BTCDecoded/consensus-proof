//! Secp256k1 backend abstraction.
//!
//! Supports both **libsecp256k1** (secp256k1 crate, crates.io) and **blvm-secp256k1** (pure Rust).
//! Uses blvm-secp256k1 batch verification when the `blvm-secp256k1` feature is enabled (default
//! with production). When not enabled, falls back to libsecp256k1 with per-signature verification.
//! API surface is identical across backends.

#[cfg(feature = "secp256k1-fallback")]
#[cfg_attr(feature = "blvm-secp256k1", allow(dead_code))]
mod secp256k1_impl;

#[cfg(feature = "blvm-secp256k1")]
mod blvm_impl;

use crate::error::Result;
use crate::types::Hash;

/// ECDSA verify: returns true if signature is valid for (msg_hash, pubkey).
pub fn verify_ecdsa(
    msg_hash: &[u8; 32],
    sig_compact: &[u8; 64],
    pubkey_compressed: &[u8; 33],
) -> Result<bool> {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_impl::verify_ecdsa(msg_hash, sig_compact, pubkey_compressed);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::verify_ecdsa(msg_hash, sig_compact, pubkey_compressed);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    Err(crate::error::ConsensusError::BlockValidation(
        "no crypto backend enabled".into(),
    ))
}

/// Schnorr verify: returns true if BIP 340 signature is valid.
pub fn verify_schnorr(sig: &[u8; 64], msg: &[u8], pubkey: &[u8; 32]) -> Result<bool> {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_impl::verify_schnorr(sig, msg, pubkey);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::verify_schnorr(sig, msg, pubkey);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    Err(crate::error::ConsensusError::BlockValidation(
        "no crypto backend enabled".into(),
    ))
}

/// Schnorr batch verify: returns `Vec<bool>` with one result per signature.
/// Uses blvm-secp256k1 batch API when available; otherwise per-sig loop via libsecp256k1.
pub fn verify_schnorr_batch(
    sigs: &[[u8; 64]],
    msgs: &[&[u8]],
    pubkeys: &[[u8; 32]],
) -> Result<Vec<bool>> {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_impl::verify_schnorr_batch(sigs, msgs, pubkeys);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::verify_schnorr_batch(sigs, msgs, pubkeys);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    Err(crate::error::ConsensusError::BlockValidation(
        "no crypto backend enabled".into(),
    ))
}

/// ECDSA batch verify: returns `Vec<bool>` with one result per signature.
/// Compact 64-byte sigs, 32-byte msgs, 33-byte compressed pubkeys.
/// With `blvm-secp256k1` + optional `gpu` feature, large batches may use ufsecp CUDA.
pub fn verify_ecdsa_batch(
    sigs: &[[u8; 64]],
    msgs: &[[u8; 32]],
    pubkeys: &[[u8; 33]],
) -> Result<Vec<bool>> {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_impl::verify_ecdsa_batch(sigs, msgs, pubkeys);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    {
        let n = sigs.len().min(msgs.len()).min(pubkeys.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(secp256k1_impl::verify_ecdsa(&msgs[i], &sigs[i], &pubkeys[i])?);
        }
        return Ok(out);
    }

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    Err(crate::error::ConsensusError::BlockValidation(
        "no crypto backend enabled".into(),
    ))
}

/// Direct ECDSA verify from DER sig bytes + pubkey bytes + msg hash.
/// Uses blvm-secp256k1 directly (no libsecp256k1 FFI).
/// Returns Some(true/false) or None on parse error.
#[cfg(feature = "blvm-secp256k1")]
#[inline]
pub fn verify_ecdsa_direct(
    der_sig: &[u8],
    pubkey_bytes: &[u8],
    msg_hash: &[u8; 32],
    strict_der: bool,
    enforce_low_s: bool,
) -> Option<bool> {
    blvm_secp256k1::ecdsa::verify_ecdsa_direct(
        der_sig,
        pubkey_bytes,
        msg_hash,
        strict_der,
        enforce_low_s,
    )
}

/// Taproot output key from internal key and merkle root (BIP 341).
pub fn taproot_output_key(internal_pubkey: &[u8; 32], merkle_root: &Hash) -> Result<[u8; 32]> {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_impl::taproot_output_key(internal_pubkey, merkle_root);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::taproot_output_key(internal_pubkey, merkle_root);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    Err(crate::error::ConsensusError::BlockValidation(
        "no crypto backend enabled".into(),
    ))
}

/// Taproot output key with parity from internal key and merkle root (BIP 341).
/// Returns (output_xonly_key, parity) where parity is 0 for even y, 1 for odd y.
pub fn taproot_output_key_with_parity(
    internal_pubkey: &[u8; 32],
    merkle_root: &Hash,
) -> Result<([u8; 32], u8)> {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_impl::taproot_output_key_with_parity(internal_pubkey, merkle_root);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::taproot_output_key_with_parity(internal_pubkey, merkle_root);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    Err(crate::error::ConsensusError::BlockValidation(
        "no crypto backend enabled".into(),
    ))
}

/// BIP 341 TapLeaf hash: tag "TapLeaf", data = leaf_version || compact_size(script_len) || script.
pub fn tap_leaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_secp256k1::taproot::tap_leaf_hash(leaf_version, script);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::tap_leaf_hash(leaf_version, script);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    [0u8; 32]
}

/// BIP 341 TapBranch hash: tag "TapBranch", data = left || right (caller must sort lexicographically).
pub fn tap_branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_secp256k1::taproot::tap_branch_hash(left, right);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::tap_branch_hash(left, right);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    [0u8; 32]
}

/// BIP 341 TapSighash: tag "TapSighash", hashes 0x00 || SigMsg for Taproot verification.
pub fn tap_sighash_hash(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "blvm-secp256k1")]
    return blvm_secp256k1::taproot::tap_sighash_hash(data);

    #[cfg(all(feature = "secp256k1-fallback", not(feature = "blvm-secp256k1")))]
    return secp256k1_impl::tap_sighash_hash(data);

    #[cfg(not(any(feature = "blvm-secp256k1", feature = "secp256k1-fallback")))]
    [0u8; 32]
}
