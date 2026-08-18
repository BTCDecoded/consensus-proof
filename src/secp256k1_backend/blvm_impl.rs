//! blvm-secp256k1 backend implementation.

use crate::error::{ConsensusError, Result};
use crate::types::Hash;
use blvm_secp256k1::ecdsa::{
    ecdsa_sig_parse_compact, ecdsa_sig_verify, ecdsa_verify_batch_results, ge_from_compressed,
};
use blvm_secp256k1::scalar::Scalar;
use blvm_secp256k1::schnorr::{schnorr_verify, schnorr_verify_batch_results};
use blvm_secp256k1::taproot::taproot_output_key as blvm_taproot_output_key;

pub fn verify_ecdsa(
    msg_hash: &[u8; 32],
    sig_compact: &[u8; 64],
    pubkey_compressed: &[u8; 33],
) -> Result<bool> {
    let (sigr, sigs) = match ecdsa_sig_parse_compact(sig_compact) {
        Some(s) => s,
        None => return Ok(false),
    };
    let pk = match ge_from_compressed(pubkey_compressed) {
        Some(p) => p,
        None => return Ok(false),
    };
    let mut msg = Scalar::zero();
    msg.set_b32(msg_hash);
    Ok(ecdsa_sig_verify(&sigr, &sigs, &pk, &msg))
}

pub fn verify_schnorr(sig: &[u8; 64], msg: &[u8], pubkey: &[u8; 32]) -> Result<bool> {
    Ok(schnorr_verify(sig, msg, pubkey))
}

pub fn verify_schnorr_batch(
    sigs: &[[u8; 64]],
    msgs: &[&[u8]],
    pubkeys: &[[u8; 32]],
) -> Result<Vec<bool>> {
    Ok(schnorr_verify_batch_results(sigs, msgs, pubkeys))
}

/// ECDSA batch verify: one result per signature (GPU when `blvm-secp256k1/gpu` is on).
pub fn verify_ecdsa_batch(
    sigs: &[[u8; 64]],
    msgs: &[[u8; 32]],
    pubkeys: &[[u8; 33]],
) -> Result<Vec<bool>> {
    Ok(ecdsa_verify_batch_results(sigs, msgs, pubkeys))
}

pub fn taproot_output_key(internal_pubkey: &[u8; 32], merkle_root: &Hash) -> Result<[u8; 32]> {
    blvm_taproot_output_key(internal_pubkey, merkle_root)
        .ok_or_else(|| ConsensusError::InvalidSignature("Invalid internal public key".into()))
}

pub fn taproot_output_key_with_parity(
    internal_pubkey: &[u8; 32],
    merkle_root: &Hash,
) -> Result<([u8; 32], u8)> {
    use blvm_secp256k1::taproot::{tap_tweak_hash, xonly_pubkey_tweak_add};
    let tweak = tap_tweak_hash(internal_pubkey, merkle_root);
    xonly_pubkey_tweak_add(internal_pubkey, &tweak)
        .ok_or_else(|| ConsensusError::InvalidSignature("Invalid taproot tweak".into()))
}
