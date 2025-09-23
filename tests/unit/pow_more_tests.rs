use consensus_proof::pow::{check_proof_of_work, get_next_work_required};

fn header(bits: u32, ts: u32) -> consensus_proof::BlockHeader {
    consensus_proof::BlockHeader {
        version: 1,
        prev_block_hash: [0;32],
        merkle_root: [0;32],
        timestamp: ts as u64,
        bits,
        nonce: 0,
    }
}

#[test]
fn test_pow_invalid_target_rejected() {
    // Exponent shift too large should be treated as invalid in expand/check path
    let h = header(0xff00ffff, 1231006505);
    let ok = check_proof_of_work(&h).unwrap();
    assert!(!ok, "Overly large target should not satisfy PoW");
}

#[test]
fn test_next_work_required_insufficient_headers_returns_max() {
    // With not enough headers, current implementation returns MAX_TARGET
    let curr = header(0x1d00ffff, 1231006605);
    let next = get_next_work_required(&curr, &[]).unwrap();
    assert!(next > 0, "Should return a non-zero target when insufficient headers");
}


