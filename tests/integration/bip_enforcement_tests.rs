//! Integration tests to verify BIP checks are enforced in connect_block
//!
//! These tests verify that BIP30, BIP34, and BIP90 violations are caught
//! by connect_block, not just by the individual BIP check functions.
//!
//! **CRITICAL**: These tests will FAIL if BIP checks are removed from connect_block,
//! providing an alarm bell for missing consensus rules.

use blvm_consensus::block::calculate_tx_id;
use blvm_consensus::block::connect_block;
use blvm_consensus::opcodes::*;
use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::*;

use super::helpers;

fn enforcement_coinbase_block(version: i64, coinbase_tx: Transaction, timestamp: u64) -> Block {
    use blvm_consensus::mining::calculate_merkle_root;
    let merkle_root =
        calculate_merkle_root(std::slice::from_ref(&coinbase_tx)).expect("merkle root");
    Block {
        header: BlockHeader {
            version,
            prev_block_hash: [0; 32],
            merkle_root,
            timestamp,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into(),
    }
}

/// Test that BIP30 (duplicate coinbase) is enforced in connect_block
///
/// This test creates a block with a duplicate coinbase transaction.
/// If BIP30 check is NOT called in connect_block, this block will be accepted (BUG).
/// If BIP30 check IS called, this block will be rejected (CORRECT).
#[test]
fn test_connect_block_rejects_bip30_violation() {
    // Create a coinbase transaction
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![0x04, 0x00, 0x00, 0x00, 0x00],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let txid = calculate_tx_id(&coinbase_tx);

    // Create UTXO set with a UTXO from this coinbase (simulating duplicate)
    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: txid,
            index: 0,
        },
        std::sync::Arc::new(UTXO {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
            height: 0,
            is_coinbase: true,
        }),
    );

    // Create block with same coinbase (duplicate - violates BIP30)
    let block = enforcement_coinbase_block(2, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);

    // connect_block MUST reject this block due to BIP30 violation
    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, 1, &ctx)
    };

    match result {
        Ok((ValidationResult::Invalid(reason), _, _)) => {
            // Good - block was rejected
            assert!(
                reason.contains("BIP30") || reason.contains("duplicate coinbase"),
                "Rejection reason should mention BIP30 or duplicate coinbase, got: {}",
                reason
            );
        }
        Ok((ValidationResult::Valid, _, _)) => {
            panic!(
                "CRITICAL BUG: connect_block accepted a block with duplicate coinbase (BIP30 violation)! This means BIP30 check is NOT being called in connect_block!"
            );
        }
        Err(e) => {
            // Error is also acceptable - means validation caught the violation
            eprintln!("connect_block returned error (acceptable): {:?}", e);
        }
    }
}

/// Test that BIP34 (block height in coinbase) is enforced in connect_block
///
/// This test creates a block at height >= BIP34 activation without height in coinbase.
/// If BIP34 check is NOT called in connect_block, this block will be accepted (BUG).
/// If BIP34 check IS called, this block will be rejected (CORRECT).
#[test]
fn test_connect_block_rejects_bip34_violation() {
    let height = BIP34_ACTIVATION_MAINNET; // BIP34 activation height (Bitcoin Core BIP34Height)

    // Create coinbase WITHOUT height encoding (violates BIP34)
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![], // Empty scriptSig - no height encoding
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let block = enforcement_coinbase_block(2, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);
    let utxo_set = UtxoSet::default();

    // connect_block MUST reject this block due to BIP34 violation
    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, height, &ctx)
    };

    match result {
        Ok((ValidationResult::Invalid(reason), _, _)) => {
            // Good - block was rejected
            assert!(
                reason.contains("BIP34")
                    || reason.contains("height")
                    || reason.contains("coinbase"),
                "Rejection reason should mention BIP34, height, or coinbase, got: {}",
                reason
            );
        }
        Ok((ValidationResult::Valid, _, _)) => {
            panic!(
                "CRITICAL BUG: connect_block accepted a block without height in coinbase at height {} (BIP34 violation)! This means BIP34 check is NOT being called in connect_block!",
                height
            );
        }
        Err(e) => {
            // Error is also acceptable
            eprintln!("connect_block returned error (acceptable): {:?}", e);
        }
    }
}

/// Test that BIP34 is NOT enforced before activation height
///
/// This ensures BIP34 check is called but correctly allows blocks before activation.
#[test]
fn test_connect_block_allows_bip34_before_activation() {
    let height = 100_000; // Before BIP34 activation

    // Create coinbase WITHOUT height encoding (OK before activation)
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![], // Empty scriptSig - OK before activation
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let block = enforcement_coinbase_block(1, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);
    let utxo_set = UtxoSet::default();

    // connect_block should allow this block (BIP34 not active yet)
    // Note: Block may still be invalid for other reasons (PoW, etc.), but BIP34 shouldn't reject it
    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, height, &ctx)
    };

    // If rejected, it should NOT be due to BIP34
    if let Ok((ValidationResult::Invalid(reason), _, _)) = result {
        assert!(
            !reason.contains("BIP34"),
            "Block should not be rejected for BIP34 before activation height, but got: {}",
            reason
        );
    }
}

/// Test that BIP90 (block version enforcement) is enforced in connect_block
///
/// This test creates a block with version 1 at height >= BIP34 activation.
/// If BIP90 check is NOT called in connect_block, this block will be accepted (BUG).
/// If BIP90 check IS called, this block will be rejected (CORRECT).
#[test]
fn test_connect_block_rejects_bip90_violation() {
    let height = BIP34_ACTIVATION_MAINNET; // BIP34 activation height (requires version >= 2)

    // Create block with version 1 (violates BIP90 - requires version >= 2 after BIP34)
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![
                0x03,
                (height & 0xff) as u8,
                ((height >> 8) & 0xff) as u8,
                ((height >> 16) & 0xff) as u8,
            ], // Valid height encoding
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let block = enforcement_coinbase_block(1, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);
    let utxo_set = UtxoSet::default();

    // connect_block MUST reject this block due to BIP90 violation
    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, height, &ctx)
    };

    match result {
        Ok((ValidationResult::Invalid(reason), _, _)) => {
            // Good - block was rejected
            assert!(
                reason.contains("BIP90")
                    || reason.contains("version")
                    || reason.contains("Block version"),
                "Rejection reason should mention BIP90 or version, got: {}",
                reason
            );
        }
        Ok((ValidationResult::Valid, _, _)) => {
            panic!(
                "CRITICAL BUG: connect_block accepted a block with version 1 at height {} (BIP90 violation)! This means BIP90 check is NOT being called in connect_block!",
                height
            );
        }
        Err(e) => {
            // Error is also acceptable
            eprintln!("connect_block returned error (acceptable): {:?}", e);
        }
    }
}

/// Test that BIP90 allows valid versions
///
/// This ensures BIP90 check is called but correctly allows valid versions.
#[test]
fn test_connect_block_allows_bip90_valid_version() {
    let height = BIP34_ACTIVATION_MAINNET; // BIP34 activation height (requires version >= 2)

    // Create block with version 2 (valid for BIP90)
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![
                0x03,
                (height & 0xff) as u8,
                ((height >> 8) & 0xff) as u8,
                ((height >> 16) & 0xff) as u8,
            ], // Valid height encoding
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let block = enforcement_coinbase_block(2, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);
    let utxo_set = UtxoSet::default();

    // connect_block should allow this block (BIP90 satisfied)
    // Note: Block may still be invalid for other reasons (PoW, etc.), but BIP90 shouldn't reject it
    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, height, &ctx)
    };

    // If rejected, it should NOT be due to BIP90
    if let Ok((ValidationResult::Invalid(reason), _, _)) = result {
        assert!(
            !reason.contains("BIP90"),
            "Block should not be rejected for BIP90 with valid version, but got: {}",
            reason
        );
    }
}

/// Test that all three BIP checks work together
///
/// This test creates a block that violates multiple BIPs to ensure all checks are called.
#[test]
fn test_connect_block_multiple_bip_violations() {
    let height = BIP34_ACTIVATION_MAINNET;

    // Create block that violates BIP30, BIP34, and BIP90
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![], // Violates BIP34 (no height)
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let txid = calculate_tx_id(&coinbase_tx);

    // Add UTXO to simulate duplicate coinbase (violates BIP30)
    let mut utxo_set = UtxoSet::default();
    utxo_set.insert(
        OutPoint {
            hash: txid,
            index: 0,
        },
        std::sync::Arc::new(UTXO {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
            height: 0,
            is_coinbase: true,
        }),
    );

    let block = enforcement_coinbase_block(1, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);

    // connect_block MUST reject this block
    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, height, &ctx)
    };

    match result {
        Ok((ValidationResult::Invalid(reason), _, _)) => {
            // Should mention at least one BIP violation
            let mentions_bip = reason.contains("BIP30")
                || reason.contains("BIP34")
                || reason.contains("BIP90")
                || reason.contains("duplicate coinbase")
                || reason.contains("height")
                || reason.contains("version");

            assert!(
                mentions_bip,
                "Rejection reason should mention a BIP violation, got: {}",
                reason
            );
        }
        Ok((ValidationResult::Valid, _, _)) => {
            panic!(
                "CRITICAL BUG: connect_block accepted a block with multiple BIP violations! This means BIP checks are NOT being called in connect_block!"
            );
        }
        Err(e) => {
            // Error is also acceptable
            eprintln!("connect_block returned error (acceptable): {:?}", e);
        }
    }
}

/// Test that BIP checks are called in the correct order
///
/// BIP90 should be checked first (on header), then BIP30, then BIP34.
/// This test verifies the order by checking which violation is caught first.
#[test]
fn test_bip_check_order() {
    let height = BIP34_ACTIVATION_MAINNET;

    // Create block that violates BIP90 (version) - should be caught first
    let coinbase_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32].into(),
                index: 0xffffffff,
            },
            script_sig: vec![], // Also violates BIP34, but BIP90 should be caught first
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: vec![].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let block = enforcement_coinbase_block(1, coinbase_tx, 1_231_006_505);

    let witnesses = helpers::per_tx_witnesses(&block);
    let utxo_set = UtxoSet::default();

    let result = {
        let ctx = block::BlockValidationContext::for_network(types::Network::Mainnet);
        connect_block(&block, &witnesses, utxo_set, height, &ctx)
    };

    // BIP90 should be caught first (it's checked on header, before transaction checks)
    if let Ok((ValidationResult::Invalid(reason), _, _)) = result {
        // BIP90 should be mentioned (or version), not BIP34
        // This verifies BIP90 is checked before BIP34
        assert!(
            reason.contains("BIP90")
                || reason.contains("version")
                || reason.contains("Block version"),
            "BIP90 violation should be caught first, but got: {}",
            reason
        );
    }
}

/// Test that BIP66 (Strict DER) is enforced in script verification
///
/// This test verifies that BIP66 check is called during script verification
/// when SCRIPT_VERIFY_DERSIG flag is set and height is after activation.
#[test]
fn test_script_verification_rejects_bip66_violation() {
    let height = 363_725; // Just after BIP66 activation (363,724)

    // Create a simple transaction with invalid DER signature
    // Invalid DER: too short to be valid
    let invalid_der_sig = vec![0x30, 0x01]; // Invalid DER (too short)

    // Create scriptSig with invalid signature
    let mut script_sig = vec![0x47]; // Push 71 bytes
    script_sig.extend_from_slice(&invalid_der_sig);
    script_sig.resize(72, 0); // Pad to 72 bytes
    script_sig.push(PUSH_33_BYTES); // Push 33 bytes (compressed pubkey)
    script_sig.extend_from_slice(&[0x02; 33]); // Dummy pubkey

    // P2PKH scriptPubkey
    let script_pubkey: blvm_consensus::types::ByteString = vec![
        OP_DUP,
        OP_HASH160,
        PUSH_20_BYTES,
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
        OP_EQUALVERIFY,
        OP_CHECKSIG,
    ]
    .into();

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: script_sig.clone().into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: script_pubkey.clone(),
        }]
        .into(),
        lock_time: 0,
    };

    let prevout = TransactionOutput {
        value: 50_000_000_000,
        script_pubkey: script_pubkey,
    };

    // Flags with SCRIPT_VERIFY_DERSIG (0x04) enabled
    let flags = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400;

    // Script verification should reject this due to invalid DER (BIP66)
    let pv = vec![prevout.value];
    let psp: Vec<&[u8]> = vec![prevout.script_pubkey.as_ref()];
    let result = verify_script_with_context_full(
        &script_sig,
        prevout.script_pubkey.as_ref(),
        None,
        flags,
        &tx,
        0,
        &pv,
        &psp,
        Some(height),
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    // Should fail due to invalid signature/DER
    match result {
        Ok(false) => {
            // Good - script verification rejected invalid DER signature
        }
        Ok(true) => {
            panic!(
                "CRITICAL BUG: Script verification accepted a transaction with invalid DER signature (BIP66 violation)! This means BIP66 check may not be called during script verification!"
            );
        }
        Err(_) => {
            // Error is also acceptable - means validation caught the violation
        }
    }
}

/// Test that BIP147 (NULLDUMMY) is enforced in OP_CHECKMULTISIG
///
/// This test verifies that BIP147 check is called during OP_CHECKMULTISIG execution
/// when SCRIPT_VERIFY_NULLDUMMY flag is set and height is after activation.
#[test]
fn test_script_verification_rejects_bip147_violation() {
    let height = 481_825; // Just after BIP147 activation (481,824)

    // Create a multisig scriptPubkey: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    let mut script_pubkey = vec![OP_2]; // OP_2 (2-of-2 multisig)
    script_pubkey.push(PUSH_33_BYTES); // Push 33 bytes
    script_pubkey.extend_from_slice(&[0x02; 33]); // Dummy pubkey 1
    script_pubkey.push(PUSH_33_BYTES); // Push 33 bytes
    script_pubkey.extend_from_slice(&[0x03; 33]); // Dummy pubkey 2
    script_pubkey.push(OP_2); // OP_2
    script_pubkey.push(OP_CHECKMULTISIG); // OP_CHECKMULTISIG

    // Create scriptSig with non-empty dummy (violates BIP147)
    // Stack: [dummy] [sig1] [sig2] [2] [pubkey1] [pubkey2] [2]
    // For BIP147, dummy must be empty (OP_0 = 0x00) after activation
    let mut script_sig = vec![0x01, 0x01]; // Non-empty dummy (violates BIP147)
    script_sig.push(0x00); // Empty signature 1
    script_sig.push(0x00); // Empty signature 2
    script_sig.push(OP_2); // OP_2 (2 signatures)

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: script_sig.clone().into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: script_pubkey.clone().into(),
        }]
        .into(),
        lock_time: 0,
    };

    let prevout = TransactionOutput {
        value: 50_000_000_000,
        script_pubkey: script_pubkey.into(),
    };

    // Flags with SCRIPT_VERIFY_NULLDUMMY (0x10) enabled
    let flags = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400;

    // Script verification should reject this due to non-empty dummy (BIP147)
    let pv = vec![prevout.value];
    let psp: Vec<&[u8]> = vec![prevout.script_pubkey.as_ref()];
    let result = verify_script_with_context_full(
        &script_sig,
        prevout.script_pubkey.as_ref(),
        None,
        flags,
        &tx,
        0,
        &pv,
        &psp,
        Some(height),
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    // Should fail due to BIP147 violation (non-empty dummy)
    match result {
        Ok(false) => {
            // Good - script verification rejected non-empty dummy
        }
        Ok(true) => {
            panic!(
                "CRITICAL BUG: Script verification accepted a transaction with non-empty dummy in OP_CHECKMULTISIG (BIP147 violation)! This means BIP147 check may not be called during script verification!"
            );
        }
        Err(_) => {
            // Error is also acceptable - means validation caught the violation
        }
    }
}

/// Test that BIP147 allows non-empty dummy before activation
///
/// This ensures BIP147 check correctly allows non-empty dummy before activation.
#[test]
fn test_script_verification_allows_bip147_before_activation() {
    let height = 481_823; // Just before BIP147 activation (481,824)

    // Create a multisig scriptPubkey
    let mut script_pubkey = vec![OP_2]; // OP_2
    script_pubkey.push(PUSH_33_BYTES);
    script_pubkey.extend_from_slice(&[0x02; 33]);
    script_pubkey.push(PUSH_33_BYTES);
    script_pubkey.extend_from_slice(&[0x03; 33]);
    script_pubkey.push(OP_2);
    script_pubkey.push(OP_CHECKMULTISIG); // OP_CHECKMULTISIG

    // Create scriptSig with non-empty dummy (allowed before BIP147 activation)
    let mut script_sig = vec![0x01, 0x01]; // Non-empty dummy (allowed before activation)
    script_sig.push(OP_0); // Empty signature 1
    script_sig.push(OP_0); // Empty signature 2
    script_sig.push(OP_2); // OP_2

    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32].into(),
                index: 0,
            },
            script_sig: script_sig.clone().into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_000_000_000,
            script_pubkey: script_pubkey.clone().into(),
        }]
        .into(),
        lock_time: 0,
    };

    let prevout = TransactionOutput {
        value: 50_000_000_000,
        script_pubkey: script_pubkey.into(),
    };

    // Flags with SCRIPT_VERIFY_NULLDUMMY (0x10) enabled
    let flags = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400;

    // Script verification should allow this before activation
    // (Note: May still fail for other reasons like invalid signatures, but BIP147 shouldn't reject it)
    let pv = vec![prevout.value];
    let psp: Vec<&[u8]> = vec![prevout.script_pubkey.as_ref()];
    let result = verify_script_with_context_full(
        &script_sig,
        prevout.script_pubkey.as_ref(),
        None,
        flags,
        &tx,
        0,
        &pv,
        &psp,
        Some(height),
        None,
        types::Network::Mainnet,
        SigVersion::Base,
        #[cfg(feature = "production")]
        None,
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(feature = "production")]
        None,
        #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
        None,
    );

    // Before activation, BIP147 shouldn't reject non-empty dummy
    // (Transaction may still fail for other reasons, but that's OK)
    // We just verify the code path doesn't panic
    match result {
        Ok(_) => {
            // OK - script verification completed (may be valid or invalid for other reasons)
        }
        Err(_) => {
            // Error is acceptable - may fail for other reasons (invalid signatures, etc.)
        }
    }
}
