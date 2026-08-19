#![no_main]
use blvm_consensus::script::verify_script_with_context_full;
use blvm_consensus::types::{Hash, Network, TimeContext};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Signature verification fuzzing
    // Tests ECDSA signature parsing, DER encoding validation, and signature verification

    if data.len() < 10 {
        return;
    }

    // Need: pubkey (33 or 65 bytes) + signature (variable DER) + sighash (32 bytes)
    // Minimum: 33 + 8 + 32 = 73 bytes for compressed pubkey
    // Minimum: 65 + 8 + 32 = 105 bytes for uncompressed pubkey

    // Parse pubkey format (first byte indicates format)
    let pubkey_format = data[0];
    let pubkey_start = 1;
    let pubkey_len = if pubkey_format & 0x01 != 0 {
        65 // Uncompressed
    } else {
        33 // Compressed
    };

    if data.len() < pubkey_start + pubkey_len {
        return;
    }

    let pubkey_bytes = &data[pubkey_start..pubkey_start + pubkey_len];

    // Find signature (DER encoded, variable length)
    let sig_start = pubkey_start + pubkey_len;
    if data.len() < sig_start + 8 {
        return;
    }

    // Try to parse DER signature length
    let sig_first_byte = data[sig_start];
    let (sig_len, sig_data_start) = if sig_first_byte == 0x30 {
        // DER sequence tag
        if data.len() < sig_start + 2 {
            return;
        }
        let length_byte = data[sig_start + 1];
        if length_byte & 0x80 == 0 {
            // Short form
            let len = length_byte as usize;
            if data.len() < sig_start + 2 + len {
                return;
            }
            (len, sig_start + 2)
        } else {
            // Long form (skip for simplicity, use fixed size)
            let len = 72.min(data.len() - sig_start - 2);
            (len, sig_start + 2)
        }
    } else {
        // Not DER format, use fixed size
        let len = 72.min(data.len() - sig_start);
        (len, sig_start)
    };

    if data.len() < sig_data_start + sig_len {
        return;
    }

    let signature_bytes = &data[sig_data_start..sig_data_start + sig_len];

    // Sighash (32 bytes)
    let sighash_start = sig_data_start + sig_len;
    if data.len() < sighash_start + 32 {
        return;
    }

    let sighash: Hash = data[sighash_start..sighash_start + 32]
        .try_into()
        .unwrap_or([0; 32]);

    // Parse script flags from remaining data
    let flags = if data.len() > sighash_start + 32 {
        let flags_bytes = &data[sighash_start + 32..];
        if flags_bytes.len() >= 4 {
            u32::from_le_bytes([
                flags_bytes[0],
                flags_bytes[1],
                flags_bytes[2],
                flags_bytes[3],
            ])
        } else if flags_bytes.len() >= 1 {
            flags_bytes[0] as u32
        } else {
            0
        }
    } else {
        0
    };

    // Test different flag combinations
    let flag_combinations = [
        0u32,              // No flags
        0x01,              // P2SH
        0x02,              // STRICTENC
        0x04,              // DERSIG (BIP66)
        0x08,              // LOW_S
        0x10,              // NULLDUMMY
        0x20,              // CHECKLOCKTIMEVERIFY
        0x40,              // CHECKSEQUENCEVERIFY
        0x80,              // WITNESS
        0x100,             // DISCOURAGE_UPGRADABLE_NOPS
        0x200,             // MINIMALIF
        0x400,             // NULLFAIL
        0x800,             // WITNESS_PUBKEYTYPE
        flags,             // Fuzzed flags
    ];

    // Test with different networks
    let networks = [Network::Mainnet, Network::Testnet, Network::Regtest];

    // Test with different heights (affects BIP66 enforcement)
    let heights = [0u64, 363724, 363725, 1000000];

    for &network in &networks {
        for &height in &heights {
            for &test_flags in &flag_combinations {
                // Create time context
                let time_context = TimeContext {
                    network_time: 0,
                    median_time_past: 0,
                };

                // Test signature verification through script execution
                // Build a script_sig with signature and script_pubkey with pubkey + OP_CHECKSIG
                let script_sig: Vec<u8> = signature_bytes.to_vec();
                let mut script_pubkey = Vec::new();
                script_pubkey.extend_from_slice(pubkey_bytes);
                script_pubkey.push(0xac); // OP_CHECKSIG

                // Create a transaction for sighash computation
                let tx = blvm_consensus::types::Transaction {
                    version: 1,
                    inputs: vec![blvm_consensus::types::TransactionInput {
                        prevout: blvm_consensus::types::OutPoint {
                            hash: sighash,
                            index: 0,
                        },
                        script_sig: vec![].into(),
                        sequence: 0xffffffff,
                    }]
                    .into(),
                    outputs: vec![blvm_consensus::types::TransactionOutput {
                        value: 0,
                        script_pubkey: vec![].into(),
                    }]
                    .into(),
                    lock_time: 0,
                };

                let pv = vec![0i64];
                let empty_sp: blvm_consensus::types::ByteString = vec![].into();
                let psp: [&[u8]; 1] = [empty_sp.as_slice()];

                // Test signature verification through script
                // Should never panic - handle errors gracefully
                let _result = verify_script_with_context_full(
                    &script_sig,
                    &script_pubkey,
                    None,
                    test_flags,
                    &tx,
                    0,
                    &pv,
                    &psp,
                    Some(height),
                    Some(time_context.median_time_past),
                    network,
                    blvm_consensus::script::SigVersion::Base,
                    None,
                    None,
                    None,
                    None,
                    None,
                
                    #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
                    None,
        );
            }
        }
    }

    // Test with invalid/edge case inputs
    // Empty pubkey
    if !pubkey_bytes.is_empty() {
        let script_sig: Vec<u8> = signature_bytes.to_vec();
        let script_pubkey: Vec<u8> = vec![0xac]; // Just OP_CHECKSIG

        let tx = blvm_consensus::types::Transaction {
            version: 1,
            inputs: vec![blvm_consensus::types::TransactionInput {
                prevout: blvm_consensus::types::OutPoint {
                    hash: sighash,
                    index: 0,
                },
                script_sig: vec![].into(),
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![blvm_consensus::types::TransactionOutput {
                value: 0,
                script_pubkey: vec![].into(),
            }]
            .into(),
            lock_time: 0,
        };

        let pv = vec![0i64];
        let empty_sp: blvm_consensus::types::ByteString = vec![].into();
        let psp: [&[u8]; 1] = [empty_sp.as_slice()];

        let _result_empty_pubkey = verify_script_with_context_full(
            &script_sig,
            &script_pubkey,
            None,
            0,
            &tx,
            0,
            &pv,
            &psp,
            Some(0),
            Some(0),
            Network::Mainnet,
            blvm_consensus::script::SigVersion::Base,
            None,
            None,
            None,
            None,
            None,
        
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            None,
        );
    }

    // Empty signature
    if !signature_bytes.is_empty() {
        let script_sig: Vec<u8> = vec![];
        let mut script_pubkey = Vec::new();
        script_pubkey.extend_from_slice(pubkey_bytes);
        script_pubkey.push(0xac); // OP_CHECKSIG

        let tx = blvm_consensus::types::Transaction {
            version: 1,
            inputs: vec![blvm_consensus::types::TransactionInput {
                prevout: blvm_consensus::types::OutPoint {
                    hash: sighash,
                    index: 0,
                },
                script_sig: vec![].into(),
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![blvm_consensus::types::TransactionOutput {
                value: 0,
                script_pubkey: vec![].into(),
            }]
            .into(),
            lock_time: 0,
        };

        let pv = vec![0i64];
        let empty_sp: blvm_consensus::types::ByteString = vec![].into();
        let psp: [&[u8]; 1] = [empty_sp.as_slice()];

        let _result_empty_sig = verify_script_with_context_full(
            &script_sig,
            &script_pubkey,
            None,
            0,
            &tx,
            0,
            &pv,
            &psp,
            Some(0),
            Some(0),
            Network::Mainnet,
            blvm_consensus::script::SigVersion::Base,
            None,
            None,
            None,
            None,
            None,
        
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            None,
        );
    }

    // Very long signature (should handle gracefully)
    if data.len() > 200 {
        let long_sig: Vec<u8> = data.iter().take(200).copied().collect();
        let mut script_pubkey = Vec::new();
        script_pubkey.extend_from_slice(pubkey_bytes);
        script_pubkey.push(0xac); // OP_CHECKSIG

        let tx = blvm_consensus::types::Transaction {
            version: 1,
            inputs: vec![blvm_consensus::types::TransactionInput {
                prevout: blvm_consensus::types::OutPoint {
                    hash: sighash,
                    index: 0,
                },
                script_sig: vec![].into(),
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![blvm_consensus::types::TransactionOutput {
                value: 0,
                script_pubkey: vec![].into(),
            }]
            .into(),
            lock_time: 0,
        };

        let pv = vec![0i64];
        let empty_sp: blvm_consensus::types::ByteString = vec![].into();
        let psp: [&[u8]; 1] = [empty_sp.as_slice()];

        let _result_long_sig = verify_script_with_context_full(
            &long_sig,
            &script_pubkey,
            None,
            0,
            &tx,
            0,
            &pv,
            &psp,
            Some(0),
            Some(0),
            Network::Mainnet,
            blvm_consensus::script::SigVersion::Base,
            None,
            None,
            None,
            None,
            None,
        
            #[cfg(all(feature = "production", feature = "blvm-secp256k1"))]
            None,
        );
    }
});

