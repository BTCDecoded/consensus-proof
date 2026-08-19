//! Regression test: block 443992, tx 5fec539b — P2SH with OP_CODESEPARATOR + CLTV.
//!
//! Unconventional P2SH redeem script mined by Bitcoin Core at block 443992:
//!   PUSH(pubkey1) CHECKSIGVERIFY  DEPTH 0NOTEQUAL NOTIF [CLTV timeout] ELSE
//!   [pubkey routing → CHECKSIG via CODESEPARATOR slots cond1..cond5] ENDIF
//!
//! The sort-merge step 6 differential logged this as "Script returned false".
//! BLVM fix: legacy sighash must strip OP_CODESEPARATOR bytes from scriptCode
//! (per Bitcoin Core SerializeScriptCode in interpreter.cpp).

#[path = "integration/helpers.rs"]
mod helpers;

use blvm_consensus::script::flags::SCRIPT_VERIFY_P2SH;
use blvm_consensus::script::{
    SigVersion, verify_script_with_context, verify_script_with_context_full,
};
use blvm_consensus::types::Network;
use blvm_consensus::{OutPoint, Transaction, TransactionInput, TransactionOutput};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Block 443992, input 0: prevout d014ff03ab6e7181...:7
// scriptSig: PUSH(sig1) PUSH(pk2) PUSH(sig2) PUSHDATA1(redeem_210bytes)
const SCRIPT_SIG_HEX: &str = "483045022100ac4319cf798ab10d864ad5f206cd405b7a15957eef2b0094ab24ffcf2c28fbfb\
022012053c8142d9e4f832d85c6ce7dba82d44d011c7713fb584771fb8770da97c0c01\
2102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf\
47304402202feedc3b54cd87868406e93ee650742b61ce39162d70b6fde5a805fd40a56c9\
00220015970a2fc874c32edfcd6341981d35e5b019a14b17662e00f49e363db72b93c01\
4cd2\
2102fb6827937707bf432d85b094bc180ab93394ee013b3ecaafa04b9135e3ab6e50\
ad74926404162c5658b15167762103db22e387923ad0552e1c4a4355324313af85926d4266c0eaa86f02eb1e01b2d2\
8763ac67762102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf\
886e6b6b0064\
ab05636f6e643175ac68\
7664756c6c6e6b6b\
ab05636f6e643275ac68\
7664756c6c6e6b6b\
ab05636f6e643375ac68\
7664756c6c6e6b6b\
ab05636f6e643475ac68\
7664756c6c6e6b6b\
ab05636f6e643575ac68\
6868";

// Prevout scriptPubkey (P2SH) from d014ff03...:7
const PREVOUT_SCRIPT_HEX: &str = "a9143ae52dbc43c884ef43211a43082d01a0091ef1e387";
const PREVOUT_VALUE: i64 = 70000;
// tx locktime = 0x58562c34 = 1482042420; CLTV value = 1482042390 (requires MTP >= this)
const TX_LOCKTIME: u64 = 1482042420;
const BLOCK_HEIGHT: u64 = 443992;
const MEDIAN_TIME_PAST: u64 = 1482042420; // conservative: use tx locktime as MTP lower bound

fn make_tx() -> Transaction {
    let script_sig = hex(&SCRIPT_SIG_HEX.replace('\n', ""));
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                // Raw prevout hash bytes as they appear in the transaction (network byte order =
                // reverse of the human-readable txid d014ff03...aa6a).
                hash: {
                    let mut h = [0u8; 32];
                    let bytes =
                        hex("6aaa18f4ab91fab80ecda666c4def68b8b75cc6bb1169ecd81716eab03ff14d0");
                    h.copy_from_slice(&bytes);
                    h
                },
                index: 7,
            },
            script_sig: script_sig.into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 20000,
            script_pubkey: hex("76a914648a4310b84426f426398ef27e3388a4d2c05a2888ac").into(),
        }]
        .into(),
        lock_time: TX_LOCKTIME,
    }
}

fn flags() -> u32 {
    // Block 443992 mainnet flags: P2SH + BIP66 (DERSIG) + BIP65 (CLTV) + BIP112 (CSV)
    const SCRIPT_VERIFY_DERSIG: u32 = 0x04;
    const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 0x0200;
    const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: u32 = 0x0400;
    SCRIPT_VERIFY_P2SH
        | SCRIPT_VERIFY_DERSIG
        | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
        | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
}

#[test]
fn test_block443992_p2sh_codesep_cltv_passes() {
    let tx = make_tx();
    let prevout_script = hex(PREVOUT_SCRIPT_HEX);
    let prevouts = vec![TransactionOutput {
        value: PREVOUT_VALUE,
        script_pubkey: prevout_script.clone().into(),
    }];

    let result = verify_script_with_context(
        &tx.inputs[0].script_sig,
        &prevout_script,
        None,
        flags(),
        &tx,
        0,
        &prevouts,
        Some(BLOCK_HEIGHT),
        Network::Mainnet,
    );
    eprintln!("verify_script_with_context result: {:?}", result);

    // Also test the redeem script directly (bypass P2SH hash check) to isolate CHECKSIGVERIFY
    let redeem = hex(
        "2102fb6827937707bf432d85b094bc180ab93394ee013b3ecaafa04b9135e3ab6e50\
ad74926404162c5658b15167762103db22e387923ad0552e1c4a4355324313af85926d4266c0eaa86f02eb1e01b2d2\
8763ac67762102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf\
886e6b6b0064ab05636f6e643175ac687664756c6c6e6b6bab05636f6e643275ac68\
7664756c6c6e6b6bab05636f6e643375ac687664756c6c6e6b6bab05636f6e643475ac68\
7664756c6c6e6b6bab05636f6e643575ac686868",
    );
    // scriptSig for direct execution: just the 3 pushes before the redeem
    let scriptsig_direct = hex(
        "483045022100ac4319cf798ab10d864ad5f206cd405b7a15957eef2b0094ab24ffcf2c28fbfb\
022012053c8142d9e4f832d85c6ce7dba82d44d011c7713fb584771fb8770da97c0c01\
2102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf\
47304402202feedc3b54cd87868406e93ee650742b61ce39162d70b6fde5a805fd40a56c9\
00220015970a2fc874c32edfcd6341981d35e5b019a14b17662e00f49e363db72b93c01",
    );
    let prevout_values = vec![PREVOUT_VALUE];
    let prevout_scripts_ref: Vec<&[u8]> = vec![&prevout_script];
    let r2 = verify_script_with_context_full(
        &scriptsig_direct.into(),
        &redeem,
        None,
        flags(),
        &tx,
        0,
        &prevout_values,
        &prevout_scripts_ref,
        Some(BLOCK_HEIGHT),
        Some(MEDIAN_TIME_PAST),
        Network::Mainnet,
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
    eprintln!("Direct redeem execution result (bypass P2SH): {:?}", r2);

    assert!(
        result.unwrap_or(false),
        "block 443992 P2SH+CLTV+CODESEPARATOR tx must verify (mined by Bitcoin Core)"
    );
}

#[test]
fn test_block443992_sig_verification_direct() {
    use blvm_consensus::script::verify_pre_extracted_ecdsa;
    let flags = flags();

    // On-chain sighashes: gate uses stripped scriptCode (Core strips OP_CODESEPARATOR in SerializeScriptCode)
    let sighash_checksigverify: [u8; 32] =
        hex::decode("1d893b45c5d005bf6a20a0ab1ad19c16e92da602e9984180d947e2798aef1e41")
            .unwrap()
            .try_into()
            .unwrap();
    // cond5 subscript (redeem[199..], 11 bytes) has no OP_CODESEPARATOR → same with or without stripping
    let sighash_cond5: [u8; 32] =
        hex::decode("6da9ad27370c9788ac72fe032e22f9391fc492c3807d670328430bafbccca704")
            .unwrap()
            .try_into()
            .unwrap();

    // sig2 (for CHECKSIGVERIFY) + pubkey1
    let sig2 = hex(
        "304402202feedc3b54cd87868406e93ee650742b61ce39162d70b6fde5a805fd40a56c9\
00220015970a2fc874c32edfcd6341981d35e5b019a14b17662e00f49e363db72b93c01",
    );
    let pubkey1 = hex("02fb6827937707bf432d85b094bc180ab93394ee013b3ecaafa04b9135e3ab6e50");

    // sig1 (for CHECKSIG cond5) + pk2 (the key used in the ELSE branch)
    let sig1 = hex(
        "3045022100ac4319cf798ab10d864ad5f206cd405b7a15957eef2b0094ab24ffcf2c28fbfb\
022012053c8142d9e4f832d85c6ce7dba82d44d011c7713fb584771fb8770da97c0c01",
    );
    let pubkey2 = hex("02c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf");

    let r1 = verify_pre_extracted_ecdsa(
        &pubkey1,
        &sig2,
        &sighash_checksigverify,
        flags,
        443992,
        Network::Mainnet,
    );
    eprintln!("CHECKSIGVERIFY (sig2 vs pubkey1): {:?}", r1);

    let r5 = verify_pre_extracted_ecdsa(
        &pubkey2,
        &sig1,
        &sighash_cond5,
        flags,
        443992,
        Network::Mainnet,
    );
    eprintln!("cond5 CHECKSIG (sig1 vs pubkey2): {:?}", r5);

    assert!(
        r1.unwrap_or(false),
        "CHECKSIGVERIFY (sig2 vs pubkey1) must pass"
    );
    assert!(
        r5.unwrap_or(false),
        "cond5 CHECKSIG (sig1 vs pubkey2) must pass"
    );
}

#[test]
fn test_block443992_sighash_debug() {
    use blvm_consensus::transaction_hash::{
        SighashType, calculate_transaction_sighash_single_input,
    };
    let tx = make_tx();
    let prevout_script = hex(PREVOUT_SCRIPT_HEX);
    let redeem = hex(
        "2102fb6827937707bf432d85b094bc180ab93394ee013b3ecaafa04b9135e3ab6e50\
ad74926404162c5658b15167762103db22e387923ad0552e1c4a4355324313af85926d4266c0eaa86f02eb1e01b2d2\
8763ac67762102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf\
886e6b6b0064ab05636f6e643175ac687664756c6c6e6b6bab05636f6e643275ac68\
7664756c6c6e6b6bab05636f6e643375ac687664756c6c6e6b6bab05636f6e643475ac68\
7664756c6c6e6b6bab05636f6e643575ac686868",
    );
    eprintln!("redeem script len: {}", redeem.len());

    // CHECKSIGVERIFY sighash: full redeem as scriptCode
    let h1 = calculate_transaction_sighash_single_input(
        &tx,
        0,
        &redeem,
        PREVOUT_VALUE,
        SighashType::from_byte(0x01),
        #[cfg(feature = "production")]
        None,
    )
    .unwrap();
    eprintln!("CHECKSIGVERIFY sighash (full redeem): {}", hex::encode(h1));

    // cond5 CHECKSIG sighash: subscript after cond5 CODESEPARATOR (byte 198)
    let cond5_sub = &redeem[199..];
    eprintln!(
        "cond5 subscript ({} bytes): {}",
        cond5_sub.len(),
        hex::encode(cond5_sub)
    );
    let h5 = calculate_transaction_sighash_single_input(
        &tx,
        0,
        cond5_sub,
        PREVOUT_VALUE,
        SighashType::from_byte(0x01),
        #[cfg(feature = "production")]
        None,
    )
    .unwrap();
    eprintln!("cond5 CHECKSIG sighash: {}", hex::encode(h5));

    // Expected values: BLVM strips OP_CODESEPARATOR from scriptCode (per Core SerializeScriptCode).
    // Gate: full 210B redeem → 5 OP_CODESEPARATOR stripped → 205B → sighash 1d893b45…
    // cond5: subscript redeem[199..] is 11B with no OP_CODESEPARATOR → unchanged → 6da9ad27…
    eprintln!(
        "Expected CHECKSIGVERIFY sighash: 1d893b45c5d005bf6a20a0ab1ad19c16e92da602e9984180d947e2798aef1e41"
    );
    eprintln!(
        "Expected cond5 CHECKSIG sighash: 6da9ad27370c9788ac72fe032e22f9391fc492c3807d670328430bafbccca704"
    );

    assert_eq!(
        hex::encode(h1),
        "1d893b45c5d005bf6a20a0ab1ad19c16e92da602e9984180d947e2798aef1e41",
        "CHECKSIGVERIFY sighash mismatch (BLVM must strip OP_CODESEPARATOR from scriptCode)"
    );
    assert_eq!(
        hex::encode(h5),
        "6da9ad27370c9788ac72fe032e22f9391fc492c3807d670328430bafbccca704",
        "cond5 CHECKSIG sighash mismatch"
    );
}

#[test]
fn test_block443992_via_context_full() {
    let tx = make_tx();
    let prevout_script = hex(PREVOUT_SCRIPT_HEX);
    let prevout_values = vec![PREVOUT_VALUE];
    let prevout_scripts_ref: Vec<&[u8]> = vec![&prevout_script];

    let result = verify_script_with_context_full(
        &tx.inputs[0].script_sig,
        &prevout_script,
        None,
        flags(),
        &tx,
        0,
        &prevout_values,
        &prevout_scripts_ref,
        Some(BLOCK_HEIGHT),
        Some(MEDIAN_TIME_PAST),
        Network::Mainnet,
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
    assert!(
        result.unwrap_or(false),
        "verify_script_with_context_full must accept block 443992 CODESEP P2SH tx"
    );
}

/// Cross-library sanity: verify sig2+pk1 via the C-backed secp256k1 crate.
/// If this returns VALID but blvm-secp256k1 returns INVALID, the bug is in our pure-Rust ecmult.
/// If both return INVALID, the bug is elsewhere (e.g. wrong sighash, wrong stack layout).
#[test]
fn test_block443992_secp256k1_c_vs_blvm_secp() {
    use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};

    let sig2_der = hex(
        "304402202feedc3b54cd87868406e93ee650742b61ce39162d70b6fde5a805fd40a56c900220015970a2fc874c32edfcd6341981d35e5b019a14b17662e00f49e363db72b93c",
    );
    let pk1_bytes = hex("02fb6827937707bf432d85b094bc180ab93394ee013b3ecaafa04b9135e3ab6e50");
    // Correct gate sighash: full redeem with OP_CODESEPARATOR stripped (205B)
    let gate_hash = hex("1d893b45c5d005bf6a20a0ab1ad19c16e92da602e9984180d947e2798aef1e41");
    let h32: [u8; 32] = gate_hash.clone().try_into().unwrap();

    let secp = Secp256k1::new();
    let msg = Message::from_digest(h32);
    let pk = PublicKey::from_slice(&pk1_bytes).expect("pk1 parse");
    let mut sig = Signature::from_der(&sig2_der).expect("sig2 DER parse");
    sig.normalize_s();
    let c_result = secp.verify_ecdsa(&msg, &sig, &pk);
    eprintln!("secp256k1-C (normalize_s): {:?}", c_result);

    let blvm_result =
        blvm_secp256k1::ecdsa::verify_ecdsa_direct(&sig2_der, &pk1_bytes, &h32, true, false);
    eprintln!("blvm-secp256k1 (strict_der): {:?}", blvm_result);

    // If the C library passes but blvm-secp256k1 fails → ecmult bug in blvm-secp256k1.
    // For now just report; the assert is the overall fix goal.
    eprintln!(
        "C VALID={} blvm_VALID={}",
        c_result.is_ok(),
        blvm_result == Some(true)
    );
}
