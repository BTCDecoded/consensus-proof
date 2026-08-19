//! Core tx_valid.json BIP143 integration: P2SH-P2WSH 6-of-6 multisig (row ~496).

#[path = "core_test_vectors/script_asm.rs"]
mod script_asm;

use blvm_consensus::script::flags::{SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS};
use blvm_consensus::script::{SigVersion, verify_script_with_context_full};
use blvm_consensus::serialization::deserialize_transaction_with_witness;
use blvm_consensus::types::Network;
use blvm_consensus::{SEGWIT_ACTIVATION_MAINNET, TransactionOutput};
use hex;

/// Core `tx_valid.json` row: "BIP143 example: P2SH-P2WSH 6-of-6 multisig signed with 6 different SIGHASH types"
const TX_HEX: &str = "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000";

const PREVOUT_TXID_RPC: &str = "6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436";
const PREVOUT_VOUT: u32 = 1;
const PREVOUT_VALUE: i64 = 987_654_321;
const PREVOUT_SCRIPT_ASM: &str = "HASH160 0x14 0x9993a429037b5d912407a71c252019287b8d27a5 EQUAL";

fn rpc_txid_to_internal_hash(hex_str: &str) -> [u8; 32] {
    let mut bytes = hex::decode(hex_str).expect("valid prevout txid hex");
    assert_eq!(bytes.len(), 32);
    bytes.reverse();
    bytes.try_into().expect("32-byte hash")
}

#[test]
fn test_bip143_p2sh_p2wsh_6of6_multisig_from_tx_valid() {
    let tx_bytes = hex::decode(TX_HEX).expect("valid tx hex");
    let (tx, witnesses, _) =
        deserialize_transaction_with_witness(&tx_bytes).expect("segwit tx deserialize");
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(witnesses.len(), 1);
    assert!(
        witnesses[0].len() > 1,
        "witness must include script + signatures"
    );

    let prevout_script =
        script_asm::parse_core_script_asm(PREVOUT_SCRIPT_ASM).expect("parse prevout scriptPubKey");
    let prevout_hash = rpc_txid_to_internal_hash(PREVOUT_TXID_RPC);

    assert_eq!(tx.inputs[0].prevout.hash.as_ref(), &prevout_hash);
    assert_eq!(tx.inputs[0].prevout.index, PREVOUT_VOUT);

    let prevouts = vec![TransactionOutput {
        value: PREVOUT_VALUE,
        script_pubkey: prevout_script.into(),
    }];
    let prevout_values = vec![PREVOUT_VALUE];
    let prevout_script_pubkeys: Vec<&[u8]> = vec![prevouts[0].script_pubkey.as_slice()];

    let flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    let height = SEGWIT_ACTIVATION_MAINNET;

    assert!(
        verify_script_with_context_full(
            &tx.inputs[0].script_sig,
            prevouts[0].script_pubkey.as_ref(),
            Some(&witnesses[0]),
            flags,
            &tx,
            0,
            &prevout_values,
            &prevout_script_pubkeys,
            Some(height),
            None,
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
        )
        .expect("script verify should not error"),
        "Core tx_valid BIP143 P2SH-P2WSH 6-of-6 multisig must verify"
    );
}
