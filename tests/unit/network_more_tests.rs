use consensus_proof::network::*;
use consensus_proof::types::math::{Hash, Natural};

fn dummy_header() -> consensus_proof::BlockHeader {
    consensus_proof::BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x0300ffff,
        nonce: 0,
    }
}

#[test]
fn test_process_verack_message() {
    let mut peer = PeerState::new();
    let resp = super::process_verack_message(&mut peer).unwrap();
    assert!(peer.verack_received);
    assert!(peer.handshake_complete);
    assert_eq!(resp, NetworkResponse::Ok);
}

#[test]
fn test_process_addr_message_limits_and_store() {
    let mut peer = PeerState::new();
    // ok path
    let msg = AddrMessage { addresses: vec!["127.0.0.1:8333".into()] };
    assert_eq!(super::process_addr_message(&msg, &mut peer).unwrap(), NetworkResponse::Ok);
    assert!(peer.known_addresses.contains("127.0.0.1:8333"));

    // reject too many
    let big: Vec<String> = (0..1001).map(|i| format!("10.0.0.{i}:8333")).collect();
    let msg = AddrMessage { addresses: big };
    let resp = super::process_addr_message(&msg, &mut peer).unwrap();
    assert!(matches!(resp, NetworkResponse::Reject(_)));
}

#[test]
fn test_process_misc_messages_ok() {
    let mut peer = PeerState::new();
    let chain = ChainState::new();

    // headers
    let headers = HeadersMessage { headers: vec![dummy_header()] };
    assert!(matches!(super::process_headers_message(&headers, &mut peer, &chain).unwrap(), NetworkResponse::Ok));

    // block, tx (simplified stubs in ChainState)
    let block = consensus_proof::Block { header: dummy_header(), transactions: vec![] };
    assert!(matches!(super::process_block_message(&block, &mut peer, &chain).unwrap(), NetworkResponse::Ok));

    let tx = consensus_proof::Transaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0 };
    assert!(matches!(super::process_tx_message(&tx, &mut peer, &chain).unwrap(), NetworkResponse::Ok));

    // ping/pong
    let ping = PingMessage { nonce: 42 };
    let pong_resp = super::process_ping_message(&ping, &mut peer).unwrap();
    assert!(matches!(pong_resp, NetworkResponse::SendMessage(NetworkMessage::Pong(PongMessage{ nonce: 42 }))));
    let pong = PongMessage { nonce: 42 };
    assert!(matches!(super::process_pong_message(&pong, &mut peer).unwrap(), NetworkResponse::Ok));
}


