//! Comprehensive tests for network protocol functions

use consensus_proof::*;
use consensus_proof::network::*;

#[test]
fn test_process_addr_message() {
    let consensus = ConsensusProof::new();
    
    let addr_msg = AddrMessage {
        addresses: vec![NetworkAddress {
            services: 0,
            ip: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 8333,
        }],
    };
    
    let message = NetworkMessage::Addr(addr_msg);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_inv_message() {
    let consensus = ConsensusProof::new();
    
    let inv_msg = InvMessage {
        inventory: vec![InventoryVector {
            inv_type: 1, // Tx
            hash: [1; 32],
        }],
    };
    
    let message = NetworkMessage::Inv(inv_msg);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    // Since chain_state is empty, it should request the data
    assert!(matches!(response, NetworkResponse::SendMessage(_)));
}

#[test]
fn test_process_getdata_message() {
    let consensus = ConsensusProof::new();
    
    let getdata_msg = GetDataMessage {
        inventory: vec![InventoryVector {
            inv_type: 2, // Block
            hash: [2; 32],
        }],
    };
    
    let message = NetworkMessage::GetData(getdata_msg);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    // GetData should return SendMessages
    assert!(matches!(response, NetworkResponse::SendMessages(_)));
}

#[test]
fn test_process_headers_message() {
    let consensus = ConsensusProof::new();
    
    let headers_msg = HeadersMessage {
        headers: vec![BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        }],
    };
    
    let message = NetworkMessage::Headers(headers_msg);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_block_message() {
    let consensus = ConsensusProof::new();
    
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![],
    };
    
    let message = NetworkMessage::Block(block);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_tx_message() {
    let consensus = ConsensusProof::new();
    
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    
    let message = NetworkMessage::Tx(tx);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_chain_state_methods() {
    let chain_state = ChainState::new();
    
    // Test has_object
    let hash = [1; 32];
    assert!(!chain_state.has_object(&hash));
    
    // Test get_object
    let obj = chain_state.get_object(&hash);
    assert!(obj.is_none());
    
    // Test get_headers
    let headers = chain_state.get_headers(&[hash], &hash);
    assert!(headers.is_empty());
    
    // Test process_header
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    assert!(chain_state.process_header(&header).is_ok());
    
    // Test process_block
    let block = Block {
        header: header.clone(),
        transactions: vec![],
    };
    assert!(chain_state.process_block(&block).is_ok());
    
    // Test process_transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    assert!(chain_state.process_transaction(&tx).is_ok());
    
    // Test get_mempool_transactions
    let mempool_txs = chain_state.get_mempool_transactions();
    assert!(mempool_txs.is_empty());
}

#[test]
fn test_chain_object_methods() {
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![],
    };
    
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    
    // Test ChainObject::as_block
    let chain_obj_block = ChainObject::Block(block.clone());
    assert!(chain_obj_block.as_block().is_some());
    assert!(chain_obj_block.as_transaction().is_none());
    
    // Test ChainObject::as_transaction
    let chain_obj_tx = ChainObject::Transaction(tx.clone());
    assert!(chain_obj_tx.as_transaction().is_some());
    assert!(chain_obj_tx.as_block().is_none());
}

#[test]
fn test_process_mempool_message() {
    let consensus = ConsensusProof::new();
    
    let message = NetworkMessage::MemPool;
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    // MemPool should return SendMessages
    assert!(matches!(response, NetworkResponse::SendMessages(_)));
}

#[test]
fn test_process_feefilter_message() {
    let consensus = ConsensusProof::new();
    
    let feefilter_msg = FeeFilterMessage {
        feerate: 1000,
    };
    let message = NetworkMessage::FeeFilter(feefilter_msg);
    let mut peer_state = PeerState::new();
    let chain_state = ChainState::new();
    
    let response = consensus.process_network_message(&message, &mut peer_state, &chain_state).unwrap();
    assert!(matches!(response, NetworkResponse::Ok));
}
