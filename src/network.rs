//! Network protocol functions from Orange Paper Section 9.2

use crate::types::*;
use crate::error::Result;
use std::collections::HashMap;

/// NetworkMessage: 𝒯𝒳 × 𝒰𝒮 → {accepted, rejected}
/// 
/// Network message types for Bitcoin P2P protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMessage {
    Version(VersionMessage),
    VerAck,
    Addr(AddrMessage),
    Inv(InvMessage),
    GetData(GetDataMessage),
    GetHeaders(GetHeadersMessage),
    Headers(HeadersMessage),
    Block(Block),
    Tx(Transaction),
    Ping(PingMessage),
    Pong(PongMessage),
    MemPool,
    FeeFilter(FeeFilterMessage),
}

/// Version message for initial handshake
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

/// Address message containing peer addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrMessage {
    pub addresses: Vec<NetworkAddress>,
}

/// Inventory message listing available objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvMessage {
    pub inventory: Vec<InventoryVector>,
}

/// GetData message requesting specific objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDataMessage {
    pub inventory: Vec<InventoryVector>,
}

/// GetHeaders message requesting block headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub block_locator_hashes: Vec<Hash>,
    pub hash_stop: Hash,
}

/// Headers message containing block headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeader>,
}

/// Ping message for connection keepalive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingMessage {
    pub nonce: u64,
}

/// Pong message responding to ping
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongMessage {
    pub nonce: u64,
}

/// FeeFilter message setting minimum fee rate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeFilterMessage {
    pub feerate: u64,
}

/// Network address structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAddress {
    pub services: u64,
    pub ip: [u8; 16], // IPv6 address
    pub port: u16,
}

/// Inventory vector identifying objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryVector {
    pub inv_type: u32,
    pub hash: Hash,
}

/// Process incoming network message
pub fn process_network_message(
    message: &NetworkMessage,
    peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    match message {
        NetworkMessage::Version(version) => {
            process_version_message(version, peer_state)
        }
        NetworkMessage::VerAck => {
            process_verack_message(peer_state)
        }
        NetworkMessage::Addr(addr) => {
            process_addr_message(addr, peer_state)
        }
        NetworkMessage::Inv(inv) => {
            process_inv_message(inv, peer_state, chain_state)
        }
        NetworkMessage::GetData(getdata) => {
            process_getdata_message(getdata, peer_state, chain_state)
        }
        NetworkMessage::GetHeaders(getheaders) => {
            process_getheaders_message(getheaders, peer_state, chain_state)
        }
        NetworkMessage::Headers(headers) => {
            process_headers_message(headers, peer_state, chain_state)
        }
        NetworkMessage::Block(block) => {
            process_block_message(block, peer_state, chain_state)
        }
        NetworkMessage::Tx(tx) => {
            process_tx_message(tx, peer_state, chain_state)
        }
        NetworkMessage::Ping(ping) => {
            process_ping_message(ping, peer_state)
        }
        NetworkMessage::Pong(pong) => {
            process_pong_message(pong, peer_state)
        }
        NetworkMessage::MemPool => {
            process_mempool_message(peer_state, chain_state)
        }
        NetworkMessage::FeeFilter(feefilter) => {
            process_feefilter_message(feefilter, peer_state)
        }
    }
}

/// Process version message
fn process_version_message(
    version: &VersionMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    // Validate version message
    if version.version < 70001 {
        return Ok(NetworkResponse::Reject("Version too old".to_string()));
    }
    
    // Update peer state
    peer_state.version = version.version;
    peer_state.services = version.services;
    peer_state.user_agent = version.user_agent.clone();
    peer_state.start_height = version.start_height;
    
    // Send verack response
    Ok(NetworkResponse::SendMessage(NetworkMessage::VerAck))
}

/// Process verack message
fn process_verack_message(peer_state: &mut PeerState) -> Result<NetworkResponse> {
    peer_state.handshake_complete = true;
    Ok(NetworkResponse::Ok)
}

/// Process addr message
fn process_addr_message(
    addr: &AddrMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    // Validate address count
    if addr.addresses.len() > 1000 {
        return Ok(NetworkResponse::Reject("Too many addresses".to_string()));
    }
    
    // Store addresses for future use
    peer_state.known_addresses.extend(addr.addresses.clone());
    
    Ok(NetworkResponse::Ok)
}

/// Process inv message
fn process_inv_message(
    inv: &InvMessage,
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Validate inventory count
    if inv.inventory.len() > 50000 {
        return Ok(NetworkResponse::Reject("Too many inventory items".to_string()));
    }
    
    // Check which items we need
    let mut needed_items = Vec::new();
    for item in &inv.inventory {
        if !chain_state.has_object(&item.hash) {
            needed_items.push(item.clone());
        }
    }
    
    if !needed_items.is_empty() {
        let getdata = NetworkMessage::GetData(GetDataMessage {
            inventory: needed_items,
        });
        return Ok(NetworkResponse::SendMessage(getdata));
    }
    
    Ok(NetworkResponse::Ok)
}

/// Process getdata message
fn process_getdata_message(
    getdata: &GetDataMessage,
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Validate request count
    if getdata.inventory.len() > 50000 {
        return Ok(NetworkResponse::Reject("Too many getdata items".to_string()));
    }
    
    // Send requested objects
    let mut responses = Vec::new();
    for item in &getdata.inventory {
        if let Some(obj) = chain_state.get_object(&item.hash) {
            match item.inv_type {
                1 => { // MSG_TX
                    if let Some(tx) = obj.as_transaction() {
                        responses.push(NetworkMessage::Tx(tx.clone()));
                    }
                }
                2 => { // MSG_BLOCK
                    if let Some(block) = obj.as_block() {
                        responses.push(NetworkMessage::Block(block.clone()));
                    }
                }
                _ => {
                    // Unknown inventory type
                }
            }
        }
    }
    
    Ok(NetworkResponse::SendMessages(responses))
}

/// Process getheaders message
fn process_getheaders_message(
    getheaders: &GetHeadersMessage,
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Find headers to send
    let headers = chain_state.get_headers(&getheaders.block_locator_hashes, &getheaders.hash_stop);
    
    let headers_msg = NetworkMessage::Headers(HeadersMessage { headers });
    Ok(NetworkResponse::SendMessage(headers_msg))
}

/// Process headers message
fn process_headers_message(
    headers: &HeadersMessage,
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Validate header count
    if headers.headers.len() > 2000 {
        return Ok(NetworkResponse::Reject("Too many headers".to_string()));
    }
    
    // Process each header
    for header in &headers.headers {
        if let Err(e) = chain_state.process_header(header) {
            return Ok(NetworkResponse::Reject(format!("Invalid header: {}", e)));
        }
    }
    
    Ok(NetworkResponse::Ok)
}

/// Process block message
fn process_block_message(
    block: &Block,
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Validate block
    if let Err(e) = chain_state.process_block(block) {
        return Ok(NetworkResponse::Reject(format!("Invalid block: {}", e)));
    }
    
    Ok(NetworkResponse::Ok)
}

/// Process transaction message
fn process_tx_message(
    tx: &Transaction,
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Validate transaction
    if let Err(e) = chain_state.process_transaction(tx) {
        return Ok(NetworkResponse::Reject(format!("Invalid transaction: {}", e)));
    }
    
    Ok(NetworkResponse::Ok)
}

/// Process ping message
fn process_ping_message(
    ping: &PingMessage,
    _peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    let pong = NetworkMessage::Pong(PongMessage {
        nonce: ping.nonce,
    });
    Ok(NetworkResponse::SendMessage(pong))
}

/// Process pong message
fn process_pong_message(
    pong: &PongMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    // Validate pong nonce matches our ping
    if peer_state.ping_nonce == Some(pong.nonce) {
        peer_state.ping_nonce = None;
        peer_state.last_pong = Some(std::time::SystemTime::now());
    }
    
    Ok(NetworkResponse::Ok)
}

/// Process mempool message
fn process_mempool_message(
    _peer_state: &mut PeerState,
    chain_state: &ChainState,
) -> Result<NetworkResponse> {
    // Send all mempool transactions
    let mempool_txs = chain_state.get_mempool_transactions();
    let mut responses = Vec::new();
    
    for tx in mempool_txs {
        responses.push(NetworkMessage::Tx(tx));
    }
    
    Ok(NetworkResponse::SendMessages(responses))
}

/// Process feefilter message
fn process_feefilter_message(
    feefilter: &FeeFilterMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    peer_state.min_fee_rate = Some(feefilter.feerate);
    Ok(NetworkResponse::Ok)
}

// ============================================================================
// TYPES
// ============================================================================

/// Network response to a message
#[derive(Debug, Clone)]
pub enum NetworkResponse {
    Ok,
    SendMessage(NetworkMessage),
    SendMessages(Vec<NetworkMessage>),
    Reject(String),
}

/// Peer connection state
#[derive(Debug, Clone)]
pub struct PeerState {
    pub version: u32,
    pub services: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub handshake_complete: bool,
    pub known_addresses: Vec<NetworkAddress>,
    pub ping_nonce: Option<u64>,
    pub last_pong: Option<std::time::SystemTime>,
    pub min_fee_rate: Option<u64>,
}

impl PeerState {
    pub fn new() -> Self {
        Self {
            version: 0,
            services: 0,
            user_agent: String::new(),
            start_height: 0,
            handshake_complete: false,
            known_addresses: Vec::new(),
            ping_nonce: None,
            last_pong: None,
            min_fee_rate: None,
        }
    }
}

/// Chain state for network operations
#[derive(Debug, Clone)]
pub struct ChainState {
    pub blocks: HashMap<Hash, Block>,
    pub transactions: HashMap<Hash, Transaction>,
    pub headers: HashMap<Hash, BlockHeader>,
    pub mempool: Vec<Transaction>,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            transactions: HashMap::new(),
            headers: HashMap::new(),
            mempool: Vec::new(),
        }
    }
    
    pub fn has_object(&self, hash: &Hash) -> bool {
        self.blocks.contains_key(hash) || self.transactions.contains_key(hash)
    }
    
    pub fn get_object(&self, hash: &Hash) -> Option<ChainObject> {
        if let Some(block) = self.blocks.get(hash) {
            return Some(ChainObject::Block(block.clone()));
        }
        if let Some(tx) = self.transactions.get(hash) {
            return Some(ChainObject::Transaction(tx.clone()));
        }
        None
    }
    
    pub fn get_headers(&self, _locator_hashes: &[Hash], _hash_stop: &Hash) -> Vec<BlockHeader> {
        // Simplified: return all headers
        self.headers.values().cloned().collect()
    }
    
    pub fn process_header(&self, _header: &BlockHeader) -> Result<()> {
        // Simplified: always accept
        Ok(())
    }
    
    pub fn process_block(&self, _block: &Block) -> Result<()> {
        // Simplified: always accept
        Ok(())
    }
    
    pub fn process_transaction(&self, _tx: &Transaction) -> Result<()> {
        // Simplified: always accept
        Ok(())
    }
    
    pub fn get_mempool_transactions(&self) -> Vec<Transaction> {
        self.mempool.clone()
    }
}

/// Chain object (block or transaction)
#[derive(Debug, Clone)]
pub enum ChainObject {
    Block(Block),
    Transaction(Transaction),
}

impl ChainObject {
    pub fn as_block(&self) -> Option<&Block> {
        match self {
            ChainObject::Block(block) => Some(block),
            _ => None,
        }
    }
    
    pub fn as_transaction(&self) -> Option<&Transaction> {
        match self {
            ChainObject::Transaction(tx) => Some(tx),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_process_version_message() {
        let mut peer_state = PeerState::new();
        let version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            addr_recv: NetworkAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            addr_from: NetworkAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            nonce: 12345,
            user_agent: "test".to_string(),
            start_height: 100,
            relay: true,
        };
        
        let response = process_version_message(&version, &mut peer_state).unwrap();
        assert!(matches!(response, NetworkResponse::SendMessage(NetworkMessage::VerAck)));
        assert_eq!(peer_state.version, 70015);
    }
    
    #[test]
    fn test_process_version_message_too_old() {
        let mut peer_state = PeerState::new();
        let version = VersionMessage {
            version: 60000, // Too old
            services: 1,
            timestamp: 1234567890,
            addr_recv: NetworkAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            addr_from: NetworkAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            nonce: 12345,
            user_agent: "test".to_string(),
            start_height: 100,
            relay: true,
        };
        
        let response = process_version_message(&version, &mut peer_state).unwrap();
        assert!(matches!(response, NetworkResponse::Reject(_)));
    }
    
    #[test]
    fn test_process_verack_message() {
        let mut peer_state = PeerState::new();
        let response = process_verack_message(&mut peer_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
        assert!(peer_state.handshake_complete);
    }
    
    #[test]
    fn test_process_ping_message() {
        let mut peer_state = PeerState::new();
        let ping = PingMessage { nonce: 12345 };
        
        let response = process_ping_message(&ping, &mut peer_state).unwrap();
        assert!(matches!(response, NetworkResponse::SendMessage(NetworkMessage::Pong(_))));
    }
    
    #[test]
    fn test_process_pong_message() {
        let mut peer_state = PeerState::new();
        peer_state.ping_nonce = Some(12345);
        
        let pong = PongMessage { nonce: 12345 };
        let response = process_pong_message(&pong, &mut peer_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
        assert!(peer_state.ping_nonce.is_none());
    }
    
    #[test]
    fn test_peer_state_new() {
        let peer_state = PeerState::new();
        assert_eq!(peer_state.version, 0);
        assert!(!peer_state.handshake_complete);
        assert!(peer_state.known_addresses.is_empty());
    }
    
    #[test]
    fn test_chain_state_new() {
        let chain_state = ChainState::new();
        assert!(chain_state.blocks.is_empty());
        assert!(chain_state.transactions.is_empty());
        assert!(chain_state.headers.is_empty());
        assert!(chain_state.mempool.is_empty());
    }
    
    // ============================================================================
    // COMPREHENSIVE NETWORK TESTS
    // ============================================================================
    
    #[test]
    fn test_process_network_message_version() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            addr_recv: NetworkAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            addr_from: NetworkAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            nonce: 12345,
            user_agent: "test".to_string(),
            start_height: 100,
            relay: true,
        };
        
        let message = NetworkMessage::Version(version);
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::SendMessage(NetworkMessage::VerAck)));
    }
    
    #[test]
    fn test_process_network_message_verack() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let message = NetworkMessage::VerAck;
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
        assert!(peer_state.handshake_complete);
    }
    
    #[test]
    fn test_process_network_message_ping() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let ping = PingMessage { nonce: 12345 };
        let message = NetworkMessage::Ping(ping);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::SendMessage(NetworkMessage::Pong(_))));
    }
    
    #[test]
    fn test_process_network_message_pong() {
        let mut peer_state = PeerState::new();
        peer_state.ping_nonce = Some(12345);
        let chain_state = ChainState::new();
        let pong = PongMessage { nonce: 12345 };
        let message = NetworkMessage::Pong(pong);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
        assert!(peer_state.ping_nonce.is_none());
    }
    
    #[test]
    fn test_process_network_message_addr() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let addr = AddrMessage {
            addresses: vec![NetworkAddress {
                services: 1,
                ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 8333,
            }],
        };
        let message = NetworkMessage::Addr(addr);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
        assert_eq!(peer_state.known_addresses.len(), 1);
    }
    
    #[test]
    fn test_process_network_message_inv() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let inv = InvMessage {
            inventory: vec![InventoryVector {
                inv_type: 2, // Block type
                hash: [1u8; 32],
            }],
        };
        let message = NetworkMessage::Inv(inv);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        // INV message returns SendMessage when requesting objects we don't have
        assert!(matches!(response, NetworkResponse::SendMessage(_)));
    }
    
    #[test]
    fn test_process_network_message_getdata() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let getdata = GetDataMessage {
            inventory: vec![InventoryVector {
                inv_type: 2, // Block type
                hash: [1u8; 32],
            }],
        };
        let message = NetworkMessage::GetData(getdata);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        // GetData message returns SendMessages (plural) when sending objects
        assert!(matches!(response, NetworkResponse::SendMessages(_)));
    }
    
    #[test]
    fn test_process_network_message_getheaders() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let getheaders = GetHeadersMessage {
            version: 70015,
            block_locator_hashes: vec![[1u8; 32]],
            hash_stop: [0u8; 32],
        };
        let message = NetworkMessage::GetHeaders(getheaders);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        // GetHeaders message returns SendMessage when sending headers
        assert!(matches!(response, NetworkResponse::SendMessage(_)));
    }
    
    #[test]
    fn test_process_network_message_headers() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let headers = HeadersMessage {
            headers: vec![BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            }],
        };
        let message = NetworkMessage::Headers(headers);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
    }
    
    #[test]
    fn test_process_network_message_block() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        let message = NetworkMessage::Block(block);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
    }
    
    #[test]
    fn test_process_network_message_tx() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let message = NetworkMessage::Tx(tx);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
    }
    
    #[test]
    fn test_process_network_message_mempool() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let message = NetworkMessage::MemPool;
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        // MemPool message returns SendMessages (plural) when sending transactions
        assert!(matches!(response, NetworkResponse::SendMessages(_)));
    }
    
    #[test]
    fn test_process_network_message_feefilter() {
        let mut peer_state = PeerState::new();
        let chain_state = ChainState::new();
        let feefilter = FeeFilterMessage { feerate: 1000 };
        let message = NetworkMessage::FeeFilter(feefilter);
        
        let response = process_network_message(&message, &mut peer_state, &chain_state).unwrap();
        assert!(matches!(response, NetworkResponse::Ok));
    }
    
    #[test]
    fn test_chain_state_has_object() {
        let mut chain_state = ChainState::new();
        let hash = [1u8; 32];
        
        // Initially no objects
        assert!(!chain_state.has_object(&hash));
        
        // Add a block
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        chain_state.blocks.insert(hash, block);
        assert!(chain_state.has_object(&hash));
        
        // Add a transaction
        let tx_hash = [2u8; 32];
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        chain_state.transactions.insert(tx_hash, tx);
        assert!(chain_state.has_object(&tx_hash));
    }
    
    #[test]
    fn test_chain_state_get_object() {
        let mut chain_state = ChainState::new();
        let hash = [1u8; 32];
        
        // Initially no objects
        assert!(chain_state.get_object(&hash).is_none());
        
        // Add a block
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        chain_state.blocks.insert(hash, block.clone());
        
        let obj = chain_state.get_object(&hash).unwrap();
        assert!(matches!(obj, ChainObject::Block(_)));
        assert_eq!(obj.as_block().unwrap(), &block);
        
        // Add a transaction
        let tx_hash = [2u8; 32];
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        chain_state.transactions.insert(tx_hash, tx.clone());
        
        let obj = chain_state.get_object(&tx_hash).unwrap();
        assert!(matches!(obj, ChainObject::Transaction(_)));
        assert_eq!(obj.as_transaction().unwrap(), &tx);
    }
    
    #[test]
    fn test_chain_state_get_headers() {
        let mut chain_state = ChainState::new();
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let hash = [1u8; 32];
        chain_state.headers.insert(hash, header.clone());
        
        let headers = chain_state.get_headers(&[], &[0u8; 32]);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], header);
    }
    
    #[test]
    fn test_chain_state_process_header() {
        let chain_state = ChainState::new();
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1234567890,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        
        // Should always succeed in simplified implementation
        assert!(chain_state.process_header(&header).is_ok());
    }
    
    #[test]
    fn test_chain_state_process_block() {
        let chain_state = ChainState::new();
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        
        // Should always succeed in simplified implementation
        assert!(chain_state.process_block(&block).is_ok());
    }
    
    #[test]
    fn test_chain_state_process_transaction() {
        let chain_state = ChainState::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        
        // Should always succeed in simplified implementation
        assert!(chain_state.process_transaction(&tx).is_ok());
    }
    
    #[test]
    fn test_chain_state_get_mempool_transactions() {
        let mut chain_state = ChainState::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        chain_state.mempool.push(tx.clone());
        
        let mempool_txs = chain_state.get_mempool_transactions();
        assert_eq!(mempool_txs.len(), 1);
        assert_eq!(mempool_txs[0], tx);
    }
    
    #[test]
    fn test_chain_object_as_block() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        
        let obj = ChainObject::Block(block.clone());
        assert_eq!(obj.as_block().unwrap(), &block);
        
        let tx_obj = ChainObject::Transaction(Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        });
        assert!(tx_obj.as_block().is_none());
    }
    
    #[test]
    fn test_chain_object_as_transaction() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        
        let obj = ChainObject::Transaction(tx.clone());
        assert_eq!(obj.as_transaction().unwrap(), &tx);
        
        let block_obj = ChainObject::Block(Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        });
        assert!(block_obj.as_transaction().is_none());
    }
    
    #[test]
    fn test_pong_message_wrong_nonce() {
        let mut peer_state = PeerState::new();
        peer_state.ping_nonce = Some(12345);
        let pong = PongMessage { nonce: 54321 }; // Wrong nonce
        
        let response = process_pong_message(&pong, &mut peer_state).unwrap();
        // The current implementation accepts any pong message
        assert!(matches!(response, NetworkResponse::Ok));
    }
    
    #[test]
    fn test_pong_message_no_pending_ping() {
        let mut peer_state = PeerState::new();
        peer_state.ping_nonce = None; // No pending ping
        let pong = PongMessage { nonce: 12345 };
        
        let response = process_pong_message(&pong, &mut peer_state).unwrap();
        // The current implementation accepts any pong message
        assert!(matches!(response, NetworkResponse::Ok));
    }
}
