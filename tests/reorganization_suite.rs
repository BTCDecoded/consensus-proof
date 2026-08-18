//! COV-C-04a: Deterministic reorganization API coverage.

use blvm_consensus::mempool::Mempool;
use blvm_consensus::opcodes::OP_1;
use blvm_consensus::reorganization::{
    BlockUndoLog, calculate_chain_work, reorganize_chain, reorganize_chain_with_witnesses,
    should_reorganize,
};
use blvm_consensus::types::{Hash, Network};
use blvm_consensus::{
    Block, BlockHeader, OutPoint, Transaction, TransactionInput, TransactionOutput, UtxoSet,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// Wall-clock stand-in for reorg connect validation (must exceed regtest block timestamps).
const TEST_NETWORK_TIME: u64 = 2_000_000_000;

fn block_hash(header: &BlockHeader) -> Hash {
    use blvm_consensus::serialization::block::serialize_block_header;
    blvm_consensus::crypto::OptimizedSha256::new().hash256(&serialize_block_header(header))
}

thread_local! {
    static REORG_TX_LOOKUP: RefCell<Option<HashMap<Hash, Transaction>>> =
        const { RefCell::new(None) };
}

fn reorg_tx_lookup(id: &Hash) -> Option<Transaction> {
    REORG_TX_LOOKUP.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|store| store.get(id).cloned())
    })
}

fn coinbase_block(n: u8, bits: u64) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: vec![n].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5_000_000_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: if n == 0 { [0; 32] } else { [n; 32] },
            merkle_root: [1; 32],
            timestamp: 1_231_006_505 + n as u64 * 600,
            bits,
            nonce: n as u64,
        },
        transactions: vec![coinbase].into(),
    }
}

fn chain(len: usize) -> Vec<Block> {
    (0..len)
        .map(|i| coinbase_block(i as u8, 0x0300ffff))
        .collect()
}

#[test]
fn test_calculate_chain_work_increases_with_length() {
    let short = chain(2);
    let long = chain(5);
    let short_work = calculate_chain_work(&short).unwrap();
    let long_work = calculate_chain_work(&long).unwrap();
    assert!(long_work >= short_work);
}

#[test]
fn test_should_reorganize_prefers_more_work() {
    let current = chain(2);
    let longer = chain(4);
    // Equal work per block in `chain()` helper — longer chain has strictly more work.
    let current_work = calculate_chain_work(&current).unwrap();
    let longer_work = calculate_chain_work(&longer).unwrap();
    assert!(longer_work > current_work);
    assert!(should_reorganize(&longer, &current).unwrap());
    assert!(!should_reorganize(&current, &longer).unwrap());
}

#[test]
fn test_reorganize_chain_empty_chains_errors() {
    let result = reorganize_chain_simple(&[], &[], UtxoSet::default(), 0);
    assert!(result.is_err());
}

#[test]
fn test_update_mempool_after_reorg_simple_removes_connected_tx() {
    use blvm_consensus::block::calculate_tx_id;
    use blvm_consensus::mempool::Mempool;
    use blvm_consensus::reorganization::{ReorganizationResult, update_mempool_after_reorg_simple};
    use std::collections::{HashMap, HashSet};

    let block = chain(1).pop().expect("one block");
    let tx_id = calculate_tx_id(&block.transactions[0]);

    let mut pool = Mempool::new();
    pool.insert(tx_id);

    let reorg_result = ReorganizationResult {
        new_utxo_set: UtxoSet::default(),
        new_height: 1,
        common_ancestor: block.header.clone(),
        disconnected_blocks: vec![],
        connected_blocks: vec![block],
        reorganization_depth: 1,
        connected_block_undo_logs: HashMap::new(),
    };

    let removed =
        update_mempool_after_reorg_simple(&mut pool, &reorg_result, &UtxoSet::default()).unwrap();
    assert!(removed.contains(&tx_id));
    assert!(!pool.contains(&tx_id));
}

#[test]
fn test_update_mempool_after_reorg_with_lookup_removes_conflict() {
    use blvm_consensus::block::calculate_tx_id;
    use blvm_consensus::mempool::Mempool;
    use blvm_consensus::reorganization::{ReorganizationResult, update_mempool_after_reorg};
    use blvm_consensus::{
        Block, BlockHeader, OutPoint, Transaction, TransactionInput, TransactionOutput,
    };
    use std::collections::{HashMap, HashSet};

    let included = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0x77; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let included_id = calculate_tx_id(&included);

    let mut conflict = included.clone();
    conflict.outputs[0].value = 900;
    let conflict_id = calculate_tx_id(&conflict);

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1_231_006_505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![included.clone()].into(),
    };

    let mut pool = Mempool::new();
    pool.insert(included_id);
    pool.insert(conflict_id);

    let mut store = HashMap::new();
    store.insert(included_id, included);
    store.insert(conflict_id, conflict);

    let reorg_result = ReorganizationResult {
        new_utxo_set: UtxoSet::default(),
        new_height: 1,
        common_ancestor: block.header.clone(),
        disconnected_blocks: vec![],
        connected_blocks: vec![block],
        reorganization_depth: 1,
        connected_block_undo_logs: HashMap::new(),
    };

    REORG_TX_LOOKUP.with(|cell| *cell.borrow_mut() = Some(store));
    let removed = update_mempool_after_reorg(
        &mut pool,
        &reorg_result,
        &UtxoSet::default(),
        Some(reorg_tx_lookup),
    )
    .unwrap();
    REORG_TX_LOOKUP.with(|cell| *cell.borrow_mut() = None);
    assert!(removed.contains(&included_id));
    assert!(removed.contains(&conflict_id));
    assert!(pool.is_empty());
}

fn encode_bip34_height(height: u64) -> Vec<u8> {
    if height == 0 {
        return vec![0x00, 0xff];
    }
    let mut height_bytes = Vec::new();
    let mut n = height;
    while n > 0 {
        height_bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    if height_bytes.last().is_some_and(|&b| b & 0x80 != 0) {
        height_bytes.push(0x00);
    }
    let mut script_sig = Vec::with_capacity(1 + height_bytes.len() + 1);
    script_sig.push(height_bytes.len() as u8);
    script_sig.extend_from_slice(&height_bytes);
    if script_sig.len() < 2 {
        script_sig.push(0xff);
    }
    script_sig
}

fn regtest_coinbase(height: u64) -> Transaction {
    Transaction {
        version: 4,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: encode_bip34_height(height).into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 5_000_000_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    }
}

fn connect_regtest_chain(block_count: usize) -> (Vec<Block>, UtxoSet) {
    let (blocks, utxo, _) = connect_regtest_chain_with_undo(block_count);
    (blocks, utxo)
}

fn connect_regtest_chain_with_undo(
    block_count: usize,
) -> (Vec<Block>, UtxoSet, HashMap<Hash, BlockUndoLog>) {
    connect_regtest_blocks_from(1, block_count, [0u8; 32], 0)
}

fn connect_regtest_blocks_from(
    start_height: usize,
    end_height: usize,
    mut prev_hash: Hash,
    nonce_offset: u64,
) -> (Vec<Block>, UtxoSet, HashMap<Hash, BlockUndoLog>) {
    use blvm_consensus::block::{BlockValidationContext, connect_block};
    use blvm_consensus::mining::calculate_merkle_root;
    use blvm_consensus::segwit::Witness;

    let ctx = BlockValidationContext::for_network(Network::Regtest);
    let mut blocks = Vec::new();
    let mut utxo = UtxoSet::default();
    let mut undo_logs = HashMap::new();

    if start_height > 1 {
        panic!("start_height > 1 requires seed utxo; use connect_regtest_chain_with_undo only");
    }

    for height in start_height..=end_height {
        let coinbase = regtest_coinbase(height as u64);
        let merkle_root = calculate_merkle_root(&[coinbase.clone()]).expect("merkle");
        let block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: prev_hash,
                merkle_root,
                timestamp: 1_600_000_000 + height as u64,
                bits: 0x0300ffff,
                nonce: nonce_offset + height as u64,
            },
            transactions: vec![coinbase].into(),
        };
        let witnesses: Vec<Vec<Witness>> = block
            .transactions
            .iter()
            .map(|tx| tx.inputs.iter().map(|_| Witness::default()).collect())
            .collect();
        let (result, new_utxo, undo) =
            connect_block(&block, witnesses.as_slice(), utxo, height as u64, &ctx).unwrap();
        assert!(
            matches!(result, blvm_consensus::ValidationResult::Valid),
            "block {height} must connect on regtest: {result:?}"
        );
        undo_logs.insert(block_hash(&block.header), undo);
        utxo = new_utxo;
        prev_hash = merkle_root;
        blocks.push(block);
    }

    (blocks, utxo, undo_logs)
}

fn extend_regtest_fork(
    prefix: &[Block],
    prefix_utxo: UtxoSet,
    mut undo_store: HashMap<Hash, BlockUndoLog>,
    extra_blocks: usize,
    nonce_offset: u64,
) -> (Vec<Block>, UtxoSet, HashMap<Hash, BlockUndoLog>) {
    use blvm_consensus::block::{BlockValidationContext, connect_block};
    use blvm_consensus::mining::calculate_merkle_root;
    use blvm_consensus::segwit::Witness;

    let ctx = BlockValidationContext::for_network(Network::Regtest);
    let mut blocks = prefix.to_vec();
    let mut utxo = prefix_utxo;
    let mut prev_hash = block_hash(&prefix.last().expect("prefix").header);
    let start_height = prefix.len() + 1;

    for i in 0..extra_blocks {
        let height = start_height + i;
        let coinbase = regtest_coinbase(height as u64);
        let merkle_root = calculate_merkle_root(&[coinbase.clone()]).expect("merkle");
        let block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: prev_hash,
                merkle_root,
                timestamp: 1_600_000_000 + height as u64 + 60,
                bits: 0x0300ffff,
                nonce: nonce_offset + height as u64,
            },
            transactions: vec![coinbase].into(),
        };
        let witnesses: Vec<Vec<Witness>> = block
            .transactions
            .iter()
            .map(|tx| tx.inputs.iter().map(|_| Witness::default()).collect())
            .collect();
        let (result, new_utxo, undo) =
            connect_block(&block, witnesses.as_slice(), utxo, height as u64, &ctx).unwrap();
        assert!(matches!(result, blvm_consensus::ValidationResult::Valid));
        undo_store.insert(block_hash(&block.header), undo);
        utxo = new_utxo;
        prev_hash = merkle_root;
        blocks.push(block);
    }

    (blocks, utxo, undo_store)
}

fn witnesses_for_chain(chain: &[Block]) -> Vec<Vec<Vec<blvm_consensus::segwit::Witness>>> {
    use blvm_consensus::segwit::Witness;
    chain
        .iter()
        .map(|block| {
            block
                .transactions
                .iter()
                .map(|tx| tx.inputs.iter().map(|_| Witness::default()).collect())
                .collect()
        })
        .collect()
}

#[test]
fn test_reorganize_chain_extends_regtest_chain() {
    let (current, utxo_at_tip) = connect_regtest_chain(2);
    let (longer, _) = connect_regtest_chain(4);

    assert_eq!(current[0].header, longer[0].header);
    assert_eq!(current[1].header, longer[1].header);

    let result = reorganize_chain_simple(&longer, &current, utxo_at_tip, 2).unwrap();
    assert_eq!(result.new_height, 4);
    // Shared prefix through current tip: no disconnect, only extend with blocks 3–4.
    assert_eq!(result.reorganization_depth, 0);
    assert_eq!(result.connected_blocks.len(), 2);
}

#[test]
fn test_should_reorganize_false_for_equal_length_same_work() {
    let a = chain(3);
    let b = chain(3);
    assert!(!should_reorganize(&b, &a).unwrap());
}

fn noop_get_undo(_: &Hash) -> Option<BlockUndoLog> {
    None
}

fn noop_put_undo(_: &Hash, _: &BlockUndoLog) -> blvm_consensus::error::Result<()> {
    Ok(())
}

fn noop_get_witnesses(_: &Block) -> Option<Vec<blvm_consensus::segwit::Witness>> {
    None
}

fn noop_get_headers(_: u64) -> Option<Vec<BlockHeader>> {
    None
}

fn reorganize_chain_simple(
    new_chain: &[Block],
    current_chain: &[Block],
    utxo: UtxoSet,
    height: u64,
) -> blvm_consensus::error::Result<blvm_consensus::reorganization::ReorganizationResult> {
    let witnesses = witnesses_for_chain(new_chain);
    reorganize_chain_with_witnesses(
        new_chain,
        &witnesses,
        None,
        current_chain,
        utxo,
        height,
        None::<fn(&Block) -> Option<Vec<blvm_consensus::segwit::Witness>>>,
        None::<fn(u64) -> Option<Vec<BlockHeader>>>,
        None::<fn(&Hash) -> Option<BlockUndoLog>>,
        None::<fn(&Hash, &BlockUndoLog) -> blvm_consensus::error::Result<()>>,
        TEST_NETWORK_TIME,
        Network::Regtest,
        None,
    )
}

#[test]
fn test_reorganize_chain_with_witnesses_extends_regtest() {
    let (current, utxo_at_tip) = connect_regtest_chain(2);
    let (longer, _, _) = connect_regtest_chain_with_undo(4);
    let witnesses = witnesses_for_chain(&longer);

    let result = reorganize_chain_with_witnesses(
        &longer,
        &witnesses,
        None,
        &current,
        utxo_at_tip,
        2,
        Some(noop_get_witnesses),
        Some(noop_get_headers),
        Some(noop_get_undo),
        Some(noop_put_undo),
        TEST_NETWORK_TIME,
        Network::Regtest,
        None,
    )
    .unwrap();

    assert_eq!(result.new_height, 4);
    assert_eq!(result.reorganization_depth, 0);
    assert_eq!(result.connected_blocks.len(), 2);
}

#[test]
fn test_reorganize_chain_with_witnesses_uses_undo_callbacks() {
    let (current, utxo_at_tip, current_undo) = connect_regtest_chain_with_undo(2);
    let (longer, _, longer_undo) = connect_regtest_chain_with_undo(4);
    let witnesses = witnesses_for_chain(&longer);

    let store = RefCell::new(current_undo);
    store.borrow_mut().extend(longer_undo);

    let get_undo = |hash: &Hash| store.borrow().get(hash).cloned();
    let put_undo = |hash: &Hash, log: &BlockUndoLog| {
        store.borrow_mut().insert(*hash, log.clone());
        Ok(())
    };

    let result = reorganize_chain_with_witnesses(
        &longer,
        &witnesses,
        None,
        &current,
        utxo_at_tip,
        2,
        Some(noop_get_witnesses),
        Some(noop_get_headers),
        Some(get_undo),
        Some(put_undo),
        TEST_NETWORK_TIME,
        Network::Regtest,
        None,
    )
    .unwrap();

    assert_eq!(result.new_height, 4);
    assert!(!result.connected_block_undo_logs.is_empty());
}

#[test]
#[should_panic(expected = "witness count")]
fn test_reorganize_chain_with_witnesses_rejects_witness_block_mismatch() {
    let (current, utxo_at_tip) = connect_regtest_chain(2);
    let (longer, _, _) = connect_regtest_chain_with_undo(4);

    let _ = reorganize_chain_with_witnesses(
        &longer,
        &[],
        None,
        &current,
        utxo_at_tip,
        2,
        Some(noop_get_witnesses),
        Some(noop_get_headers),
        None::<fn(&Hash) -> Option<BlockUndoLog>>,
        None::<fn(&Hash, &BlockUndoLog) -> blvm_consensus::error::Result<()>>,
        TEST_NETWORK_TIME,
        Network::Regtest,
        None,
    );
}

#[test]
fn test_reorganize_chain_rejects_empty_new_chain() {
    let (current, utxo) = connect_regtest_chain(2);
    let result = reorganize_chain_simple(&[], &current, utxo, 2);
    assert!(result.is_err());
}

#[test]
fn test_update_mempool_after_reorg_removes_spent_prevout_without_block_include() {
    use blvm_consensus::block::calculate_tx_id;
    use blvm_consensus::mempool::Mempool;
    use blvm_consensus::reorganization::{ReorganizationResult, update_mempool_after_reorg};

    let spent_prevout = OutPoint {
        hash: [0x88; 32],
        index: 0,
    };
    let mempool_tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: spent_prevout,
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 500,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let mempool_id = calculate_tx_id(&mempool_tx);

    let connected_spend = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: spent_prevout,
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 400,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1_231_006_505,
            bits: 0x0300ffff,
            nonce: 0,
        },
        transactions: vec![connected_spend].into(),
    };

    let mut pool = Mempool::new();
    pool.insert(mempool_id);

    let mut store = HashMap::new();
    store.insert(mempool_id, mempool_tx);

    let reorg_result = ReorganizationResult {
        new_utxo_set: UtxoSet::default(),
        new_height: 1,
        common_ancestor: block.header.clone(),
        disconnected_blocks: vec![],
        connected_blocks: vec![block],
        reorganization_depth: 1,
        connected_block_undo_logs: HashMap::new(),
    };

    REORG_TX_LOOKUP.with(|cell| *cell.borrow_mut() = Some(store));
    let removed = update_mempool_after_reorg(
        &mut pool,
        &reorg_result,
        &UtxoSet::default(),
        Some(reorg_tx_lookup),
    )
    .unwrap();
    REORG_TX_LOOKUP.with(|cell| *cell.borrow_mut() = None);

    assert!(removed.contains(&mempool_id));
    assert!(!pool.contains(&mempool_id));
}

#[test]
fn test_update_mempool_after_reorg_readds_disconnected_tx() {
    use blvm_consensus::block::calculate_tx_id;
    use blvm_consensus::reorganization::{
        ReorgMempoolReaddParams, ReorganizationResult, update_mempool_after_reorg_with_readd,
    };

    #[path = "test_helpers.rs"]
    mod test_helpers;
    use test_helpers::{create_test_tx, create_test_utxo};

    let (utxo_set, _) = create_test_utxo(10_000);
    let tx = create_test_tx(8_500, None, None, None);
    let tx_id = calculate_tx_id(&tx);

    let disconnected = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1_600_000_000,
            bits: 0x0300ffff,
            nonce: 1,
        },
        transactions: vec![tx].into(),
    };

    let reorg_result = ReorganizationResult {
        new_utxo_set: utxo_set.clone(),
        new_height: 100,
        common_ancestor: disconnected.header.clone(),
        disconnected_blocks: vec![disconnected],
        connected_blocks: vec![],
        reorganization_depth: 1,
        connected_block_undo_logs: HashMap::new(),
    };

    let mut pool = Mempool::new();
    let readd = ReorgMempoolReaddParams {
        height: 100,
        time_context: None,
        network: Network::Regtest,
    };

    let (removed, readded) = update_mempool_after_reorg_with_readd(
        &mut pool,
        &reorg_result,
        &utxo_set,
        None::<fn(&Hash) -> Option<Transaction>>,
        &readd,
        None::<fn(&Hash) -> Option<Vec<blvm_consensus::segwit::Witness>>>,
    )
    .unwrap();

    assert!(removed.is_empty());
    assert!(readded.contains(&tx_id));
    assert!(pool.contains(&tx_id));
}

#[test]
fn test_reorganize_fork_disconnects_tip_with_undo_logs() {
    let (current, utxo_at_3, mut undo_store) = connect_regtest_chain_with_undo(3);
    let prefix = current[0..2].to_vec();
    let (_, utxo_at_2, _) = connect_regtest_chain_with_undo(2);

    let (longer, _, longer_undo) =
        extend_regtest_fork(&prefix, utxo_at_2, HashMap::new(), 2, 10_000);
    undo_store.extend(longer_undo);

    let store = RefCell::new(undo_store);
    let get_undo = |hash: &Hash| store.borrow().get(hash).cloned();
    let put_undo = |hash: &Hash, log: &BlockUndoLog| {
        store.borrow_mut().insert(*hash, log.clone());
        Ok(())
    };

    let witnesses = witnesses_for_chain(&longer);
    let result = reorganize_chain_with_witnesses(
        &longer,
        &witnesses,
        None,
        &current,
        utxo_at_3,
        3,
        Some(noop_get_witnesses),
        Some(noop_get_headers),
        Some(get_undo),
        Some(put_undo),
        TEST_NETWORK_TIME,
        Network::Regtest,
        None,
    )
    .unwrap();

    assert_eq!(result.new_height, 4);
    // Fork at height 2 (index 1): disconnect one stale tip block, connect two fork blocks.
    assert_eq!(result.reorganization_depth, 1);
    assert_eq!(result.disconnected_blocks.len(), 1);
    assert_eq!(result.connected_blocks.len(), 2);
}

#[test]
fn test_calculate_chain_work_empty_chain_is_zero() {
    assert_eq!(
        calculate_chain_work(&[]).unwrap(),
        blvm_consensus::pow::U256::zero()
    );
}

#[test]
fn test_reorganize_chain_empty_current_chain_errors() {
    let (_, utxo) = connect_regtest_chain(1);
    let longer = chain(2);
    assert!(reorganize_chain_simple(&longer, &[], utxo, 0).is_err());
}

#[test]
fn test_should_reorganize_false_when_new_chain_shorter() {
    let longer = chain(4);
    let shorter = chain(2);
    assert!(!should_reorganize(&shorter, &longer).unwrap());
}

#[test]
fn test_should_reorganize_prefers_more_work_at_equal_length() {
    let harder = (0..3)
        .map(|i| coinbase_block(i as u8, 0x0300ffff))
        .collect::<Vec<_>>();
    let easier = (0..3)
        .map(|i| coinbase_block(i as u8, 0x0400ffff))
        .collect::<Vec<_>>();
    let harder_work = calculate_chain_work(&harder).unwrap();
    let easier_work = calculate_chain_work(&easier).unwrap();
    assert!(harder_work > easier_work);
    assert!(should_reorganize(&harder, &easier).unwrap());
    assert!(!should_reorganize(&easier, &harder).unwrap());
}

#[test]
fn test_reorganize_chain_rejects_unrelated_chains() {
    let current = chain(2);
    let mut unrelated = chain(3);
    unrelated[0].header.nonce = 99;
    let (_, utxo) = connect_regtest_chain(2);
    assert!(reorganize_chain_simple(&unrelated, &current, utxo, 2).is_err());
}

#[test]
fn test_calculate_chain_work_rejects_target_too_large() {
    let block = coinbase_block(0, 0x2100_ffff);
    assert!(calculate_chain_work(&[block]).is_err());
}

#[test]
#[allow(deprecated)]
fn test_reorganize_chain_rejects_segwit_without_witnesses() {
    use blvm_consensus::opcodes::OP_0;

    let mut spk = vec![OP_0, 0x14];
    spk.extend([0u8; 20]);
    let segwit_tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0xab; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1_000,
            script_pubkey: spk.into(),
        }]
        .into(),
        lock_time: 0,
    };

    let coinbase = coinbase_block(0, 0x0300ffff).transactions[0].clone();
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [2; 32],
            timestamp: 1_700_000_000,
            bits: 0x0300ffff,
            nonce: 1,
        },
        transactions: vec![coinbase, segwit_tx].into(),
    };

    let result = reorganize_chain(&[block], &[], UtxoSet::default(), 0, Network::Regtest);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("reorganize_chain_with_witnesses")
    );
}
