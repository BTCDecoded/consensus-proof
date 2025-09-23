//! Bitcoin consensus constants from Orange Paper

/// Maximum money supply: 21,000,000 BTC in satoshis
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// Maximum transaction size: 1MB
pub const MAX_TX_SIZE: usize = 1_000_000;

/// Maximum block size: 4MB (with SegWit)
pub const MAX_BLOCK_SIZE: usize = 4_000_000;

/// Maximum number of inputs per transaction
pub const MAX_INPUTS: usize = 1000;

/// Maximum number of outputs per transaction
pub const MAX_OUTPUTS: usize = 1000;

/// Maximum script length
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum stack size during script execution
pub const MAX_STACK_SIZE: usize = 1000;

/// Maximum number of operations in script
pub const MAX_SCRIPT_OPS: usize = 201;

/// Halving interval: 210,000 blocks
pub const HALVING_INTERVAL: u64 = 210_000;

/// Initial block subsidy: 50 BTC
pub const INITIAL_SUBSIDY: i64 = 50 * 100_000_000;

/// Satoshis per BTC
pub const SATOSHIS_PER_BTC: i64 = 100_000_000;

/// Difficulty adjustment interval: 2016 blocks
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Target time per block: 10 minutes
pub const TARGET_TIME_PER_BLOCK: u64 = 600;

/// Maximum target (minimum difficulty)
pub const MAX_TARGET: u32 = 0x1d00ffff;

/// Minimum target (maximum difficulty) - Bitcoin's genesis target
pub const MIN_TARGET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Lock time threshold: transactions with lock time < this are block height
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Sequence number for final transaction
pub const SEQUENCE_FINAL: u32 = 0xffffffff;

/// Sequence number for RBF
pub const SEQUENCE_RBF: u32 = 0xfffffffe;
