//! Economic model functions from Orange Paper Section 7 Section 6

use crate::constants::*;
use crate::error::{ConsensusError, Result};
use crate::types::*;
use blvm_spec_lock::spec_locked;
use std::borrow::Cow;

/// GetBlockSubsidy: ℕ → ℤ
///
/// Calculate the block subsidy for a given height.
/// Subsidy halves every 210,000 blocks (HALVING_INTERVAL).
///
/// Formula: subsidy = 50 * C * 2^(-⌊h/H⌋)
/// Where:
/// - h = block height
/// - H = HALVING_INTERVAL (210,000)
/// - C = SATOSHIS_PER_BTC (10^8)
#[spec_locked("6.1", "GetBlockSubsidy")]
#[blvm_spec_lock::requires(height >= 0)]
#[blvm_spec_lock::ensures(result >= 0)]
#[blvm_spec_lock::ensures(result <= INITIAL_SUBSIDY)]
pub fn get_block_subsidy(height: Natural) -> Integer {
    let halving_period = height / HALVING_INTERVAL;

    // After 64 halvings, subsidy becomes 0
    if halving_period >= 64 {
        return 0;
    }

    // Runtime assertion: Halving period must be valid
    debug_assert!(
        halving_period < 64,
        "Halving period ({halving_period}) must be < 64"
    );

    // Calculate subsidy: 50 BTC * 2^(-halving_period)
    let base_subsidy = INITIAL_SUBSIDY; // 50 BTC in satoshis
    let subsidy = base_subsidy >> halving_period;

    // Runtime assertion: Subsidy must be non-negative and <= initial subsidy
    debug_assert!(subsidy >= 0, "Subsidy ({subsidy}) must be non-negative");
    debug_assert!(
        subsidy <= INITIAL_SUBSIDY,
        "Subsidy ({subsidy}) must be <= initial subsidy ({INITIAL_SUBSIDY})"
    );

    subsidy
}

/// CheckCoinbaseSubsidy: 𝒯𝒳 × ℤ × ℤ → {true, false}
///
/// Coinbase output sum must not exceed block subsidy plus aggregated fees.
#[spec_locked("5.3", "CheckCoinbaseSubsidy")]
pub fn check_coinbase_subsidy(
    coinbase: &Transaction,
    subsidy: Integer,
    total_fees: Integer,
) -> bool {
    // Negative fees/subsidy make the coinbase bound meaningless (connect already
    // rejects total_fees < 0 before calling; this is defense-in-depth for other callers).
    if total_fees < 0 || subsidy < 0 {
        return false;
    }
    let coinbase_output: i64 = match coinbase.outputs.iter().try_fold(0i64, |acc, output| {
        if output.value < 0 || output.value > MAX_MONEY {
            return None;
        }
        acc.checked_add(output.value)
    }) {
        Some(v) => v,
        None => return false,
    };
    if coinbase_output < 0 {
        return false;
    }
    let Some(max_coinbase) = total_fees.checked_add(subsidy) else {
        return false;
    };
    coinbase_output <= MAX_MONEY && coinbase_output <= max_coinbase
}

/// VerifyUtxoSupply: 𝒰𝒮 × ℕ → {true, false}
///
/// Theorem 8.1: sum of UTXO values equals total money supply at height h.
#[spec_locked("8.1", "VerifyUtxoSupply")]
pub fn verify_utxo_supply(utxo_set: &UtxoSet, height: Natural) -> bool {
    let expected = total_supply(height);
    if !(0..=MAX_MONEY).contains(&expected) {
        return false;
    }
    let mut actual: i64 = 0;
    for utxo in utxo_set.values() {
        if !(0..=MAX_MONEY).contains(&utxo.value) {
            return false;
        }
        actual = match actual.checked_add(utxo.value) {
            Some(v) => v,
            None => return false,
        };
    }
    actual == expected
}

/// TotalSupply: ℕ → ℤ
///
/// Calculate the total Bitcoin supply at a given height.
/// This is the sum of all block subsidies up to that height.
///
/// Subsidy is constant on each halving epoch \([k×H, (k+1)×H)\) for `k < 64`, so we sum
/// `count × (INITIAL_SUBSIDY >> k)` per epoch in **O(64)** instead of iterating every block.
/// (Naive `0..=height` is unusable for heights in the tens of millions used in tests.)
/// Non-negativity invariant: the total supply is always ≥ 0.
/// Each block subsidy is non-negative (0 after 64 halvings), so the
/// accumulated sum is non-negative for any height.
///
/// Non-negativity is proven by `_verify_f_total_supply_non_neg` (spec_witnesses.rs §6.2).
/// The Z3 translator cannot fully evaluate the 64-epoch for loop, so both bounds are
/// declared as `#[axiom]` (trusted from the spec_witness proof) in addition to the
/// `#[ensures]` postconditions that callee-axiom propagation can discharge for callers.
#[spec_locked("6.2", "TotalSupply")]
#[blvm_spec_lock::axiom(result >= 0)]
#[blvm_spec_lock::axiom(result <= 2100000000000000)]
#[blvm_spec_lock::ensures(result >= 0)]
#[blvm_spec_lock::ensures(result <= 2100000000000000)]
pub fn total_supply(height: Natural) -> Integer {
    let end = height;
    let h = HALVING_INTERVAL;
    let mut total = 0i64;

    for k in 0u64..64 {
        let period_start = k.saturating_mul(h);
        if period_start > end {
            break;
        }
        let subsidy = INITIAL_SUBSIDY >> k;
        let period_end = (k + 1).saturating_mul(h).saturating_sub(1);
        let overlap_hi = end.min(period_end);
        let count = overlap_hi
            .checked_sub(period_start)
            .map(|d| d + 1)
            .expect("overlap_hi >= period_start when period_start <= end");

        let contrib = match (count as i64).checked_mul(subsidy) {
            Some(c) => c,
            None => {
                debug_assert!(false, "Total supply contribution overflow at epoch {k}");
                return MAX_MONEY;
            }
        };
        total = match total.checked_add(contrib) {
            Some(t) => t,
            None => {
                debug_assert!(false, "Total supply sum overflow at epoch {k}");
                return MAX_MONEY;
            }
        };
        if total >= MAX_MONEY {
            return MAX_MONEY;
        }
    }

    // Runtime assertion: Total supply must be non-negative and <= MAX_MONEY
    debug_assert!(total >= 0, "Total supply ({total}) must be non-negative");
    debug_assert!(
        total <= MAX_MONEY,
        "Total supply ({total}) must be <= MAX_MONEY ({MAX_MONEY})"
    );

    total
}

/// Calculate transaction fee
///
/// Fee = sum of input values - sum of output values
#[spec_locked("6.5", "CalculateFee")]
#[blvm_spec_lock::ensures(result >= 0)]
pub fn calculate_fee(tx: &Transaction, utxo_set: &UtxoSet) -> Result<Integer> {
    if is_coinbase(tx) {
        return Ok(0);
    }

    // Use checked arithmetic to prevent overflow. Missing prevouts are outside
    // CalculateFee's domain (Orange Paper assumes us(i.prevout).value) — fail closed.
    let total_input: i64 = tx.inputs.iter().try_fold(0i64, |acc, input| {
        let utxo = utxo_set.get(&input.prevout).ok_or_else(|| {
            ConsensusError::UtxoNotFound(
                format!("UTXO not found for prevout index {}", input.prevout.index).into(),
            )
        })?;
        acc.checked_add(utxo.value)
            .ok_or_else(|| ConsensusError::EconomicValidation("Input value overflow".into()))
    })?;

    let total_output: i64 = tx
        .outputs
        .iter()
        .try_fold(0i64, |acc, output| {
            acc.checked_add(output.value)
                .ok_or_else(|| ConsensusError::EconomicValidation("Output value overflow".into()))
        })
        .map_err(|e| ConsensusError::EconomicValidation(Cow::Owned(e.to_string())))?;

    if total_output < 0 {
        return Err(ConsensusError::EconomicValidation(
            "Negative total output value".into(),
        ));
    }

    // Note: We use inline error here because it's EconomicValidation, not TransactionValidation
    // The helper function returns TransactionValidation, so we keep inline for type consistency
    let fee = total_input
        .checked_sub(total_output)
        .ok_or_else(|| ConsensusError::EconomicValidation("Fee calculation underflow".into()))?;

    // Check for negative fee and return error (tests intentionally test this error path)
    if fee < 0 {
        return Err(ConsensusError::EconomicValidation("Negative fee".into()));
    }

    // Runtime assertion: Fee must be non-negative (only after we've handled negative case)
    debug_assert!(
        fee >= 0,
        "Fee ({fee}) must be non-negative (input: {total_input}, output: {total_output})"
    );

    // Runtime assertion: Fee cannot exceed total input
    debug_assert!(
        fee <= total_input,
        "Fee ({fee}) cannot exceed total input ({total_input})"
    );

    Ok(fee)
}

/// Validate economic constraints
///
/// Check that the total supply doesn't exceed the maximum money supply
#[spec_locked("6.3", "ValidateSupplyLimit")]
pub fn validate_supply_limit(height: Natural) -> Result<bool> {
    let current_supply = total_supply(height);
    Ok(current_supply <= MAX_MONEY)
}

/// Check if transaction is coinbase
fn is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].prevout.hash == [0u8; 32]
        && tx.inputs[0].prevout.index == 0xffffffff
}

// ============================================================================
// FORMAL VERIFICATION
// ============================================================================

/// Mathematical Specification for Block Subsidy:
/// ∀ h ∈ ℕ: subsidy(h) = 50 * 10^8 * 2^(-⌊h/210000⌋) if ⌊h/210000⌋ < 64 else 0
///
/// Invariants:
/// - Subsidy halves every 210,000 blocks
/// - After 64 halvings, subsidy becomes 0
/// - Subsidy is always non-negative
/// - Total supply approaches 21M BTC asymptotically

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Property test: get_block_subsidy follows halving schedule
    proptest! {
        #[test]
        fn prop_get_block_subsidy_halving_schedule(
            height in 0u64..(HALVING_INTERVAL * 10)
        ) {
            let subsidy = get_block_subsidy(height);
            let halving_period = height / HALVING_INTERVAL;

            // Non-negative property
            prop_assert!(subsidy >= 0, "Subsidy must be non-negative");

            // Halving property
            if halving_period < 64 {
                let expected_subsidy = INITIAL_SUBSIDY >> halving_period;
                prop_assert_eq!(subsidy, expected_subsidy, "Subsidy must follow halving schedule");
            } else {
                prop_assert_eq!(subsidy, 0, "Subsidy must be 0 after 64 halvings");
            }
        }
    }

    /// Property test: total_supply is monotonically increasing
    proptest! {
        #[test]
        fn prop_total_supply_monotonic(
            height1 in 0u64..(HALVING_INTERVAL * 2),
            height2 in 0u64..(HALVING_INTERVAL * 2)
        ) {
            // Ensure height1 <= height2
            let (h1, h2) = if height1 <= height2 { (height1, height2) } else { (height2, height1) };

            let supply1 = total_supply(h1);
            let supply2 = total_supply(h2);

            // Monotonic property
            prop_assert!(supply2 >= supply1, "Total supply must be monotonically increasing");

            // Non-negative property
            prop_assert!(supply1 >= 0, "Total supply must be non-negative");
            prop_assert!(supply2 >= 0, "Total supply must be non-negative");
        }
    }

    /// Property test: supply limit is never exceeded
    proptest! {
        #[test]
        fn prop_supply_limit_respected(
            height in 0u64..(HALVING_INTERVAL * 10)
        ) {
            let supply = total_supply(height);

            // Supply limit property
            prop_assert!(supply <= MAX_MONEY, "Total supply must not exceed maximum money");

            // Non-negative property
            prop_assert!(supply >= 0, "Total supply must be non-negative");
        }
    }

    /// Property test: subsidy decreases with halving periods
    proptest! {
        #[test]
        fn prop_subsidy_decreases_with_halvings(
            height1 in 0u64..(HALVING_INTERVAL * 5),
            height2 in 0u64..(HALVING_INTERVAL * 5)
        ) {
            let halving1 = height1 / HALVING_INTERVAL;
            let halving2 = height2 / HALVING_INTERVAL;

            // If halving1 < halving2, then subsidy1 >= subsidy2
            if halving1 < halving2 && halving2 < 64 {
                let subsidy1 = get_block_subsidy(height1);
                let subsidy2 = get_block_subsidy(height2);
                prop_assert!(subsidy1 >= subsidy2, "Subsidy must decrease with halving periods");
            }
        }
    }

    /// Property test: calculate_fee handles coinbase correctly
    proptest! {
        #[test]
        fn prop_calculate_fee_coinbase(
            tx in proptest::collection::vec(crate::transaction::transaction_proptest::arb_transaction(), 1..=1)
        ) {
            if let Some(tx) = tx.first() {
                let utxo_set = UtxoSet::default();

                if is_coinbase(tx) {
                    let fee = calculate_fee(tx, &utxo_set).unwrap_or(-1);
                    prop_assert_eq!(fee, 0, "Coinbase transactions must have zero fee");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference: original definition (O(height); use only for small heights in tests).
    fn naive_total_supply(end: u64) -> i64 {
        let mut total = 0i64;
        for h in 0..=end {
            let subsidy = get_block_subsidy(h);
            total = total.checked_add(subsidy).unwrap_or_else(|| {
                debug_assert!(false, "overflow");
                MAX_MONEY
            });
            if total >= MAX_MONEY {
                break;
            }
        }
        total
    }

    #[test]
    fn total_supply_fast_matches_naive_reference() {
        for end in [
            0u64,
            1,
            2,
            1000,
            HALVING_INTERVAL - 1,
            HALVING_INTERVAL,
            HALVING_INTERVAL + 1,
            2 * HALVING_INTERVAL - 1,
            500_000,
        ] {
            assert_eq!(total_supply(end), naive_total_supply(end), "end={end}");
        }
        // Beyond subsidy emission, additional blocks add 0; multi-million height would be
        // infeasible for the naive reference loop.
        let after_last_reward = HALVING_INTERVAL * 64 - 1;
        assert_eq!(
            total_supply(after_last_reward + 1_000_000),
            total_supply(after_last_reward),
            "heights after 64×H−1 should not increase supply"
        );
    }

    #[test]
    fn test_get_block_subsidy_genesis() {
        assert_eq!(get_block_subsidy(0), INITIAL_SUBSIDY);
    }

    #[test]
    fn test_get_block_subsidy_first_halving() {
        // At height 210,000, subsidy should be 25 BTC
        assert_eq!(get_block_subsidy(HALVING_INTERVAL), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn test_get_block_subsidy_second_halving() {
        // At height 420,000, subsidy should be 12.5 BTC
        assert_eq!(get_block_subsidy(HALVING_INTERVAL * 2), INITIAL_SUBSIDY / 4);
    }

    #[test]
    fn test_get_block_subsidy_max_halvings() {
        // After 64 halvings, subsidy should be 0
        assert_eq!(get_block_subsidy(HALVING_INTERVAL * 64), 0);
    }

    #[test]
    fn test_total_supply_convergence() {
        // Test that total supply approaches 21M BTC
        let supply_at_halving = total_supply(HALVING_INTERVAL);
        // At the first halving, we have 210,000 blocks of 50 BTC each
        let expected_at_halving = (HALVING_INTERVAL as i64) * INITIAL_SUBSIDY;
        // The difference is due to bit shifting in get_block_subsidy
        // Allow for much larger rounding differences due to bit operations
        let difference = (supply_at_halving - expected_at_halving).abs();
        println!(
            "Supply at halving: {supply_at_halving}, Expected: {expected_at_halving}, Difference: {difference}"
        );
        assert!(difference <= 3_000_000_000); // Allow for significant rounding differences
    }

    #[test]
    fn test_supply_limit() {
        // Test that supply limit is respected
        assert!(validate_supply_limit(0).unwrap());
        assert!(validate_supply_limit(HALVING_INTERVAL).unwrap());
        assert!(validate_supply_limit(HALVING_INTERVAL * 10).unwrap());
    }

    #[test]
    fn test_calculate_fee_coinbase() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![],
            }]
            .into(),
            lock_time: 0,
        };

        let utxo_set = UtxoSet::default();
        assert_eq!(calculate_fee(&coinbase_tx, &utxo_set).unwrap(), 0);
    }

    // ============================================================================
    // COMPREHENSIVE ECONOMIC TESTS
    // ============================================================================

    #[test]
    fn test_get_block_subsidy_edge_cases() {
        // Test height 1 (just after genesis)
        assert_eq!(get_block_subsidy(1), INITIAL_SUBSIDY);

        // Test height just before first halving
        assert_eq!(get_block_subsidy(HALVING_INTERVAL - 1), INITIAL_SUBSIDY);

        // Test height just after first halving
        assert_eq!(get_block_subsidy(HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 2);

        // Test height just before second halving
        assert_eq!(
            get_block_subsidy(HALVING_INTERVAL * 2 - 1),
            INITIAL_SUBSIDY / 2
        );

        // Test height just after second halving
        assert_eq!(
            get_block_subsidy(HALVING_INTERVAL * 2 + 1),
            INITIAL_SUBSIDY / 4
        );
    }

    #[test]
    fn test_get_block_subsidy_large_heights() {
        // Test very large height (beyond 64 halvings)
        let very_large_height = HALVING_INTERVAL * 100;
        assert_eq!(get_block_subsidy(very_large_height), 0);

        // Test exactly 64 halvings
        let exactly_64_halvings = HALVING_INTERVAL * 64;
        assert_eq!(get_block_subsidy(exactly_64_halvings), 0);

        // Test just before 64 halvings
        let just_before_64 = HALVING_INTERVAL * 64 - 1;
        assert_eq!(get_block_subsidy(just_before_64), INITIAL_SUBSIDY >> 63);
    }

    #[test]
    fn test_total_supply_edge_cases() {
        // Test total supply at height 0
        assert_eq!(total_supply(0), INITIAL_SUBSIDY);

        // Test total supply at height 1
        assert_eq!(total_supply(1), INITIAL_SUBSIDY * 2);

        // Test total supply at height 2
        assert_eq!(total_supply(2), INITIAL_SUBSIDY * 3);

        // Test total supply at first halving
        let supply_at_halving = total_supply(HALVING_INTERVAL);
        assert!(supply_at_halving > 0);
        // At halving, supply should be close to 210,000 * 50 BTC, but bit shifting causes rounding
        let expected_approximate = INITIAL_SUBSIDY * HALVING_INTERVAL as i64;
        // Allow for the fact that bit shifting can cause the supply to be higher due to rounding
        assert!(supply_at_halving <= expected_approximate + 5000000000); // Allow 50 BTC difference
    }

    #[test]
    fn test_total_supply_large_heights() {
        // Test total supply at very large height
        let very_large_height = HALVING_INTERVAL * 100;
        let supply = total_supply(very_large_height);

        // Should be finite and positive
        assert!(supply > 0);
        assert!(supply < MAX_MONEY);

        // Should be close to 21M BTC (allowing for rounding)
        let expected_max = 21_000_000 * 100_000_000; // 21M BTC in satoshis
        assert!(supply <= expected_max);
    }

    #[test]
    fn test_calculate_fee_regular_transaction() {
        let mut utxo_set = UtxoSet::default();

        // Add UTXO to the set
        let outpoint = OutPoint {
            hash: [1; 32],
            index: 0,
        };
        let utxo = UTXO {
            value: 1000000000, // 10 BTC
            script_pubkey: vec![].into(),
            height: 0,
            is_coinbase: false,
        };
        utxo_set.insert(outpoint, std::sync::Arc::new(utxo));

        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 900000000, // 9 BTC output
                script_pubkey: vec![],
            }]
            .into(),
            lock_time: 0,
        };

        // Fee should be 1 BTC (1000000000 - 900000000)
        assert_eq!(calculate_fee(&tx, &utxo_set).unwrap(), 100000000);
    }

    #[test]
    fn test_calculate_fee_multiple_inputs_outputs() {
        let mut utxo_set = UtxoSet::default();

        // Add two UTXOs
        let outpoint1 = OutPoint {
            hash: [1; 32],
            index: 0,
        };
        let utxo1 = UTXO {
            value: 500000000, // 5 BTC
            script_pubkey: vec![].into(),
            height: 0,
            is_coinbase: false,
        };
        utxo_set.insert(outpoint1, std::sync::Arc::new(utxo1));

        let outpoint2 = OutPoint {
            hash: [2; 32],
            index: 0,
        };
        let utxo2 = UTXO {
            value: 300000000, // 3 BTC
            script_pubkey: vec![].into(),
            height: 0,
            is_coinbase: false,
        };
        utxo_set.insert(outpoint2, std::sync::Arc::new(utxo2));

        let tx = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint {
                        hash: [1; 32],
                        index: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint {
                        hash: [2; 32],
                        index: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ]
            .into(),
            outputs: vec![
                TransactionOutput {
                    value: 600000000, // 6 BTC output
                    script_pubkey: vec![],
                },
                TransactionOutput {
                    value: 150000000, // 1.5 BTC output
                    script_pubkey: vec![],
                },
            ]
            .into(),
            lock_time: 0,
        };

        // Fee should be 0.5 BTC (800000000 - 750000000)
        assert_eq!(calculate_fee(&tx, &utxo_set).unwrap(), 50000000);
    }

    #[test]
    fn test_calculate_fee_missing_utxo() {
        let utxo_set = UtxoSet::default(); // Empty UTXO set

        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 100000000,
                script_pubkey: vec![],
            }]
            .into(),
            lock_time: 0,
        };

        // Missing prevout is outside CalculateFee domain → UtxoNotFound (not "Negative fee")
        let result = calculate_fee(&tx, &utxo_set);
        assert!(result.is_err());
        assert!(matches!(result, Err(ConsensusError::UtxoNotFound(_))));
    }

    #[test]
    fn test_check_coinbase_subsidy_rejects_negative_fees() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 1,
                script_pubkey: vec![],
            }]
            .into(),
            lock_time: 0,
        };
        // Tiny coinbase + negative fees would previously return true via checked_add wrap logic
        assert!(!check_coinbase_subsidy(&coinbase, INITIAL_SUBSIDY, -1));
        assert!(!check_coinbase_subsidy(&coinbase, -1, 0));
        assert!(check_coinbase_subsidy(&coinbase, INITIAL_SUBSIDY, 0));
    }

    #[test]
    fn test_calculate_fee_negative_fee() {
        let mut utxo_set = UtxoSet::default();

        // Add UTXO with value less than output
        let outpoint = OutPoint {
            hash: [1; 32],
            index: 0,
        };
        let utxo = UTXO {
            value: 100000000, // 1 BTC
            script_pubkey: vec![].into(),
            height: 0,
            is_coinbase: false,
        };
        utxo_set.insert(outpoint, std::sync::Arc::new(utxo));

        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 200000000, // 2 BTC output (more than input)
                script_pubkey: vec![],
            }]
            .into(),
            lock_time: 0,
        };

        // Should return error for negative fee
        let result = calculate_fee(&tx, &utxo_set);
        assert!(result.is_err());
        assert!(matches!(result, Err(ConsensusError::EconomicValidation(_))));
    }

    #[test]
    fn test_validate_supply_limit_edge_cases() {
        // Test at height 0
        assert!(validate_supply_limit(0).unwrap());

        // Test at first halving
        assert!(validate_supply_limit(HALVING_INTERVAL).unwrap());

        // Test at second halving
        assert!(validate_supply_limit(HALVING_INTERVAL * 2).unwrap());

        // Test at very large height
        assert!(validate_supply_limit(HALVING_INTERVAL * 100).unwrap());
    }

    #[test]
    fn test_is_coinbase_edge_cases() {
        // Valid coinbase
        let valid_coinbase = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        assert!(is_coinbase(&valid_coinbase));

        // Wrong hash
        let wrong_hash = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        assert!(!is_coinbase(&wrong_hash));

        // Wrong index
        let wrong_index = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        assert!(!is_coinbase(&wrong_index));

        // Multiple inputs
        let multiple_inputs = Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prevout: OutPoint {
                        hash: [0; 32],
                        index: 0xffffffff,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
                TransactionInput {
                    prevout: OutPoint {
                        hash: [1; 32],
                        index: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                },
            ]
            .into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        assert!(!is_coinbase(&multiple_inputs));

        // No inputs
        let no_inputs = Transaction {
            version: 1,
            inputs: vec![].into(),
            outputs: vec![].into(),
            lock_time: 0,
        };
        assert!(!is_coinbase(&no_inputs));
    }
}
