//! Zava — 8-week savings discipline proof (Medium tier).
//!
//! Proves: "I made 8 deposits, each ≥ `min_weekly_amount`, with no gap
//! exceeding 8 days between consecutive deposits, and I know the secret
//! behind each on-chain commitment."
//!
//! Reveals: how many weeks (8), the threshold claimed, and one nullifier
//!          + one commitment per deposit.
//! Hides:   the secret, the actual amounts, the timestamps, the wallet.

use std;

// One per tier.
global N: u32 = 8;

// 8 days in seconds. Deposits must be ≤ 8 days apart and strictly increasing.
global MAX_GAP_SECS: u64 = 691200;

fn main(
    // -------- Private witness --------
    secret: Field,
    weekly_amounts: [u64; N],
    deposit_timestamps: [u64; N],
    week_numbers: [u32; N],

    // -------- Public inputs ----------
    min_weekly_amount: pub u64,
    consistency_weeks: pub u32,
    commitments: pub [Field; N],
    nullifiers: pub [Field; N],
) {
    // Bind this circuit to its tier — a 12-week or 24-week claim cannot
    // route to the 8-week verifier even if the caller tries.
    assert(consistency_weeks == N);

    for i in 0..N {
        // 1. Amount meets the claimed threshold.
        assert(weekly_amounts[i] >= min_weekly_amount);

        // 2. Commitment binding: hash(secret, amount) matches the public
        //    commitment, which the verifier contract checks against on-chain
        //    storage. This is what stops a prover from inflating amounts.
        let expected_commitment =
            std::hash::pedersen_hash([secret, weekly_amounts[i] as Field]);
        assert(expected_commitment == commitments[i]);

        // 3. Nullifier binding: hash(secret, week_number) matches the public
        //    nullifier; the verifier checks it exists on-chain.
        let expected_nullifier =
            std::hash::pedersen_hash([secret, week_numbers[i] as Field]);
        assert(expected_nullifier == nullifiers[i]);
    }

    for i in 1..N {
        // 4. Week numbers strictly increasing (no replay, no reordering).
        assert(week_numbers[i] > week_numbers[i - 1]);

        // 5. Timestamp gap > 0 and ≤ 8 days.
        let gap = deposit_timestamps[i] - deposit_timestamps[i - 1];
        assert(gap > 0);
        assert(gap <= MAX_GAP_SECS);
    }
}

#[test]
fn test_valid_8_week_proof() {
    let secret: Field = 12345;
    let amounts: [u64; 8] = [
        400_000_000, 400_000_000, 500_000_000, 450_000_000,
        420_000_000, 480_000_000, 410_000_000, 460_000_000,
    ];
    let timestamps: [u64; 8] = [
        1_700_000_000,
        1_700_604_800, // +7 days
        1_701_209_600,
        1_701_814_400,
        1_702_419_200,
        1_703_024_000,
        1_703_628_800,
        1_704_233_600,
    ];
    let weeks: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    let mut commitments: [Field; 8] = [0; 8];
    let mut nullifiers: [Field; 8] = [0; 8];
    for i in 0..8 {
        commitments[i] = std::hash::pedersen_hash([secret, amounts[i] as Field]);
        nullifiers[i] = std::hash::pedersen_hash([secret, weeks[i] as Field]);
    }

    main(
        secret,
        amounts,
        timestamps,
        weeks,
        400_000_000,
        8,
        commitments,
        nullifiers,
    );
}
