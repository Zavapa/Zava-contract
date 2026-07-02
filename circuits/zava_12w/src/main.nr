//! Zava - 12-week savings discipline proof (Low-risk tier).
//!
//! See `zava_8w` for the design rationale. This is the same circuit with
//! N = 12 so it produces a different verification key and a different
//! Groth16 verifier contract instance.

use std;

global N: u32 = 12;
global MAX_GAP_SECS: u64 = 691200;

fn main(
    secret: Field,
    weekly_amounts: [u64; N],
    deposit_timestamps: [u64; N],
    week_numbers: [u32; N],

    min_weekly_amount: pub u64,
    consistency_weeks: pub u32,
    commitments: pub [Field; N],
    nullifiers: pub [Field; N],
) {
    assert(consistency_weeks == N);

    for i in 0..N {
        assert(weekly_amounts[i] >= min_weekly_amount);

        let expected_commitment =
            std::hash::pedersen_hash([secret, weekly_amounts[i] as Field]);
        assert(expected_commitment == commitments[i]);

        let expected_nullifier =
            std::hash::pedersen_hash([secret, week_numbers[i] as Field]);
        assert(expected_nullifier == nullifiers[i]);
    }

    for i in 1..N {
        assert(week_numbers[i] > week_numbers[i - 1]);
        let gap = deposit_timestamps[i] - deposit_timestamps[i - 1];
        assert(gap > 0);
        assert(gap <= MAX_GAP_SECS);
    }
}

#[test]
fn test_valid_12_week_proof() {
    let secret: Field = 12345;
    let amounts: [u64; 12] = [400_000_000; 12];
    let mut timestamps: [u64; 12] = [0; 12];
    let mut weeks: [u32; 12] = [0; 12];

    for i in 0..12 {
        timestamps[i] = 1_700_000_000 + (i as u64) * 604_800;
        weeks[i] = i as u32;
    }

    let mut commitments: [Field; 12] = [0; 12];
    let mut nullifiers: [Field; 12] = [0; 12];
    for i in 0..12 {
        commitments[i] = std::hash::pedersen_hash([secret, amounts[i] as Field]);
        nullifiers[i] = std::hash::pedersen_hash([secret, weeks[i] as Field]);
    }

    main(
        secret,
        amounts,
        timestamps,
        weeks,
        400_000_000,
        12,
        commitments,
        nullifiers,
    );
}
