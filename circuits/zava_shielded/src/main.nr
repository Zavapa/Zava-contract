//! # Zava Shielded Circuit
//!
//! Proves withdrawal OR private transfer from the ZavaVault pool.
//!
//! ## What the proof guarantees
//!
//! 1. The prover knows a `secret` such that `commitment = pedersen_hash([secret, amount])`
//!    is a leaf in the Merkle tree at `root`  (proves pool membership).
//! 2. `nullifier == pedersen_hash([secret, 0])` - unique per commitment,
//!    preventing double-spend.
//! 3. `recipient_hash == pedersen_hash([recipient_bytes])` - binds the proof
//!    to a specific destination address so a relay cannot redirect the payout.
//!    Set to [0;32] for a private in-pool transfer (no token output).
//! 4. `amount_out == amount` - the contract releases exactly what was deposited.
//!    Set to 0 for a private in-pool transfer.
//!
//! ## Private inputs (the witness - never revealed)
//! - `secret`                  - the depositor's random 32-byte secret.
//! - `amount`                  - the deposit amount in stroops (u64).
//! - `merkle_path`             - sibling hashes along the Merkle path.
//! - `merkle_path_indices`     - 0 = left, 1 = right at each level.
//!
//! ## Public inputs (committed to in the proof, verified on-chain)
//! - `root`           - the Merkle root used during proof generation.
//! - `nullifier`      - pedersen_hash([secret, 0]).
//! - `recipient_hash` - pedersen_hash([recipient_address_bytes]) or [0;32].
//! - `amount_out`     - amount released (must equal `amount`), or 0 for transfer.

use std::hash::pedersen_hash;

global LEVELS: u32 = 20; // must match the contract's Merkle tree depth

fn merkle_root(
    leaf: Field,
    path: [Field; LEVELS],
    indices: [bool; LEVELS],
) -> Field {
    let mut current = leaf;
    for i in 0..LEVELS {
        let (left, right) = if !indices[i] {
            (current, path[i])  // current is left child
        } else {
            (path[i], current)  // current is right child
        };
        current = pedersen_hash([left, right]);
    }
    current
}

fn main(
    // -- Private witness ------------------------------------------------------
    secret: Field,
    amount: u64,
    merkle_path: [Field; LEVELS],
    merkle_path_indices: [bool; LEVELS],

    // -- Public inputs ---------------------------------------------------------
    root: pub Field,
    nullifier: pub Field,
    recipient_hash: pub Field,  // 0 for in-pool transfer
    amount_out: pub u64,        // 0 for in-pool transfer
) {
    // 1. Commitment is pedersen_hash([secret, amount])
    let commitment = pedersen_hash([secret, amount as Field]);

    // 2. Computed Merkle root must match the public root.
    let computed_root = merkle_root(commitment, merkle_path, merkle_path_indices);
    assert(computed_root == root);

    // 3. Nullifier is pedersen_hash([secret, 0]) - unique per commitment.
    let expected_nullifier = pedersen_hash([secret, 0]);
    assert(expected_nullifier == nullifier);

    // 4. Amount conservation: either a withdrawal (amount_out == amount)
    //    or a transfer (both are 0 in public inputs, amount checked separately
    //    by the new commitment created on-chain).
    let is_transfer = (recipient_hash == 0) & (amount_out == 0);
    if !is_transfer {
        // Withdrawal: public amount_out must equal the private amount.
        assert(amount_out == amount);
        // recipient_hash must be non-zero (a relay cannot steal by setting it
        // to zero - the contract rejects zero recipient_hash for withdrawals).
        assert(recipient_hash != 0);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_valid_withdrawal() {
    let secret: Field = 42;
    let amount: u64   = 500_000_000; // 50 XLM in stroops

    let commitment = pedersen_hash([secret, amount as Field]);
    let nullifier  = pedersen_hash([secret, 0]);

    // For a depth-20 tree with only one leaf, all siblings are zero.
    let path: [Field; LEVELS] = [0; LEVELS];
    let indices: [bool; LEVELS] = [false; LEVELS];

    // Root of a tree whose only leaf is `commitment` at index 0.
    let mut root = commitment;
    for i in 0..LEVELS {
        root = pedersen_hash([root, path[i]]);
        let _ = i;
    }

    // recipient_hash - pedersen_hash of some recipient bytes (mock).
    let recipient_hash: Field = pedersen_hash([0xdeadbeef]);
    let amount_out: u64 = amount;

    main(secret, amount, path, indices, root, nullifier, recipient_hash, amount_out);
}

#[test]
fn test_valid_transfer() {
    let secret: Field = 99;
    let amount: u64   = 100_000_000;

    let commitment = pedersen_hash([secret, amount as Field]);
    let nullifier  = pedersen_hash([secret, 0]);

    let path: [Field; LEVELS] = [0; LEVELS];
    let indices: [bool; LEVELS] = [false; LEVELS];

    let mut root = commitment;
    for i in 0..LEVELS {
        root = pedersen_hash([root, path[i]]);
        let _ = i;
    }

    // In-pool transfer: recipient_hash = 0, amount_out = 0
    main(secret, amount, path, indices, root, nullifier, 0, 0);
}

#[test(should_fail)]
fn test_wrong_amount_fails() {
    let secret: Field = 1;
    let amount: u64   = 100_000_000;

    let commitment = pedersen_hash([secret, amount as Field]);
    let nullifier  = pedersen_hash([secret, 0]);

    let path: [Field; LEVELS] = [0; LEVELS];
    let indices: [bool; LEVELS] = [false; LEVELS];

    let mut root = commitment;
    for i in 0..LEVELS {
        root = pedersen_hash([root, path[i]]);
        let _ = i;
    }

    // amount_out doesn't match private amount -> should fail
    main(secret, amount, path, indices, root, nullifier, 1, 200_000_000);
}

#[test(should_fail)]
fn test_wrong_nullifier_fails() {
    let secret: Field = 7;
    let amount: u64   = 100_000_000;

    let commitment = pedersen_hash([secret, amount as Field]);

    let path: [Field; LEVELS] = [0; LEVELS];
    let indices: [bool; LEVELS] = [false; LEVELS];

    let mut root = commitment;
    for i in 0..LEVELS {
        root = pedersen_hash([root, path[i]]);
        let _ = i;
    }

    // Wrong nullifier -> should fail
    let bad_nullifier: Field = pedersen_hash([secret, 999]);
    main(secret, amount, path, indices, root, bad_nullifier, 0, 0);
}
