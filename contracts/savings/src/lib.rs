#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Bytes, BytesN, Env, Vec,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A single weekly savings deposit, stored as a commitment.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    /// Pedersen hash of (secret, amount) — computed off-chain.
    pub hash: BytesN<32>,
    /// Pedersen hash of (secret) — used for replay protection.
    pub nullifier: BytesN<32>,
    /// Which savings week this deposit belongs to (0-indexed).
    pub week_number: u32,
    /// Ledger timestamp at time of deposit.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Vec<Commitment> — all deposits ever recorded.
    Commitments,
    /// BytesN<32> — current Merkle root.
    MerkleRoot,
    /// bool — whether a specific nullifier has been spent.
    NullifierSpent(BytesN<32>),
    /// u32 — last recorded week number (for gap detection).
    LastWeek,
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum SavingsError {
    NullifierAlreadySpent = 1,
    InvalidWeekNumber = 2,
    WeekGapTooLarge = 3,
    InvalidCommitmentLength = 4,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct SavingsContract;

#[contractimpl]
impl SavingsContract {
    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// Record a new weekly savings deposit as a cryptographic commitment.
    ///
    /// # Arguments
    /// * `commitment`  — Pedersen hash of `(secret, amount)`, computed off-chain.
    /// * `nullifier`   — Pedersen hash of `(secret)`, prevents replay.
    /// * `week_number` — Savings week index (0-indexed, must not skip >2 weeks).
    pub fn deposit(
        env: Env,
        commitment: BytesN<32>,
        nullifier: BytesN<32>,
        week_number: u32,
    ) {
        // --- Replay protection ---
        let spent_key = DataKey::NullifierSpent(nullifier.clone());
        let already_spent: bool = env
            .storage()
            .persistent()
            .get(&spent_key)
            .unwrap_or(false);
        assert!(!already_spent, "nullifier already spent");

        // --- Week number validation ---
        let last_week: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LastWeek)
            .unwrap_or(0);

        // Week 0 is valid for first deposit; otherwise must not regress or
        // skip more than 2 weeks.
        if env.storage().persistent().has(&DataKey::LastWeek) {
            assert!(
                week_number > last_week,
                "week number must advance"
            );
            assert!(
                week_number <= last_week + 2,
                "week gap too large (max 2)"
            );
        }

        // --- Build and store the commitment ---
        let entry = Commitment {
            hash: commitment,
            nullifier: nullifier.clone(),
            week_number,
            timestamp: env.ledger().timestamp(),
        };

        let mut commitments: Vec<Commitment> = env
            .storage()
            .persistent()
            .get(&DataKey::Commitments)
            .unwrap_or_else(|| Vec::new(&env));

        commitments.push_back(entry);

        env.storage()
            .persistent()
            .set(&DataKey::Commitments, &commitments);

        // --- Mark nullifier spent ---
        env.storage()
            .persistent()
            .set(&spent_key, &true);

        // --- Update last week ---
        env.storage()
            .persistent()
            .set(&DataKey::LastWeek, &week_number);

        // --- Recompute Merkle root ---
        let new_root = Self::compute_merkle_root(&env, &commitments);
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &new_root);

        // --- Emit events ---
        env.events().publish(
            (symbol_short!("deposit"), symbol_short!("recorded")),
            (week_number, env.ledger().timestamp()),
        );
        env.events().publish(
            (symbol_short!("merkle"), symbol_short!("updated")),
            new_root,
        );
    }

    // -----------------------------------------------------------------------
    // Read functions
    // -----------------------------------------------------------------------

    /// Returns the current Merkle root of all recorded commitments.
    /// Used as a public input when generating a ZK proof off-chain.
    pub fn get_merkle_root(env: Env) -> BytesN<32> {
        env.storage()
            .persistent()
            .get(&DataKey::MerkleRoot)
            .unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Returns the total number of commitments recorded.
    pub fn get_commitment_count(env: Env) -> u32 {
        let commitments: Vec<Commitment> = env
            .storage()
            .persistent()
            .get(&DataKey::Commitments)
            .unwrap_or_else(|| Vec::new(&env));
        commitments.len()
    }

    /// Checks whether a nullifier has already been spent.
    pub fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::NullifierSpent(nullifier))
            .unwrap_or(false)
    }

    /// Returns all commitments whose `week_number` falls in `[start, end]`.
    /// Used by the frontend to build private inputs for proof generation.
    pub fn get_commitments_by_range(
        env: Env,
        start: u32,
        end: u32,
    ) -> Vec<Commitment> {
        let all: Vec<Commitment> = env
            .storage()
            .persistent()
            .get(&DataKey::Commitments)
            .unwrap_or_else(|| Vec::new(&env));

        let mut result = Vec::new(&env);
        for i in 0..all.len() {
            let c = all.get(i).unwrap();
            if c.week_number >= start && c.week_number <= end {
                result.push_back(c);
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Minimal iterative Merkle root computation over commitment hashes.
    ///
    /// In production this should use a proper binary Merkle tree with a
    /// ZK-friendly hash (e.g. Poseidon / SHA-256). For now it hashes
    /// each commitment hash into the running accumulator using the SDK's
    /// `env.crypto().sha256()`.
    fn compute_merkle_root(env: &Env, commitments: &Vec<Commitment>) -> BytesN<32> {
        if commitments.is_empty() {
            return BytesN::from_array(env, &[0u8; 32]);
        }

        // Start with the first commitment hash.
        let first = commitments.get(0).unwrap();
        let mut running: [u8; 32] = first.hash.to_array();

        for i in 1..commitments.len() {
            let c = commitments.get(i).unwrap();
            // Concatenate running || commitment_hash and re-hash.
            let mut buf = Bytes::new(env);
            buf.extend_from_array(&running);
            buf.extend_from_array(&c.hash.to_array());
            let digest = env.crypto().sha256(&buf);
            running = digest.to_array();
        }

        BytesN::from_array(env, &running)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Ledger, Env};

    fn make_env() -> Env {
        Env::default()
    }

    fn make_hash(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    #[test]
    fn test_valid_deposit_stored() {
        let env = make_env();
        let contract_id = env.register_contract(None, SavingsContract);
        let client = SavingsContractClient::new(&env, &contract_id);

        let commitment = make_hash(&env, 1);
        let nullifier = make_hash(&env, 2);

        client.deposit(&commitment, &nullifier, &0u32);

        assert_eq!(client.get_commitment_count(), 1);
    }

    #[test]
    #[should_panic(expected = "nullifier already spent")]
    fn test_duplicate_nullifier_rejected() {
        let env = make_env();
        let contract_id = env.register_contract(None, SavingsContract);
        let client = SavingsContractClient::new(&env, &contract_id);

        let commitment = make_hash(&env, 1);
        let nullifier = make_hash(&env, 2);

        client.deposit(&commitment, &nullifier, &0u32);
        // Second deposit with same nullifier must panic.
        client.deposit(&make_hash(&env, 3), &nullifier, &1u32);
    }

    #[test]
    fn test_merkle_root_updates() {
        let env = make_env();
        let contract_id = env.register_contract(None, SavingsContract);
        let client = SavingsContractClient::new(&env, &contract_id);

        let root_before = client.get_merkle_root();

        client.deposit(&make_hash(&env, 10), &make_hash(&env, 11), &0u32);

        let root_after = client.get_merkle_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    #[should_panic(expected = "week gap too large")]
    fn test_large_week_gap_rejected() {
        let env = make_env();
        let contract_id = env.register_contract(None, SavingsContract);
        let client = SavingsContractClient::new(&env, &contract_id);

        client.deposit(&make_hash(&env, 1), &make_hash(&env, 2), &0u32);
        // Gap of 3 should be rejected.
        client.deposit(&make_hash(&env, 3), &make_hash(&env, 4), &3u32);
    }

    #[test]
    fn test_nullifier_spent_flag() {
        let env = make_env();
        let contract_id = env.register_contract(None, SavingsContract);
        let client = SavingsContractClient::new(&env, &contract_id);

        let nullifier = make_hash(&env, 99);
        assert!(!client.is_nullifier_spent(&nullifier));

        client.deposit(&make_hash(&env, 5), &nullifier, &0u32);
        assert!(client.is_nullifier_spent(&nullifier));
    }

    #[test]
    fn test_get_commitments_by_range() {
        let env = make_env();
        let contract_id = env.register_contract(None, SavingsContract);
        let client = SavingsContractClient::new(&env, &contract_id);

        client.deposit(&make_hash(&env, 1), &make_hash(&env, 2), &0u32);
        client.deposit(&make_hash(&env, 3), &make_hash(&env, 4), &1u32);
        client.deposit(&make_hash(&env, 5), &make_hash(&env, 6), &2u32);

        let range = client.get_commitments_by_range(&1u32, &2u32);
        assert_eq!(range.len(), 2);
    }
}
