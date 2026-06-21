#![no_std]

//! # Savings Contract
//!
//! Records weekly savings deposits as cryptographic commitments and tracks
//! per-deposit nullifiers. The contract intentionally stores no wallet
//! addresses and no raw amounts — only Pedersen-hash commitments computed
//! off-chain by the user.
//!
//! Anyone can submit a deposit (no `require_auth`) — the privacy guarantee
//! is that on-chain observers learn nothing about the depositor beyond the
//! fact that *some* deposit was recorded at a given week.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short,
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
    /// Pedersen hash of (secret, week_number) — used for replay protection
    /// and to bind a deposit to its claimed week.
    pub nullifier: BytesN<32>,
    /// Savings week index (0-indexed).
    pub week_number: u32,
    /// Ledger timestamp at time of deposit.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// `Vec<Commitment>` — all deposits ever recorded.
    Commitments,
    /// `BytesN<32>` — current Merkle root over commitment hashes.
    MerkleRoot,
    /// `bool` — whether a specific nullifier has been spent.
    NullifierSpent(BytesN<32>),
    /// `u32` — last recorded week number (for gap detection).
    LastWeek,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SavingsError {
    NullifierAlreadySpent = 1,
    WeekNumberMustAdvance = 2,
    WeekGapTooLarge = 3,
    RangeInverted = 4,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum gap (in weeks) between consecutive deposits. The Noir circuit
/// is responsible for enforcing the *strict* "no missed weeks" rule — this
/// is just a coarse on-chain sanity bound to keep the Merkle tree honest.
const MAX_WEEK_GAP: u32 = 2;

/// Persistent storage TTL extension (in ledgers) — ~30 days at 5s per ledger.
const PERSISTENT_TTL_LEDGERS: u32 = 518_400;

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct SavingsContract;

#[contractimpl]
impl SavingsContract {
    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    /// Record a new weekly savings deposit as a cryptographic commitment.
    ///
    /// # Arguments
    /// * `commitment`  — Pedersen hash of `(secret, amount)`, computed off-chain.
    /// * `nullifier`   — Pedersen hash binding `(secret, week_number)`.
    /// * `week_number` — Savings week index (0-indexed; gap ≤ [`MAX_WEEK_GAP`]).
    pub fn deposit(
        env: Env,
        commitment: BytesN<32>,
        nullifier: BytesN<32>,
        week_number: u32,
    ) -> Result<(), SavingsError> {
        // Replay protection: a nullifier may be recorded exactly once.
        let spent_key = DataKey::NullifierSpent(nullifier.clone());
        if env.storage().persistent().get(&spent_key).unwrap_or(false) {
            return Err(SavingsError::NullifierAlreadySpent);
        }

        // Week number validation — first deposit can pick any week; after
        // that we require monotonic advance with a bounded gap.
        if env.storage().persistent().has(&DataKey::LastWeek) {
            let last_week: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::LastWeek)
                .unwrap();
            if week_number <= last_week {
                return Err(SavingsError::WeekNumberMustAdvance);
            }
            if week_number - last_week > MAX_WEEK_GAP {
                return Err(SavingsError::WeekGapTooLarge);
            }
        }

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
        env.storage().persistent().set(&spent_key, &true);
        env.storage()
            .persistent()
            .set(&DataKey::LastWeek, &week_number);

        let new_root = Self::compute_merkle_root(&env, &commitments);
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &new_root);

        // Refresh TTL on the entries we just touched so the deposit history
        // and root survive the default rent window.
        let touched: [DataKey; 4] = [
            DataKey::Commitments,
            DataKey::MerkleRoot,
            DataKey::LastWeek,
            DataKey::NullifierSpent(nullifier),
        ];
        for k in touched.iter() {
            env.storage()
                .persistent()
                .extend_ttl(k, PERSISTENT_TTL_LEDGERS / 2, PERSISTENT_TTL_LEDGERS);
        }

        env.events().publish(
            (symbol_short!("deposit"), symbol_short!("recorded")),
            (week_number, env.ledger().timestamp()),
        );
        env.events().publish(
            (symbol_short!("merkle"), symbol_short!("updated")),
            new_root,
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    /// Returns the current Merkle root of all recorded commitments.
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

    /// Returns whether a nullifier has been recorded by a prior deposit.
    /// The verifier contract calls this to confirm that each nullifier
    /// referenced in a credit proof corresponds to a real on-chain deposit.
    pub fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::NullifierSpent(nullifier))
            .unwrap_or(false)
    }

    /// Returns all commitments whose `week_number` falls within `[start, end]`.
    pub fn get_commitments_by_range(
        env: Env,
        start: u32,
        end: u32,
    ) -> Result<Vec<Commitment>, SavingsError> {
        if start > end {
            return Err(SavingsError::RangeInverted);
        }

        let all: Vec<Commitment> = env
            .storage()
            .persistent()
            .get(&DataKey::Commitments)
            .unwrap_or_else(|| Vec::new(&env));

        let mut result = Vec::new(&env);
        for c in all.iter() {
            if c.week_number >= start && c.week_number <= end {
                result.push_back(c);
            }
        }
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Iterative left-fold Merkle root over commitment hashes using SHA-256.
    ///
    /// This is a placeholder for a proper binary Merkle tree with a ZK-friendly
    /// hash (Poseidon). It is consistent and deterministic — sufficient for
    /// integration plumbing — but the Noir circuit must use a matching scheme
    /// before this contract is shipped for real credit decisions.
    fn compute_merkle_root(env: &Env, commitments: &Vec<Commitment>) -> BytesN<32> {
        if commitments.is_empty() {
            return BytesN::from_array(env, &[0u8; 32]);
        }
        let first = commitments.get(0).unwrap();
        let mut running: [u8; 32] = first.hash.to_array();
        for i in 1..commitments.len() {
            let c = commitments.get(i).unwrap();
            let mut buf = Bytes::new(env);
            buf.extend_from_array(&running);
            buf.extend_from_array(&c.hash.to_array());
            running = env.crypto().sha256(&buf).to_array();
        }
        BytesN::from_array(env, &running)
    }
}

#[cfg(test)]
mod test;
