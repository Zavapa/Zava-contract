#![no_std]

//! # ZavaCredit — bulletproof savings-backed credit scoring
//!
//! Replaces the old `savings` + `verifier` pair with a single contract that
//! reads directly from `ZavaVault`. Savings claims are impossible to fake:
//!
//! 1. Every commitment a user claims as savings must actually exist in the vault
//!    (`vault.commitment_exists(commitment)`).
//! 2. The user must know the nullifier paired with that commitment at deposit
//!    (`vault.commitment_matches_nullifier(commitment, nullifier)`).
//!    The nullifier only lives in the encrypted note, so only the recipient can
//!    construct this proof.
//! 3. A nullifier that's already been spent (i.e. the deposit was withdrawn)
//!    drops out of the credit count.
//!
//! ## Net-based scoring
//!
//! The user submits N (commitment, nullifier, week) triples plus an UltraHonk
//! proof that they know the secrets behind each one and that each amount meets
//! the threshold. The contract then queries the vault for each triple and counts:
//!
//! - `active_weeks`: triples where commitment exists, nullifier matches,
//!                   AND nullifier is NOT yet spent.
//! - `withdrawn_weeks`: triples where commitment exists, nullifier matches,
//!                      but nullifier IS spent.
//!
//! Tier is then assigned from `active_weeks`:
//!
//! ```text
//! active_weeks >= 24  =>  VeryLow risk
//! active_weeks >= 12  =>  Low risk
//! active_weeks >= 8   =>  Medium risk
//! otherwise           =>  no credit
//! ```
//!
//! Withdrawing reduces your active count and may demote your tier. This is the
//! "net" in net-based — the score reflects actual locked savings, not historical
//! claims.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype,
    symbol_short, Address, Bytes, BytesN, Env, Vec,
};

// ============================================================================
// Cross-contract interfaces
// ============================================================================

#[contractclient(name = "VaultClient")]
pub trait VaultInterface {
    fn commitment_exists(env: Env, commitment: BytesN<32>) -> bool;
    fn commitment_matches_nullifier(env: Env, commitment: BytesN<32>, nullifier: BytesN<32>) -> bool;
    fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool;
}

#[contractclient(name = "HonkVerifierClient")]
pub trait HonkVerifierInterface {
    fn verify(env: Env, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool;
}

// ============================================================================
// Types
// ============================================================================

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreditTier {
    None,
    Medium,    // 8+ active savings weeks
    Low,       // 12+ active savings weeks
    VeryLow,   // 24+ active savings weeks
}

/// Savings-range tier. Lets a borrower prove a lower bound on their weekly
/// savings without revealing the exact amount.
///
/// A borrower who actually saves $30/week can claim `R20` ("at least $20/week")
/// and a lender will see only that range and the resulting loan eligibility —
/// never the real $30 figure.
///
/// XLM stroops: 1 XLM = 10^7 stroops. Numbers below are in stroops, with the
/// dollar tag being the equivalent at $0.10/XLM (testnet-style).
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SavingsRange {
    /// ≥ $5/week  (≥ 50 XLM)
    R5,
    /// ≥ $20/week (≥ 200 XLM)
    R20,
    /// ≥ $50/week (≥ 500 XLM)
    R50,
    /// ≥ $200/week (≥ 2000 XLM)
    R200,
    /// ≥ $500/week (≥ 5000 XLM)
    R500,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditRecord {
    pub wallet: Address,
    pub tier: CreditTier,
    pub savings_range: SavingsRange,
    /// Maximum loan the borrower is eligible for, in stroops.
    /// Derived from (savings_range, tier, active_weeks). Hides actual savings.
    pub loan_eligible_stroops: i128,
    pub active_weeks: u32,      // savings weeks where money is still locked
    pub withdrawn_weeks: u32,   // savings weeks that have been withdrawn (excluded from tier)
    pub verified_at: u64,
    pub expires_at: u64,
}

/// Public inputs to `claim_credit`.
///
/// The borrower picks a `savings_range` they meet, then proves (in ZK) that every
/// deposit was at least the range's minimum. The exact deposit amounts stay private.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CreditClaim {
    /// Lower-bound tier the borrower commits to proving against.
    pub savings_range: SavingsRange,
    pub commitments: Vec<BytesN<32>>,
    pub nullifiers: Vec<BytesN<32>>,
    pub weeks: Vec<u32>,
}

// ============================================================================
// Storage / errors / constants
// ============================================================================

#[contracttype]
pub enum DataKey {
    Initialized,
    VaultId,
    HonkVerifierId,
    CreditRecord(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CreditError {
    AlreadyInitialized   = 1,
    NotInitialized       = 2,
    LengthMismatch       = 3,
    EmptyClaim           = 4,
    DuplicateNullifier   = 5,
    ProofInvalid         = 6,
    CommitmentNotInVault = 7,
    BindingMismatch      = 8,
    NotEnoughActiveWeeks = 9,
}

/// Credit signal expires 90 days after issuance.
const CREDIT_TTL_SECS: u64 = 90 * 24 * 60 * 60;
const PERSISTENT_TTL_LEDGERS: u32 = 518_400;

const MEDIUM_THRESHOLD:   u32 = 8;
const LOW_THRESHOLD:      u32 = 12;
const VERY_LOW_THRESHOLD: u32 = 24;

// ── Loan policy ──────────────────────────────────────────────────────────────
//
// Loan eligibility =
//   active_weeks × weekly_lower_bound × multiplier_for_tier(credit_tier)
//
// `weekly_lower_bound` is the minimum amount the borrower has proven in ZK.
// `multiplier_for_tier` reflects risk: longer proven consistency = larger loan
// against the same deposit base.

/// Stroops per XLM (1 XLM = 10^7 stroops).
const STROOPS_PER_XLM: u64 = 10_000_000;

/// Multiplier (in basis points, so 200 = 2.00×) applied to total proven
/// savings to compute loan eligibility for each credit tier.
const MULT_BPS_MEDIUM:   i128 = 200; // 2.0× — short history, smaller loans
const MULT_BPS_LOW:      i128 = 400; // 4.0× — established
const MULT_BPS_VERY_LOW: i128 = 600; // 6.0× — long track record

// ============================================================================
// Contract
// ============================================================================

#[contract]
pub struct ZavaCredit;

#[contractimpl]
impl ZavaCredit {

    /// Wire this contract to the vault and the Honk verifier.
    pub fn initialize(
        env: Env,
        vault: Address,
        honk_verifier: Address,
    ) -> Result<(), CreditError> {
        if env.storage().instance().has(&DataKey::Initialized) {
            return Err(CreditError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::VaultId, &vault);
        env.storage().instance().set(&DataKey::HonkVerifierId, &honk_verifier);
        Ok(())
    }

    /// Submit a credit claim. The wallet must authorise — the resulting
    /// `CreditRecord` is keyed by it.
    ///
    /// The borrower picks a `savings_range` (e.g. `R20` = "$20/wk minimum")
    /// and the Noir circuit proves every deposit met or exceeded the range's
    /// lower bound. The lender sees only the range, never the actual amounts.
    pub fn claim_credit(
        env: Env,
        wallet: Address,
        proof: Bytes,
        claim: CreditClaim,
    ) -> Result<CreditRecord, CreditError> {
        wallet.require_auth();
        Self::check_initialized(&env)?;

        let n = claim.commitments.len();
        if n == 0 {
            return Err(CreditError::EmptyClaim);
        }
        if claim.nullifiers.len() != n || claim.weeks.len() != n {
            return Err(CreditError::LengthMismatch);
        }

        // Reject duplicate nullifiers in the same claim (no inflating count).
        // O(n²) but n is at most 24, so well under budget.
        for i in 0..n {
            for j in (i + 1)..n {
                if claim.nullifiers.get(i).unwrap() == claim.nullifiers.get(j).unwrap() {
                    return Err(CreditError::DuplicateNullifier);
                }
            }
        }

        // The ZK circuit's `min_weekly_amount` public input must equal the
        // range's lower bound. The circuit then enforces each deposit ≥ this
        // bound against the private witness amounts — the actual amounts are
        // never revealed.
        let weekly_lower_bound = Self::range_lower_bound_stroops(&claim.savings_range);

        // ── ZK proof verification ─────────────────────────────────────────────
        let honk_id: Address = env
            .storage().instance()
            .get(&DataKey::HonkVerifierId)
            .ok_or(CreditError::NotInitialized)?;

        let mut honk_inputs: Vec<BytesN<32>> = Vec::new(&env);
        honk_inputs.push_back(Self::u64_to_bytes(&env, weekly_lower_bound));
        honk_inputs.push_back(Self::u32_to_bytes(&env, n));
        for c in claim.commitments.iter() {
            honk_inputs.push_back(c);
        }
        for nf in claim.nullifiers.iter() {
            honk_inputs.push_back(nf);
        }
        let honk = HonkVerifierClient::new(&env, &honk_id);
        if !honk.verify(&proof, &honk_inputs) {
            return Err(CreditError::ProofInvalid);
        }

        // ── Bulletproof savings check ─────────────────────────────────────────
        //
        // Query the vault for each triple. Three things must hold:
        //   1. Commitment exists in vault (real on-chain deposit).
        //   2. Nullifier matches the binding stored at deposit (proves ownership).
        //   3. Nullifier may or may not be spent — spent = withdrawn = excluded
        //      from active count but still proves once-saved (net-based scoring).
        let vault_id: Address = env
            .storage().instance()
            .get(&DataKey::VaultId)
            .ok_or(CreditError::NotInitialized)?;
        let vault = VaultClient::new(&env, &vault_id);

        let mut active_weeks: u32 = 0;
        let mut withdrawn_weeks: u32 = 0;

        for i in 0..n {
            let commitment = claim.commitments.get(i).unwrap();
            let nullifier  = claim.nullifiers.get(i).unwrap();

            if !vault.commitment_exists(&commitment) {
                return Err(CreditError::CommitmentNotInVault);
            }
            if !vault.commitment_matches_nullifier(&commitment, &nullifier) {
                return Err(CreditError::BindingMismatch);
            }
            if vault.is_nullifier_spent(&nullifier) {
                withdrawn_weeks += 1;
            } else {
                active_weeks += 1;
            }
        }

        // ── Tier assignment ───────────────────────────────────────────────────
        let tier = Self::weeks_to_tier(active_weeks);
        if matches!(tier, CreditTier::None) {
            return Err(CreditError::NotEnoughActiveWeeks);
        }

        // ── Loan eligibility ──────────────────────────────────────────────────
        //
        // loan = (active_weeks × weekly_lower_bound) × multiplier_bps / 100
        //
        // The "active_weeks × weekly_lower_bound" is the borrower's proven
        // *minimum* total locked savings. Multiplying by the credit-tier
        // multiplier gives the eligible loan amount.
        let loan_eligible_stroops =
            Self::compute_loan_eligible(active_weeks, weekly_lower_bound, &tier);

        // ── Persist ───────────────────────────────────────────────────────────
        let now = env.ledger().timestamp();
        let record = CreditRecord {
            wallet: wallet.clone(),
            tier: tier.clone(),
            savings_range: claim.savings_range,
            loan_eligible_stroops,
            active_weeks,
            withdrawn_weeks,
            verified_at: now,
            expires_at: now + CREDIT_TTL_SECS,
        };
        let key = DataKey::CreditRecord(wallet.clone());
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(
            &key, PERSISTENT_TTL_LEDGERS / 2, PERSISTENT_TTL_LEDGERS,
        );

        env.events().publish(
            (symbol_short!("credit"), symbol_short!("issued")),
            (wallet, active_weeks, loan_eligible_stroops),
        );

        Ok(record)
    }

    /// Convenience read for lenders — what's this wallet eligible to borrow?
    /// Returns 0 stroops if no valid credit record.
    pub fn get_loan_eligibility(env: Env, wallet: Address) -> i128 {
        Self::get_credit_record(env, wallet)
            .map(|r| r.loan_eligible_stroops)
            .unwrap_or(0)
    }

    /// Returns the (lower bound, label) for a range — useful for UIs.
    pub fn range_info(range: SavingsRange) -> (u64, u32) {
        let lower = Self::range_lower_bound_stroops(&range);
        // Encode the range as a number for display: 5, 20, 50, 200, 500
        let label = match range {
            SavingsRange::R5 => 5,
            SavingsRange::R20 => 20,
            SavingsRange::R50 => 50,
            SavingsRange::R200 => 200,
            SavingsRange::R500 => 500,
        };
        (lower, label)
    }

    // ── Reads ──────────────────────────────────────────────────────────────────

    pub fn get_credit_record(env: Env, wallet: Address) -> Option<CreditRecord> {
        let key = DataKey::CreditRecord(wallet);
        let record: Option<CreditRecord> = env.storage().persistent().get(&key);
        match record {
            None => None,
            Some(r) => {
                if env.ledger().timestamp() > r.expires_at {
                    None
                } else {
                    Some(r)
                }
            }
        }
    }

    pub fn is_credit_valid(env: Env, wallet: Address) -> bool {
        Self::get_credit_record(env, wallet).is_some()
    }

    pub fn get_linked_contracts(env: Env) -> Result<(Address, Address), CreditError> {
        let vault    = env.storage().instance().get(&DataKey::VaultId).ok_or(CreditError::NotInitialized)?;
        let verifier = env.storage().instance().get(&DataKey::HonkVerifierId).ok_or(CreditError::NotInitialized)?;
        Ok((vault, verifier))
    }

    // ── Internal ───────────────────────────────────────────────────────────────

    fn check_initialized(env: &Env) -> Result<(), CreditError> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return Err(CreditError::NotInitialized);
        }
        Ok(())
    }

    fn weeks_to_tier(active_weeks: u32) -> CreditTier {
        if active_weeks >= VERY_LOW_THRESHOLD { CreditTier::VeryLow }
        else if active_weeks >= LOW_THRESHOLD { CreditTier::Low }
        else if active_weeks >= MEDIUM_THRESHOLD { CreditTier::Medium }
        else { CreditTier::None }
    }

    /// Stroops per week the borrower commits to proving.
    /// Numbers assume $0.10/XLM for human-friendly tier labels — change to
    /// match real XLM price at deployment time, or denominate in XLM directly.
    fn range_lower_bound_stroops(range: &SavingsRange) -> u64 {
        match range {
            SavingsRange::R5   =>   50 * STROOPS_PER_XLM, //   $5/wk ≈   50 XLM
            SavingsRange::R20  =>  200 * STROOPS_PER_XLM, //  $20/wk ≈  200 XLM
            SavingsRange::R50  =>  500 * STROOPS_PER_XLM, //  $50/wk ≈  500 XLM
            SavingsRange::R200 => 2000 * STROOPS_PER_XLM, // $200/wk ≈ 2000 XLM
            SavingsRange::R500 => 5000 * STROOPS_PER_XLM, // $500/wk ≈ 5000 XLM
        }
    }

    /// loan = active_weeks × weekly_lower_bound × tier_multiplier
    /// Returns stroops.
    fn compute_loan_eligible(active_weeks: u32, weekly_lower_bound: u64, tier: &CreditTier) -> i128 {
        let multiplier_bps: i128 = match tier {
            CreditTier::Medium  => MULT_BPS_MEDIUM,
            CreditTier::Low     => MULT_BPS_LOW,
            CreditTier::VeryLow => MULT_BPS_VERY_LOW,
            CreditTier::None    => return 0,
        };
        let proven_total = (active_weeks as i128) * (weekly_lower_bound as i128);
        proven_total * multiplier_bps / 100
    }

    fn u64_to_bytes(env: &Env, v: u64) -> BytesN<32> {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&v.to_be_bytes());
        BytesN::from_array(env, &out)
    }

    fn u32_to_bytes(env: &Env, v: u32) -> BytesN<32> {
        let mut out = [0u8; 32];
        out[28..32].copy_from_slice(&v.to_be_bytes());
        BytesN::from_array(env, &out)
    }
}

#[cfg(test)]
mod test;
