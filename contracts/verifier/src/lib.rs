#![no_std]

//! # Verifier / Credit Contract
//!
//! Business-logic layer sitting on top of the savings contract and three
//! Honk verifier contracts (one per credit tier: 8 / 12 / 24 weeks).
//!
//! Flow:
//!   1. A wallet calls [`VerifierContract::verify_proof`] with a Noir
//!      UltraHonk proof and the public inputs it was generated against.
//!   2. The contract picks the right Honk verifier instance based on
//!      `consistency_weeks` (8 → Medium, 12 → Low, 24 → VeryLow).
//!   3. It checks each commitment + nullifier in the public inputs was
//!      actually recorded by a prior deposit in the savings contract.
//!      This is what binds the proof to real on-chain state.
//!   4. It delegates the cryptographic check to the chosen Honk verifier.
//!   5. On success, it records a `CreditRecord` for the calling wallet
//!      with a 90-day expiry. Re-proving before expiry overwrites it.
//!
//! No admin key, no upgrade path, no mutable configuration. The savings
//! and Honk verifier addresses are set exactly once at initialisation.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype,
    symbol_short, Address, Bytes, BytesN, Env, Vec,
};

// ---------------------------------------------------------------------------
// Cross-contract interfaces
// ---------------------------------------------------------------------------
//
// Declared inline so this contract does not pull the other contracts' WASM
// exports into its own binary. Only primitive SDK types cross the boundary.

#[contractclient(name = "SavingsClient")]
pub trait SavingsInterface {
    fn get_merkle_root(env: Env) -> BytesN<32>;
    fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool;
    fn is_commitment_recorded(env: Env, commitment: BytesN<32>) -> bool;
}

#[contractclient(name = "HonkVerifierClient")]
pub trait HonkVerifierInterface {
    fn verify(env: Env, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool;
    fn get_verification_key(env: Env) -> Bytes;
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Credit tier assigned after a successful ZK proof verification.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreditTier {
    /// 8 consecutive weeks proven.
    Medium,
    /// 12 consecutive weeks proven.
    Low,
    /// 24 consecutive weeks proven.
    VeryLow,
}

/// On-chain credit record written after a valid proof.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditRecord {
    pub wallet: Address,
    pub tier: CreditTier,
    pub verified_at: u64,
    pub consistency_weeks: u32,
    pub expires_at: u64,
}

/// Public inputs supplied alongside the ZK proof.
///
/// `commitments` and `nullifiers` must each have length == `consistency_weeks`.
/// The verifier checks each one exists in the savings contract before
/// delegating to the Honk verifier.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub min_weekly_amount: u64,
    pub consistency_weeks: u32,
    pub commitments: Vec<BytesN<32>>,
    pub nullifiers: Vec<BytesN<32>>,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    SavingsContractId,
    /// Honk verifier for the 8-week (Medium) tier.
    Honk8w,
    /// Honk verifier for the 12-week (Low) tier.
    Honk12w,
    /// Honk verifier for the 24-week (VeryLow) tier.
    Honk24w,
    CreditRecord(Address),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidConsistencyWeeks = 3,
    NullifierCountMismatch = 4,
    CommitmentCountMismatch = 5,
    NullifierNotRecorded = 6,
    CommitmentNotRecorded = 7,
    ProofInvalid = 8,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Credit signals expire after 90 days.
const CREDIT_TTL_SECS: u64 = 90 * 24 * 60 * 60;

/// Persistent storage TTL extension (in ledgers) — ~30 days at 5s per ledger.
const PERSISTENT_TTL_LEDGERS: u32 = 518_400;

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Bind this contract to a savings deployment + three Honk verifier
    /// instances (one per credit tier). Callable exactly once.
    pub fn initialize(
        env: Env,
        savings_contract: Address,
        honk_8w: Address,
        honk_12w: Address,
        honk_24w: Address,
    ) -> Result<(), VerifierError> {
        if env.storage().instance().has(&DataKey::SavingsContractId) {
            return Err(VerifierError::AlreadyInitialized);
        }
        env.storage()
            .instance()
            .set(&DataKey::SavingsContractId, &savings_contract);
        env.storage().instance().set(&DataKey::Honk8w, &honk_8w);
        env.storage().instance().set(&DataKey::Honk12w, &honk_12w);
        env.storage().instance().set(&DataKey::Honk24w, &honk_24w);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Core verification
    // -----------------------------------------------------------------------

    /// Verify a Noir-generated UltraHonk proof and, on success, record a
    /// credit tier for `wallet`.
    ///
    /// `wallet` must authorise the call — the credit record is keyed by it.
    pub fn verify_proof(
        env: Env,
        wallet: Address,
        proof: Bytes,
        public_inputs: PublicInputs,
    ) -> Result<CreditTier, VerifierError> {
        wallet.require_auth();

        let tier = Self::weeks_to_tier(public_inputs.consistency_weeks)?;

        if public_inputs.nullifiers.len() != public_inputs.consistency_weeks {
            return Err(VerifierError::NullifierCountMismatch);
        }
        if public_inputs.commitments.len() != public_inputs.consistency_weeks {
            return Err(VerifierError::CommitmentCountMismatch);
        }

        let savings_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::SavingsContractId)
            .ok_or(VerifierError::NotInitialized)?;
        let honk_id = Self::honk_for_tier(&env, &tier)?;

        let savings = SavingsClient::new(&env, &savings_id);

        // Bind each public commitment and nullifier to a real on-chain
        // deposit. This is the proof-of-state-integration check.
        for commitment in public_inputs.commitments.iter() {
            if !savings.is_commitment_recorded(&commitment) {
                return Err(VerifierError::CommitmentNotRecorded);
            }
        }
        for nullifier in public_inputs.nullifiers.iter() {
            if !savings.is_nullifier_spent(&nullifier) {
                return Err(VerifierError::NullifierNotRecorded);
            }
        }

        // Delegate the cryptographic proof check. Public-input ordering here
        // MUST match the order the Noir circuits declare:
        //   [min_weekly_amount, consistency_weeks, commitments…, nullifiers…]
        let mut honk_inputs: Vec<BytesN<32>> = Vec::new(&env);
        honk_inputs.push_back(Self::u64_to_bytes(&env, public_inputs.min_weekly_amount));
        honk_inputs.push_back(Self::u32_to_bytes(&env, public_inputs.consistency_weeks));
        for c in public_inputs.commitments.iter() {
            honk_inputs.push_back(c);
        }
        for n in public_inputs.nullifiers.iter() {
            honk_inputs.push_back(n);
        }

        let honk = HonkVerifierClient::new(&env, &honk_id);
        if !honk.verify(&proof, &honk_inputs) {
            env.events().publish(
                (symbol_short!("proof"), symbol_short!("rejected")),
                wallet.clone(),
            );
            return Err(VerifierError::ProofInvalid);
        }

        // Record credit. Overwrites any prior record for this wallet.
        let now = env.ledger().timestamp();
        let expires_at = now + CREDIT_TTL_SECS;
        let record = CreditRecord {
            wallet: wallet.clone(),
            tier: tier.clone(),
            verified_at: now,
            consistency_weeks: public_inputs.consistency_weeks,
            expires_at,
        };
        let key = DataKey::CreditRecord(wallet.clone());
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_TTL_LEDGERS / 2,
            PERSISTENT_TTL_LEDGERS,
        );

        env.events().publish(
            (symbol_short!("credit"), symbol_short!("verified")),
            (wallet, public_inputs.consistency_weeks, expires_at),
        );

        Ok(tier)
    }

    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    /// Returns the most recent non-expired `CreditRecord` for `wallet`, or
    /// `None` if no record exists or the record has expired.
    pub fn get_credit_tier(env: Env, wallet: Address) -> Option<CreditRecord> {
        let key = DataKey::CreditRecord(wallet.clone());
        let record: Option<CreditRecord> = env.storage().persistent().get(&key);
        match record {
            None => None,
            Some(r) => {
                if env.ledger().timestamp() > r.expires_at {
                    env.events().publish(
                        (symbol_short!("credit"), symbol_short!("expired")),
                        (wallet, r.expires_at),
                    );
                    None
                } else {
                    Some(r)
                }
            }
        }
    }

    /// Returns `true` iff `wallet` currently has a non-expired credit record.
    pub fn is_credit_valid(env: Env, wallet: Address) -> bool {
        Self::get_credit_tier(env, wallet).is_some()
    }

    /// Returns the verification key embedded in the Honk verifier contract
    /// for the requested credit tier. Convenience pass-through for tooling.
    pub fn get_verification_key(env: Env, tier: CreditTier) -> Result<Bytes, VerifierError> {
        let honk_id = Self::honk_for_tier(&env, &tier)?;
        let honk = HonkVerifierClient::new(&env, &honk_id);
        Ok(honk.get_verification_key())
    }

    /// Returns (savings, honk_8w, honk_12w, honk_24w).
    pub fn get_linked_contracts(
        env: Env,
    ) -> Result<(Address, Address, Address, Address), VerifierError> {
        let savings = env
            .storage()
            .instance()
            .get(&DataKey::SavingsContractId)
            .ok_or(VerifierError::NotInitialized)?;
        let g8 = env
            .storage()
            .instance()
            .get(&DataKey::Honk8w)
            .ok_or(VerifierError::NotInitialized)?;
        let g12 = env
            .storage()
            .instance()
            .get(&DataKey::Honk12w)
            .ok_or(VerifierError::NotInitialized)?;
        let g24 = env
            .storage()
            .instance()
            .get(&DataKey::Honk24w)
            .ok_or(VerifierError::NotInitialized)?;
        Ok((savings, g8, g12, g24))
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn honk_for_tier(env: &Env, tier: &CreditTier) -> Result<Address, VerifierError> {
        let key = match tier {
            CreditTier::Medium => DataKey::Honk8w,
            CreditTier::Low => DataKey::Honk12w,
            CreditTier::VeryLow => DataKey::Honk24w,
        };
        env.storage()
            .instance()
            .get(&key)
            .ok_or(VerifierError::NotInitialized)
    }

    fn weeks_to_tier(weeks: u32) -> Result<CreditTier, VerifierError> {
        match weeks {
            8 => Ok(CreditTier::Medium),
            12 => Ok(CreditTier::Low),
            24 => Ok(CreditTier::VeryLow),
            _ => Err(VerifierError::InvalidConsistencyWeeks),
        }
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
