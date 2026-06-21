#![no_std]

//! # Verifier / Credit Contract
//!
//! Business-logic layer that sits on top of the savings + groth16 contracts.
//!
//! Flow:
//!   1. A wallet calls [`VerifierContract::verify_proof`] with a Noir-generated
//!      Groth16 proof and the public inputs the proof was generated against.
//!   2. The contract cross-checks the commitment root against the savings
//!      contract (binding the proof to current on-chain state) and confirms
//!      each nullifier in the proof was actually recorded by a prior deposit.
//!   3. It delegates the cryptographic check to the groth16 contract.
//!   4. On success, it records a `CreditRecord` for the calling wallet with
//!      a 90-day expiry. Re-proving before expiry overwrites the record.
//!
//! There is no admin key, no upgrade path, and no mutable configuration —
//! the savings and groth16 contract addresses are set exactly once at
//! initialisation.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype,
    symbol_short, Address, Bytes, BytesN, Env, Vec,
};

// ---------------------------------------------------------------------------
// Cross-contract interfaces
// ---------------------------------------------------------------------------
//
// Declared inline so this contract does not pull the other contracts' WASM
// exports into its own binary (which would cause duplicate-symbol linker
// errors). Only primitive SDK types cross the boundary — the savings and
// groth16 contracts are free to evolve their internal structs without
// breaking this client.

#[contractclient(name = "SavingsClient")]
pub trait SavingsInterface {
    fn get_merkle_root(env: Env) -> BytesN<32>;
    fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool;
}

#[contractclient(name = "Groth16Client")]
pub trait Groth16Interface {
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
#[contracttype]
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// Must match the current Merkle root in the savings contract.
    pub commitment_root: BytesN<32>,
    /// Minimum weekly savings threshold claimed (in stroops).
    pub min_weekly_amount: u64,
    /// Number of consecutive weeks claimed (8, 12, or 24).
    pub consistency_weeks: u32,
    /// One nullifier per deposit period claimed.
    pub nullifiers: Vec<BytesN<32>>,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    SavingsContractId,
    Groth16ContractId,
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
    CommitmentRootMismatch = 4,
    NullifierNotRecorded = 5,
    NullifierCountMismatch = 6,
    ProofInvalid = 7,
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

    /// Bind this contract to a specific savings + groth16 deployment.
    /// Callable exactly once.
    pub fn initialize(
        env: Env,
        savings_contract: Address,
        groth16_contract: Address,
    ) -> Result<(), VerifierError> {
        if env.storage().instance().has(&DataKey::SavingsContractId) {
            return Err(VerifierError::AlreadyInitialized);
        }
        env.storage()
            .instance()
            .set(&DataKey::SavingsContractId, &savings_contract);
        env.storage()
            .instance()
            .set(&DataKey::Groth16ContractId, &groth16_contract);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Core verification
    // -----------------------------------------------------------------------

    /// Verify a Noir-generated Groth16 proof and, on success, record a
    /// credit tier for `wallet`.
    ///
    /// `wallet` must authorise the call — the credit record is keyed by it,
    /// so the wallet that pays for verification earns the reputation.
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

        let (savings_id, groth16_id) = Self::contract_ids(&env)?;

        // 1. Bind the proof to the current on-chain Merkle root.
        let savings = SavingsClient::new(&env, &savings_id);
        if savings.get_merkle_root() != public_inputs.commitment_root {
            return Err(VerifierError::CommitmentRootMismatch);
        }

        // 2. Confirm each nullifier in the proof was actually recorded
        //    on-chain by a prior deposit. Existence check — not a
        //    double-spend guard (re-proving before TTL is allowed).
        for nullifier in public_inputs.nullifiers.iter() {
            if !savings.is_nullifier_spent(&nullifier) {
                return Err(VerifierError::NullifierNotRecorded);
            }
        }

        // 3. Delegate the cryptographic check.
        let mut g16_inputs: Vec<BytesN<32>> = Vec::new(&env);
        g16_inputs.push_back(public_inputs.commitment_root.clone());
        g16_inputs.push_back(Self::u64_to_bytes(&env, public_inputs.min_weekly_amount));
        g16_inputs.push_back(Self::u32_to_bytes(&env, public_inputs.consistency_weeks));
        for n in public_inputs.nullifiers.iter() {
            g16_inputs.push_back(n);
        }

        let g16 = Groth16Client::new(&env, &groth16_id);
        if !g16.verify(&proof, &g16_inputs) {
            env.events().publish(
                (symbol_short!("proof"), symbol_short!("rejected")),
                wallet.clone(),
            );
            return Err(VerifierError::ProofInvalid);
        }

        // 4. Record credit. Overwrites any prior record for this wallet.
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

    /// Returns the Groth16 verification key embedded in the linked groth16
    /// contract. Convenience pass-through for tooling/auditors so they can
    /// confirm the circuit without first looking up the groth16 address.
    pub fn get_verification_key(env: Env) -> Result<Bytes, VerifierError> {
        let (_, groth16_id) = Self::contract_ids(&env)?;
        let g16 = Groth16Client::new(&env, &groth16_id);
        Ok(g16.get_verification_key())
    }

    /// Returns the (savings, groth16) addresses this contract is bound to.
    pub fn get_linked_contracts(env: Env) -> Result<(Address, Address), VerifierError> {
        Self::contract_ids(&env)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn contract_ids(env: &Env) -> Result<(Address, Address), VerifierError> {
        let savings = env
            .storage()
            .instance()
            .get(&DataKey::SavingsContractId)
            .ok_or(VerifierError::NotInitialized)?;
        let groth16 = env
            .storage()
            .instance()
            .get(&DataKey::Groth16ContractId)
            .ok_or(VerifierError::NotInitialized)?;
        Ok((savings, groth16))
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
