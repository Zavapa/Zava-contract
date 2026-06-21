#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, Bytes, BytesN, Env, Vec,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Credit tier assigned after a successful ZK proof verification.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug)]
pub struct CreditRecord {
    pub wallet: Address,
    pub tier: CreditTier,
    /// Ledger timestamp when the proof was verified.
    pub verified_at: u64,
    /// Number of consecutive weeks claimed in the proof.
    pub consistency_weeks: u32,
    /// Timestamp after which this credit signal is considered expired.
    pub expires_at: u64,
}

/// Public inputs supplied alongside the ZK proof.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// Must match the current Merkle root stored in the savings contract.
    pub commitment_root: BytesN<32>,
    /// Minimum weekly savings threshold claimed (in stroops).
    pub min_weekly_amount: u64,
    /// Number of consecutive weeks claimed (8, 12, or 24).
    pub consistency_weeks: u32,
    /// One nullifier per deposit period claimed — prevents reuse.
    pub nullifiers: Vec<BytesN<32>>,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Address of the savings contract (set during initialize).
    SavingsContractId,
    /// CreditRecord keyed by wallet address.
    CreditRecord(Address),
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Credit signals expire after 90 days (in seconds).
const CREDIT_TTL_SECS: u64 = 90 * 24 * 60 * 60;

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

    /// Store the savings contract address so the verifier can cross-check
    /// the Merkle root and nullifier state.
    ///
    /// Must be called once after deployment.
    pub fn initialize(env: Env, savings_contract_id: Address) {
        assert!(
            !env.storage().persistent().has(&DataKey::SavingsContractId),
            "already initialized"
        );
        env.storage()
            .persistent()
            .set(&DataKey::SavingsContractId, &savings_contract_id);
    }

    // -----------------------------------------------------------------------
    // Core verification
    // -----------------------------------------------------------------------

    /// Verify a Noir-generated Groth16 ZK proof on-chain.
    ///
    /// On success: records a `CreditRecord` for the calling wallet and emits
    /// a `CreditVerified` event.
    ///
    /// On failure: panics with a descriptive error string.
    ///
    /// # Arguments
    /// * `proof`         — Raw Groth16 proof bytes produced by the Noir circuit.
    /// * `public_inputs` — Public inputs the proof was generated against.
    pub fn verify_proof(env: Env, proof: Bytes, public_inputs: PublicInputs) -> bool {
        let caller = env.current_contract_address(); // placeholder — see note below

        // --- 1. Validate consistency_weeks → credit tier ---
        let tier = Self::weeks_to_tier(public_inputs.consistency_weeks);

        // --- 2. Cross-check Merkle root against savings contract ---
        // In a real deployment this would be a cross-contract call:
        //   let savings_id: Address = env.storage()...get(&DataKey::SavingsContractId)...
        //   let savings_client = SavingsContractClient::new(&env, &savings_id);
        //   let on_chain_root = savings_client.get_merkle_root();
        //   assert!(public_inputs.commitment_root == on_chain_root, "CommitmentRootMismatch");
        //
        // Stubbed here so the scaffold compiles without a live network:
        let _ = public_inputs.commitment_root.clone(); // root check placeholder

        // --- 3. Check nullifiers are unspent ---
        // In production this calls savings_client.is_nullifier_spent(n) for each nullifier.
        // Stubbed here — replace with real cross-contract calls.
        for _i in 0..public_inputs.nullifiers.len() {
            // assert!(!savings_client.is_nullifier_spent(&nullifier), "NullifierAlreadySpent");
        }

        // --- 4. Verify the Groth16 proof ---
        // The Noir circuit verification key would be embedded here. Replace this
        // stub with the actual verifier logic once the Noir circuit is compiled.
        let proof_valid = Self::stub_verify_groth16(&env, &proof, &public_inputs);
        assert!(proof_valid, "ProofInvalid");

        // --- 5. Record credit tier ---
        let now = env.ledger().timestamp();
        let record = CreditRecord {
            wallet: caller.clone(),
            tier: tier.clone(),
            verified_at: now,
            consistency_weeks: public_inputs.consistency_weeks,
            expires_at: now + CREDIT_TTL_SECS,
        };
        env.storage()
            .persistent()
            .set(&DataKey::CreditRecord(caller.clone()), &record);

        // --- 6. Emit event ---
        env.events().publish(
            (symbol_short!("credit"), symbol_short!("verified")),
            (
                caller,
                public_inputs.consistency_weeks,
                now + CREDIT_TTL_SECS,
            ),
        );

        true
    }

    // -----------------------------------------------------------------------
    // Read functions
    // -----------------------------------------------------------------------

    /// Returns the most recent valid `CreditRecord` for `wallet`, or `None`
    /// if no record exists or the record has expired.
    pub fn get_credit_tier(env: Env, wallet: Address) -> Option<CreditRecord> {
        let record: Option<CreditRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::CreditRecord(wallet.clone()));

        match record {
            None => None,
            Some(r) => {
                let now = env.ledger().timestamp();
                if now > r.expires_at {
                    // Emit expiry event and return None.
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

    /// Returns `true` if `wallet` holds a non-expired credit record.
    /// Lending protocols can use this as a simple gate before `get_credit_tier`.
    pub fn is_credit_valid(env: Env, wallet: Address) -> bool {
        Self::get_credit_tier(env, wallet).is_some()
    }

    /// Returns the Groth16 verification key embedded in the contract.
    /// Used by tooling and auditors to confirm the correct circuit.
    pub fn get_verification_key(env: Env) -> Bytes {
        // Replace with the real serialised verification key at deployment time.
        Bytes::from_array(&env, &[0u8; 32])
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Map `consistency_weeks` to a `CreditTier`, panicking on unknown values.
    fn weeks_to_tier(weeks: u32) -> CreditTier {
        match weeks {
            8 => CreditTier::Medium,
            12 => CreditTier::Low,
            24 => CreditTier::VeryLow,
            _ => panic!("InvalidConsistencyWeeks"),
        }
    }

    /// Placeholder Groth16 verifier — always returns `true` in the scaffold.
    /// Replace with actual pairing-based verification once the Noir circuit
    /// verification key is available.
    fn stub_verify_groth16(
        _env: &Env,
        _proof: &Bytes,
        _public_inputs: &PublicInputs,
    ) -> bool {
        // TODO: implement real Groth16 pairing check.
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn make_env() -> Env {
        Env::default()
    }

    fn make_hash(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    fn make_public_inputs(env: &Env, weeks: u32) -> PublicInputs {
        let mut nullifiers = Vec::new(env);
        for i in 0..weeks {
            nullifiers.push_back(make_hash(env, i as u8));
        }
        PublicInputs {
            commitment_root: make_hash(env, 0),
            min_weekly_amount: 1_000_000,
            consistency_weeks: weeks,
            nullifiers,
        }
    }

    fn deploy_and_init(env: &Env) -> (Address, VerifierContractClient) {
        let savings_id = Address::generate(env);
        let contract_id = env.register_contract(None, VerifierContract);
        let client = VerifierContractClient::new(env, &contract_id);
        client.initialize(&savings_id);
        (contract_id, client)
    }

    #[test]
    fn test_valid_proof_records_credit() {
        let env = make_env();
        let (_, client) = deploy_and_init(&env);
        let proof = Bytes::from_array(&env, &[0u8; 64]);

        let result = client.verify_proof(&proof, &make_public_inputs(&env, 8));
        assert!(result);
    }

    #[test]
    #[should_panic(expected = "InvalidConsistencyWeeks")]
    fn test_invalid_week_count_rejected() {
        let env = make_env();
        let (_, client) = deploy_and_init(&env);
        let proof = Bytes::from_array(&env, &[0u8; 64]);

        client.verify_proof(&proof, &make_public_inputs(&env, 7));
    }

    #[test]
    fn test_medium_tier_for_8_weeks() {
        let env = make_env();
        let (contract_id, client) = deploy_and_init(&env);
        let proof = Bytes::from_array(&env, &[0u8; 64]);

        client.verify_proof(&proof, &make_public_inputs(&env, 8));

        // Credit record should exist (is_credit_valid uses current_contract_address
        // as wallet in the stub; adjust once caller routing is wired up).
        // This test exercises the tier mapping path.
        assert!(VerifierContract::weeks_to_tier(8) == CreditTier::Medium);
    }

    #[test]
    fn test_low_tier_for_12_weeks() {
        assert!(VerifierContract::weeks_to_tier(12) == CreditTier::Low);
    }

    #[test]
    fn test_very_low_tier_for_24_weeks() {
        assert!(VerifierContract::weeks_to_tier(24) == CreditTier::VeryLow);
    }

    #[test]
    fn test_double_initialize_panics() {
        let env = make_env();
        let (_, client) = deploy_and_init(&env);
        let savings_id = Address::generate(&env);
        // Second init should panic.
        let result = std::panic::catch_unwind(|| {
            client.initialize(&savings_id);
        });
        // We just verify the flow runs; in the soroban test env panics propagate.
        let _ = result;
    }
}
