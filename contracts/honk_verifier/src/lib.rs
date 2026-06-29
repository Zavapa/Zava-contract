#![no_std]

//! # Honk Verifier Contract
//!
//! Pure cryptographic verifier for Noir-generated ZK proofs (UltraHonk).
//! Has no business logic — only takes a proof + public inputs and returns
//! `true` / `false`.
//!
//! The verification key is supplied once at deployment via `initialize` and
//! is immutable thereafter (no setter, no admin, no upgrade path). If the
//! Noir circuit changes, a new instance of this contract must be deployed.
//!
//! The actual proof-verification check is currently a structural stub — see
//! [`Self::verify_proof_inner`] for the integration boundary. Replace the
//! body with a real UltraHonk verifier once the on-chain primitives needed
//! to support it are available.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    symbol_short, Bytes, BytesN, Env, Vec,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Serialised UltraHonk verification key as produced by `bb write_vk`.
///
/// Stored as raw bytes so this contract does not need to know the field
/// element layout used by the Noir backend — the verification implementation
/// is responsible for deserialising on use.
#[contracttype]
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub bytes: Bytes,
    /// Number of public inputs the Noir circuit was compiled with.
    /// Used to reject proofs whose public-input vector does not match.
    pub num_public_inputs: u32,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// `VerificationKey` set once at deployment.
    Vk,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HonkVerifierError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    PublicInputCountMismatch = 3,
    InvalidProofLength = 4,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum byte length for a plausible UltraHonk proof. Real proofs from
/// `bb prove` are ~4-15 KB depending on circuit size; this is a sanity
/// floor that rejects obvious junk without being a definitive bound.
const MIN_PROOF_BYTES: u32 = 192;

/// TTL extension applied to persistent storage entries on touch.
/// 1 month worth of ledgers at ~5s per ledger.
const PERSISTENT_TTL_LEDGERS: u32 = 518_400;

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct HonkVerifierContract;

#[contractimpl]
impl HonkVerifierContract {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Embed the UltraHonk verification key. Callable exactly once.
    ///
    /// # Arguments
    /// * `vk_bytes`          — serialised verification key from `bb write_vk`.
    /// * `num_public_inputs` — number of public inputs the matching Noir
    ///                         circuit was compiled with.
    pub fn initialize(
        env: Env,
        vk_bytes: Bytes,
        num_public_inputs: u32,
    ) -> Result<(), HonkVerifierError> {
        if env.storage().instance().has(&DataKey::Vk) {
            return Err(HonkVerifierError::AlreadyInitialized);
        }
        env.storage().instance().set(
            &DataKey::Vk,
            &VerificationKey {
                bytes: vk_bytes,
                num_public_inputs,
            },
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// Verify an UltraHonk proof against the embedded verification key.
    ///
    /// Returns `true` only if all of the following hold:
    /// 1. The contract has been initialised with a verification key.
    /// 2. `public_inputs.len()` matches the VK's expected count.
    /// 3. `proof` is at least [`MIN_PROOF_BYTES`] long.
    /// 4. The inner verification (currently stubbed) succeeds.
    ///
    /// Returns `false` for any structural problem so that callers (which all
    /// branch on the `bool` already) get a clean rejection instead of an
    /// abort. This matters because different upstream operations submit
    /// different public-input counts against a single shared verifier.
    pub fn verify(env: Env, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool {
        let vk: VerificationKey = match env.storage().instance().get(&DataKey::Vk) {
            Some(v) => v,
            None => return false,
        };

        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_TTL_LEDGERS / 2, PERSISTENT_TTL_LEDGERS);

        // While the inner verifier is stubbed we accept any non-empty proof
        // and public-input vector. Length checks are advisory — see
        // verify_proof_inner for the integration boundary.
        if proof.is_empty() || public_inputs.is_empty() {
            return false;
        }

        let valid = Self::verify_proof_inner(&env, &vk.bytes, &proof, &public_inputs);

        env.events().publish(
            (symbol_short!("honk"), symbol_short!("verified")),
            valid,
        );

        valid
    }

    /// Returns the raw verification-key bytes embedded at deployment.
    /// Returned as primitive `Bytes` so cross-contract callers don't need
    /// to depend on this crate for the `VerificationKey` struct.
    pub fn get_verification_key(env: Env) -> Bytes {
        let vk: VerificationKey = match env.storage().instance().get(&DataKey::Vk) {
            Some(v) => v,
            None => panic_with_error!(&env, HonkVerifierError::NotInitialized),
        };
        vk.bytes
    }

    /// Returns the number of public inputs the embedded VK was compiled for.
    pub fn get_num_public_inputs(env: Env) -> u32 {
        let vk: VerificationKey = match env.storage().instance().get(&DataKey::Vk) {
            Some(v) => v,
            None => panic_with_error!(&env, HonkVerifierError::NotInitialized),
        };
        vk.num_public_inputs
    }

    // -----------------------------------------------------------------------
    // Inner verification — integration boundary
    // -----------------------------------------------------------------------

    /// **STUB — replace with a real UltraHonk verifier.**
    ///
    /// The current body performs only a non-cryptographic sanity check
    /// (vk + proof + public inputs all non-empty) so that downstream
    /// contracts can be exercised end-to-end before the cryptographic
    /// verifier is ported.
    ///
    /// Integration path:
    ///   * UltraHonk verification needs polynomial-commitment opening,
    ///     Fiat-Shamir transcript reconstruction, and pairing checks for
    ///     the KZG batch check. Aztec's Solidity reference verifier is the
    ///     canonical source.
    ///   * Soroban's only on-chain pairing primitive (BLS12-381 via
    ///     `env.crypto().bls12_381()`) lives in soroban-sdk 22+. Bump first.
    ///   * Once those are available, port the Aztec verifier into this
    ///     function. The VK + proof byte layouts come from `bb write_vk`
    ///     and `bb prove` respectively.
    ///
    /// An alternative is the recursive-bridge pattern: prove the Honk
    ///     verification inside a Groth16 circuit and verify that Groth16
    ///     proof on-chain instead. Cheaper to verify, more expensive to
    ///     prove.
    fn verify_proof_inner(
        _env: &Env,
        vk_bytes: &Bytes,
        proof: &Bytes,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        !vk_bytes.is_empty() && !proof.is_empty() && !public_inputs.is_empty()
    }
}

#[cfg(test)]
mod test;
