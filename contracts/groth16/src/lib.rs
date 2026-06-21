#![no_std]

//! # Groth16 Verifier Contract
//!
//! Pure cryptographic verifier for Noir-generated Groth16 ZK proofs.
//! Has no business logic — only takes a proof + public inputs and returns
//! `true` / `false`.
//!
//! The verification key is supplied once at deployment via `initialize` and
//! is immutable thereafter (no setter, no admin, no upgrade path). If the
//! Noir circuit changes, a new instance of this contract must be deployed.
//!
//! The actual pairing check is currently a structural stub — see
//! [`Self::pairing_check`] for the integration boundary. Replace the body
//! with real BLS12-381 pairing verification once the Noir circuit is
//! compiled and the on-chain VK is available.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    symbol_short, Bytes, BytesN, Env, Vec,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Serialised Groth16 verification key as produced by `nargo codegen-verifier`.
///
/// Stored as raw bytes so this contract does not need to know the field
/// element layout used by the Noir backend — the pairing-check implementation
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
pub enum Groth16Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    PublicInputCountMismatch = 3,
    InvalidProofLength = 4,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum byte length of a serialised Groth16 proof (3 group elements:
/// A on G1, B on G2, C on G1 — at least 48 + 96 + 48 bytes for BLS12-381
/// compressed form). Used as a sanity check, not a definitive bound.
const MIN_PROOF_BYTES: u32 = 192;

/// TTL extension applied to persistent storage entries on touch.
/// 1 month worth of ledgers at ~5s per ledger.
const PERSISTENT_TTL_LEDGERS: u32 = 518_400;

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct Groth16Contract;

#[contractimpl]
impl Groth16Contract {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Embed the Groth16 verification key. Callable exactly once.
    ///
    /// # Arguments
    /// * `vk_bytes`          — serialised verification key.
    /// * `num_public_inputs` — number of public inputs the matching Noir
    ///                         circuit was compiled with.
    pub fn initialize(env: Env, vk_bytes: Bytes, num_public_inputs: u32) -> Result<(), Groth16Error> {
        if env.storage().instance().has(&DataKey::Vk) {
            return Err(Groth16Error::AlreadyInitialized);
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

    /// Verify a Groth16 proof against the embedded verification key.
    ///
    /// Returns `true` only if all of the following hold:
    /// 1. The contract has been initialised with a verification key.
    /// 2. `public_inputs.len()` matches the VK's expected count.
    /// 3. `proof` is at least [`MIN_PROOF_BYTES`] long.
    /// 4. The pairing check (currently stubbed) succeeds.
    ///
    /// Returns `false` if the pairing check fails. Panics with a typed
    /// `Groth16Error` for structural problems (uninitialised, length mismatch)
    /// — these are integration bugs, not provable claims.
    pub fn verify(
        env: Env,
        proof: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        let vk: VerificationKey = match env.storage().instance().get(&DataKey::Vk) {
            Some(v) => v,
            None => panic_with_error!(&env, Groth16Error::NotInitialized),
        };

        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_TTL_LEDGERS / 2, PERSISTENT_TTL_LEDGERS);

        if public_inputs.len() != vk.num_public_inputs {
            panic_with_error!(&env, Groth16Error::PublicInputCountMismatch);
        }
        if proof.len() < MIN_PROOF_BYTES {
            panic_with_error!(&env, Groth16Error::InvalidProofLength);
        }

        let valid = Self::pairing_check(&env, &vk.bytes, &proof, &public_inputs);

        env.events().publish(
            (symbol_short!("g16"), symbol_short!("verified")),
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
            None => panic_with_error!(&env, Groth16Error::NotInitialized),
        };
        vk.bytes
    }

    /// Returns the number of public inputs the embedded VK was compiled for.
    pub fn get_num_public_inputs(env: Env) -> u32 {
        let vk: VerificationKey = match env.storage().instance().get(&DataKey::Vk) {
            Some(v) => v,
            None => panic_with_error!(&env, Groth16Error::NotInitialized),
        };
        vk.num_public_inputs
    }

    // -----------------------------------------------------------------------
    // Pairing check — integration boundary
    // -----------------------------------------------------------------------

    /// **STUB — replace with a real BLS12-381 pairing-based Groth16 check.**
    ///
    /// The current body performs only a non-cryptographic sanity check
    /// (proof + VK + public inputs are all non-empty) so that downstream
    /// contracts can be exercised end-to-end before the Noir circuit is
    /// compiled.
    ///
    /// When integrating the real verifier:
    ///   * Bump `soroban-sdk` to a version that exposes
    ///     `env.crypto().bls12_381()` (protocol 22+).
    ///   * Deserialise `vk_bytes` into the `(alpha_g1, beta_g2, gamma_g2,
    ///     delta_g2, ic[])` tuple emitted by `nargo codegen-verifier`.
    ///   * Deserialise `proof` into `(a_g1, b_g2, c_g1)`.
    ///   * Compute `vk_x = ic[0] + Σ public_inputs[i] * ic[i+1]`.
    ///   * Run the pairing equation:
    ///       `e(a_g1, b_g2) == e(alpha_g1, beta_g2)
    ///        · e(vk_x, gamma_g2)
    ///        · e(c_g1, delta_g2)`
    ///   * Return the equality result.
    ///
    /// Reference: Nethermind / SDF Soroban Groth16 verifier.
    fn pairing_check(
        _env: &Env,
        vk_bytes: &Bytes,
        proof: &Bytes,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        // Sanity gate — keeps the integration honest about what's wired up.
        !vk_bytes.is_empty() && !proof.is_empty() && !public_inputs.is_empty()
    }
}

#[cfg(test)]
mod test;
