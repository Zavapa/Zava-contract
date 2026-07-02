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
//! Verification runs through the `ultrahonk_soroban_verifier` crate — a
//! Rust port of Aztec's Barretenberg reference — which is compatible with
//! `bb prove` / `bb write_vk` output and can route BN254 pairings through
//! Protocol 26 host precompiles.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    symbol_short, Bytes, BytesN, Env, Vec,
};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, VkLoadError, PROOF_BYTES};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Serialised UltraHonk verification key as produced by `bb write_vk`.
///
/// Stored as raw bytes; the verifier crate is responsible for parsing the
/// field-element layout on use.
#[contracttype]
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub bytes: Bytes,
    /// Number of public inputs the Noir circuit was compiled with.
    /// Kept as a fast structural gate; the verifier also enforces this
    /// against the count embedded in the VK header.
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
    /// VK byte slice does not match the expected exact length.
    VkInvalidLength = 5,
    /// VK header contains out-of-range structural parameters.
    VkInvalidParameters = 6,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TTL extension applied to persistent storage entries on touch.
/// ~30 days at 5s per ledger.
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
    /// The VK is parsed synchronously so that a malformed key is rejected at
    /// deployment time rather than at first proof submission.
    pub fn initialize(
        env: Env,
        vk_bytes: Bytes,
        num_public_inputs: u32,
    ) -> Result<(), HonkVerifierError> {
        if env.storage().instance().has(&DataKey::Vk) {
            return Err(HonkVerifierError::AlreadyInitialized);
        }
        UltraHonkVerifier::new(&env, &vk_bytes).map_err(|e| match e {
            VkLoadError::WrongLength => HonkVerifierError::VkInvalidLength,
            VkLoadError::InvalidParameters => HonkVerifierError::VkInvalidParameters,
        })?;
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
    /// 2. `proof.len() == PROOF_BYTES` (exact `bb prove` output size).
    /// 3. `public_inputs.len()` matches the count declared at initialize.
    /// 4. The cryptographic verification (Sumcheck + Shplemini) succeeds.
    ///
    /// Returns `false` for any structural or cryptographic failure so that
    /// upstream callers (which all branch on the `bool`) get a clean
    /// rejection instead of an abort.
    pub fn verify(env: Env, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool {
        let vk: VerificationKey = match env.storage().instance().get(&DataKey::Vk) {
            Some(v) => v,
            None => return false,
        };

        // Cheap structural gates before the expensive crypto path.
        if proof.len() as usize != PROOF_BYTES {
            return false;
        }
        if public_inputs.len() != vk.num_public_inputs {
            return false;
        }

        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_TTL_LEDGERS / 2, PERSISTENT_TTL_LEDGERS);

        // Verifier expects `public_inputs` as raw 32-byte-aligned concat.
        let mut public_inputs_bytes = Bytes::new(&env);
        for pi in public_inputs.iter() {
            let arr: [u8; 32] = pi.into();
            public_inputs_bytes.extend_from_array(&arr);
        }

        let verifier = match UltraHonkVerifier::new(&env, &vk.bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let valid = verifier
            .verify(&env, &proof, &public_inputs_bytes)
            .is_ok();

        // `Events::publish` is soft-deprecated in soroban-sdk 26 in favour of
        // `#[contractevent]` types. Migrating this is a separate refactor —
        // the current shape keeps the event schema stable for existing
        // downstream indexers.
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("honk"), symbol_short!("verified")),
            valid,
        );

        valid
    }

    /// Returns the raw verification-key bytes embedded at deployment.
    /// Returned as primitive `Bytes` so cross-contract callers don't need to
    /// depend on this crate for the `VerificationKey` struct.
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
}

#[cfg(test)]
mod test;
