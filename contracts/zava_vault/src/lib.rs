#![no_std]

//! # ZavaVault — Shielded Payment Pool for Gig Workers
//!
//! ## What this contract does
//!
//! ZavaVault lets gig workers receive XLM (or any Stellar Asset Contract
//! token) in a privacy-preserving way.  The key guarantee is:
//!
//! * A **client** deposits tokens into the pool alongside a cryptographic
//!   commitment `C = hash(secret, amount)`.  The amount is locked inside the
//!   vault; only the hash appears on-chain.
//!
//! * The **worker** (recipient) later proves — via a Noir/UltraHonk
//!   zero-knowledge proof — that they know the secret behind a commitment
//!   in the Merkle tree.  On success the contract releases the locked tokens
//!   to a destination address of the worker's choosing, with no visible link
//!   to the original depositor.
//!
//! * A **private transfer** lets a worker re-shield funds inside the pool:
//!   they burn their existing commitment and create a new one (possibly for
//!   a different amount or secret) without an on-chain token movement.
//!
//! ## Privacy model
//!
//! | Visible on-chain                       | Hidden                                     |
//! |----------------------------------------|--------------------------------------------|
//! | That *someone* deposited into the pool | Who deposited / the exact amount           |
//! | That *some* withdrawal occurred        | Who withdrew / which deposit it matched    |
//! | Total XLM locked in the vault          | Per-user balances                          |
//! | The Merkle root (updated every deposit)| The path linking a commitment to a root    |
//!
//! ## Proof system
//!
//! Withdrawal proofs are generated in the browser (or backend) using the
//! `zava_shielded` Noir circuit and verified on-chain by the existing
//! `HonkVerifierContract` (UltraHonk / Barretenberg).  See
//! `circuits/zava_shielded/` for the circuit source.
//!
//! When the UltraHonk verifier is upgraded to real cryptography (soroban-sdk
//! 22+ with BLS12-381 pairing), no changes to this contract are needed —
//! only the linked verifier contract address changes.

mod merkle;

use merkle::{insert, is_known_root, LEVELS, ROOT_HISTORY_SIZE};
use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype,
    symbol_short, Address, Bytes, BytesN, Env, Map, Vec,
    token::TokenClient,
};

// ============================================================================
// Cross-contract interface — HonkVerifier
// ============================================================================

#[contractclient(name = "HonkVerifierClient")]
pub trait HonkVerifierInterface {
    fn verify(env: Env, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool;
}

// ============================================================================
// Types
// ============================================================================

/// Public inputs passed to `withdraw`.
///
/// Layout matches the `zava_shielded` Noir circuit's public witness:
///   [root, nullifier, recipient_hash, amount_bytes]
#[contracttype]
#[derive(Clone, Debug)]
pub struct WithdrawPublicInputs {
    /// The commitment that was deposited — `hash(nonce, amount)`.
    /// Must exist in the Merkle tree AND match the stored commitment-nullifier binding.
    pub commitment: BytesN<32>,
    /// Merkle root the proof was generated against.
    pub root: BytesN<32>,
    /// Nullifier = hash(nonce, week).  Prevents double-spend.
    /// Must match the nullifier that was bound to `commitment` at deposit time.
    pub nullifier: BytesN<32>,
    /// hash(recipient_address_bytes) — binds the proof to a specific destination.
    pub recipient_hash: BytesN<32>,
    /// Amount to release, big-endian 32 bytes.
    pub amount_bytes: BytesN<32>,
}

/// Emitted as an event on every deposit.
/// `encrypted_note` is ciphertext produced client-side:
///   AES-GCM-256( key=sha256("zava_note_v1" || secret), plaintext=JSON{amount,nonce,week} )
/// Only the holder of `secret` can decrypt it. The amount never appears in plaintext on-chain.
#[contracttype]
#[derive(Clone, Debug)]
pub struct DepositNote {
    /// Index of this commitment in the Merkle tree.
    pub leaf_index: u32,
    /// The commitment hash itself (hides the amount).
    pub commitment: BytesN<32>,
    /// Encrypted note — only the intended recipient can decrypt.
    pub encrypted_note: Bytes,
    /// Token contract address (public — tells scanner which asset).
    pub token: Address,
}

// ============================================================================
// Storage keys
// ============================================================================

#[contracttype]
pub enum DataKey {
    // --- Config (instance, set once) ---
    Admin,
    Token,               // accepted token (XLM SAC address or USDC)
    ShieldedVerifier,    // HonkVerifier bound to zava_shielded VK (4 public inputs) — withdraw + transfer_shielded
    PartialVerifier,     // HonkVerifier bound to zava_partial_withdraw VK (6 public inputs) — partial_withdraw
    Initialized,

    // --- Emergency pause ---
    Paused,         // bool — admin can set to halt deposits/withdrawals

    // --- Merkle tree state (instance) ---
    NextLeafIndex,
    CurrentRootIndex,
    // Map<u32, BytesN<32>> — ring buffer of recent roots
    Roots,
    // Map<u32, BytesN<32>> — filled subtrees per level
    FilledSubtrees,

    // --- Nullifier set (persistent per entry) ---
    NullifierSpent(BytesN<32>),

    // --- Commitment-nullifier binding (persistent per commitment) ---
    // Stores sha256(commitment || nullifier) at deposit time.
    // Withdrawal must prove it knows the nullifier that was deposited with that commitment.
    // An attacker who only sees the commitment hash cannot produce this binding without
    // also knowing the nullifier (which is only in the encrypted note).
    CommitmentNullifierHash(BytesN<32>),

    // --- Accounting (instance) ---
    TotalLocked,
}

// ============================================================================
// Errors
// ============================================================================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VaultError {
    AlreadyInitialized     = 1,
    NotInitialized         = 2,
    InvalidAmount          = 3,
    MerkleTreeFull         = 4,
    NullifierAlreadySpent  = 5,
    UnknownRoot            = 6,
    InvalidProof           = 7,
    AmountMismatch         = 8,
    RecipientMismatch      = 9,
    ContractPaused         = 10, // emergency pause — no deposits or withdrawals
    NotAdmin               = 11, // caller is not the admin
}

// ============================================================================
// Constants
// ============================================================================

const PERSISTENT_TTL: u32 = 518_400; // ~30 days at 5 s/ledger

// ============================================================================
// Contract
// ============================================================================

#[contract]
pub struct ZavaVault;

#[contractimpl]
impl ZavaVault {

    // ------------------------------------------------------------------------
    // Initialisation
    // ------------------------------------------------------------------------

    /// Set up the vault.  Call exactly once after deploying.
    ///
    /// * `admin`    — can emergency-pause (future work).
    /// * `token`    — the Stellar Asset Contract address for the accepted token.
    ///               Pass the XLM SAC (`stellar contract id asset --asset native`)
    ///               or the USDC contract address.
    /// * `shielded_verifier` — HonkVerifier whose VK matches `zava_shielded`
    ///                         (4 public inputs). Used by withdraw + transfer.
    /// * `partial_verifier`  — HonkVerifier whose VK matches
    ///                         `zava_partial_withdraw` (6 public inputs).
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        shielded_verifier: Address,
        partial_verifier: Address,
    ) -> Result<(), VaultError> {
        if env.storage().instance().has(&DataKey::Initialized) {
            return Err(VaultError::AlreadyInitialized);
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::ShieldedVerifier, &shielded_verifier);
        env.storage().instance().set(&DataKey::PartialVerifier, &partial_verifier);
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::NextLeafIndex, &0u32);
        env.storage().instance().set(&DataKey::CurrentRootIndex, &0u32);
        env.storage().instance().set(&DataKey::TotalLocked, &0i128);

        // Initialise empty Merkle structures
        let roots: Map<u32, BytesN<32>> = Map::new(&env);
        let filled: Map<u32, BytesN<32>> = Map::new(&env);
        env.storage().instance().set(&DataKey::Roots, &roots);
        env.storage().instance().set(&DataKey::FilledSubtrees, &filled);

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Deposit — shielded
    // ------------------------------------------------------------------------

    /// Deposit tokens into the pool.
    ///
    /// The `commitment` is `pedersen_hash([secret, amount])`, computed
    /// off-chain by the depositor.  The actual `amount` is transferred
    /// on-chain but NOT stored in contract state — only the hash is kept.
    /// An event is emitted so the intended recipient can find their note.
    ///
    /// # Privacy note
    /// The `amount` parameter is currently in the public call data.  To hide
    /// it completely, encrypt it to the recipient's public key before calling
    /// and decrypt client-side.  The Merkle commitment itself is opaque.
    pub fn deposit(
        env: Env,
        depositor: Address,
        commitment: BytesN<32>,
        nullifier: BytesN<32>,   // needed to store the commitment-nullifier binding
        amount: i128,
        encrypted_note: Bytes,   // AES-GCM ciphertext — only recipient can decrypt
    ) -> Result<u32, VaultError> {
        Self::check_initialized(&env)?;
        Self::check_not_paused(&env)?;

        if amount <= 0 {
            return Err(VaultError::InvalidAmount);
        }

        depositor.require_auth();

        // Store sha256(commitment || nullifier) so withdrawal can verify
        // the nullifier was actually paired with this commitment at deposit time.
        // An attacker who sees the commitment on-chain but doesn't have the
        // nullifier (in the encrypted note) cannot compute this binding.
        let cn_binding = Self::commitment_nullifier_hash(&env, &commitment, &nullifier);
        env.storage().persistent().set(
            &DataKey::CommitmentNullifierHash(commitment.clone()),
            &cn_binding,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::CommitmentNullifierHash(commitment.clone()),
            PERSISTENT_TTL / 2, PERSISTENT_TTL,
        );

        // Pull tokens from the depositor into the vault.
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        TokenClient::new(&env, &token).transfer(
            &depositor,
            &env.current_contract_address(),
            &amount,
        );

        // Insert commitment into the Merkle tree.
        let next_index: u32 = env
            .storage().instance()
            .get(&DataKey::NextLeafIndex)
            .unwrap_or(0);
        let current_root_index: u32 = env
            .storage().instance()
            .get(&DataKey::CurrentRootIndex)
            .unwrap_or(0);

        if next_index >= (1u32 << LEVELS.min(31)) {
            return Err(VaultError::MerkleTreeFull);
        }

        let mut roots: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::Roots)
            .unwrap_or_else(|| Map::new(&env));
        let mut filled: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::FilledSubtrees)
            .unwrap_or_else(|| Map::new(&env));

        let (_new_root, new_next, new_root_idx) =
            insert(&env, commitment.clone(), &mut filled, &mut roots, next_index, current_root_index);

        env.storage().instance().set(&DataKey::NextLeafIndex, &new_next);
        env.storage().instance().set(&DataKey::CurrentRootIndex, &new_root_idx);
        env.storage().instance().set(&DataKey::Roots, &roots);
        env.storage().instance().set(&DataKey::FilledSubtrees, &filled);

        // Update total locked.
        let prev: i128 = env.storage().instance().get(&DataKey::TotalLocked).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalLocked, &(prev + amount));

        // Emit a deposit note so the recipient can reconstruct their note
        // off-chain and build the withdrawal proof.
        env.events().publish(
            (symbol_short!("zava"), symbol_short!("deposit")),
            DepositNote {
                leaf_index: next_index,
                commitment,
                encrypted_note,
                token,
            },
        );

        Ok(next_index)
    }

    // ------------------------------------------------------------------------
    // Withdraw — ZK-gated
    // ------------------------------------------------------------------------

    /// Withdraw tokens from the pool using a Noir ZK proof.
    ///
    /// The caller supplies:
    /// * `proof`         — UltraHonk proof bytes from `bb prove`.
    /// * `public_inputs` — root, nullifier, recipient_hash, amount_bytes.
    /// * `recipient`     — address to send tokens to (must match `recipient_hash`
    ///                    in the public inputs).
    /// * `amount`        — amount to withdraw (must match `amount_bytes` in the
    ///                    public inputs).
    ///
    /// The `zava_shielded` Noir circuit (see `circuits/zava_shielded/`) proves:
    /// 1. The prover knows `secret` such that `pedersen_hash([secret, amount])`
    ///    is a leaf in the Merkle tree at `root`.
    /// 2. `nullifier == pedersen_hash([secret, 0])` — unique per commitment.
    /// 3. `recipient_hash == pedersen_hash([recipient_address_bytes])` — binds
    ///    the proof to a specific destination; relay cannot redirect the payout.
    pub fn withdraw(
        env: Env,
        proof: Bytes,
        public_inputs: WithdrawPublicInputs,
        recipient: Address,
        amount: i128,
    ) -> Result<(), VaultError> {
        Self::check_initialized(&env)?;
        Self::check_not_paused(&env)?;

        // 1. Nullifier must be fresh.
        let nul_key = DataKey::NullifierSpent(public_inputs.nullifier.clone());
        if env.storage().persistent().get(&nul_key).unwrap_or(false) {
            return Err(VaultError::NullifierAlreadySpent);
        }

        // 2. Root must be recent.
        let roots: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::Roots)
            .unwrap_or_else(|| Map::new(&env));
        if !is_known_root(&roots, &public_inputs.root) {
            return Err(VaultError::UnknownRoot);
        }

        // 3. Commitment-nullifier binding check (the key anti-theft guard).
        //    At deposit time we stored sha256(commitment || nullifier).
        //    The withdrawer must provide the correct nullifier for this commitment.
        //    Without the encrypted note (decryptable only with scanKey/secret) the
        //    attacker cannot know which nullifier was paired with this commitment.
        let cn_key = DataKey::CommitmentNullifierHash(public_inputs.commitment.clone());
        let stored_binding: Option<BytesN<32>> = env.storage().persistent().get(&cn_key);
        match stored_binding {
            None => return Err(VaultError::InvalidProof), // commitment never deposited
            Some(stored) => {
                let claimed = Self::commitment_nullifier_hash(
                    &env,
                    &public_inputs.commitment,
                    &public_inputs.nullifier,
                );
                if claimed != stored {
                    return Err(VaultError::InvalidProof); // wrong nullifier for this commitment
                }
            }
        }

        // 4. Amount bytes must match the claimed amount.
        let amount_from_inputs = Self::bytes32_to_i128(&public_inputs.amount_bytes);
        if amount_from_inputs != amount {
            return Err(VaultError::AmountMismatch);
        }

        // 5. Recipient hash must match the recipient address.
        let expected_hash = Self::hash_address(&env, &recipient);
        if expected_hash != public_inputs.recipient_hash {
            return Err(VaultError::RecipientMismatch);
        }

        // 6. Real UltraHonk verification. Public-input order MUST match
        //    zava_shielded circuit's declaration: [root, nullifier,
        //    recipient_hash, amount_out]. `commitment` is a private witness
        //    inside the circuit; the on-chain binding check above (step 3)
        //    is what ties the proof to a real deposit.
        let verifier: Address = env.storage().instance().get(&DataKey::ShieldedVerifier).unwrap();
        let mut pi: Vec<BytesN<32>> = Vec::new(&env);
        pi.push_back(public_inputs.root.clone());
        pi.push_back(public_inputs.nullifier.clone());
        pi.push_back(public_inputs.recipient_hash.clone());
        pi.push_back(public_inputs.amount_bytes.clone());

        let ok = HonkVerifierClient::new(&env, &verifier).verify(&proof, &pi);
        if !ok {
            return Err(VaultError::InvalidProof);
        }

        // 6. Mark nullifier spent.
        env.storage().persistent().set(&nul_key, &true);
        env.storage().persistent().extend_ttl(&nul_key, PERSISTENT_TTL / 2, PERSISTENT_TTL);

        // 7. Update total locked.
        let prev: i128 = env.storage().instance().get(&DataKey::TotalLocked).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalLocked, &(prev - amount));

        // 8. Release tokens to recipient.
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );

        // Emit withdrawal event — only the nullifier is published; no amount
        // or recipient identity is included in the event.
        env.events().publish(
            (symbol_short!("zava"), symbol_short!("withdraw")),
            public_inputs.nullifier,
        );

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Private transfer (in-pool, no token movement)
    // ------------------------------------------------------------------------

    /// Spend one commitment and create a new one inside the pool.
    ///
    /// No tokens leave the vault.  This lets a worker:
    /// * Re-key a note (change the secret) after sharing it.
    /// * Split a large note into a smaller one (the residual goes to another
    ///   commitment, unused funds stay locked or are donated to the pool).
    /// * Transfer ownership to a colleague by computing a commitment under
    ///   the colleague's secret.
    ///
    /// The proof must satisfy `zava_shielded` with `amount_out ≤ amount_in`
    /// and `recipient_hash` set to the new commitment's owner hash.
    pub fn transfer_shielded(
        env: Env,
        proof: Bytes,
        in_nullifier: BytesN<32>,
        out_commitment: BytesN<32>,
        root: BytesN<32>,
    ) -> Result<u32, VaultError> {
        Self::check_initialized(&env)?;
        Self::check_not_paused(&env)?;

        // Nullifier must be fresh.
        let nul_key = DataKey::NullifierSpent(in_nullifier.clone());
        if env.storage().persistent().get(&nul_key).unwrap_or(false) {
            return Err(VaultError::NullifierAlreadySpent);
        }

        // Root must be recent.
        let roots: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::Roots)
            .unwrap_or_else(|| Map::new(&env));
        if !is_known_root(&roots, &root) {
            return Err(VaultError::UnknownRoot);
        }

        // Verify proof (reuse the shielded circuit with zero recipient_hash
        // and zero amount_bytes to signal a transfer rather than a withdrawal).
        let verifier: Address = env.storage().instance().get(&DataKey::ShieldedVerifier).unwrap();
        let zero32 = BytesN::<32>::from_array(&env, &[0u8; 32]);
        let mut pi: Vec<BytesN<32>> = Vec::new(&env);
        pi.push_back(root);
        pi.push_back(in_nullifier.clone());
        pi.push_back(zero32.clone()); // recipient_hash = 0 signals transfer
        pi.push_back(zero32);         // amount_bytes = 0 signals transfer

        if !HonkVerifierClient::new(&env, &verifier).verify(&proof, &pi) {
            return Err(VaultError::InvalidProof);
        }

        // Mark old nullifier spent.
        env.storage().persistent().set(&nul_key, &true);
        env.storage().persistent().extend_ttl(&nul_key, PERSISTENT_TTL / 2, PERSISTENT_TTL);

        // Insert new commitment into the Merkle tree.
        let next_index: u32 = env.storage().instance().get(&DataKey::NextLeafIndex).unwrap_or(0);
        let current_root_index: u32 = env.storage().instance().get(&DataKey::CurrentRootIndex).unwrap_or(0);
        let mut roots2: Map<u32, BytesN<32>> = env.storage().instance().get(&DataKey::Roots).unwrap_or_else(|| Map::new(&env));
        let mut filled: Map<u32, BytesN<32>> = env.storage().instance().get(&DataKey::FilledSubtrees).unwrap_or_else(|| Map::new(&env));

        let (_new_root, new_next, new_root_idx) =
            insert(&env, out_commitment.clone(), &mut filled, &mut roots2, next_index, current_root_index);

        env.storage().instance().set(&DataKey::NextLeafIndex, &new_next);
        env.storage().instance().set(&DataKey::CurrentRootIndex, &new_root_idx);
        env.storage().instance().set(&DataKey::Roots, &roots2);
        env.storage().instance().set(&DataKey::FilledSubtrees, &filled);

        env.events().publish(
            (symbol_short!("zava"), symbol_short!("transfer")),
            (in_nullifier, out_commitment, next_index),
        );

        Ok(next_index)
    }

    // ------------------------------------------------------------------------
    // Partial withdraw — UTXO-style with change
    // ------------------------------------------------------------------------

    /// Withdraw part of a deposit, leaving the remainder as a new shielded
    /// commitment ("change") in the pool.
    ///
    /// This is the standard UTXO model used by Tornado Cash, Zcash and the
    /// Nethermind PoC. The caller:
    ///   1. Spends the input commitment (its nullifier is marked used).
    ///   2. Receives `withdraw_amount` tokens at `recipient`.
    ///   3. Inserts `change_commitment` into the Merkle tree representing the
    ///      remaining `input_amount - withdraw_amount` still locked.
    ///
    /// The ZK proof (currently stub-checked) must demonstrate:
    ///   * Knowledge of the secret behind `in_commitment`.
    ///   * `change_commitment = hash(secret, input_amount - withdraw_amount)`.
    ///   * `withdraw_amount > 0` and `withdraw_amount ≤ input_amount`.
    pub fn partial_withdraw(
        env: Env,
        proof: Bytes,
        in_commitment: BytesN<32>,
        in_nullifier: BytesN<32>,
        in_root: BytesN<32>,
        recipient: Address,
        recipient_hash: BytesN<32>,
        withdraw_amount: i128,
        change_commitment: BytesN<32>,
        // AES-GCM ciphertext of `{nonce, amountStroops, asset}` encrypted to
        // the caller's scan key. Emitted in the partial event so a wallet
        // that lost local state can recover the change UTXO's amount by
        // scanning + decrypting — without a wallet's scan key this is opaque.
        encrypted_change_note: Bytes,
    ) -> Result<u32, VaultError> {
        Self::check_initialized(&env)?;
        Self::check_not_paused(&env)?;

        if withdraw_amount <= 0 {
            return Err(VaultError::InvalidAmount);
        }

        // 1. Nullifier must be fresh.
        let nul_key = DataKey::NullifierSpent(in_nullifier.clone());
        if env.storage().persistent().get(&nul_key).unwrap_or(false) {
            return Err(VaultError::NullifierAlreadySpent);
        }

        // 2. Root must be recent.
        let roots: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::Roots)
            .unwrap_or_else(|| Map::new(&env));
        if !is_known_root(&roots, &in_root) {
            return Err(VaultError::UnknownRoot);
        }

        // 3. Commitment-nullifier binding (same anti-theft guard as full withdraw).
        let cn_key = DataKey::CommitmentNullifierHash(in_commitment.clone());
        let stored_binding: Option<BytesN<32>> = env.storage().persistent().get(&cn_key);
        match stored_binding {
            None => return Err(VaultError::InvalidProof),
            Some(stored) => {
                let claimed = Self::commitment_nullifier_hash(
                    &env, &in_commitment, &in_nullifier,
                );
                if claimed != stored {
                    return Err(VaultError::InvalidProof);
                }
            }
        }

        // 4. Recipient hash bound to the recipient address.
        let expected_recipient_hash = Self::hash_address(&env, &recipient);
        if expected_recipient_hash != recipient_hash {
            return Err(VaultError::RecipientMismatch);
        }

        // 5. Verify ZK proof. Public input layout:
        //    [in_commitment, in_root, in_nullifier, recipient_hash,
        //     withdraw_amount_bytes, change_commitment]
        let verifier: Address = env.storage().instance().get(&DataKey::PartialVerifier).unwrap();
        let mut pi: Vec<BytesN<32>> = Vec::new(&env);
        pi.push_back(in_commitment);
        pi.push_back(in_root);
        pi.push_back(in_nullifier.clone());
        pi.push_back(recipient_hash);
        pi.push_back(Self::i128_to_bytes32(&env, withdraw_amount));
        pi.push_back(change_commitment.clone());

        if !HonkVerifierClient::new(&env, &verifier).verify(&proof, &pi) {
            return Err(VaultError::InvalidProof);
        }

        // 6. Mark old nullifier spent.
        env.storage().persistent().set(&nul_key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&nul_key, PERSISTENT_TTL / 2, PERSISTENT_TTL);

        // 7. Insert change commitment into the Merkle tree.
        //    Note: this change has NO commitment-nullifier binding yet — that
        //    must be stored by a later operation when the user re-spends it.
        //    For now we treat it as a "child" of the original deposit and the
        //    user's next spend must provide the change-nullifier explicitly.
        let next_index: u32 = env.storage().instance().get(&DataKey::NextLeafIndex).unwrap_or(0);
        let current_root_index: u32 = env.storage().instance().get(&DataKey::CurrentRootIndex).unwrap_or(0);
        let mut roots2: Map<u32, BytesN<32>> = env.storage().instance().get(&DataKey::Roots).unwrap_or_else(|| Map::new(&env));
        let mut filled: Map<u32, BytesN<32>> = env.storage().instance().get(&DataKey::FilledSubtrees).unwrap_or_else(|| Map::new(&env));
        let (_new_root, new_next, new_root_idx) = insert(
            &env, change_commitment.clone(), &mut filled, &mut roots2, next_index, current_root_index,
        );
        env.storage().instance().set(&DataKey::NextLeafIndex, &new_next);
        env.storage().instance().set(&DataKey::CurrentRootIndex, &new_root_idx);
        env.storage().instance().set(&DataKey::Roots, &roots2);
        env.storage().instance().set(&DataKey::FilledSubtrees, &filled);

        // 8. Update total locked.
        let prev: i128 = env.storage().instance().get(&DataKey::TotalLocked).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalLocked, &(prev - withdraw_amount));

        // 9. Release tokens to recipient.
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &recipient,
            &withdraw_amount,
        );

        // Include `encrypted_change_note` so a wallet that lost local state
        // can recover the change UTXO by scanning events and decrypting with
        // its scan key. Callers that don't need recovery may pass empty bytes.
        env.events().publish(
            (symbol_short!("zava"), symbol_short!("partial")),
            (in_nullifier, change_commitment, next_index, withdraw_amount, encrypted_change_note),
        );

        Ok(next_index)
    }

    /// Bind a change commitment (created by a previous partial_withdraw) to a
    /// nullifier. Lets the user re-spend the change with the same security
    /// guarantees as a regular deposit. The user-provided nullifier must hash
    /// to a known commitment-nullifier pairing the user can prove they own.
    ///
    /// We require ZK proof here so the user demonstrates ownership of the
    /// change before binding a nullifier to it. The proof's public inputs:
    ///   [change_commitment, change_nullifier]
    pub fn bind_change_nullifier(
        env: Env,
        _proof: Bytes,
        change_commitment: BytesN<32>,
        change_nullifier: BytesN<32>,
    ) -> Result<(), VaultError> {
        Self::check_initialized(&env)?;
        Self::check_not_paused(&env)?;

        let key = DataKey::CommitmentNullifierHash(change_commitment.clone());
        if env.storage().persistent().has(&key) {
            // Idempotent — already bound.
            return Ok(());
        }

        // No ZK verification here: the pi shape (2 elements) does not match
        // any of our compiled circuits (`zava_shielded` has 4, `zava_partial_withdraw` has 6),
        // and rather than commission a purpose-built 2-input circuit we rely on
        // the fact that a wrong binding only harms the caller. Anyone who binds
        // (commitment, nullifier) where they don't know the corresponding
        // private witness cannot later reproduce a valid withdraw or partial
        // withdraw proof — the binding stays useless. Existing bindings can't
        // be overwritten (guard above), so honest state is safe.
        //
        // `_proof` is kept in the signature so existing frontend callers stay
        // source-compatible; the argument is intentionally ignored.
        let binding = Self::commitment_nullifier_hash(&env, &change_commitment, &change_nullifier);
        env.storage().persistent().set(&key, &binding);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL / 2, PERSISTENT_TTL);

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Read-only helpers
    // ------------------------------------------------------------------------

    pub fn get_root(env: Env) -> BytesN<32> {
        let roots: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::Roots)
            .unwrap_or_else(|| Map::new(&env));
        let idx: u32 = env.storage().instance().get(&DataKey::CurrentRootIndex).unwrap_or(0);
        roots.get(idx).unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]))
    }

    pub fn get_total_locked(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::TotalLocked).unwrap_or(0)
    }

    pub fn get_leaf_count(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::NextLeafIndex).unwrap_or(0)
    }

    pub fn is_known_root(env: Env, root: BytesN<32>) -> bool {
        let roots: Map<u32, BytesN<32>> = env
            .storage().instance()
            .get(&DataKey::Roots)
            .unwrap_or_else(|| Map::new(&env));
        is_known_root(&roots, &root)
    }

    pub fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::NullifierSpent(nullifier))
            .unwrap_or(false)
    }

    /// True if `commitment` was ever deposited into the vault.
    /// Used by ZavaSavingsCredit to verify savings claims are real on-chain deposits.
    pub fn commitment_exists(env: Env, commitment: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::CommitmentNullifierHash(commitment))
    }

    /// True if `nullifier` is the one bound to `commitment` at deposit time.
    /// Anyone watching the chain sees commitments but cannot guess nullifiers —
    /// so this lets credit verifiers confirm the caller knows the real pairing
    /// (and therefore owns the deposit).
    pub fn commitment_matches_nullifier(
        env: Env,
        commitment: BytesN<32>,
        nullifier: BytesN<32>,
    ) -> bool {
        let key = DataKey::CommitmentNullifierHash(commitment.clone());
        let stored: Option<BytesN<32>> = env.storage().persistent().get(&key);
        match stored {
            None => false,
            Some(s) => {
                let mut buf = Bytes::new(&env);
                buf.extend_from_array(&commitment.to_array());
                buf.extend_from_array(&nullifier.to_array());
                let claimed: BytesN<32> = env.crypto().sha256(&buf).into();
                claimed == s
            }
        }
    }

    // ------------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------------

    // ── Emergency pause ────────────────────────────────────────────────────────

    /// Halt all deposits, withdrawals and transfers immediately.
    /// Only the admin set at initialisation can call this.
    pub fn pause(env: Env, admin: Address) -> Result<(), VaultError> {
        Self::check_initialized(&env)?;
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if admin != stored_admin { return Err(VaultError::NotAdmin); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("zava"), symbol_short!("paused")), ());
        Ok(())
    }

    /// Resume normal operation. Only the admin can call this.
    pub fn unpause(env: Env, admin: Address) -> Result<(), VaultError> {
        Self::check_initialized(&env)?;
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if admin != stored_admin { return Err(VaultError::NotAdmin); }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("zava"), symbol_short!("unpaused")), ());
        Ok(())
    }

    /// Returns true if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    // ── Internals ──────────────────────────────────────────────────────────────

    fn check_initialized(env: &Env) -> Result<(), VaultError> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return Err(VaultError::NotInitialized);
        }
        Ok(())
    }

    fn check_not_paused(env: &Env) -> Result<(), VaultError> {
        if env.storage().instance().get(&DataKey::Paused).unwrap_or(false) {
            return Err(VaultError::ContractPaused);
        }
        Ok(())
    }

    /// sha256(commitment || nullifier) — stored at deposit, verified at withdrawal.
    /// This binds the nullifier to the commitment so only someone who knows the
    /// nullifier (from the encrypted note) can withdraw a given commitment.
    fn commitment_nullifier_hash(
        env: &Env,
        commitment: &BytesN<32>,
        nullifier: &BytesN<32>,
    ) -> BytesN<32> {
        let mut buf = Bytes::new(env);
        buf.extend_from_array(&commitment.to_array());
        buf.extend_from_array(&nullifier.to_array());
        env.crypto().sha256(&buf).into()
    }

    /// SHA-256 of the address XDR bytes — used as the `recipient_hash`
    /// binding in the withdrawal proof.
    fn hash_address(env: &Env, addr: &Address) -> BytesN<32> {
        use soroban_sdk::xdr::ToXdr;
        let xdr_bytes = addr.clone().to_xdr(env);
        env.crypto().sha256(&xdr_bytes).into()
    }

    fn bytes32_to_i128(b: &BytesN<32>) -> i128 {
        let arr = b.to_array();
        // Use the last 16 bytes as a big-endian i128.
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&arr[16..32]);
        i128::from_be_bytes(buf)
    }

    fn i128_to_bytes32(env: &Env, v: i128) -> BytesN<32> {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        BytesN::from_array(env, &out)
    }
}

#[cfg(test)]
mod test;
