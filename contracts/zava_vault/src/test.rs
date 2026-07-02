#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient as SacTokenClient},
    Address, Bytes, BytesN, Env,
};

// ============================================================================
// Mock verifier — accepts any proof. Mirrors the stub behaviour of the
// honk_verifier we currently use, so the vault's own security checks
// (commitment-nullifier binding, recipient binding, etc.) are what the
// tests actually exercise.
// ============================================================================

mod mock_verifier {
    use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};

    #[contract]
    pub struct MockVerifier;

    #[contractimpl]
    impl MockVerifier {
        pub fn verify(_env: Env, _proof: Bytes, _public_inputs: Vec<BytesN<32>>) -> bool {
            true
        }
    }
}

// ============================================================================
// Test harness
// ============================================================================

struct Harness<'a> {
    env: Env,
    admin: Address,
    token_admin: Address,
    token_id: Address,
    vault: ZavaVaultClient<'a>,
    vault_id: Address,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    // Real Stellar Asset Contract (SAC) — the same kind ZavaVault accepts in prod.
    let token_admin = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract(token_admin.clone());

    let verifier_id = env.register_contract(None, mock_verifier::MockVerifier);
    let admin = Address::generate(&env);

    let vault_id = env.register_contract(None, ZavaVault);
    let vault = ZavaVaultClient::new(&env, &vault_id);
    // Reuse the same stub verifier address for both slots — tests don't
    // exercise the crypto path.
    vault.initialize(&admin, &token_id, &verifier_id, &verifier_id);

    Harness {
        env,
        admin,
        token_admin,
        token_id,
        vault,
        vault_id,
    }
}

/// Mint `amount` of the test token to `who`.
fn mint(h: &Harness, who: &Address, amount: i128) {
    StellarAssetClient::new(&h.env, &h.token_id).mint(who, &amount);
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    SacTokenClient::new(&h.env, &h.token_id).balance(who)
}

fn b32(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

/// Compute the same commitment-nullifier binding the contract stores.
fn cn_hash(env: &Env, commitment: &BytesN<32>, nullifier: &BytesN<32>) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.extend_from_array(&commitment.to_array());
    buf.extend_from_array(&nullifier.to_array());
    env.crypto().sha256(&buf).into()
}

/// Build the amount_bytes field used in WithdrawPublicInputs.
fn amount_bytes(env: &Env, amount: i128) -> BytesN<32> {
    let mut buf = [0u8; 32];
    buf[16..32].copy_from_slice(&amount.to_be_bytes());
    BytesN::from_array(env, &buf)
}

/// Compute the same recipient hash the contract uses (sha256 of XDR-encoded address).
fn recipient_hash(env: &Env, addr: &Address) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    let xdr = addr.clone().to_xdr(env);
    env.crypto().sha256(&xdr).into()
}

// ============================================================================
// Initialisation
// ============================================================================

#[test]
fn initialize_sets_initial_state() {
    let h = setup();
    assert_eq!(h.vault.get_leaf_count(), 0);
    assert_eq!(h.vault.get_total_locked(), 0);
    assert!(!h.vault.is_paused());
}

#[test]
fn cannot_initialize_twice() {
    let h = setup();
    let result = h.vault.try_initialize(&h.admin, &h.token_id, &h.token_id, &h.token_id);
    assert_eq!(result, Err(Ok(VaultError::AlreadyInitialized)));
}

#[test]
fn nullifier_starts_unspent() {
    let h = setup();
    assert!(!h.vault.is_nullifier_spent(&b32(&h.env, 7)));
}

// ============================================================================
// Deposit — happy path and rejections
// ============================================================================

#[test]
fn deposit_locks_tokens_and_updates_state() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 500_000_000;
    let note = Bytes::from_slice(&h.env, b"encrypted-note-bytes");

    let leaf = h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &note);
    assert_eq!(leaf, 0);

    assert_eq!(h.vault.get_leaf_count(), 1);
    assert_eq!(h.vault.get_total_locked(), amount);
    assert_eq!(token_balance(&h, &depositor), 500_000_000);
    assert_eq!(token_balance(&h, &h.vault_id), amount);
}

#[test]
fn deposit_with_zero_amount_rejected() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let result = h.vault.try_deposit(
        &depositor,
        &b32(&h.env, 1),
        &b32(&h.env, 2),
        &0i128,
        &Bytes::new(&h.env),
    );
    assert_eq!(result, Err(Ok(VaultError::InvalidAmount)));
}

#[test]
fn deposit_with_negative_amount_rejected() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let result = h.vault.try_deposit(
        &depositor,
        &b32(&h.env, 1),
        &b32(&h.env, 2),
        &-100i128,
        &Bytes::new(&h.env),
    );
    assert_eq!(result, Err(Ok(VaultError::InvalidAmount)));
}

#[test]
fn multiple_deposits_increment_leaf_index() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let note = Bytes::new(&h.env);
    let leaf_0 = h.vault.deposit(&depositor, &b32(&h.env, 1), &b32(&h.env, 2), &100i128, &note);
    let leaf_1 = h.vault.deposit(&depositor, &b32(&h.env, 3), &b32(&h.env, 4), &200i128, &note);
    let leaf_2 = h.vault.deposit(&depositor, &b32(&h.env, 5), &b32(&h.env, 6), &300i128, &note);

    assert_eq!(leaf_0, 0);
    assert_eq!(leaf_1, 1);
    assert_eq!(leaf_2, 2);
    assert_eq!(h.vault.get_leaf_count(), 3);
    assert_eq!(h.vault.get_total_locked(), 600);
}

#[test]
fn merkle_root_changes_after_deposit() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let before = h.vault.get_root();
    h.vault.deposit(
        &depositor,
        &b32(&h.env, 10),
        &b32(&h.env, 20),
        &100i128,
        &Bytes::new(&h.env),
    );
    let after = h.vault.get_root();
    assert_ne!(before, after);
    assert!(h.vault.is_known_root(&after));
}

// ============================================================================
// Withdraw — happy path
// ============================================================================

#[test]
fn withdraw_releases_tokens_to_recipient() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 500_000_000;
    let note = Bytes::new(&h.env);

    h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &note);
    let root = h.vault.get_root();

    let inputs = WithdrawPublicInputs {
        commitment: commitment.clone(),
        root,
        nullifier: nullifier.clone(),
        recipient_hash: recipient_hash(&h.env, &recipient),
        amount_bytes: amount_bytes(&h.env, amount),
    };

    h.vault.withdraw(&Bytes::from_slice(&h.env, &[0u8; 256]), &inputs, &recipient, &amount);

    assert_eq!(token_balance(&h, &recipient), amount);
    assert_eq!(h.vault.get_total_locked(), 0);
    assert!(h.vault.is_nullifier_spent(&nullifier));
}

// ============================================================================
// Withdraw — the core security checks
// ============================================================================

#[test]
fn cannot_withdraw_with_wrong_nullifier_for_commitment() {
    // This is the KEY security test: an attacker who knows the commitment
    // (visible on-chain) but not the nullifier (only in the encrypted note)
    // cannot drain the vault even though the ZK verifier is stubbed.
    let h = setup();
    let depositor = Address::generate(&h.env);
    let attacker  = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let real_nullifier = b32(&h.env, 2);
    let amount: i128 = 100_000_000;
    let note = Bytes::new(&h.env);
    h.vault.deposit(&depositor, &commitment, &real_nullifier, &amount, &note);

    // Attacker tries to withdraw with a guessed nullifier
    let fake_nullifier = b32(&h.env, 99);
    let inputs = WithdrawPublicInputs {
        commitment: commitment.clone(),
        root: h.vault.get_root(),
        nullifier: fake_nullifier,
        recipient_hash: recipient_hash(&h.env, &attacker),
        amount_bytes: amount_bytes(&h.env, amount),
    };

    let result = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &attacker,
        &amount,
    );
    assert_eq!(result, Err(Ok(VaultError::InvalidProof)));
    assert_eq!(token_balance(&h, &attacker), 0); // attacker got nothing
}

#[test]
fn cannot_withdraw_with_unknown_commitment() {
    // Attacker invents a commitment that was never deposited.
    let h = setup();
    let attacker = Address::generate(&h.env);
    let depositor = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    // One real deposit so vault has funds
    h.vault.deposit(
        &depositor,
        &b32(&h.env, 1),
        &b32(&h.env, 2),
        &500_000_000i128,
        &Bytes::new(&h.env),
    );

    let inputs = WithdrawPublicInputs {
        commitment: b32(&h.env, 200), // never deposited
        root: h.vault.get_root(),
        nullifier: b32(&h.env, 201),
        recipient_hash: recipient_hash(&h.env, &attacker),
        amount_bytes: amount_bytes(&h.env, 100i128),
    };

    let result = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &attacker,
        &100i128,
    );
    assert_eq!(result, Err(Ok(VaultError::InvalidProof)));
}

#[test]
fn cannot_double_spend_same_nullifier() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 100_000_000;

    h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &Bytes::new(&h.env));

    let inputs = WithdrawPublicInputs {
        commitment: commitment.clone(),
        root: h.vault.get_root(),
        nullifier: nullifier.clone(),
        recipient_hash: recipient_hash(&h.env, &recipient),
        amount_bytes: amount_bytes(&h.env, amount),
    };

    // First withdraw — should succeed
    h.vault.withdraw(&Bytes::from_slice(&h.env, &[0u8; 256]), &inputs, &recipient, &amount);

    // Need to re-deposit to keep vault funded, but reuse the same nullifier:
    // actually we just try to re-use the spent nullifier. We need to redeposit
    // a different commitment+nullifier first to refund the pool, then attempt
    // to replay the original nullifier with its original commitment.
    mint(&h, &depositor, 1_000_000_000);
    h.vault.deposit(
        &depositor,
        &b32(&h.env, 50),
        &b32(&h.env, 51),
        &amount,
        &Bytes::new(&h.env),
    );

    let replay = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &recipient,
        &amount,
    );
    assert_eq!(replay, Err(Ok(VaultError::NullifierAlreadySpent)));
}

#[test]
fn cannot_withdraw_with_mismatched_amount() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let deposited: i128 = 500_000_000;
    h.vault.deposit(&depositor, &commitment, &nullifier, &deposited, &Bytes::new(&h.env));

    // The amount_bytes says one thing but the explicit amount arg says another
    let inputs = WithdrawPublicInputs {
        commitment,
        root: h.vault.get_root(),
        nullifier,
        recipient_hash: recipient_hash(&h.env, &recipient),
        amount_bytes: amount_bytes(&h.env, deposited),
    };

    let result = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &recipient,
        &(deposited + 1), // <-- mismatched
    );
    assert_eq!(result, Err(Ok(VaultError::AmountMismatch)));
}

#[test]
fn cannot_withdraw_to_wrong_recipient() {
    // Attacker steals a valid proof+inputs but tries to redirect funds to themselves.
    let h = setup();
    let depositor       = Address::generate(&h.env);
    let real_recipient  = Address::generate(&h.env);
    let attacker        = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 100_000_000;
    h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &Bytes::new(&h.env));

    let inputs = WithdrawPublicInputs {
        commitment,
        root: h.vault.get_root(),
        nullifier,
        // recipient_hash is bound to real_recipient
        recipient_hash: recipient_hash(&h.env, &real_recipient),
        amount_bytes: amount_bytes(&h.env, amount),
    };

    let result = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &attacker, // <-- attacker tries to receive
        &amount,
    );
    assert_eq!(result, Err(Ok(VaultError::RecipientMismatch)));
    assert_eq!(token_balance(&h, &attacker), 0);
}

#[test]
fn cannot_withdraw_with_unknown_root() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 100_000_000;
    h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &Bytes::new(&h.env));

    let inputs = WithdrawPublicInputs {
        commitment,
        root: b32(&h.env, 0xff), // root that never existed
        nullifier,
        recipient_hash: recipient_hash(&h.env, &recipient),
        amount_bytes: amount_bytes(&h.env, amount),
    };

    let result = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &recipient,
        &amount,
    );
    assert_eq!(result, Err(Ok(VaultError::UnknownRoot)));
}

// ============================================================================
// Emergency pause
// ============================================================================

#[test]
fn admin_can_pause_and_unpause() {
    let h = setup();
    assert!(!h.vault.is_paused());

    h.vault.pause(&h.admin);
    assert!(h.vault.is_paused());

    h.vault.unpause(&h.admin);
    assert!(!h.vault.is_paused());
}

#[test]
fn non_admin_cannot_pause() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let result = h.vault.try_pause(&stranger);
    assert_eq!(result, Err(Ok(VaultError::NotAdmin)));
}

#[test]
fn non_admin_cannot_unpause() {
    let h = setup();
    h.vault.pause(&h.admin);
    let stranger = Address::generate(&h.env);
    let result = h.vault.try_unpause(&stranger);
    assert_eq!(result, Err(Ok(VaultError::NotAdmin)));
}

#[test]
fn deposit_rejected_when_paused() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);
    h.vault.pause(&h.admin);

    let result = h.vault.try_deposit(
        &depositor,
        &b32(&h.env, 1),
        &b32(&h.env, 2),
        &100i128,
        &Bytes::new(&h.env),
    );
    assert_eq!(result, Err(Ok(VaultError::ContractPaused)));
}

#[test]
fn withdraw_rejected_when_paused() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 100_000_000;
    h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &Bytes::new(&h.env));

    h.vault.pause(&h.admin);

    let inputs = WithdrawPublicInputs {
        commitment,
        root: h.vault.get_root(),
        nullifier,
        recipient_hash: recipient_hash(&h.env, &recipient),
        amount_bytes: amount_bytes(&h.env, amount),
    };
    let result = h.vault.try_withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &recipient,
        &amount,
    );
    assert_eq!(result, Err(Ok(VaultError::ContractPaused)));
}

#[test]
fn withdraw_works_again_after_unpause() {
    let h = setup();
    let depositor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    mint(&h, &depositor, 1_000_000_000);

    let commitment = b32(&h.env, 1);
    let nullifier  = b32(&h.env, 2);
    let amount: i128 = 100_000_000;
    h.vault.deposit(&depositor, &commitment, &nullifier, &amount, &Bytes::new(&h.env));

    h.vault.pause(&h.admin);
    h.vault.unpause(&h.admin);

    let inputs = WithdrawPublicInputs {
        commitment,
        root: h.vault.get_root(),
        nullifier,
        recipient_hash: recipient_hash(&h.env, &recipient),
        amount_bytes: amount_bytes(&h.env, amount),
    };
    h.vault.withdraw(
        &Bytes::from_slice(&h.env, &[0u8; 256]),
        &inputs,
        &recipient,
        &amount,
    );
    assert_eq!(token_balance(&h, &recipient), amount);
}

// ============================================================================
// Sanity — internal commitment-nullifier hash matches what tests compute
// ============================================================================

#[test]
fn cn_hash_is_stable_and_distinct() {
    let env = Env::default();
    let c1 = b32(&env, 1);
    let n1 = b32(&env, 2);
    let n2 = b32(&env, 3);

    let h1 = cn_hash(&env, &c1, &n1);
    let h2 = cn_hash(&env, &c1, &n1);
    let h3 = cn_hash(&env, &c1, &n2);

    assert_eq!(h1, h2);     // deterministic
    assert_ne!(h1, h3);     // different nullifier → different binding
}
