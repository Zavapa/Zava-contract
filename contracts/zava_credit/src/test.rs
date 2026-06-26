#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    Address, Bytes, BytesN, Env, Vec,
};

// ============================================================================
// Mock vault — implements the three read methods ZavaCredit needs.
// Configurable per-test so we can simulate various deposit/withdrawal states.
// ============================================================================

mod mock_vault {
    use soroban_sdk::{contract, contractimpl, contracttype, BytesN, Env};

    #[contracttype]
    pub enum K {
        Exists(BytesN<32>),
        Binding(BytesN<32>),        // commitment → bound nullifier
        Spent(BytesN<32>),          // nullifier → spent flag
    }

    #[contract]
    pub struct MockVault;

    #[contractimpl]
    impl MockVault {
        pub fn add_deposit(env: Env, commitment: BytesN<32>, nullifier: BytesN<32>) {
            env.storage().persistent().set(&K::Exists(commitment.clone()), &true);
            env.storage().persistent().set(&K::Binding(commitment), &nullifier);
        }

        pub fn mark_spent(env: Env, nullifier: BytesN<32>) {
            env.storage().persistent().set(&K::Spent(nullifier), &true);
        }

        // ── Interface used by ZavaCredit ────────────────────────────────────────

        pub fn commitment_exists(env: Env, commitment: BytesN<32>) -> bool {
            env.storage().persistent().has(&K::Exists(commitment))
        }

        pub fn commitment_matches_nullifier(env: Env, commitment: BytesN<32>, nullifier: BytesN<32>) -> bool {
            let stored: Option<BytesN<32>> = env.storage().persistent().get(&K::Binding(commitment));
            match stored {
                Some(s) => s == nullifier,
                None    => false,
            }
        }

        pub fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool {
            env.storage().persistent().has(&K::Spent(nullifier))
        }
    }
}

// ============================================================================
// Mock verifier — accepts any proof (mirrors current stub behaviour).
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

// Rejecting verifier — used to test proof-invalid path.
mod reject_verifier {
    use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};

    #[contract]
    pub struct RejectVerifier;

    #[contractimpl]
    impl RejectVerifier {
        pub fn verify(_env: Env, _proof: Bytes, _public_inputs: Vec<BytesN<32>>) -> bool {
            false
        }
    }
}

// ============================================================================
// Harness
// ============================================================================

struct Harness<'a> {
    env: Env,
    credit: ZavaCreditClient<'a>,
    vault_client: mock_vault::MockVaultClient<'a>,
}

/// Standard setup: mock vault + accept-all verifier.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let vault_id    = env.register_contract(None, mock_vault::MockVault);
    let verifier_id = env.register_contract(None, mock_verifier::MockVerifier);
    let credit_id   = env.register_contract(None, ZavaCredit);

    let credit = ZavaCreditClient::new(&env, &credit_id);
    credit.initialize(&vault_id, &verifier_id);

    let vault_client = mock_vault::MockVaultClient::new(&env, &vault_id);
    Harness { env, credit, vault_client }
}

fn setup_reject_verifier() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let vault_id    = env.register_contract(None, mock_vault::MockVault);
    let verifier_id = env.register_contract(None, reject_verifier::RejectVerifier);
    let credit_id   = env.register_contract(None, ZavaCredit);

    let credit = ZavaCreditClient::new(&env, &credit_id);
    credit.initialize(&vault_id, &verifier_id);

    let vault_client = mock_vault::MockVaultClient::new(&env, &vault_id);
    Harness { env, credit, vault_client }
}

fn b32(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

/// Helper: pretend N savings deposits exist in the mock vault.
/// Commitment/nullifier seeds run from 1..2N+1 so they don't collide.
fn populate_vault(h: &Harness, n: u32) -> (Vec<BytesN<32>>, Vec<BytesN<32>>, Vec<u32>) {
    let mut commits = Vec::new(&h.env);
    let mut nulls   = Vec::new(&h.env);
    let mut weeks   = Vec::new(&h.env);
    for i in 0..n {
        let c = b32(&h.env, (i + 1) as u8);
        let n = b32(&h.env, (100 + i) as u8);
        h.vault_client.add_deposit(&c, &n);
        commits.push_back(c);
        nulls.push_back(n);
        weeks.push_back(i);
    }
    (commits, nulls, weeks)
}

fn claim_of(_env: &Env, commits: Vec<BytesN<32>>, nulls: Vec<BytesN<32>>, weeks: Vec<u32>) -> CreditClaim {
    CreditClaim {
        savings_range: SavingsRange::R20, // default to "≥ $20/wk" for tests
        commitments: commits,
        nullifiers: nulls,
        weeks,
    }
}

fn claim_with_range(_env: &Env, range: SavingsRange, commits: Vec<BytesN<32>>, nulls: Vec<BytesN<32>>, weeks: Vec<u32>) -> CreditClaim {
    CreditClaim {
        savings_range: range,
        commitments: commits,
        nullifiers: nulls,
        weeks,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn initialize_once_only() {
    let h = setup();
    let result = h.credit.try_initialize(&h.vault_client.address, &h.vault_client.address);
    assert_eq!(result, Err(Ok(CreditError::AlreadyInitialized)));
}

#[test]
fn no_record_when_unverified() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    assert!(h.credit.get_credit_record(&wallet).is_none());
    assert!(!h.credit.is_credit_valid(&wallet));
}

#[test]
fn empty_claim_rejected() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let claim = claim_of(&h.env, Vec::new(&h.env), Vec::new(&h.env), Vec::new(&h.env));
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::EmptyClaim)));
}

#[test]
fn mismatched_array_lengths_rejected() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let mut commits = Vec::new(&h.env);
    commits.push_back(b32(&h.env, 1));
    let nulls = Vec::new(&h.env); // empty — mismatch
    let weeks = Vec::new(&h.env);
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::LengthMismatch)));
}

#[test]
fn duplicate_nullifier_in_claim_rejected() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (mut commits, mut nulls, mut weeks) = populate_vault(&h, 8);
    // Force a duplicate nullifier
    nulls.set(1, nulls.get(0).unwrap());
    // Make the commitment-nullifier binding consistent in the mock vault
    h.vault_client.add_deposit(&commits.get(1).unwrap(), &nulls.get(0).unwrap());
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::DuplicateNullifier)));
}

#[test]
fn medium_tier_with_8_active_weeks() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 8);
    let claim = claim_of(&h.env, commits, nulls, weeks);

    let record = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(record.tier, CreditTier::Medium);
    assert_eq!(record.active_weeks, 8);
    assert_eq!(record.withdrawn_weeks, 0);
    assert!(h.credit.is_credit_valid(&wallet));
}

#[test]
fn low_tier_with_12_active_weeks() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 12);
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let record = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(record.tier, CreditTier::Low);
    assert_eq!(record.active_weeks, 12);
}

#[test]
fn very_low_tier_with_24_active_weeks() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 24);
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let record = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(record.tier, CreditTier::VeryLow);
    assert_eq!(record.active_weeks, 24);
}

#[test]
fn not_enough_weeks_rejected() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 7); // below medium threshold
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::NotEnoughActiveWeeks)));
}

#[test]
fn withdrawn_deposit_demotes_tier() {
    // 12 deposits made, but 5 were withdrawn → only 7 active → below medium → rejected.
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 12);
    for i in 0..5 {
        h.vault_client.mark_spent(&nulls.get(i).unwrap());
    }
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::NotEnoughActiveWeeks)));
}

#[test]
fn net_based_scoring_demotes_low_to_medium() {
    // 12 deposits made, 4 withdrawn → 8 active → Medium tier (not Low).
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 12);
    for i in 0..4 {
        h.vault_client.mark_spent(&nulls.get(i).unwrap());
    }
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let record = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(record.tier, CreditTier::Medium); // demoted from Low
    assert_eq!(record.active_weeks, 8);
    assert_eq!(record.withdrawn_weeks, 4);
}

#[test]
fn fake_commitment_not_in_vault_rejected() {
    // Bypass attempt: claim 8 commitments but only 7 are real on-chain deposits.
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (mut commits, mut nulls, mut weeks) = populate_vault(&h, 7);
    // Fake 8th week
    commits.push_back(b32(&h.env, 200));
    nulls.push_back(b32(&h.env, 201));
    weeks.push_back(7);
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::CommitmentNotInVault)));
}

#[test]
fn wrong_nullifier_for_real_commitment_rejected() {
    // Attacker sees a real commitment but doesn't know its nullifier.
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (mut commits, mut nulls, mut weeks) = populate_vault(&h, 8);
    // Replace the 3rd nullifier with a guess
    nulls.set(3, b32(&h.env, 99));
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::BindingMismatch)));
}

#[test]
fn invalid_zk_proof_rejected() {
    let h = setup_reject_verifier();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 8);
    let claim = claim_of(&h.env, commits, nulls, weeks);
    let result = h.credit.try_claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(result, Err(Ok(CreditError::ProofInvalid)));
}

#[test]
fn re_claim_overwrites_previous_record() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 8);

    let first = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim_of(&h.env, commits.clone(), nulls.clone(), weeks.clone()));
    assert_eq!(first.tier, CreditTier::Medium);

    // Add 4 more deposits to bring the user up to Low tier
    let (extra_c, extra_n, extra_w) = populate_vault_with_offset(&h, 4, 50);
    let mut all_c = commits;
    let mut all_n = nulls;
    let mut all_w = weeks;
    for i in 0..4 {
        all_c.push_back(extra_c.get(i).unwrap());
        all_n.push_back(extra_n.get(i).unwrap());
        all_w.push_back(extra_w.get(i).unwrap() + 8);
    }
    let second = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim_of(&h.env, all_c, all_n, all_w));
    assert_eq!(second.tier, CreditTier::Low);
    assert_eq!(second.active_weeks, 12);
}

// ============================================================================
// Loan eligibility & savings range tests
// ============================================================================

#[test]
fn medium_tier_r5_loan_amount() {
    // 8 active weeks × 50 XLM × 2.0 multiplier = 800 XLM = 8_000_000_000 stroops
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 8);
    let claim = claim_with_range(&h.env, SavingsRange::R5, commits, nulls, weeks);
    let record = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(record.tier, CreditTier::Medium);
    assert_eq!(record.savings_range, SavingsRange::R5);
    // 8 * 50 * 10_000_000 * 200 / 100 = 8_000_000_000 stroops = 800 XLM
    assert_eq!(record.loan_eligible_stroops, 8_000_000_000);
    assert_eq!(h.credit.get_loan_eligibility(&wallet), 8_000_000_000);
    // Loan = ~$80 at $0.10/XLM, makes sense for someone saving ~$5/wk for 8 weeks.
}

#[test]
fn very_low_tier_r500_unlocks_big_loan() {
    // 24 active weeks × 5000 XLM × 6.0 multiplier = 720000 XLM
    let h = setup();
    let wallet = Address::generate(&h.env);
    let (commits, nulls, weeks) = populate_vault(&h, 24);
    let claim = claim_with_range(&h.env, SavingsRange::R500, commits, nulls, weeks);
    let record = h.credit.claim_credit(&wallet, &Bytes::new(&h.env), &claim);
    assert_eq!(record.tier, CreditTier::VeryLow);
    assert_eq!(record.savings_range, SavingsRange::R500);
    // 24 * 5000 * 10_000_000 * 600 / 100 = 7_200_000_000_000
    assert_eq!(record.loan_eligible_stroops, 7_200_000_000_000);
}

#[test]
fn higher_range_at_same_weeks_gives_bigger_loan() {
    // Two users with same 12 active weeks but different claimed ranges.
    let h = setup();

    let wallet_a = Address::generate(&h.env);
    let (a_c, a_n, a_w) = populate_vault(&h, 12);
    let record_a = h.credit.claim_credit(
        &wallet_a,
        &Bytes::new(&h.env),
        &claim_with_range(&h.env, SavingsRange::R5, a_c, a_n, a_w),
    );

    let wallet_b = Address::generate(&h.env);
    let (b_c, b_n, b_w) = populate_vault_with_offset(&h, 12, 200);
    let record_b = h.credit.claim_credit(
        &wallet_b,
        &Bytes::new(&h.env),
        &claim_with_range(&h.env, SavingsRange::R50, b_c, b_n, b_w),
    );

    assert_eq!(record_a.tier, CreditTier::Low);
    assert_eq!(record_b.tier, CreditTier::Low);
    assert!(record_b.loan_eligible_stroops > record_a.loan_eligible_stroops);
    // R5:  12 *  50 * 10M * 400/100 =  24_000_000_000
    // R50: 12 * 500 * 10M * 400/100 = 240_000_000_000 (10× more)
    assert_eq!(record_a.loan_eligible_stroops,  24_000_000_000);
    assert_eq!(record_b.loan_eligible_stroops, 240_000_000_000);
}

#[test]
fn longer_history_at_same_range_gives_bigger_loan() {
    // Two users with same R20 range but different tier.
    let h = setup();

    let wallet_a = Address::generate(&h.env);
    let (a_c, a_n, a_w) = populate_vault(&h, 8);
    let record_a = h.credit.claim_credit(
        &wallet_a, &Bytes::new(&h.env),
        &claim_with_range(&h.env, SavingsRange::R20, a_c, a_n, a_w),
    );

    let wallet_b = Address::generate(&h.env);
    let (b_c, b_n, b_w) = populate_vault_with_offset(&h, 24, 100);
    let record_b = h.credit.claim_credit(
        &wallet_b, &Bytes::new(&h.env),
        &claim_with_range(&h.env, SavingsRange::R20, b_c, b_n, b_w),
    );

    assert_eq!(record_a.tier, CreditTier::Medium);
    assert_eq!(record_b.tier, CreditTier::VeryLow);
    assert!(record_b.loan_eligible_stroops > record_a.loan_eligible_stroops);
    // Medium:  8 * 200 * 10M * 200/100 =  32_000_000_000
    // VeryLow: 24 * 200 * 10M * 600/100 = 288_000_000_000 (9× more)
    assert_eq!(record_a.loan_eligible_stroops,  32_000_000_000);
    assert_eq!(record_b.loan_eligible_stroops, 288_000_000_000);
}

#[test]
fn no_loan_eligibility_without_record() {
    let h = setup();
    let wallet = Address::generate(&h.env);
    assert_eq!(h.credit.get_loan_eligibility(&wallet), 0);
}

#[test]
fn range_info_returns_correct_bounds() {
    let h = setup();
    let (lower, label) = h.credit.range_info(&SavingsRange::R5);
    assert_eq!(lower, 50 * 10_000_000);
    assert_eq!(label, 5);
    let (lower, label) = h.credit.range_info(&SavingsRange::R500);
    assert_eq!(lower, 5000 * 10_000_000);
    assert_eq!(label, 500);
}

fn populate_vault_with_offset(h: &Harness, n: u32, seed_offset: u8) -> (Vec<BytesN<32>>, Vec<BytesN<32>>, Vec<u32>) {
    let mut commits = Vec::new(&h.env);
    let mut nulls   = Vec::new(&h.env);
    let mut weeks   = Vec::new(&h.env);
    for i in 0..n {
        // Use distinct seed bytes: high byte = offset, low byte = i.
        // Avoids u8 overflow when offset + i can exceed 255.
        let mut c_arr = [0u8; 32]; c_arr[0] = seed_offset; c_arr[31] = i as u8;
        let mut n_arr = [0u8; 32]; n_arr[0] = seed_offset; n_arr[31] = 200 - (i as u8);
        let c = BytesN::from_array(&h.env, &c_arr);
        let n = BytesN::from_array(&h.env, &n_arr);
        h.vault_client.add_deposit(&c, &n);
        commits.push_back(c);
        nulls.push_back(n);
        weeks.push_back(i);
    }
    (commits, nulls, weeks)
}
