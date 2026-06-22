#![cfg(test)]

use super::*;
use honk_verifier::{HonkVerifierContract, HonkVerifierContractClient};
use savings::{SavingsContract, SavingsContractClient};
use soroban_sdk::{testutils::Address as _, Bytes, BytesN, Env, Vec};

// ---------- harness --------------------------------------------------------

struct Harness<'a> {
    env: Env,
    savings: SavingsContractClient<'a>,
    verifier: VerifierContractClient<'a>,
}

fn make_hash(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn fixture_proof(env: &Env) -> Bytes {
    // 192 zero bytes — long enough for the Honk stub's length gate.
    Bytes::from_array(env, &[0u8; 192])
}

/// Public-input count the verifier passes through to the Honk verifier:
///   [min_amount, weeks, commitments(N), nullifiers(N)] = 2 + 2N
fn honk_input_count(weeks: u32) -> u32 {
    2 + 2 * weeks
}

/// Deploy savings + three Honk verifiers (one per tier) + the credit
/// verifier contract, all wired up.
fn setup<'a>() -> Harness<'a> {
    let env = Env::default();
    env.mock_all_auths();

    let savings_id = env.register_contract(None, SavingsContract);
    let savings = SavingsContractClient::new(&env, &savings_id);

    let vk_bytes = Bytes::from_array(&env, &[0xABu8; 64]);
    let mut honk_ids = [None, None, None];
    for (slot, weeks) in [(0, 8u32), (1, 12u32), (2, 24u32)].iter() {
        let id = env.register_contract(None, HonkVerifierContract);
        let client = HonkVerifierContractClient::new(&env, &id);
        client.initialize(&vk_bytes, &honk_input_count(*weeks));
        honk_ids[*slot] = Some(id);
    }

    let verifier_id = env.register_contract(None, VerifierContract);
    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(
        &savings_id,
        honk_ids[0].as_ref().unwrap(),
        honk_ids[1].as_ref().unwrap(),
        honk_ids[2].as_ref().unwrap(),
    );

    Harness { env, savings, verifier }
}

/// Deposit `weeks` commitments into savings and return (commitments, nullifiers)
/// in deposit order, ready to feed into the proof's public inputs.
fn seed_savings(h: &Harness, weeks: u32) -> (Vec<BytesN<32>>, Vec<BytesN<32>>) {
    let mut commitments = Vec::new(&h.env);
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..weeks {
        let commitment = make_hash(&h.env, (w as u8).wrapping_add(1));
        let nullifier = make_hash(&h.env, (w as u8).wrapping_add(100));
        h.savings.deposit(&commitment, &nullifier, &w);
        commitments.push_back(commitment);
        nullifiers.push_back(nullifier);
    }
    (commitments, nullifiers)
}

fn public_inputs_for(
    weeks: u32,
    commitments: Vec<BytesN<32>>,
    nullifiers: Vec<BytesN<32>>,
) -> PublicInputs {
    PublicInputs {
        min_weekly_amount: 400_000_000, // $40 in stroops (7 dp)
        consistency_weeks: weeks,
        commitments,
        nullifiers,
    }
}

// ---------- tests ----------------------------------------------------------

#[test]
fn end_to_end_medium_tier() {
    let h = setup();
    let (commitments, nullifiers) = seed_savings(&h, 8);
    let inputs = public_inputs_for(8, commitments, nullifiers);
    let wallet = Address::generate(&h.env);

    let tier = h.verifier.verify_proof(&wallet, &fixture_proof(&h.env), &inputs);
    assert_eq!(tier, CreditTier::Medium);

    let record = h.verifier.get_credit_tier(&wallet).unwrap();
    assert_eq!(record.tier, CreditTier::Medium);
    assert_eq!(record.consistency_weeks, 8);
    assert!(h.verifier.is_credit_valid(&wallet));
}

#[test]
fn end_to_end_low_tier() {
    let h = setup();
    let (commitments, nullifiers) = seed_savings(&h, 12);
    let inputs = public_inputs_for(12, commitments, nullifiers);
    let wallet = Address::generate(&h.env);

    let tier = h.verifier.verify_proof(&wallet, &fixture_proof(&h.env), &inputs);
    assert_eq!(tier, CreditTier::Low);
}

#[test]
fn end_to_end_very_low_tier() {
    let h = setup();
    let (commitments, nullifiers) = seed_savings(&h, 24);
    let inputs = public_inputs_for(24, commitments, nullifiers);
    let wallet = Address::generate(&h.env);

    let tier = h.verifier.verify_proof(&wallet, &fixture_proof(&h.env), &inputs);
    assert_eq!(tier, CreditTier::VeryLow);
}

#[test]
fn invalid_week_count_rejected() {
    let h = setup();
    let mut commitments = Vec::new(&h.env);
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..7 {
        commitments.push_back(make_hash(&h.env, w as u8));
        nullifiers.push_back(make_hash(&h.env, (w + 100) as u8));
    }
    let inputs = PublicInputs {
        min_weekly_amount: 1,
        consistency_weeks: 7,
        commitments,
        nullifiers,
    };
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::InvalidConsistencyWeeks)));
}

#[test]
fn nullifier_count_mismatch_rejected() {
    let h = setup();
    let mut commitments = Vec::new(&h.env);
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..8 {
        commitments.push_back(make_hash(&h.env, w as u8));
    }
    for w in 0..7 {
        nullifiers.push_back(make_hash(&h.env, (w + 100) as u8));
    }
    let inputs = PublicInputs {
        min_weekly_amount: 1,
        consistency_weeks: 8,
        commitments,
        nullifiers,
    };
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::NullifierCountMismatch)));
}

#[test]
fn commitment_count_mismatch_rejected() {
    let h = setup();
    let mut commitments = Vec::new(&h.env);
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..7 {
        commitments.push_back(make_hash(&h.env, w as u8));
    }
    for w in 0..8 {
        nullifiers.push_back(make_hash(&h.env, (w + 100) as u8));
    }
    let inputs = PublicInputs {
        min_weekly_amount: 1,
        consistency_weeks: 8,
        commitments,
        nullifiers,
    };
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::CommitmentCountMismatch)));
}

#[test]
fn unrecorded_nullifier_rejected() {
    let h = setup();
    let (commitments, mut nullifiers) = seed_savings(&h, 8);
    // Swap the last nullifier for one savings never saw.
    nullifiers.set(7, make_hash(&h.env, 0xEE));
    let inputs = public_inputs_for(8, commitments, nullifiers);
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::NullifierNotRecorded)));
}

#[test]
fn unrecorded_commitment_rejected() {
    let h = setup();
    let (mut commitments, nullifiers) = seed_savings(&h, 8);
    // Swap the last commitment for one savings never saw.
    commitments.set(7, make_hash(&h.env, 0xDD));
    let inputs = public_inputs_for(8, commitments, nullifiers);
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::CommitmentNotRecorded)));
}

#[test]
fn double_initialize_rejected() {
    let h = setup();
    let other = Address::generate(&h.env);
    let res = h.verifier.try_initialize(&other, &other, &other, &other);
    assert_eq!(res, Err(Ok(VerifierError::AlreadyInitialized)));
}

#[test]
fn get_linked_contracts_returns_four_addresses() {
    let h = setup();
    let (s, g8, g12, g24) = h.verifier.get_linked_contracts();
    // All four should be distinct.
    assert!(s != g8 && s != g12 && s != g24);
    assert!(g8 != g12 && g8 != g24 && g12 != g24);
}

#[test]
fn get_verification_key_per_tier() {
    let h = setup();
    // All three tiers share the same fixture vk in this harness.
    let vk_medium = h.verifier.get_verification_key(&CreditTier::Medium);
    let vk_low = h.verifier.get_verification_key(&CreditTier::Low);
    let vk_very_low = h.verifier.get_verification_key(&CreditTier::VeryLow);
    assert_eq!(vk_medium, vk_low);
    assert_eq!(vk_low, vk_very_low);
}
