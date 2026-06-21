#![cfg(test)]

use super::*;
use groth16::{Groth16Contract, Groth16ContractClient};
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
    // 192 zero bytes — long enough for the groth16 stub's length gate.
    Bytes::from_array(env, &[0u8; 192])
}

/// Deploy savings + groth16 + verifier and wire them together.
/// The groth16 contract is initialised with `3 + nullifier_count`
/// public inputs (root, min_weekly_amount, consistency_weeks, then one
/// per nullifier) so it matches what the verifier will pass through.
fn setup<'a>(nullifier_count: u32) -> Harness<'a> {
    let env = Env::default();
    env.mock_all_auths();

    let savings_id = env.register_contract(None, SavingsContract);
    let savings = SavingsContractClient::new(&env, &savings_id);

    let g16_id = env.register_contract(None, Groth16Contract);
    let g16 = Groth16ContractClient::new(&env, &g16_id);
    g16.initialize(
        &Bytes::from_array(&env, &[0xABu8; 64]),
        &(3 + nullifier_count),
    );

    let verifier_id = env.register_contract(None, VerifierContract);
    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(&savings_id, &g16_id);

    Harness { env, savings, verifier }
}

/// Deposit `weeks` commitments into savings and return the nullifiers
/// in deposit order (for the proof's public inputs).
fn seed_savings(h: &Harness, weeks: u32) -> Vec<BytesN<32>> {
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..weeks {
        let commitment = make_hash(&h.env, (w as u8).wrapping_add(1));
        let nullifier = make_hash(&h.env, (w as u8).wrapping_add(100));
        h.savings.deposit(&commitment, &nullifier, &w);
        nullifiers.push_back(nullifier);
    }
    nullifiers
}

fn public_inputs_for(h: &Harness, weeks: u32, nullifiers: Vec<BytesN<32>>) -> PublicInputs {
    PublicInputs {
        commitment_root: h.savings.get_merkle_root(),
        min_weekly_amount: 400_000_000, // $40 in stroops (7 dp)
        consistency_weeks: weeks,
        nullifiers,
    }
}

// ---------- tests ----------------------------------------------------------

#[test]
fn end_to_end_medium_tier() {
    let h = setup(8);
    let nullifiers = seed_savings(&h, 8);
    let inputs = public_inputs_for(&h, 8, nullifiers);
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
    let h = setup(12);
    let nullifiers = seed_savings(&h, 12);
    let inputs = public_inputs_for(&h, 12, nullifiers);
    let wallet = Address::generate(&h.env);

    let tier = h.verifier.verify_proof(&wallet, &fixture_proof(&h.env), &inputs);
    assert_eq!(tier, CreditTier::Low);
}

#[test]
fn invalid_week_count_rejected() {
    let h = setup(7);
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..7 {
        nullifiers.push_back(make_hash(&h.env, w as u8));
    }
    let inputs = PublicInputs {
        commitment_root: h.savings.get_merkle_root(),
        min_weekly_amount: 1,
        consistency_weeks: 7,
        nullifiers,
    };
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::InvalidConsistencyWeeks)));
}

#[test]
fn nullifier_count_mismatch_rejected() {
    let h = setup(8);
    let mut nullifiers = Vec::new(&h.env);
    for w in 0..7 {
        nullifiers.push_back(make_hash(&h.env, w as u8));
    }
    let inputs = PublicInputs {
        commitment_root: h.savings.get_merkle_root(),
        min_weekly_amount: 1,
        consistency_weeks: 8,
        nullifiers,
    };
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::NullifierCountMismatch)));
}

#[test]
fn commitment_root_mismatch_rejected() {
    let h = setup(8);
    let nullifiers = seed_savings(&h, 8);
    let mut inputs = public_inputs_for(&h, 8, nullifiers);
    inputs.commitment_root = make_hash(&h.env, 0xFF); // tampered root
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::CommitmentRootMismatch)));
}

#[test]
fn unrecorded_nullifier_rejected() {
    let h = setup(8);
    let mut nullifiers = seed_savings(&h, 8);
    // Swap the last nullifier for one savings never saw.
    nullifiers.set(7, make_hash(&h.env, 0xEE));
    let inputs = public_inputs_for(&h, 8, nullifiers);
    let res = h
        .verifier
        .try_verify_proof(&Address::generate(&h.env), &fixture_proof(&h.env), &inputs);
    assert_eq!(res, Err(Ok(VerifierError::NullifierNotRecorded)));
}

#[test]
fn double_initialize_rejected() {
    let h = setup(8);
    let other = Address::generate(&h.env);
    let res = h.verifier.try_initialize(&other, &other);
    assert_eq!(res, Err(Ok(VerifierError::AlreadyInitialized)));
}

#[test]
fn get_linked_contracts_returns_addresses() {
    let h = setup(8);
    let (s, g) = h.verifier.get_linked_contracts();
    assert!(s != g);
}
