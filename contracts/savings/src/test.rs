#![cfg(test)]

use super::*;
use soroban_sdk::Env;

fn make_hash(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn deploy(env: &Env) -> SavingsContractClient<'_> {
    let id = env.register_contract(None, SavingsContract);
    SavingsContractClient::new(env, &id)
}

#[test]
fn valid_deposit_stored() {
    let env = Env::default();
    let client = deploy(&env);
    client.deposit(&make_hash(&env, 1), &make_hash(&env, 2), &0u32);
    assert_eq!(client.get_commitment_count(), 1);
}

#[test]
fn duplicate_nullifier_rejected() {
    let env = Env::default();
    let client = deploy(&env);
    let nullifier = make_hash(&env, 2);
    client.deposit(&make_hash(&env, 1), &nullifier, &0u32);
    let res = client.try_deposit(&make_hash(&env, 3), &nullifier, &1u32);
    assert_eq!(res, Err(Ok(SavingsError::NullifierAlreadySpent)));
}

#[test]
fn merkle_root_updates_on_deposit() {
    let env = Env::default();
    let client = deploy(&env);
    let before = client.get_merkle_root();
    client.deposit(&make_hash(&env, 10), &make_hash(&env, 11), &0u32);
    assert_ne!(before, client.get_merkle_root());
}

#[test]
fn large_week_gap_rejected() {
    let env = Env::default();
    let client = deploy(&env);
    client.deposit(&make_hash(&env, 1), &make_hash(&env, 2), &0u32);
    let res = client.try_deposit(&make_hash(&env, 3), &make_hash(&env, 4), &3u32);
    assert_eq!(res, Err(Ok(SavingsError::WeekGapTooLarge)));
}

#[test]
fn week_regression_rejected() {
    let env = Env::default();
    let client = deploy(&env);
    client.deposit(&make_hash(&env, 1), &make_hash(&env, 2), &5u32);
    let res = client.try_deposit(&make_hash(&env, 3), &make_hash(&env, 4), &5u32);
    assert_eq!(res, Err(Ok(SavingsError::WeekNumberMustAdvance)));
}

#[test]
fn nullifier_spent_flag() {
    let env = Env::default();
    let client = deploy(&env);
    let nullifier = make_hash(&env, 99);
    assert!(!client.is_nullifier_spent(&nullifier));
    client.deposit(&make_hash(&env, 5), &nullifier, &0u32);
    assert!(client.is_nullifier_spent(&nullifier));
}

#[test]
fn range_query() {
    let env = Env::default();
    let client = deploy(&env);
    client.deposit(&make_hash(&env, 1), &make_hash(&env, 2), &0u32);
    client.deposit(&make_hash(&env, 3), &make_hash(&env, 4), &1u32);
    client.deposit(&make_hash(&env, 5), &make_hash(&env, 6), &2u32);
    let range = client.get_commitments_by_range(&1u32, &2u32);
    assert_eq!(range.len(), 2);
}

#[test]
fn inverted_range_rejected() {
    let env = Env::default();
    let client = deploy(&env);
    let res = client.try_get_commitments_by_range(&5u32, &1u32);
    assert_eq!(res, Err(Ok(SavingsError::RangeInverted)));
}
