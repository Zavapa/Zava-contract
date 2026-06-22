#![cfg(test)]

use super::*;
use soroban_sdk::{Env, Error};

fn fixture_vk(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xAB; 256])
}

fn fixture_proof(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xCD; MIN_PROOF_BYTES as usize])
}

fn fixture_inputs(env: &Env, n: u32) -> Vec<BytesN<32>> {
    let mut v = Vec::new(env);
    for i in 0..n {
        v.push_back(BytesN::from_array(env, &[i as u8; 32]));
    }
    v
}

fn deploy(env: &Env, num_inputs: u32) -> HonkVerifierContractClient<'_> {
    let id = env.register_contract(None, HonkVerifierContract);
    let client = HonkVerifierContractClient::new(env, &id);
    client.initialize(&fixture_vk(env), &num_inputs);
    client
}

fn expect_err(
    res: Result<Result<bool, soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>,
    code: HonkVerifierError,
) {
    let actual = res
        .err()
        .expect("expected Err")
        .expect("expected contract error");
    assert_eq!(actual, Error::from_contract_error(code as u32));
}

#[test]
fn verifies_valid_shaped_proof() {
    let env = Env::default();
    let client = deploy(&env, 4);
    assert!(client.verify(&fixture_proof(&env), &fixture_inputs(&env, 4)));
}

#[test]
fn rejects_wrong_input_count() {
    let env = Env::default();
    let client = deploy(&env, 4);
    let res = client.try_verify(&fixture_proof(&env), &fixture_inputs(&env, 3));
    expect_err(res, HonkVerifierError::PublicInputCountMismatch);
}

#[test]
fn rejects_short_proof() {
    let env = Env::default();
    let client = deploy(&env, 1);
    let short = Bytes::from_array(&env, &[0u8; 10]);
    let res = client.try_verify(&short, &fixture_inputs(&env, 1));
    expect_err(res, HonkVerifierError::InvalidProofLength);
}

#[test]
fn rejects_uninitialised_contract() {
    let env = Env::default();
    let id = env.register_contract(None, HonkVerifierContract);
    let client = HonkVerifierContractClient::new(&env, &id);
    let res = client.try_verify(&fixture_proof(&env), &fixture_inputs(&env, 1));
    expect_err(res, HonkVerifierError::NotInitialized);
}

#[test]
fn double_initialize_rejected() {
    let env = Env::default();
    let client = deploy(&env, 2);
    let res = client.try_initialize(&fixture_vk(&env), &2u32);
    assert_eq!(res, Err(Ok(HonkVerifierError::AlreadyInitialized)));
}

#[test]
fn vk_accessors_roundtrip() {
    let env = Env::default();
    let client = deploy(&env, 5);
    assert_eq!(client.get_verification_key(), fixture_vk(&env));
    assert_eq!(client.get_num_public_inputs(), 5);
}
