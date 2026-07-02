#![cfg(test)]

//! Structural tests. Full cryptographic verification is exercised by the
//! deploy-side integration tests under `test_snapshots/` and the CLI-driven
//! e2e flow, both of which supply real `bb write_vk` / `bb prove` output.
//! Real UltraHonk VKs are ~1–3 KiB and are rejected as malformed by the
//! synchronous parser in `initialize` if the wrong bytes are supplied — so a
//! stub-VK path is intentionally absent here.

use super::*;
use soroban_sdk::{Bytes, Env, Vec};

fn empty_bytes(env: &Env) -> Bytes {
    Bytes::new(env)
}

#[test]
fn initialize_rejects_empty_vk() {
    let env = Env::default();
    let id = env.register(HonkVerifierContract, ());
    let client = HonkVerifierContractClient::new(&env, &id);
    // Empty bytes are guaranteed to fail structural VK parsing.
    let res = client.try_initialize(&empty_bytes(&env), &4u32);
    assert!(res.is_err(), "empty VK must be rejected at initialize");
}

#[test]
fn verify_uninitialised_returns_false_gracefully() {
    let env = Env::default();
    let id = env.register(HonkVerifierContract, ());
    let client = HonkVerifierContractClient::new(&env, &id);
    let proof = empty_bytes(&env);
    let pi: Vec<BytesN<32>> = Vec::new(&env);
    // Business layer branches on the returned bool, so uninitialised must
    // yield `false` (never panic).
    assert!(!client.verify(&proof, &pi));
}
