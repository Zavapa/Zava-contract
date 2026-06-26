//! Fixed-depth incremental Merkle tree with root history.
//!
//! Adapted from Nethermind's `MerkleTreeWithHistory` for the ZavaVault.
//! Uses SHA-256 as the hash function (upgrade path: swap for Poseidon2
//! once `env.crypto().poseidon2()` is stable on Soroban).
//!
//! Each call to `insert` adds one leaf and returns the new root.
//! The last `ROOT_HISTORY_SIZE` roots are kept so that proofs generated
//! just before a new deposit can still be verified.

use soroban_sdk::{Bytes, BytesN, Env, Map};

pub const LEVELS: u32 = 20;           // supports 2^20 ≈ 1M leaves
pub const ROOT_HISTORY_SIZE: u32 = 30;

// Storage key helpers — kept local so the parent module owns the DataKey enum.
pub const KEY_NEXT_INDEX: &str   = "mt_next";
pub const KEY_CURRENT_IDX: &str  = "mt_ridx";   // index into root ring
pub const KEY_FILLED: &str       = "mt_zeros";   // pre-filled zero hashes

/// Insert a new leaf and return the new Merkle root.
/// `filled_subtrees` and `roots` are passed as `&mut Map` slices to keep
/// contract-level storage keys decoupled from this module.
pub fn insert(
    env: &Env,
    leaf: BytesN<32>,
    filled_subtrees: &mut Map<u32, BytesN<32>>,
    roots: &mut Map<u32, BytesN<32>>,
    next_index: u32,
    current_root_index: u32,
) -> (BytesN<32>, u32, u32) {
    let mut current_index = next_index;
    let mut current_level_hash = leaf;

    for i in 0..LEVELS {
        let (left, right) = if current_index % 2 == 0 {
            let zero = zero_value(env, i);
            filled_subtrees.set(i, current_level_hash.clone());
            (current_level_hash, zero)
        } else {
            let left = filled_subtrees.get(i).unwrap_or_else(|| zero_value(env, i));
            (left, current_level_hash)
        };
        current_level_hash = hash_pair(env, &left, &right);
        current_index /= 2;
    }

    let new_root_index = (current_root_index + 1) % ROOT_HISTORY_SIZE;
    roots.set(new_root_index, current_level_hash.clone());

    (current_level_hash, next_index + 1, new_root_index)
}

/// True if `root` is among the last `ROOT_HISTORY_SIZE` roots.
pub fn is_known_root(roots: &Map<u32, BytesN<32>>, root: &BytesN<32>) -> bool {
    for i in 0..ROOT_HISTORY_SIZE {
        if let Some(r) = roots.get(i) {
            if &r == root {
                return true;
            }
        }
    }
    false
}

/// SHA-256( left || right ) — swap for Poseidon2 in production.
pub fn hash_pair(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.extend_from_array(&left.to_array());
    buf.extend_from_array(&right.to_array());
    env.crypto().sha256(&buf).into()
}

/// The zero-value for level `level` (hash of two zero children at that depth).
fn zero_value(env: &Env, level: u32) -> BytesN<32> {
    let mut current = BytesN::<32>::from_array(env, &[0u8; 32]);
    for _ in 0..level {
        current = hash_pair(env, &current, &current);
    }
    current
}
