# Zava — Contracts & Circuits

This repo contains the on-chain contracts and zero-knowledge circuits that power Zava: a privacy-preserving savings-and-credit reputation system on Stellar.

The goal of this README is to make the whole system understandable. By the end you should know:

- What problem each piece solves
- What data flows where, and what stays private
- Why each design choice was made the way it was
- What's real cryptography and what's still a placeholder
- How to build, test, and deploy everything

If you're new to ZK terminology, jump to the [Glossary](#glossary) first.

---

## Table of contents

1. [What Zava does (the one-paragraph version)](#what-zava-does)
2. [The mental model](#the-mental-model)
3. [System architecture](#system-architecture)
4. [The deposit flow — what happens when you save](#the-deposit-flow)
5. [The proof flow — what happens when you ask for credit](#the-proof-flow)
6. [The contracts in detail](#the-contracts-in-detail)
   - [Savings](#savings-contract)
   - [Honk verifier](#honk-verifier-contract)
   - [Credit verifier](#credit-verifier-contract)
7. [The circuits in detail](#the-circuits-in-detail)
8. [Trust and security model](#trust-and-security-model)
9. [What's stubbed (and why)](#whats-stubbed-and-why)
10. [Building, testing, deploying](#building-testing-deploying)
11. [Repo layout](#repo-layout)
12. [Glossary](#glossary)

---

## What Zava does

A user deposits a portion of every payment they receive into Zava as a cryptographic *commitment* — the on-chain record reveals nothing about who they are or how much they saved. After enough weeks of consistent saving, they generate a zero-knowledge proof of their savings discipline. The proof, verified on-chain, unlocks a credit tier they can use to borrow from any lender that supports Zava credit signals. The lender never sees the user's balance, income, identity, or transaction history — only the credit tier and how many weeks of discipline backed it.

## The mental model

The hardest thing about ZK systems is keeping straight *who knows what at each step*. Here is the table you should re-check every time the design feels confusing:

| Actor           | Knows the secret? | Sees the amounts? | Sees the wallet? | Sees the credit tier? |
| --------------- | ----------------- | ----------------- | ---------------- | --------------------- |
| User            | yes               | yes               | yes              | yes                   |
| Random observer | no                | no                | no               | no                    |
| Lender          | no                | no                | yes (the borrowing wallet) | yes |
| Tax authority   | only if the user voluntarily shares a viewing key |

The user's `secret` is the only piece of information that links every other piece of data together. The secret never leaves the user's device. Everything on-chain is either:

- A **commitment** — the hash of `(secret, amount)`. Reveals nothing about either.
- A **nullifier** — the hash of `(secret, week_number)`. Reveals nothing, but is unique per deposit so it prevents replay.
- A **credit record** — the *outcome* of a verified proof, keyed by wallet.

Everything else (the actual amounts, the timestamps, the secret itself) stays on the user's device.

---

## System architecture

Zava is five deployed contract instances on Stellar plus three Noir circuits compiled to ACIR bytecode (which the user's browser uses to generate proofs locally).

```
┌─────────────────────────────────────────────────────────────────┐
│                       USER'S BROWSER                            │
│                                                                 │
│   Holds: secret, amounts, timestamps                            │
│   Runs:  Noir WASM → produces UltraHonk proof                   │
└─────────────────────────────────────────────────────────────────┘
                      │ deposit(commitment, nullifier, week)
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                  SAVINGS CONTRACT (1 instance)                  │
│                                                                 │
│   Records: { commitment, nullifier, week, timestamp }           │
│   Tracks:  per-commitment & per-nullifier existence flags       │
└─────────────────────────────────────────────────────────────────┘
                      ▲
                      │ is_commitment_recorded()
                      │ is_nullifier_spent()
                      │
┌─────────────────────────────────────────────────────────────────┐
│              CREDIT VERIFIER CONTRACT (1 instance)              │
│                                                                 │
│   verify_proof(wallet, proof, public_inputs)                    │
│     1. Routes to right Honk verifier (by week count)            │
│     2. Checks commitments + nullifiers exist in savings         │
│     3. Calls Honk verifier with the proof                       │
│     4. Records CreditRecord { tier, expires_at } for wallet     │
└─────────────────────────────────────────────────────────────────┘
       │ verify(proof, public_inputs)
       ▼
┌──────────────────┬──────────────────┬─────────────────────────┐
│ HONK VERIFIER 8w │ HONK VERIFIER 12w│ HONK VERIFIER 24w       │
│                  │                  │                         │
│ embedded VK from │ embedded VK from │ embedded VK from        │
│ circuits/zava_8w │ circuits/zava_12w│ circuits/zava_24w       │
│                  │                  │                         │
│ verify(...) → bool                                            │
└──────────────────┴──────────────────┴─────────────────────────┘
       ▲                  ▲                  ▲
       │   VK + proofs    │   VK + proofs    │   VK + proofs
┌──────┴────────┐ ┌───────┴────────┐ ┌──────┴────────────────┐
│ circuits/     │ │ circuits/      │ │ circuits/             │
│ zava_8w       │ │ zava_12w       │ │ zava_24w              │
│ N=8 Pedersen  │ │ N=12 Pedersen  │ │ N=24 Pedersen         │
└───────────────┘ └────────────────┘ └───────────────────────┘
```

**Why three Honk verifiers (one per tier)?** Noir circuits have fixed-size arrays at compile time. A "12-week proof" circuit has hardcoded `N=12` everywhere — the public input count, the loop bounds, the hash arities. Different `N` means a different circuit means a different verification key. We deploy three Honk verifier instances, each pre-loaded with one of the three VKs, and the credit verifier picks the right one at runtime based on the `consistency_weeks` field in the proof's public inputs.

---

## The deposit flow

**Goal:** record a savings deposit on-chain without revealing the amount, the depositor, or any link between deposits made by the same person.

What the user's device does (off-chain):

1. Generate (or load) a random 32-byte `secret`. This is the user's master key and lives only on their device.
2. Pick an `amount` (e.g. 400000000 stroops = $40).
3. Pick the `week_number` (0 for the first deposit, then 1, 2, 3, … strictly increasing).
4. Compute:
   - `commitment = pedersen_hash([secret, amount])`
   - `nullifier  = pedersen_hash([secret, week_number])`
5. Submit `deposit(commitment, nullifier, week_number)` to the savings contract.

What the savings contract does:

1. Reject if `nullifier` was already recorded (per-deposit uniqueness — prevents the same `(secret, week)` from being committed twice).
2. Reject if `week_number` would skip backward or jump more than `MAX_WEEK_GAP` (a coarse on-chain sanity check; the Noir circuit later enforces stricter "no missed weeks" within proof windows).
3. Store the new `Commitment { hash, nullifier, week_number, timestamp }` in the deposit list.
4. Set the flags `CommitmentRecorded(commitment) = true` and `NullifierSpent(nullifier) = true`. These two flags are what later lets the credit verifier check that a proof references real on-chain deposits.
5. Recompute and store the chain-hash `MerkleRoot` over all commitments. (This is now mostly a public progress fingerprint — see [why we don't use it cryptographically](#what-the-merkle-root-is-and-isnt).)
6. Emit `(deposit, recorded)` and `(merkle, updated)` events.

Privacy invariant after a deposit: an outside observer sees a 32-byte commitment, a 32-byte nullifier, an integer week index, and a timestamp. Nothing about the depositor's identity, no balance, no link between this deposit and any other deposit unless they can guess the secret.

---

## The proof flow

**Goal:** convince the credit verifier that the user has made `N` consistent deposits matching certain criteria, without revealing the secret, the amounts, or the timestamps.

What the user's device does (off-chain):

1. Pick the tier they want to claim — Medium (8 weeks), Low (12 weeks), or VeryLow (24 weeks). This determines which circuit to load.
2. Gather the relevant on-chain commitments and pick the corresponding private witness:
   - The user already knows their own `secret`, the amounts they deposited, the timestamps, and the week numbers.
3. Recompute each `commitment[i] = pedersen([secret, amount[i]])` and each `nullifier[i] = pedersen([secret, week[i]])` to make sure they match what's on-chain.
4. Run the matching Noir circuit in the browser via WASM. The circuit takes:
   - **Private** inputs: `secret`, `weekly_amounts`, `deposit_timestamps`, `week_numbers`.
   - **Public** inputs: `min_weekly_amount`, `consistency_weeks`, `commitments`, `nullifiers`.
5. The circuit produces an UltraHonk **proof** (a binary blob, ~5-15 KB). The proof, together with the public inputs, is what gets submitted on-chain. Generating the proof takes 15-30 seconds in the browser depending on circuit size.

What the credit verifier contract does:

1. `wallet.require_auth()` — the calling wallet must authorise. This wallet is what gets the credit record, so they need to sign.
2. Map `consistency_weeks` to a tier (8 → Medium, 12 → Low, 24 → VeryLow). Reject anything else.
3. Sanity-check that `commitments.len() == consistency_weeks` and `nullifiers.len() == consistency_weeks`.
4. For each `commitment[i]`, call `savings.is_commitment_recorded(commitment[i])`. If any returns false → reject with `CommitmentNotRecorded`.
5. For each `nullifier[i]`, call `savings.is_nullifier_spent(nullifier[i])`. If any returns false → reject with `NullifierNotRecorded`.
6. Build the public-input vector in the exact order the matching Noir circuit declares (`min_weekly_amount`, `consistency_weeks`, `commitments…`, `nullifiers…`).
7. Call `honk.verify(proof, public_inputs)` on the Honk verifier contract for that tier. If it returns false → reject with `ProofInvalid`.
8. Write a `CreditRecord { wallet, tier, verified_at, consistency_weeks, expires_at: now + 90 days }` to persistent storage keyed by `wallet`. Re-proving before expiry just overwrites the existing record.
9. Emit `(credit, verified)`.

The result: the lender can call `verifier.get_credit_tier(wallet)` and get back the tier, or `None` if the record has expired or never existed.

### Why this design binds the proof to real on-chain deposits

The Noir circuit by itself only enforces *internal* consistency: amounts ≥ threshold, no missed weeks, commitments and nullifiers correctly derived from the same secret. It doesn't know what's actually on Stellar.

The binding to on-chain reality is achieved by the credit verifier contract, which checks every commitment and nullifier exists in the savings contract. Combined with the circuit's constraint that `commitment[i] = pedersen([secret, amount[i]])`, this means:

- If you claim `amount[i] = $1000`, your commitment must be `pedersen([secret, $1000])`. The verifier checks that exact commitment exists in savings. It can only exist if you actually deposited `$1000` for that secret — there's no way to fake the commitment without finding a pre-image of the Pedersen hash, which is the entire security assumption of the scheme.

Without this commitment-existence check, a user could claim arbitrarily inflated amounts in their proof and the cryptography would happily accept — because the circuit never sees the *real* on-chain state. This is why we added `is_commitment_recorded` to savings: it's the bridge between "what the circuit proves" and "what's actually saved".

---

## The contracts in detail

### Savings contract

**Path:** `contracts/savings/`

**Purpose:** anonymous ledger of savings commitments + per-commitment and per-nullifier existence flags.

**Storage layout:**

| Key                            | Type            | Purpose                                                      |
| ------------------------------ | --------------- | ------------------------------------------------------------ |
| `Commitments`                  | `Vec<Commitment>` | Append-only list of every deposit ever made.               |
| `MerkleRoot`                   | `BytesN<32>`    | Running chain-hash fingerprint over commitment hashes. Public progress indicator only — see below. |
| `NullifierSpent(BytesN<32>)`   | `bool`          | One key per spent nullifier — `true` iff recorded.           |
| `CommitmentRecorded(BytesN<32>)` | `bool`        | One key per recorded commitment — `true` iff recorded.       |
| `LastWeek`                     | `u32`           | Highest week number recorded so far (used for gap detection). |

**Each `Commitment` entry:**

```rust
pub struct Commitment {
    pub hash: BytesN<32>,        // pedersen(secret, amount), computed off-chain
    pub nullifier: BytesN<32>,   // pedersen(secret, week_number), computed off-chain
    pub week_number: u32,
    pub timestamp: u64,
}
```

**Methods:**

| Method | Signature | What it does |
| --- | --- | --- |
| `deposit` | `(commitment, nullifier, week_number) -> Result<()>` | Record a new deposit. Rejects on replay (nullifier already seen), regression (week goes backward), or excessive gap. |
| `get_merkle_root` | `() -> BytesN<32>` | Returns the current chain-hash fingerprint. |
| `get_commitment_count` | `() -> u32` | Total number of deposits. |
| `is_nullifier_spent` | `(nullifier) -> bool` | True iff that nullifier has been recorded. Used by the credit verifier. |
| `is_commitment_recorded` | `(commitment) -> bool` | True iff that commitment has been recorded. Used by the credit verifier. |
| `get_commitments_by_range` | `(start, end) -> Vec<Commitment>` | Read commitments for week numbers in `[start, end]`. Used by the frontend to assemble proof inputs. |

**Errors:**

| Code | Meaning |
| --- | --- |
| 1 — `NullifierAlreadySpent` | `deposit` got a nullifier that's already been recorded. |
| 2 — `WeekNumberMustAdvance` | `deposit` got a `week_number` ≤ the last one. |
| 3 — `WeekGapTooLarge` | `deposit` skipped more than `MAX_WEEK_GAP` weeks. |
| 4 — `RangeInverted` | `get_commitments_by_range` got `start > end`. |

**Why no `require_auth`?** Anyone can submit a deposit. That's intentional: the privacy guarantee depends on the depositor being anonymous from the chain's perspective. If we required the wallet to authorise, then the wallet address would be linked to the deposit forever in the transaction history. The deposit's value is in the commitment, not in who sent the transaction.

#### What the Merkle root is and isn't

The savings contract maintains a `MerkleRoot` field, but it's computed as a sequential SHA-256 chain hash over *all* commitments globally, not a real binary Merkle tree. That means:

- You can read it as a fingerprint: "the savings ledger is currently in state X".
- You **cannot** efficiently prove membership in it. To recompute the root, you'd need every commitment ever made — defeating the point of a per-user proof.

The original briefing planned to use this root inside the ZK circuit as a public input. We dropped that approach because no individual prover can recompute the root without all of the global state. The cryptographic binding to on-chain reality is instead achieved by the per-deposit existence checks (`is_commitment_recorded`, `is_nullifier_spent`), which the credit verifier calls during proof verification. The chain-hash root remains useful as a public state fingerprint for tooling.

---

### Honk verifier contract

**Path:** `contracts/honk_verifier/`

**Purpose:** pure cryptographic verifier for one specific Noir circuit. Three instances are deployed — one for each credit tier.

**Storage:**

| Key  | Type             | Purpose                                                         |
| ---- | ---------------- | --------------------------------------------------------------- |
| `Vk` | `VerificationKey` | The UltraHonk verification key for this tier's circuit, set once at init. Immutable. |

```rust
pub struct VerificationKey {
    pub bytes: Bytes,            // 3680 bytes, from `bb write_vk`
    pub num_public_inputs: u32,  // 2 + 2*N where N is the tier's week count
}
```

**Methods:**

| Method | Signature | What it does |
| --- | --- | --- |
| `initialize` | `(vk_bytes, num_public_inputs) -> Result<()>` | Embed the VK exactly once. Subsequent calls return `AlreadyInitialized`. |
| `verify` | `(proof, public_inputs) -> bool` | Check the proof against the embedded VK. Returns true/false; panics with a typed error on structural problems (uninitialised, wrong input count, proof too short). |
| `get_verification_key` | `() -> Bytes` | Returns the raw VK bytes. Used by auditors to confirm which circuit a deployed instance corresponds to. |
| `get_num_public_inputs` | `() -> u32` | Returns the expected public-input count. |

**Errors:**

| Code | Meaning |
| --- | --- |
| 1 — `AlreadyInitialized` | `initialize` called more than once. |
| 2 — `NotInitialized` | Any method called before `initialize`. |
| 3 — `PublicInputCountMismatch` | `verify` got a public-input vector of the wrong length. |
| 4 — `InvalidProofLength` | `verify` got a proof shorter than the minimum sanity bound. |

**Design notes:**

- One contract type, three deployed instances. Each instance gets a different VK and a different `num_public_inputs` (18 for 8w, 26 for 12w, 50 for 24w — that's `2 + 2*N`).
- No admin, no upgrade path. If the matching Noir circuit changes, you deploy a new instance and point the credit verifier at it.
- The contract returns `bool` rather than `Result<bool, _>` because cross-contract callers (the credit verifier) only care about the verdict. Structural failures (an uninitialised contract, a malformed input vector) panic with a typed error so the call trace shows what went wrong rather than silently failing.

---

### Credit verifier contract

**Path:** `contracts/verifier/`

**Purpose:** the business-logic layer that ties everything together. This is the only contract a lender talks to.

**Storage:**

| Key                       | Type         | Purpose                          |
| ------------------------- | ------------ | -------------------------------- |
| `SavingsContractId`       | `Address`    | The savings contract to query. |
| `Honk8w`                  | `Address`    | The 8-week Honk verifier.        |
| `Honk12w`                 | `Address`    | The 12-week Honk verifier.       |
| `Honk24w`                 | `Address`    | The 24-week Honk verifier.       |
| `CreditRecord(Address)`   | `CreditRecord` | One per wallet that has ever earned credit. |

```rust
pub enum CreditTier {
    Medium,   //  8 weeks proven
    Low,      // 12 weeks proven
    VeryLow,  // 24 weeks proven
}

pub struct CreditRecord {
    pub wallet: Address,
    pub tier: CreditTier,
    pub verified_at: u64,
    pub consistency_weeks: u32,
    pub expires_at: u64,
}

pub struct PublicInputs {
    pub min_weekly_amount: u64,
    pub consistency_weeks: u32,
    pub commitments: Vec<BytesN<32>>,
    pub nullifiers: Vec<BytesN<32>>,
}
```

**Methods:**

| Method | Signature | What it does |
| --- | --- | --- |
| `initialize` | `(savings, honk_8w, honk_12w, honk_24w) -> Result<()>` | Bind the contract to its four counterparts. Callable once. |
| `verify_proof` | `(wallet, proof, public_inputs) -> Result<CreditTier>` | The main entry point. See the [proof flow](#the-proof-flow) for the full sequence. `wallet` must authorise. |
| `get_credit_tier` | `(wallet) -> Option<CreditRecord>` | Returns the wallet's current record, or `None` if expired/missing. |
| `is_credit_valid` | `(wallet) -> bool` | Convenience boolean over `get_credit_tier`. |
| `get_verification_key` | `(tier) -> Result<Bytes>` | Pass-through to the matching Honk verifier so tooling doesn't need to know the Honk verifier addresses. |
| `get_linked_contracts` | `() -> Result<(savings, honk_8w, honk_12w, honk_24w)>` | All four bound addresses. |

**Errors:**

| Code | Meaning |
| --- | --- |
| 1 — `AlreadyInitialized` | `initialize` called more than once. |
| 2 — `NotInitialized` | Method called before init. |
| 3 — `InvalidConsistencyWeeks` | `consistency_weeks` was not 8, 12, or 24. |
| 4 — `NullifierCountMismatch` | `nullifiers.len() != consistency_weeks`. |
| 5 — `CommitmentCountMismatch` | `commitments.len() != consistency_weeks`. |
| 6 — `NullifierNotRecorded` | One of the nullifiers is not in savings. |
| 7 — `CommitmentNotRecorded` | One of the commitments is not in savings. |
| 8 — `ProofInvalid` | Honk verifier rejected the proof. |

**Why the cross-contract calls go through a trait, not the crate?** The credit verifier doesn't import the savings or honk_verifier crate as a runtime dependency. If it did, the WASM linker would pull their exported contract symbols into the credit verifier's binary, producing duplicate-symbol errors. Instead, both client interfaces are declared inline as `#[contractclient]` traits with only SDK primitive types (`Address`, `Bytes`, `BytesN<32>`, `Vec<…>`) crossing the boundary.

---

## The circuits in detail

**Path:** `circuits/zava_8w/`, `circuits/zava_12w/`, `circuits/zava_24w/`

All three circuits are identical except for one constant `N` (8, 12, or 24). They're written in Noir 1.0-beta and produce UltraHonk proofs via the `bb` (barretenberg) backend.

### What a single circuit proves

In English: "I know a `secret` and a sequence of `N` (amount, timestamp, week) tuples such that:

1. every amount is ≥ the public `min_weekly_amount`,
2. every consecutive pair of timestamps is ≤ 8 days apart and strictly increasing,
3. every consecutive pair of week numbers is strictly increasing,
4. for every `i`, the public `commitment[i] = pedersen(secret, amount[i])`,
5. for every `i`, the public `nullifier[i] = pedersen(secret, week_number[i])`,
6. and the public `consistency_weeks` equals `N`."

The verifier sees the public inputs (`min_weekly_amount`, `consistency_weeks`, the `commitments`, the `nullifiers`) and the proof. It learns *nothing* about the secret, amounts, timestamps, or actual week indices beyond what the public inputs already say.

### Inputs

| Name | Visibility | Type      | Notes                                                                    |
| ---- | ---------- | --------- | ------------------------------------------------------------------------ |
| `secret`                | private | `Field`    | The user's master key.                                                  |
| `weekly_amounts`        | private | `[u64; N]` | Actual amounts deposited (e.g. `400000000` stroops = $40).              |
| `deposit_timestamps`    | private | `[u64; N]` | Ledger timestamps from each deposit.                                    |
| `week_numbers`          | private | `[u32; N]` | The week-index field for each deposit (must match what was on-chain).   |
| `min_weekly_amount`     | public  | `u64`      | Threshold being claimed.                                                |
| `consistency_weeks`     | public  | `u32`      | Must equal `N`. Used by the routing layer in the credit verifier.       |
| `commitments`           | public  | `[Field; N]` | Pedersen hashes the verifier will cross-check against savings.        |
| `nullifiers`            | public  | `[Field; N]` | Pedersen-hashed week tags the verifier will cross-check against savings. |

The on-chain public-input vector that gets passed to the Honk verifier is `[min_weekly_amount, consistency_weeks, commitments..., nullifiers...]`, in that exact order. The credit verifier serialises u64/u32 as big-endian into `BytesN<32>` so every public input is a single 32-byte value — matching the field-element layout the Honk verifier expects.

### Why three separate circuits

Noir array lengths are compile-time constants. `[Field; 12]` and `[Field; 24]` are different types — they produce different ACIRs, different VKs, and different on-chain Honk verifier instances. Three options for handling tier variation:

1. **Three circuits, three deployed verifiers (what we did).** Each tier has its own focused circuit; the credit verifier routes by `consistency_weeks`. Simple, correct, no padding. Cost: a small amount of duplicated Noir source between the three packages.
2. **One circuit at the max length (24), pad shorter proofs with zeroes.** Saves a deployed verifier per tier. Cost: a 12-week claim still produces a 24-element proof and pays the verification cost of the larger circuit; the circuit also has to handle the masking logic correctly.
3. **Recursion: one outer circuit that takes a variable-length inner proof.** Most flexible. Cost: significantly more complex, slower proving.

For a hackathon the cost of option 1 is the lowest. The duplication is genuinely trivial (~70 lines per circuit, near-identical) and the runtime story is dead simple.

### Constraints, in order

```noir
// 1. Tier binding — the claimed tier must match this circuit's N.
assert(consistency_weeks == N);

for i in 0..N {
    // 2. Amount meets the claimed threshold.
    assert(weekly_amounts[i] >= min_weekly_amount);

    // 3. Commitment binding.
    let expected_commitment = pedersen_hash([secret, weekly_amounts[i] as Field]);
    assert(expected_commitment == commitments[i]);

    // 4. Nullifier binding.
    let expected_nullifier = pedersen_hash([secret, week_numbers[i] as Field]);
    assert(expected_nullifier == nullifiers[i]);
}

for i in 1..N {
    // 5. Week numbers strictly increasing.
    assert(week_numbers[i] > week_numbers[i - 1]);

    // 6. Timestamps strictly increasing with gap ≤ 8 days.
    let gap = deposit_timestamps[i] - deposit_timestamps[i - 1];
    assert(gap > 0);
    assert(gap <= 691200);  // 8 days in seconds
}
```

Each circuit also has a `#[test]` that demonstrates a valid proof against fixture data; run them with `nargo test` (see the build section below).

---

## Trust and security model

### What's cryptographically enforced

| Property | Where it's enforced | How |
| --- | --- | --- |
| The prover knows `secret`. | Circuit | If they didn't, they couldn't produce `nullifier[i] = pedersen(secret, week[i])` matching the on-chain nullifier. |
| Amounts are above threshold. | Circuit | `assert(amount[i] >= min_weekly_amount)` directly. |
| Timestamps don't skip more than 8 days. | Circuit | The `gap` assertion. |
| Commitments correspond to real deposits. | Credit verifier contract | Calls `savings.is_commitment_recorded(commitment[i])` for each. |
| Nullifiers correspond to real deposits. | Credit verifier contract | Calls `savings.is_nullifier_spent(nullifier[i])` for each. |
| Proof matches the embedded VK. | Honk verifier contract | (Currently stubbed — see next section.) |
| Credit tier matches what the proof claims. | Credit verifier contract | `weeks_to_tier(consistency_weeks)` plus routing to the matching Honk verifier (which enforces the VK's public-input count). |

### What's prevented by design, not by cryptography

| Property | How |
| --- | --- |
| No admin can change verification keys. | The Honk verifier has no setter for `Vk` after `initialize`. |
| No admin can issue credit. | The credit verifier has no setter for `CreditRecord` outside `verify_proof`. |
| Credit records reflect *current* discipline. | 90-day expiry. The user must re-prove to maintain access. |
| One user can't double-count deposits. | Each deposit's nullifier is unique (`nullifier = hash(secret, week_number)`). Two proofs at the same tier from the same secret would reference the same nullifiers — which is fine since both are valid, but they can't *add* to each other. |

### What the system does not protect against

- A user revealing their own secret. (Self-doxxing.)
- A user generating proofs with someone else's secret — but only if the attacker actually knows that secret. Once known, the attacker can do everything the user can.
- An off-chain payment processor leaking the link between a wallet and a real-world identity. The privacy guarantees are about what's *on-chain*; an upstream leak isn't recoverable.
- Lenders demanding off-chain identity disclosure before disbursing a loan, in which case the on-chain privacy is a backstop, not a hard guarantee.

---

## What's stubbed (and why)

`HonkVerifierContract::verify_proof_inner` is currently a non-cryptographic sanity check (vk + proof + public inputs all non-empty). Real UltraHonk verification is not yet wired up.

**Why it's stubbed:**

1. Noir's modern toolchain (1.0-beta+) produces UltraHonk proofs, not Groth16. UltraHonk verification on-chain is significantly more involved than 3-pairing Groth16 verification — Aztec's Solidity reference verifier is ~2,000 lines and consumes a lot of gas.
2. Soroban's only on-chain pairing primitive (`env.crypto().bls12_381()`) ships in soroban-sdk 22+. We're on 21 to keep the rest of the SDK API stable for now.
3. The cryptographic verifier is independent of every other piece of architecture. The integration boundary is one function (`verify_proof_inner`); swapping in real verification doesn't touch the savings contract, the credit verifier, the circuits, or the frontend.

**The path to real verification, in order of effort:**

1. **Bump soroban-sdk to 22.x.** Audit the diff; the breaking changes are mostly in storage and event APIs and likely contained to small adjustments.
2. **Port an UltraHonk verifier.** Aztec ships a Solidity reference; a Rust no_std port can use the BLS12-381 host functions for the final KZG batch check. This is the bulk of the work — easily a week of focused crypto coding plus testing against real `bb prove` outputs.
3. **Alternative: recursive bridge.** Prove the Honk verification inside a Groth16 circuit, then verify the (much cheaper) Groth16 proof on-chain. More expensive proving for the user, dramatically cheaper verification. The Soroban contract would still be a pairing-based verifier, just for Groth16 instead of Honk.

Until one of those is in place, the system runs end-to-end but the proof check is structural. This is fine for local testing and demo flows, **not** fine for real credit decisions.

---

## Building, testing, deploying

### One-time toolchain setup

```bash
# Noir (nargo)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
source ~/.bashrc
noirup

# Barretenberg (bb) — needed for VK extraction
curl -sL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
source ~/.bashrc
bbup

# Stellar CLI — needed for deployment
curl -sSf https://soroban.stellar.org/install.sh | sh

# Rust wasm target
rustup target add wasm32-unknown-unknown
```

After setup you should have `nargo 1.0.0-beta.22+`, `bb 5.0+`, and `stellar` on your PATH.

### Build everything

```bash
./scripts/build.sh
```

This:
- Compiles each of `circuits/zava_8w`, `circuits/zava_12w`, `circuits/zava_24w` with `nargo compile`, producing `target/zava_*w.json` (the ACIR).
- Runs `bb write_vk` on each compiled circuit to produce `target/vk/vk` (3680 bytes, UltraHonk).
- Builds the Soroban WASM artifacts: `savings.wasm`, `honk_verifier.wasm`, `verifier.wasm` in `contracts/target/wasm32-unknown-unknown/release/`.

### Test everything

```bash
# Soroban contract tests (26 total across three packages)
cd contracts && cargo test --workspace

# Noir circuit tests (one per tier, all hit the valid-proof happy path)
for tier in zava_8w zava_12w zava_24w; do
    (cd circuits/$tier && nargo test)
done
```

### Deploy to testnet

```bash
# One-time: create and fund a testnet identity
stellar keys generate --global default --network testnet --fund

# Deploy + initialise everything
./scripts/deploy.sh testnet
```

The script deploys five contract instances (1 savings, 3 honk_verifier with the per-tier VKs from `circuits/zava_*w/target/vk/vk`, 1 credit verifier) and writes their addresses to `.deploy.testnet.env`.

### Use the deployed contracts

After a successful deploy, source the env file to bring the contract IDs into your shell:

```bash
source .deploy.testnet.env

# Make a deposit
stellar contract invoke --id $ZAVA_SAVINGS --source default --network testnet -- \
    deposit \
    --commitment 0xabc...32-byte-hex... \
    --nullifier  0xdef...32-byte-hex... \
    --week_number 0

# Check current state
stellar contract invoke --id $ZAVA_SAVINGS --source default --network testnet -- \
    get_commitment_count

# Submit a proof
stellar contract invoke --id $ZAVA_VERIFIER --source default --network testnet -- \
    verify_proof --wallet $YOUR_WALLET --proof 0x...  --public_inputs '{...}'
```

---

## Repo layout

```
.
├── README.md                     ← this file
├── LICENSE
├── circuits/
│   ├── zava_8w/                  ← Medium-tier circuit (N=8)
│   │   ├── Nargo.toml
│   │   ├── src/main.nr
│   │   └── target/               ← built artifacts (gitignored)
│   │       ├── zava_8w.json      ← ACIR bytecode
│   │       └── vk/
│   │           ├── vk            ← 3680-byte UltraHonk VK
│   │           └── vk_hash       ← fingerprint of the VK
│   ├── zava_12w/                 ← Low-tier circuit (N=12)
│   └── zava_24w/                 ← VeryLow-tier circuit (N=24)
├── contracts/
│   ├── Cargo.toml                ← workspace
│   ├── savings/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            ← contract logic
│   │       └── test.rs           ← unit tests
│   ├── honk_verifier/            ← the cryptographic verifier (3 instances deployed)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── test.rs
│   └── verifier/                 ← credit / business-logic verifier (1 instance deployed)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           └── test.rs
└── scripts/
    ├── build.sh                  ← compile circuits + extract VKs + build contracts
    └── deploy.sh                 ← deploy the 5 contract instances and init them
```

---

## Glossary

**ACIR.** Abstract Circuit Intermediate Representation. The bytecode Noir compiles to before it's handed to a proving backend.

**Barretenberg / `bb`.** Aztec's proving backend. Takes an ACIR plus a witness and produces a proof; takes an ACIR alone and produces a verification key. Currently supports the UltraHonk proving system (not Groth16).

**Commitment.** A cryptographic hash that hides a value (the amount) but binds the prover to it — they can't change it later without changing the hash. We use `pedersen_hash([secret, amount])`.

**Honk / UltraHonk.** The proving system Noir currently produces. Built on polynomial commitments and a Fiat-Shamir transcript. Verifies in ~tens of pairings rather than the 3 of Groth16, but it's what the toolchain ships.

**Merkle root (in this project).** A sequential chain hash over all commitments. We keep it as a public state fingerprint, not as a cryptographic membership-proof anchor — see [the savings contract](#what-the-merkle-root-is-and-isnt).

**Noir.** The ZK DSL (Aztec) we use to write circuits. Looks like Rust.

**Nullifier.** A deterministic per-deposit tag derived from the user's secret. Two deposits with the same `(secret, week_number)` produce the same nullifier, and the contract rejects duplicates — preventing replay. Also used during proof verification to confirm a claimed deposit actually exists on-chain.

**Pedersen hash.** A collision-resistant hash that's cheap to compute inside a ZK circuit. Standard choice for ZK-friendly commitments and nullifiers.

**Private input (to a circuit).** A value only the prover knows. Doesn't appear in the proof or in any chain transaction.

**Public input (to a circuit).** A value both the prover and the verifier see. Encoded in the proof as a 32-byte field element. Both sides must agree on its order and content for verification to succeed.

**Soroban.** Stellar's smart-contract platform. Contracts are Rust compiled to WebAssembly.

**Stroop.** The smallest unit of a Stellar asset. 1 USDC = 10,000,000 stroops (7 decimal places).

**Verification key (VK).** A circuit-specific cryptographic object that the verifier uses to check proofs. Distinct from the proving key (which the prover needs). For UltraHonk, a VK is ~3680 bytes.

**Witness.** The set of all values inside a circuit when run on specific inputs — both public and private. The proof is constructed from the witness and the proving key; the verifier never sees it.
