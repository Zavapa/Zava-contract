# Zava — Contracts & Circuits (Soroban + Noir on Stellar)

[![Stellar](https://img.shields.io/badge/Built%20on-Stellar-000?logo=stellar&logoColor=white)](https://stellar.org)
[![Soroban](https://img.shields.io/badge/Soroban-Protocol%2026-3E1BDB)](https://developers.stellar.org/docs/build/smart-contracts)
[![UltraHonk](https://img.shields.io/badge/ZK-UltraHonk%20(real)-6A0DAD)](https://github.com/AztecProtocol/aztec-packages)
[![Noir](https://img.shields.io/badge/Circuits-Noir%201.0.0--beta.9-8B5CF6)](https://noir-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](./LICENSE)

The **on-chain contracts and zero-knowledge circuits** that power Zava — a privacy-preserving savings, credit, and payments protocol on **Stellar**. Real UltraHonk verification wired end-to-end through Stellar Protocol 26 BN254 host precompiles (CAP-74 / CAP-80).

> **This repo is one third of an open-source system on Stellar:**
> **this repo** (Soroban + Noir) → **[Backend](https://github.com/Zavapa/Zava/tree/main/backend)** (indexer + submitter) → **[Frontend](https://github.com/Zavapa/Zava/tree/main/frontend)** (in-browser UltraHonk prover + dashboard UI).

## On-Chain Evidence

Real UltraHonk verification, not a stub. Both completeness and soundness are demonstrable from public chain state.

| Test | Tx | Result |
|---|---|---|
| Valid `bb prove` output → verified on chain | [`aa6df56c…`](https://stellar.expert/explorer/testnet/tx/aa6df56c789367547c80cdb5c51dd844958eb94ebd09e51c362406bf7ffa848d) | `honk verified true` |
| Tampered proof → rejected on chain | [`40cb44ee…`](https://stellar.expert/explorer/testnet/tx/40cb44eea1d270eb400b4c8cff77388939446118e6c65b7ddb65fbebf9965f62) | `honk verified false` |
| Browser-generated proof via `@aztec/bb.js` → verified on chain | [`406808eb…`](https://stellar.expert/explorer/testnet/tx/406808eb61f8d265ac59e22ca999506a6b3c161f8367182687b5c7dfe93c16ed) | `honk verified true` |

**Stack summary:**

- **Verifier crate:** [`yugocabrio/ultrahonk-rust-verifier`](https://github.com/yugocabrio/ultrahonk-rust-verifier) @ `661db07` — Rust port of Aztec's Barretenberg reference, routing BN254 ops through Stellar Protocol 26 host precompiles.
- **Toolchain (exact pins):** `nargo 1.0.0-beta.9`, `bb 0.87.0`, `@aztec/bb.js@0.87.0`, `@noir-lang/noir_js@1.0.0-beta.9` — CLI and browser produce byte-identical proofs.
- **Circuits:** 3 credit-tier (`zava_8w` / `zava_12w` / `zava_24w`) + `zava_shielded` (4 pi) + `zava_partial_withdraw` (6 pi). VKs 1,760 B, proofs 14,592 B.
- **WASM contract sizes:** `honk_verifier` 48 KiB (37% of Soroban's 128 KiB limit).

---

## How It Works — The Whole System On One Page

### The 30-second version

```text
User (browser)          Circuit                       Stellar (Soroban)
─────────────          ───────                       ─────────────────

Freighter → derives `secret`
   │
   │ Deposit:
   │   commitment = pedersen([secret, amount])
   │   nullifier  = pedersen([secret, week_number])
   │   encrypted_note = AES-GCM({amount, nonce, week}, scan_key)
   ▼
Vault.deposit(...)                                   ├─ locks real tokens
                                                     ├─ stores sha256(c||n)  (anti-theft binding)
                                                     ├─ inserts c into Merkle tree
                                                     └─ emits `zava/deposit` event

── weeks pass ──

Prover (Web Worker, ~10s)
   Private witness:  secret + amounts + timestamps + weeks
   Public inputs:    min_weekly_amount, consistency_weeks, commitments[N], nullifiers[N]
   Circuit `zava_{8,12,24}w` checks: all amounts ≥ threshold, all weeks strictly monotonic,
                                     gaps ≤ 8 days, commitments and nullifiers correctly derived
   ▼  14,592-byte proof
ZavaCredit.claim_credit(...)                         ├─ wallet.require_auth()
                                                     ├─ savings.commitment_exists(c) foreach
                                                     ├─ savings.matches_nullifier(c,n) foreach
                                                     ├─ HonkVerifier.verify(proof, pi)
                                                     │      (Sumcheck + Shplemini + BN254 pairing)
                                                     ├─ tier = weeks_to_tier(active_weeks)
                                                     └─ writes CreditRecord{tier, loan, expires_at}

Lender → ZavaCredit.get_credit_record(wallet)
        sees only tier + loan cap + weeks proven.
        Never sees: amounts, secret, individual commitments, timestamps, history.
```

### Contract map

- **Savings** (1): append-only commitment ledger. Book, not a wallet.
- **Vaults** (2 — XLM + USDC): hold real tokens, Merkle tree of shielded UTXOs, use their own pair of Honk verifiers.
- **Honk verifiers** (5 — 8w, 12w, 24w, Shielded, Partial): pure crypto. Each embeds one VK, delegates BN254 pairings to Protocol 26 host functions.
- **Credit verifier** (1): routes tier proofs to the right Honk verifier, writes `CreditRecord`.
- **Zava Credit** (1): savings-range → loan-cap sizing on top of credit verifier.

---

## The Contracts — What Each One Does And Why

There are **five distinct contract types**, deployed as 10 instances on testnet. Each has a single well-defined responsibility. The composition is the whole point.

### 1. Savings — the append-only commitment ledger

- **File**: `contracts/savings/src/lib.rs`
- **Address**: `CAEWAADG5Y2VM42VERCYMZUCCJIENBQFQDNICMX6WEDBMIPOQVE5D6DA`
- **Job**: record weekly savings deposits as opaque commitments + nullifiers so the credit-verifier layer can later confirm "this claim references real historical data."
- **Explicitly does NOT hold real tokens.** It's a book, not a wallet. The vault is where actual money lives.

```
     ┌───────────────────── SAVINGS CONTRACT ─────────────────────┐
     │                                                            │
     │   deposit(commitment, nullifier, week_number)              │
     │     │                                                      │
     │     ├─► reject if nullifier already spent                  │
     │     ├─► enforce global LastWeek monotonic (gap ≤ 2)        │
     │     ├─► append Commitment{hash, nullifier, week, ts}       │
     │     ├─► set NullifierSpent[nullifier]  = true              │
     │     ├─► set CommitmentRecorded[c]      = true              │
     │     └─► recompute MerkleRoot                               │
     │                                                            │
     │   is_commitment_recorded(c) -> bool                        │
     │   is_nullifier_spent(n)     -> bool                        │
     │   get_merkle_root()         -> BytesN<32>                  │
     │                                                            │
     └────────────────────────────────────────────────────────────┘

   Key design choice: NO require_auth on deposit. Privacy — no wallet
   address is stored, no auth is recorded. Anyone can submit a
   commitment; the crypto (secret unknown ⇒ can't generate a valid
   circuit witness later) is what prevents forgery.
```

### 2. Vault (XLM + USDC) — the actual money box

- **Files**: `contracts/zava_vault/src/lib.rs`
- **Addresses**: `CDKAGIC…PZLM` (XLM), `CBZCANTD…REKP` (USDC) — one instance per asset
- **Job**: hold real tokens behind a shielded pool. Users deposit, withdraw, transfer between commitments, or split via partial withdraw. Every operation except pure-info reads passes through a real UltraHonk verifier.

```
   ┌──────────────────────── VAULT CONTRACT ─────────────────────────┐
   │                                                                 │
   │   deposit(depositor, commitment, nullifier, amount, enc_note)   │
   │     ├─► depositor.require_auth()                                │
   │     ├─► pull `amount` tokens from depositor                     │
   │     ├─► store sha256(commitment||nullifier) ← anti-theft binding│
   │     ├─► insert commitment into Merkle tree (depth 20)           │
   │     └─► emit `zava/deposit` event  (encrypted note goes public, │
   │                                     only scan_key can decrypt)  │
   │                                                                 │
   │   withdraw(proof, public_inputs{root, nullifier,                │
   │            recipient_hash, amount_bytes})                       │
   │     ├─► check nullifier fresh                                   │
   │     ├─► check root is in the recent-root ring                   │
   │     ├─► check stored binding == sha256(commitment||nullifier)   │
   │     ├─► check recipient_hash == pedersen(recipient_bytes)       │
   │     ├─► ShieldedVerifier.verify(proof, 4 public inputs) ✓       │
   │     ├─► mark nullifier spent                                    │
   │     └─► transfer tokens out                                     │
   │                                                                 │
   │   partial_withdraw(proof, in_commitment, in_nullifier, in_root, │
   │            recipient, recipient_hash, withdraw_amount,          │
   │            change_commitment, encrypted_change_note)            │
   │     ├─► same guards as withdraw                                 │
   │     ├─► PartialVerifier.verify(proof, 6 public inputs) ✓        │
   │     ├─► mark old nullifier spent                                │
   │     ├─► insert change_commitment into Merkle tree               │
   │     ├─► transfer withdraw_amount to recipient                   │
   │     └─► emit `zava/partial` event with encrypted_change_note    │
   │         ┌─────────────────────────────────────────────────┐     │
   │         │ Recovery invariant: with only the wallet secret │     │
   │         │ + on-chain events, a wallet can rebuild its     │     │
   │         │ entire deposit + change history. localStorage   │     │
   │         │ is a performance cache, not a source of truth.  │     │
   │         └─────────────────────────────────────────────────┘     │
   │                                                                 │
   │   transfer_shielded(proof, in_nullifier, out_commitment, root)  │
   │     ├─► ShieldedVerifier.verify(proof, 4 pi)  ✓                 │
   │     │      (recipient_hash=0, amount_out=0 signal "in-pool")    │
   │     └─► spend one commitment, create one — no token movement    │
   └─────────────────────────────────────────────────────────────────┘

   Key design choice: TWO verifier addresses stored in vault state.
   `ShieldedVerifier` handles 4-input operations (withdraw + transfer).
   `PartialVerifier`  handles 6-input operations (partial_withdraw).
   Public-input arity is fixed by each honk_verifier's VK, so a
   single verifier cannot serve both.
```

### 3. Honk Verifier — the pure crypto layer

- **File**: `contracts/honk_verifier/src/lib.rs`
- **5 deployed instances**: one per circuit, each initialized once with the matching VK.
- **Job**: pure cryptographic verification, zero business logic. Given a proof, public inputs, and the embedded VK, run Sumcheck + Shplemini + a BN254 pairing check. Return `bool`.

```
   ┌──────────────────── HONK VERIFIER ─────────────────────┐
   │                                                        │
   │   initialize(vk_bytes, num_public_inputs)              │
   │     ├─► UltraHonkVerifier::new(vk_bytes) — must parse  │
   │     └─► store {bytes, num_public_inputs}   (once only) │
   │                                                        │
   │   verify(proof, public_inputs: Vec<BytesN<32>>) -> bool│
   │     │                                                  │
   │     ├─► check proof.len() == 14,592                    │
   │     ├─► check public_inputs.len() == num_public_inputs │
   │     ├─► flatten Vec<BytesN<32>> → Bytes                │
   │     ├─► UltraHonkVerifier.verify(proof, pi_bytes)      │
   │     │     ├─► reconstruct Fiat-Shamir transcript       │
   │     │     ├─► Sumcheck relations                       │
   │     │     ├─► Shplemini (Gemini + Shplonk) opening     │
   │     │     └─► KZG pairing check via BN254 host fns    │
   │     └─► emit `honk/verified` event + return bool       │
   │                                                        │
   └────────────────────────────────────────────────────────┘

   Verifier crate: yugocabrio/ultrahonk-rust-verifier
   Pinned rev:     661db07200f890b1bd9a7349ed787c70a706dd12
   Compiled WASM:  26 KiB (20% of Soroban's 128 KiB budget)
```

The 5 deployed instances differ only in embedded VK:

| Instance | Circuit | Public inputs | Purpose |
|---|---|---|---|
| `CAUHYBIQ…` | zava_8w | 18 | Credit tier Medium (8 weeks) |
| `CBCUHXCT…` | zava_12w | 26 | Credit tier Low (12 weeks) |
| `CA6ORCVS…` | zava_24w | 50 | Credit tier VeryLow (24 weeks) |
| `CA5ACPEE…` | zava_shielded | 4 | Vault withdraw + transfer |
| `CAFAC6VA…` | zava_partial_withdraw | 6 | Vault partial withdraw (with change) |

### 4. Credit Verifier — routes credit-tier claims to the right honk

- **File**: `contracts/verifier/src/lib.rs`
- **Address**: `CATO3SP3…TI2B`
- **Job**: the business-logic layer for the *classic* credit flow. Uses the savings contract as the historical ledger. Routes to 8w/12w/24w honk verifier based on the caller's `consistency_weeks`.

```
   ┌──────────────── CREDIT VERIFIER (classic) ────────────────┐
   │                                                           │
   │   verify_proof(wallet, proof, PublicInputs{               │
   │                min_weekly_amount, consistency_weeks,      │
   │                commitments[], nullifiers[]})              │
   │     │                                                     │
   │     ├─► wallet.require_auth()                             │
   │     ├─► tier = weeks_to_tier(consistency_weeks)           │
   │     │     8→Medium,  12→Low,  24→VeryLow, else reject     │
   │     ├─► foreach c: Savings.is_commitment_recorded(c)      │
   │     ├─► foreach n: Savings.is_nullifier_spent(n)          │
   │     ├─► honk_id = route_by_tier(tier)                     │
   │     ├─► HonkVerifier[honk_id].verify(proof, pi)  ✓        │
   │     ├─► write CreditRecord{wallet, tier, verified_at,     │
   │     │                     expires_at = now + 90 days}     │
   │     └─► emit `credit/verified` event                      │
   │                                                           │
   └───────────────────────────────────────────────────────────┘
```

### 5. Zava Credit — the bulletproof, vault-backed credit issuer

- **File**: `contracts/zava_credit/src/lib.rs`
- **Address**: `CB6E3NOD…TF44`
- **Job**: same idea as Credit Verifier but reads from the **vault** (real deposits) instead of the savings contract, and computes an actual **loan cap** using the tier multiplier. This is the flow the frontend `/dashboard/credit` uses.

```
   ┌────────────────── ZAVA CREDIT ───────────────────┐
   │                                                  │
   │   initialize(vault, honk_verifier)               │
   │                                                  │
   │   claim_credit(wallet, proof, CreditClaim{       │
   │           savings_range, commitments,            │
   │           nullifiers, weeks})                    │
   │     │                                            │
   │     ├─► wallet.require_auth()                    │
   │     ├─► reject duplicate nullifiers within claim │
   │     ├─► weekly_lower_bound = range → stroops     │
   │     ├─► pi = [lb, n, commits.., nulls..]         │
   │     ├─► HonkVerifier.verify(proof, pi)  ✓        │
   │     │                                            │
   │     ├─► foreach: Vault.commitment_exists(c)      │
   │     ├─► foreach: Vault.commitment_matches_       │
   │     │            nullifier(c, n)                 │
   │     │     └─► proves ownership: only someone     │
   │     │        who knew the secret at deposit      │
   │     │        time can produce a matching binding │
   │     ├─► if Vault.is_nullifier_spent(n):          │
   │     │       withdrawn_weeks += 1                 │
   │     │   else:                                    │
   │     │       active_weeks += 1                    │
   │     │                                            │
   │     ├─► tier = weeks_to_tier(active_weeks)       │
   │     │       reject if active_weeks < 8           │
   │     │                                            │
   │     ├─► loan = active_weeks                      │
   │     │        × weekly_lower_bound                │
   │     │        × tier_multiplier / 100             │
   │     │                                            │
   │     └─► write CreditRecord{wallet, tier,         │
   │              loan_eligible_stroops, active,      │
   │              withdrawn, verified_at, expires_at} │
   │                                                  │
   └──────────────────────────────────────────────────┘
```

---

## The Scoring System — Exact Formula

### Step 1: pick a savings range

Each range fixes the **weekly minimum** the borrower is claiming they've saved. The borrower commits to this number BEFORE generating a proof — cheating by claiming a higher range than they can prove would just make the proof fail.

| Range | Weekly minimum (XLM) | Weekly minimum (USD, $0.10/XLM) |
|---|---|---|
| `R5`   | 50 XLM   | ~$5   |
| `R20`  | 200 XLM  | ~$20  |
| `R50`  | 500 XLM  | ~$50  |
| `R200` | 2 000 XLM | ~$200 |
| `R500` | 5 000 XLM | ~$500 |

### Step 2: prove N weeks of savings

The ZK circuit proves the borrower deposited **at least** `range.weekly_minimum` for `N` consecutive weeks. `N` becomes `active_weeks` after the vault check filters out any already-withdrawn commitments.

### Step 3: map active weeks to tier

| `active_weeks` | Tier |
|---|---|
| `< 8`   | rejected |
| `8..12` | Medium |
| `12..24`| Low |
| `≥ 24`  | Very Low |

Constants in `zava_credit/src/lib.rs`: `MEDIUM_THRESHOLD = 8`, `LOW_THRESHOLD = 12`, `VERY_LOW_THRESHOLD = 24`.

### Step 4: compute loan eligibility

```text
loan_eligible_stroops = active_weeks × weekly_lower_bound_stroops × tier_multiplier_bps ÷ 100

tier_multiplier_bps:  Medium=200 (2×) · Low=400 (4×) · Very Low=600 (6×)
```

### Worked examples

Assume `$0.10/XLM` for the USD column.

| active_weeks | range | weekly_bound (XLM) | tier | multiplier | loan (XLM) | loan (USD) |
|---:|:---:|---:|:---:|---:|---:|---:|
| 8  | R5   | 50    | Medium  | 2.0× | 800    | ~$80    |
| 8  | R20  | 200   | Medium  | 2.0× | 3 200  | ~$320   |
| 12 | R20  | 200   | Low     | 4.0× | 9 600  | ~$960   |
| 12 | R50  | 500   | Low     | 4.0× | 24 000 | ~$2 400 |
| 24 | R20  | 200   | VeryLow | 6.0× | 28 800 | ~$2 880 |
| 24 | R200 | 2 000 | VeryLow | 6.0× | 288 000| ~$28 800|
| 24 | R500 | 5 000 | VeryLow | 6.0× | 720 000| ~$72 000|

### Why this formula was chosen

- **Linear in `active_weeks`** — every additional week of proven discipline adds real capacity. No cliff.
- **Multiplied by weekly floor**, not by claimed amount — the borrower's actual deposit history stays hidden. Only the floor is public.
- **Tier multiplier increases with tenure** — 6× at 24 weeks vs 2× at 8 weeks reflects the risk delta of a 6-month vs 2-month track record.
- **Withdrawn weeks are counted but don't inflate the tier** — a borrower who withdrew half their savings gets credit for the withdrawn history (they proved discipline once) but the loan cap is set from what's currently locked.

### What the lender sees vs what stays private

**Lender reads:** wallet address · tier (Medium / Low / Very Low) · `active_weeks` and `withdrawn_weeks` counts · `loan_eligible_stroops` · `verified_at` / `expires_at` · `savings_range` key (R5..R500).

**Lender never sees:** actual amounts per week · total balance saved · withdrawn amounts · individual commitments · the wallet secret · vault deposit timing · any per-tx info below the range threshold.

---

## The Circuits — What Each One Actually Proves

All circuits use Pedersen hashes for commitments/nullifiers, are compiled with Noir 1.0.0-beta.9, proved with Barretenberg 0.87.0, and use keccak Fiat-Shamir transcripts. Each produces a 14 592-byte proof and a 1 760-byte VK.

### zava_8w / zava_12w / zava_24w — credit tier circuits

The three tier circuits are structurally identical, differing only in the `N` constant (8, 12, 24).

```
   ┌──────── zava_Nw ────────┐
   │                         │
   │   PRIVATE WITNESS       │
   │   ─────────────────     │
   │     secret : Field      │
   │     weekly_amounts[N]   │
   │     deposit_ts[N]       │
   │     week_numbers[N]     │
   │                         │
   │   PUBLIC INPUTS         │
   │   ─────────────────     │
   │     min_weekly_amount   │
   │     consistency_weeks   │
   │     commitments[N]      │
   │     nullifiers[N]       │
   │                         │
   │   ASSERTIONS            │
   │   ─────────────────     │
   │   1. consistency_weeks == N                                     │
   │   2. ∀i: pedersen(secret, amounts[i]) == commitments[i]         │
   │   3. ∀i: pedersen(secret, week_numbers[i]) == nullifiers[i]     │
   │   4. ∀i: amounts[i] ≥ min_weekly_amount                         │
   │   5. ∀i>0: week_numbers[i] > week_numbers[i-1]                  │
   │   6. ∀i>0: 0 < deposit_ts[i] - deposit_ts[i-1] ≤ 8 days         │
   │                         │
   └─────────────────────────┘

   Public input count = 2 + 2N:
     8w  → 18 (2 + 16)
     12w → 26 (2 + 24)
     24w → 50 (2 + 48)
```

### zava_shielded — vault withdraw + transfer

```
   ┌──── zava_shielded ────┐
   │                       │
   │   PRIVATE             │
   │     secret            │
   │     amount            │
   │     merkle_path[20]   │
   │     merkle_indices[20]│
   │                       │
   │   PUBLIC (4 inputs)   │
   │     root              │
   │     nullifier         │
   │     recipient_hash    │
   │     amount_out        │
   │                       │
   │   ASSERTIONS          │
   │   1. commitment = pedersen(secret, amount)                     │
   │   2. merkle_root(commitment, path, indices) == root            │
   │   3. nullifier == pedersen(secret, 0)                          │
   │   4. recipient_hash == 0    OR   amount_out == amount          │
   │      (recipient_hash=0 signals "in-pool transfer",             │
   │       any other value binds the proof to a specific recipient) │
   │                       │
   └───────────────────────┘
```

### zava_partial_withdraw — split into "sent" + "change"

```
   ┌──── zava_partial_withdraw ────┐
   │                               │
   │   PRIVATE                     │
   │     secret                    │
   │     input_amount              │
   │     week                      │
   │     merkle_path[20]           │
   │     merkle_indices[20]        │
   │     change_secret             │
   │                               │
   │   PUBLIC (6 inputs)           │
   │     in_commitment             │
   │     in_root                   │
   │     in_nullifier              │
   │     recipient_hash            │
   │     withdraw_amount           │
   │     change_commitment         │
   │                               │
   │   ASSERTIONS                  │
   │   1. in_commitment == pedersen(secret, input_amount)           │
   │   2. in_nullifier == pedersen(secret, week)                    │
   │   3. merkle_root(in_commitment, path, indices) == in_root      │
   │   4. 0 < withdraw_amount ≤ input_amount                        │
   │   5. change_amount = input_amount - withdraw_amount            │
   │   6. change_commitment == pedersen(change_secret, change_amount)│
   │                               │
   └───────────────────────────────┘
```

---

## End-to-End Data Flows

**A. Deposit into the vault.** Browser generates a nonce, computes `commitment = H(nonce, amount)` and `nullifier = H(nonce, week)`, and encrypts `{amount, nonce, week}` under the wallet's scan key. `vault.deposit(...)` transfers the tokens in, stores `sha256(commitment||nullifier)` as an anti-theft binding, Merkle-inserts the commitment, and emits `zava/deposit` with the encrypted note.

**B. Claim credit.** Browser scans vault events for its own deposits, picks 8/12/24 qualifying ones, and hands `{secret, amounts, timestamps, weeks, commitments, nullifiers, min_weekly_amount, consistency_weeks}` to the Web Worker. Worker calls `noir.execute()` → witness, then `bb.generateProof(witness, { keccak: true })` → 14,592-byte proof. `zava_credit.claim_credit(wallet, proof, claim)` then: authorizes wallet → verifies every commitment exists and matches its nullifier via savings/vault reads → calls `honk_verifier.verify(proof, pi)` (real Sumcheck + Shplemini + BN254 pairing) → sizes the loan → writes `CreditRecord`.

**C. Partial withdraw with change.** Browser derives `change_secret = H(secret || "zava_change_v1" || in_commitment || in_nullifier)` deterministically, computes `change_commitment` and encrypts `{change_secret, change_amount, asset}` under scan key. `vault.partial_withdraw(proof, ..., encrypted_change_note)` verifies the 6-pi proof, spends the input nullifier, Merkle-inserts the change commitment, sends `withdraw_amount` to the recipient, and emits `zava/partial` with the encrypted note. If the user wipes localStorage, their wallet can re-scan `partial` events and reconstruct the change UTXO from wallet secret alone.

---

## What Stays Private, What Doesn't — The Full Table

| Fact on chain                                      | Public? | Private? | How? |
|---|:---:|:---:|---|
| A commitment was recorded                          | ✅ | | Merkle leaf visible |
| Which wallet made a deposit                        | ✅ | | `require_auth` in tx |
| Deposit amount (in `vault.deposit`)                | ✅ | | i128 in tx call data |
| The `secret` behind a commitment                   | | ✅ | Never leaves the browser |
| Which commitment maps to which deposit             | | ✅ | Hidden by hashing |
| Amount per commitment used in a credit proof       | | ✅ | Private witness in circuit |
| Whether a specific week's amount ≥ range threshold | ✅ | | Circuit publishes "yes" via VK check |
| Actual amounts per week                            | | ✅ | Private witness |
| Total balance across all deposits                  | | ✅ | Requires enumerating commitments + amounts |
| Tier + loan cap                                    | ✅ | | Written to `CreditRecord` |
| Change UTXO amount                                 | | ✅ | Encrypted in `partial` event |
| Nullifier ↔ commitment link                        | | ✅ | Bound via sha256 hash; requires knowing both |

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

**Verification key (VK).** A circuit-specific cryptographic object that the verifier uses to check proofs. Distinct from the proving key (which the prover needs). For UltraHonk, a VK is ~1,760 bytes.

**Witness.** The set of all values inside a circuit when run on specific inputs — both public and private. The proof is constructed from the witness and the proving key; the verifier never sees it.

---

## Contributing

PRs welcome — see [`Zava/README.md#contributing`](https://github.com/Zavapa/Zava/blob/main/README.md#contributing) for the full workflow. Good starter contributions specific to this repo:

- Add a new tier circuit (`zava_16w`, `zava_36w`) and deploy a new `honk_verifier` instance with its VK.
- Add support for a new Stellar Asset Contract in a new `zava_vault` instance.
- More Noir circuit tests (`nargo test`) — soundness cases where the constraints should fail.
- More contract tests (`cargo test --workspace`) — cross-contract fuzzing, replay attempts, malformed proof rejection.
- Reduce the WASM sizes further via feature flags on the verifier crate.

**Security issues:** email `olowodarey@gmail.com`, do not file a public GitHub issue. See [`SECURITY.md`](./SECURITY.md) for the contract-side threat model.

---

## License

**MIT** — see [`LICENSE`](./LICENSE).

---

## Related repos

- **App (frontend + backend):** [`Zavapa/Zava`](https://github.com/Zavapa/Zava)
- **Hackathon page:** [Stellar Hacks: Real-World ZK on DoraHacks](https://dorahacks.io/hackathon/stellar-hacks-zk)

**Witness.** The set of all values inside a circuit when run on specific inputs — both public and private. The proof is constructed from the witness and the proving key; the verifier never sees it.
