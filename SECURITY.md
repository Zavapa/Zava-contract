# Zava Contract Security

> **Status: Testnet demo. Not audited. Do not use with real assets.**

This document covers the threat model, protections in place, known vulnerabilities,
and the production readiness checklist for the Zava smart contract suite.

---

## Contracts in scope

| Contract | Address (testnet) | Purpose |
|---|---|---|
| `savings` | `CAEWAADG5Y2VM42VERCYMZUCCJIENBQFQDNICMX6WEDBMIPOQVE5D6DA` | Records savings commitments for credit scoring |
| `honk_verifier` (8w) | `CAUHYBIQ4AWHVVSCSKFX262JP2AKHWHVB2ADWAH2NNF52IILNBVEWYU6` | UltraHonk proof verifier for 8-week credit tier |
| `honk_verifier` (12w) | `CBCUHXCTSGNRVPMNDSUCDDGPRDMIGIQWOT2O6ELYSYAHWUTM6LJ34WR6` | UltraHonk proof verifier for 12-week credit tier |
| `honk_verifier` (24w) | `CA6ORCVSHMO4TDIAYFXT2YWGUXFJ4Z7LVX2CXQOMV2S2BEV3UMMMWGQH` | UltraHonk proof verifier for 24-week credit tier |
| `verifier` (credit) | `CATO3SP3FPFR36KR4H67NOO7ETSZ5JP3OHQXZFIYKG6JSKBIYGE2TI2B` | Business logic: issues credit tiers after valid ZK proof |
| `zava_vault` | `CCEP74ATJ4GFNMZ53Q27LIBL7QYS4YHW6B75I53STBVFBNF4J7KMALNT` | Shielded payment pool — holds real XLM/USDC |
| `honk_verifier` (shielded) | `CBE7SVEGDWUFRYVEBPYF3GHEBPZKJPEZWDXIF342CKWQTQ5UYDJN4WX3` | UltraHonk proof verifier for vault withdrawals |

---

## How the security model works

### ZavaVault — shielded payment pool

The vault protects funds through **layered checks**. Every withdrawal must pass all of
them in order:

```
1. Is the nullifier already spent?
   → Prevents the same deposit being withdrawn twice (replay attack)

2. Is the Merkle root recent? (within last 30 deposits)
   → Prevents proofs generated against stale state

3. Does sha256(commitment || nullifier) match what was stored at deposit?
   → The KEY anti-theft check — see "Commitment-nullifier binding" below

4. Do the amount bytes match the claimed withdrawal amount?
   → Prevents claiming more than was deposited

5. Does the recipient hash match the recipient address?
   → Prevents a relay or middleman redirecting funds to themselves

6. Does the ZK proof verify?
   → Currently stubbed — see "Known vulnerabilities" below
```

### Commitment-nullifier binding (check 3)

This is the primary protection against theft while the ZK verifier is stubbed.

At deposit time, the contract stores:
```
sha256(commitment || nullifier)  →  committed to on-chain storage
```

The `commitment` is public (visible in the Merkle tree).
The `nullifier` is **only inside the encrypted note**, which is encrypted with the
recipient's `scanKey` and unreadable without it.

To pass check 3, an attacker must know the correct `nullifier` for a given commitment.
Without decrypting the encrypted note — which requires the recipient's `scanKey` or
`secret` — they cannot determine which nullifier was paired with which commitment.

**What this means in practice:** An attacker who scans the blockchain, sees all
commitment hashes, and tries random nullifiers will be rejected at check 3 every time.

### Savings contract

The savings contract stores only commitment hashes and nullifiers — no wallet
addresses, no raw amounts. It does **not hold any tokens**. Security here is
about data integrity, not fund custody.

---

## Known vulnerabilities

### CRITICAL — Stub ZK verifier (check 6 always passes)

**All three `honk_verifier` contracts and the `honk_verifier` (shielded) are stubs.**
They return `true` for any proof, regardless of validity.

```rust
// Current stub in honk_verifier/src/lib.rs
fn verify_proof_inner(_env, vk_bytes, proof, public_inputs) -> bool {
    !vk_bytes.is_empty() && !proof.is_empty() && !public_inputs.is_empty()
}
```

**Impact:** Without the commitment-nullifier binding (check 3), anyone could call
`vault.withdraw()` with random bytes and drain the vault.

**Mitigation in place:** The commitment-nullifier binding (check 3) blocks this attack
because the attacker must know the nullifier — which is only in the encrypted note.

**Proper fix:** Deploy a real UltraHonk verifier built with matching `nargo` and `bb`
versions. The compiled verifier WASM exists at
`/tmp/ultrahonk-rust-verifier/target/wasm32v1-none/release/rs_soroban_ultrahonk.wasm`
but deployment failed due to a VK format mismatch between `bb 0.82.2` (which the
verifier was written for) and our current `bb 5.0.0-nightly` (which generates 1825-byte
VKs vs the expected 1760 bytes). Requires either updating the Rust verifier crate to
support the new VK format or rebuilding our circuits with bb 0.82.2.

---

### HIGH — Secret stored in browser localStorage

The user's `secret` (32-byte random value) is persisted in browser localStorage.
If an attacker obtains the secret (device compromise, XSS, malware), they can:
- Compute any commitment/nullifier for any deposit
- Pass check 3
- Drain all funds belonging to that user

**Mitigation in place:** None — this is a browser security boundary.

**Proper fix:** Derive the secret from a hardware wallet signing operation so it
never exists in plain text in the browser. Alternatively use Freighter's internal
key management if Freighter exposes a deterministic signing API.

---

### HIGH — No smart contract audit

None of the Zava contracts have been reviewed by an external security expert.
Potential undetected issues:

- Integer overflow in Merkle root computation
- Off-by-one errors in the Merkle tree insertion logic  
- Edge cases in nullifier storage TTL expiry
- Reentrancy-like patterns in cross-contract calls to `TokenClient`
- Storage key collisions between `DataKey` enum variants

**Mitigation in place:** None — audit is required before mainnet.

---

### MEDIUM — Stellar event retention (7 days)

The Stellar RPC only retains contract events for approximately 7 days. The encrypted
note that tells a recipient about their incoming deposit is stored as a Stellar event.
If the recipient does not scan events within 7 days of deployment, notes may be
unrecoverable from the standard RPC.

**Mitigation in place:** Local `savingsStore` tracks deposits made from the same
browser session. Cross-device recovery requires event scanning within the retention
window.

**Proper fix:** Run a dedicated event indexer (e.g. a simple Cloudflare Worker that
subscribes to vault events and stores them in a database) so notes are available
indefinitely.

---

### MEDIUM — Merkle root history window (30 roots)

The vault keeps only the last 30 Merkle roots. A ZK proof generated against an older
root will be rejected if more than 30 new deposits have occurred since.

**Mitigation in place:** In low-activity testnet conditions this is unlikely to be
an issue. The root history size can be increased in a new deployment.

---

### LOW — Payment link reveals scanKey (viewing key)

Payment links contain both `zavaId` and `scanKey`. Anyone who saves or forwards the
link can decrypt all incoming vault notes (see amounts received). They cannot withdraw.

```
/pay?zavaId=<sha256("zava_id_v1"||secret)>
    &scanKey=<sha256("zava_scan_v1"||secret)>
    &nonce=<random>
    ...
```

**By design:** `scanKey` is a viewing key. Knowing it lets you see incoming payments
but **not** withdraw funds (the `secret` is needed for withdrawal and is never in any URL).

**Proper fix:** For maximum privacy, generate a one-time `scanKey` per payment rather
than a per-wallet key. Future versions should use Diffie-Hellman key exchange so the
payer derives an encryption key from the recipient's public key without the key
appearing in the URL at all.

---

### LOW — Amount visible in deposit call data

`vault.deposit()` takes `amount: i128` as a parameter. The exact amount is visible
in the Soroban transaction's call data, even though it is not stored in contract
persistent storage.

**Impact:** An observer who monitors the blockchain at the time of deposit can see
the deposited amount. Privacy is not broken retroactively but deposit timing is traceable.

**Proper fix:** Use fixed-denomination notes (like Tornado Cash) so all deposits look
identical on-chain. Alternatively, route deposits through a proxy contract that batches
calls.

---

## Emergency controls

### Pause / unpause

The vault has an admin-only emergency pause:

```bash
# Freeze all deposits, withdrawals and transfers
stellar contract invoke \
  --id CCEP74ATJ4GFNMZ53Q27LIBL7QYS4YHW6B75I53STBVFBNF4J7KMALNT \
  --source <ADMIN_ACCOUNT> \
  --network testnet \
  -- pause --admin <ADMIN_ADDRESS>

# Resume normal operation
stellar contract invoke \
  --id CCEP74ATJ4GFNMZ53Q27LIBL7QYS4YHW6B75I53STBVFBNF4J7KMALNT \
  --source <ADMIN_ACCOUNT> \
  --network testnet \
  -- unpause --admin <ADMIN_ADDRESS>

# Check current state
stellar contract invoke \
  --id CCEP74ATJ4GFNMZ53Q27LIBL7QYS4YHW6B75I53STBVFBNF4J7KMALNT \
  --network testnet \
  -- is_paused
```

The admin address is `GDK47RSAVFJISUOQTJEUBFXKB7W7TTKNTHWWWQSNRM7KZE6DBUVWPWVT`.

If a vulnerability is discovered, pause the vault immediately then coordinate
user withdrawals after the fix is deployed to a new contract.

---

## ZK circuit security

### Circuits in scope

| Circuit | File | Tier |
|---|---|---|
| `zava_8w` | `circuits/zava_8w/src/main.nr` | Medium (8-week credit) |
| `zava_12w` | `circuits/zava_12w/src/main.nr` | Low (12-week credit) |
| `zava_24w` | `circuits/zava_24w/src/main.nr` | Very Low (24-week credit) |
| `zava_shielded` | `circuits/zava_shielded/src/main.nr` | Vault withdrawal/transfer |

### What each circuit proves

**Credit circuits (8w/12w/24w):**
- The prover knows `secret` such that `pedersen_hash([secret, amount[i]]) == commitment[i]`
  for each of the N claimed deposits
- Each `amount[i] >= min_weekly_amount`
- `pedersen_hash([secret, week[i]]) == nullifier[i]` for each deposit
- Week numbers are strictly increasing
- Time gaps between deposits are ≤ 8 days

**Shielded circuit:**
- The prover knows `secret` such that `pedersen_hash([secret, amount]) == commitment`
  and that commitment is a leaf in the Merkle tree at the claimed root
- `pedersen_hash([secret, 0]) == nullifier` (unique per commitment, prevents double-spend)
- `recipient_hash == sha256(recipient_address)` (binds withdrawal to a specific address)
- `amount_out == amount` (for withdrawal) OR both zero (for in-pool transfer)

### Circuit test results

```
zava_8w:      all unit tests pass
zava_12w:     all unit tests pass  
zava_24w:     all unit tests pass
zava_shielded: 4/4 tests pass
  ✓ test_valid_withdrawal
  ✓ test_valid_transfer
  ✓ test_wrong_amount_fails
  ✓ test_wrong_nullifier_fails
```

### Toolchain versions

```
nargo:  1.0.0-beta.22
bb:     5.0.0-nightly.20260522
```

> The `honk_verifier` contracts were written for `bb 0.82.2` which generates
> 1760-byte VKs. Current `bb` generates 1825-byte VKs. On-chain verification is
> therefore stubbed until the verifier crate is updated to match.

---

## Production readiness checklist

### Before accepting real funds

- [ ] Deploy real UltraHonk verifier (matching bb version)
- [ ] Replace stub `verify_proof_inner` with actual cryptographic verification
- [ ] External security audit of all Soroban contracts (minimum 2 independent firms)
- [ ] External audit of all Noir circuits
- [ ] Fuzz testing of deposit/withdrawal paths
- [ ] Move admin key to multisig (2-of-3 minimum)

### Before mainnet launch

- [ ] Trusted setup ceremony or verification that UltraHonk does not require one
- [ ] Fixed-denomination vault notes (removes amount visibility from call data)
- [ ] Dedicated event indexer (removes 7-day event expiry limitation)
- [ ] Derive secret from hardware wallet (removes localStorage risk)
- [ ] Bug bounty program open for at least 60 days on testnet
- [ ] On-chain rate limiting (max withdrawal per ledger)
- [ ] Timelocked upgrade path for contract migrations

---

## Reporting vulnerabilities

If you discover a vulnerability, do not open a public GitHub issue.

Contact: Cleop8076@gmail.com

Please include:
- A description of the vulnerability
- Steps to reproduce
- An estimate of impact (funds at risk, users affected)
- Your preferred contact method for follow-up

We aim to acknowledge all reports within 48 hours.

---

## References

- Nethermind Stellar Private Payments (inspiration): https://github.com/NethermindEth/stellar-private-payments
- UltraHonk Soroban verifier: https://github.com/yugocabrio/ultrahonk-rust-verifier
- Stellar ZK docs: https://developers.stellar.org/docs/build/apps/zk
- Privacy Pools whitepaper: https://privacypools.com/whitepaper.pdf
- Noir language: https://noir-lang.org/docs/
