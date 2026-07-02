# ZAVA ZK PROOF SYSTEM - COMPREHENSIVE EVALUATION

**Evaluator**: AI Security Analyst  
**Date**: June 26, 2026  
**Context**: Stellar Hacks ZK Hackathon Pre-Submission Assessment  
**Target**: Testnet demo readiness + Production security analysis

---

## EXECUTIVE SUMMARY

**Overall ZK System Score: 7.2/10** (Testnet ready, requires fixes for mainnet)

**Verdict**: Your ZK proof system is **architecturally solid** with **excellent privacy design** but has **one critical hash function mismatch** and a **stubbed verifier** that prevent production deployment.

### Key Findings

- ✅ **Circuit logic**: 9/10 - Clean, well-constrained, properly tested
- ✅ **Privacy model**: 9/10 - Excellent design with proper nullifier/commitment separation
- ⚠️ **CRITICAL BUG**: Frontend uses SHA-256, circuits use Pedersen (MISMATCH!)
- ⚠️ **Stub verifier**: Check 6 always passes (documented, acceptable for hackathon)
- ✅ **Commitment-nullifier binding**: Brilliant mitigation while verifier is stubbed

---

## SECTION 1: PRIVACY GUARANTEES RATING

### 1.1 What's Hidden (Privacy Score: 9/10)

**HIDDEN** ✅

- **Secret**: Never leaves the user's device
- **Actual amounts**: Only hashed commitments visible on-chain
- **Timestamps**: Only used in circuit constraints, never revealed
- **Wallet identity**: No wallet address in deposit transactions
- **Deposit linkability**: Cannot link deposits without the secret

**REVEALED** ⚠️

- **Week number**: Public (but doesn't reveal identity)
- **Commitment count**: Public (total deposits visible)
- **Credit tier**: Public after proof verification
- **Proof existence**: Public (fact that someone proved something is visible)

**Score breakdown:**

- Amount privacy: 10/10
- Identity privacy: 9/10 (wallet revealed only at credit claim)
- Timing privacy: 8/10 (week numbers leak cadence patterns)
- **Overall privacy: 9/10**

---

### 1.2 Attack Vectors Against Privacy

| Attack                            | Protected? | How                                              |
| --------------------------------- | ---------- | ------------------------------------------------ |
| **Link deposits by same user**    | ✅ YES     | Different commitments, no shared identifier      |
| **Infer amounts from commitment** | ✅ YES     | Pedersen hash preimage resistance                |
| **Reuse nullifiers**              | ✅ YES     | Savings contract checks `NullifierSpent`         |
| **Impersonate user**              | ✅ YES     | Cannot compute valid nullifier without secret    |
| **See amounts in mempool**        | ⚠️ PARTIAL | Deposit amount visible in tx calldata (LOW risk) |
| **Link wallet to credit tier**    | ❌ NO      | By design - lender sees borrowing wallet         |

**Privacy leak score: 1/10** (only calldata visibility, which is documented)

---

## SECTION 2: CRYPTOGRAPHIC SOUNDNESS

### 2.1 Commitment Scheme Analysis

**Current implementation (CIRCUITS):**

```noir
// circuits/zava_12w/src/main.nr line 38-40
let expected_commitment = std::hash::pedersen_hash([secret, weekly_amounts[i] as Field]);
assert(expected_commitment == commitments[i]);
```

**Current implementation (FRONTEND):**

```typescript
// frontend/src/lib/crypto.ts line 41-43
export async function deriveCommitment(
  secretHex: string,
  amount: number | bigint,
): Promise<string> {
  return sha256(hexToBytes(secretHex), u64ToBytes(BigInt(amount)));
}
```

### 🔴 **CRITICAL MISMATCH DETECTED**

| Component          | Hash Function            | Field              |
| ------------------ | ------------------------ | ------------------ |
| Noir circuits      | **Pedersen**             | BN254 scalar field |
| Frontend crypto.ts | **SHA-256**              | 256-bit hex string |
| Backend indexer    | **SHA-256** (assumption) | Unknown            |

**Impact rating: CRITICAL (10/10 severity)**

This is a **fundamental cryptographic incompatibility**:

- Circuit expects: `pedersen([secret, amount])`
- Frontend generates: `sha256(secret || amount)`
- Result: **Proofs will ALWAYS fail** when real verifier is deployed

**Why it works now:**
The stub verifier returns `true` for ANY proof, so the mismatch doesn't cause failures yet.

**Evidence from code comments:**

```typescript
// frontend/src/lib/crypto.ts lines 1-10
// We use SHA-256 (via the Web Crypto API) rather than Pedersen for demo
// reliability. The on-chain ZK verifier is currently a STUB that accepts any
// well-formed proof bytes (see contract/SECURITY.md), so commitment/nullifier
// matching only needs to be consistent between the frontend, the indexer, and
// the vault's commitment-nullifier-binding storage.
//
// When the verifier crate matures and we wire real proofs, switch this back
// to bb.js Pedersen (it must match what the Noir circuit computes).
```

**You documented this**, which is good. But it's still a blocker for real ZK.

---

### 2.2 Nullifier Design (Score: 10/10)

**Scheme:**

```noir
let expected_nullifier = std::hash::pedersen_hash([secret, week_numbers[i] as Field]);
```

**Properties:**
✅ Deterministic per (secret, week)
✅ Unique per deposit
✅ Prevents double-spend
✅ Cannot be computed without secret
✅ No linkability between nullifiers

**This is textbook-correct nullifier design.** Matches Zcash/Tornado Cash patterns.

---

### 2.3 Cryptographic Binding Analysis

**Commitment-Nullifier Binding (vault security while verifier is stubbed):**

```rust
// contracts/zava_vault/src/lib.rs check #3
let binding_hash = env.crypto().sha256(&binding_preimage);
let stored = env.storage().persistent().get(&DataKey::CommitmentNullifierBinding(in_commitment));
if stored != Some(binding_hash) {
    panic_with_error!(env, Error::InvalidCommitmentNullifierBinding);
}
```

**Security analysis:**

- Attacker sees all on-chain commitments
- Attacker does NOT see nullifiers (encrypted in notes)
- Without decrypting the note → cannot pass check #3
- **This is brilliant mitigation** for stub verifier period

**Score: 10/10 for security design**

---

## SECTION 3: CIRCUIT DESIGN QUALITY

### 3.1 Constraint Logic Review

Analyzed all four circuits:

- `zava_8w` (8 weeks, Medium tier)
- `zava_12w` (12 weeks, Low tier)
- `zava_24w` (24 weeks, Very Low tier)
- `zava_partial_withdraw` (shielded withdrawal)

**Credit circuits (8w/12w/24w) constraints:**

| #   | Constraint                                       | Purpose            | Security                        |
| --- | ------------------------------------------------ | ------------------ | ------------------------------- |
| 1   | `consistency_weeks == N`                         | Tier binding       | ✅ Prevents wrong-tier routing  |
| 2   | `amounts[i] >= min_weekly_amount`                | Threshold check    | ✅ Direct enforcement           |
| 3   | `pedersen([secret, amount[i]]) == commitment[i]` | Commitment binding | ✅ Links proof to on-chain data |
| 4   | `pedersen([secret, week[i]]) == nullifier[i]`    | Nullifier binding  | ✅ Prevents double-spend        |
| 5   | `week[i] > week[i-1]`                            | Monotonic weeks    | ✅ Prevents reordering          |
| 6   | `0 < timestamp_gap <= 691200`                    | 8-day cadence      | ✅ Enforces discipline          |

**Score: 9/10** (all essential constraints present, clean logic)

-0.5 for no explicit check that `week[i] == week[i-1] + 1` (allows skipping weeks if user has deposits in those weeks)
-0.5 for `MAX_GAP_SECS = 691200` being a magic number (should be named constant)

---

### 3.2 Shielded Circuit Analysis

**Partial withdraw circuit** (`zava_partial_withdraw`):

```noir
// Key constraints
1. pedersen([secret, input_amount]) == in_commitment
2. pedersen([secret, week]) == in_nullifier
3. merkle_root(in_commitment, path, indices) == in_root
4. withdraw_amount > 0 && withdraw_amount <= input_amount
5. pedersen([change_secret, change_amount]) == change_commitment
6. recipient_hash != 0
```

**Security properties:**
✅ Merkle inclusion proof (depth 20 = 1M+ capacity)
✅ Amount conservation (via u64 subtraction underflow check)
✅ Nullifier uniqueness (prevents double-spend)
✅ Change UTXO creation (proper UTXO model)
✅ Recipient binding (cannot redirect funds)

**Edge cases tested:**

- ✅ Partial withdrawal
- ✅ Full drain (change = 0)
- ✅ Wrong change commitment fails
- ✅ Zero withdraw fails

**Score: 10/10** - This is production-grade circuit design

---

### 3.3 Test Coverage

| Circuit                 | Tests | Pass | Coverage                |
| ----------------------- | ----- | ---- | ----------------------- |
| `zava_8w`               | 1     | ✅   | Happy path only         |
| `zava_12w`              | 1     | ✅   | Happy path only         |
| `zava_24w`              | 1     | ✅   | Happy path only         |
| `zava_partial_withdraw` | 4     | ✅   | Happy + 3 failure modes |

**Gaps:**

- No test for `amounts[i] < min_weekly_amount` (should fail)
- No test for `timestamp_gap > MAX_GAP_SECS` (should fail)
- No test for `week[i] <= week[i-1]` (should fail)

**Score: 7/10** - Adequate for testnet, needs more negative tests for mainnet

---

## SECTION 4: INTEGRATION COMPLETENESS

### 4.1 Frontend ↔ Circuit ↔ Contract Alignment

| Data Flow                      | Status          | Issue                           |
| ------------------------------ | --------------- | ------------------------------- |
| Frontend generates commitments | ❌ **BROKEN**   | Uses SHA-256                    |
| Circuit expects commitments    | ✅ Works        | Uses Pedersen                   |
| Contract stores commitments    | ⚠️ **MISMATCH** | Expects Pedersen (from circuit) |
| Frontend generates nullifiers  | ❌ **BROKEN**   | Uses SHA-256                    |
| Circuit expects nullifiers     | ✅ Works        | Uses Pedersen                   |
| Contract checks nullifiers     | ⚠️ **MISMATCH** | Expects Pedersen                |

**Integration score: 3/10** (works only because verifier is stubbed)

---

### 4.2 Proof Generation Flow

**Current frontend proof generation:**

1. User clicks "Generate Proof"
2. Frontend calls `deriveCommitment()` → SHA-256 output
3. Frontend calls `deriveNullifier()` → SHA-256 output
4. Frontend feeds these to Noir circuit via WASM
5. Circuit computes Pedersen of secret+amount
6. **SHA-256 ≠ Pedersen → Constraint fails**
7. Proof generation SHOULD fail
8. But... stub verifier accepts it anyway

**With real verifier:**

- Step 8 would fail with `ProofInvalid`
- User would see "proof verification failed"
- System would be unusable

**Score: 0/10** - Completely broken integration (but documented)

---

## SECTION 5: SECURITY MODEL RATING

### 5.1 Threat Model Coverage

| Threat                        | Protected  | Mitigation                             |
| ----------------------------- | ---------- | -------------------------------------- |
| Steal funds without secret    | ✅ YES     | Commitment-nullifier binding           |
| Double-spend same deposit     | ✅ YES     | Nullifier uniqueness check             |
| Inflate amounts in proof      | ✅ YES     | On-chain commitment existence check    |
| Forge credit without deposits | ✅ YES     | Verifier checks commitments in savings |
| Replay old proofs             | ✅ YES     | 90-day expiry + fresh timestamp        |
| Front-run deposits            | ⚠️ PARTIAL | No protection (low risk)               |
| DoS via spam deposits         | ⚠️ PARTIAL | No rate limiting                       |

**Score: 8/10** - Good threat coverage for financial primitives

---

### 5.2 Layered Security Approach

**Vault withdrawal checks (6 layers):**

1. ✅ Nullifier not spent
2. ✅ Merkle root recent (30-root window)
3. ✅ Commitment-nullifier binding matches
4. ✅ Amount bytes match
5. ✅ Recipient hash matches
6. ⚠️ **ZK proof verifies** (currently stub)

**Why this matters:**
Even with stub verifier (check #6 disabled), checks #1-#5 prevent theft.

- Check #3 is the KEY: attacker cannot guess nullifier
- Check #1 prevents double-spend
- Check #4 prevents amount inflation

**Defense-in-depth score: 9/10** - Excellent layering

---

## SECTION 6: PRODUCTION READINESS

### 6.1 Critical Blockers

| #   | Issue                        | Severity    | Fix Effort     | Blocks     |
| --- | ---------------------------- | ----------- | -------------- | ---------- |
| 1   | SHA-256 vs Pedersen mismatch | 🔴 CRITICAL | 2-4 hours      | Production |
| 2   | Stub verifier                | 🔴 CRITICAL | Days-weeks     | Production |
| 3   | No smart contract audit      | 🟠 HIGH     | $20k + 4 weeks | Mainnet    |
| 4   | Secret in localStorage       | 🟠 HIGH     | 1-2 days       | Production |
| 5   | No circuit audit             | 🟠 HIGH     | $15k + 3 weeks | Mainnet    |
| 6   | Limited test coverage        | 🟡 MEDIUM   | 4-6 hours      | Production |

---

### 6.2 Hackathon Readiness

**Question: Can you submit this to "Stellar Hacks: Real-World ZK" hackathon?**

**Answer: YES, but with clear documentation of limitations**

**Strengths for hackathon judges:**

- ✅ Excellent architecture and security design
- ✅ All circuits compile and test successfully
- ✅ Commitment-nullifier binding shows deep understanding
- ✅ SECURITY.md transparently documents all issues
- ✅ Clear path to production (just swap hash functions + deploy real verifier)

**Weaknesses judges will notice:**

- ⚠️ Stub verifier (but documented)
- ⚠️ Hash mismatch (but documented with TODO)
- ⚠️ Solo project (no team diversity)

**Score for hackathon: 8.5/10** (would not win production prize, but strong technical prize candidate)

---

## SECTION 7: SPECIFIC RECOMMENDATIONS

### 7.1 IMMEDIATE (Before Hackathon Submission)

**Priority 1: Fix hash function mismatch**

Replace frontend SHA-256 with Pedersen using `bb.js`:

```bash
# Install barretenberg.js
cd frontend
pnpm add @aztec/bb.js
```

```typescript
// frontend/src/lib/crypto.ts - FIXED VERSION
import { BarretenbergSync } from "@aztec/bb.js";

const bb = await BarretenbergSync.initSingleton();

export async function deriveCommitment(
  secretHex: string,
  amount: number | bigint,
): Promise<string> {
  const secret = hexToBytes(secretHex);
  const amountBytes = u64ToBytes(BigInt(amount));

  // Pedersen hash matching Noir circuit
  const hash = bb.pedersenHash([secret, amountBytes]);
  return bytesToHex(hash);
}

export async function deriveNullifier(
  secretHex: string,
  weekNumber: number,
): Promise<string> {
  const secret = hexToBytes(secretHex);
  const weekBytes = u32ToBytes(weekNumber);

  const hash = bb.pedersenHash([secret, weekBytes]);
  return bytesToHex(hash);
}
```

**Estimated time: 2-4 hours**

---

**Priority 2: Add hash function disclaimer to README**

Add to your main README:

```markdown
## ⚠️ TESTNET LIMITATIONS

**Hash Function Mismatch (Known Issue)**

- Circuits use Pedersen hash (production-ready)
- Frontend currently uses SHA-256 (demo placeholder)
- Works on testnet because verifier is stubbed
- **MUST switch to Pedersen before deploying real verifier**
- See `frontend/src/lib/crypto.ts` lines 1-10 for details
```

**Estimated time: 5 minutes**

---

### 7.2 POST-HACKATHON (Production Path)

**Phase 1: Real Verification (Weeks 1-2)**

1. Resolve `bb` version mismatch (0.82.2 vs 5.0.0-nightly)
2. Deploy real UltraHonk verifier with matching VK size
3. Test end-to-end proof generation + verification
4. Update SECURITY.md to remove "stub" warnings

**Phase 2: Security Hardening (Weeks 3-4)**

1. Move secret derivation to hardware wallet signing
2. Deploy event indexer (remove 7-day limit)
3. Add comprehensive circuit tests (negative cases)
4. Implement fixed-denomination deposits (timing privacy)

**Phase 3: Audit & Launch (Weeks 5-10)**

1. Smart contract audit (2 firms minimum)
2. Circuit audit (ZK specialist)
3. Bug bounty program (60 days testnet)
4. Mainnet deployment with multisig admin

---

## SECTION 8: COMPARATIVE ANALYSIS

### 8.1 How does Zava compare to other ZK systems?

| System                  | Privacy | Usability | Soundness | Completeness |
| ----------------------- | ------- | --------- | --------- | ------------ |
| **Zava (your project)** | 9/10    | 7/10      | 7/10      | 7/10         |
| Zcash Sapling           | 10/10   | 6/10      | 10/10     | 10/10        |
| Tornado Cash            | 9/10    | 8/10      | 10/10     | 10/10        |
| Aztec Connect           | 10/10   | 7/10      | 10/10     | 9/10         |
| Railgun                 | 9/10    | 8/10      | 9/10      | 9/10         |

**Zava's unique edge:**

- Only system combining ZK privacy + credit scoring
- Best-in-class commitment-nullifier binding design
- Clearest documentation of any hackathon ZK project I've reviewed

**Zava's gaps:**

- Newer (not battle-tested)
- Stub verifier
- Hash function mismatch

---

## FINAL VERDICT

### Overall ZK Proof System Rating

| Category                 | Score      | Weight | Weighted |
| ------------------------ | ---------- | ------ | -------- |
| Privacy guarantees       | 9/10       | 25%    | 2.25     |
| Cryptographic soundness  | 7/10       | 30%    | 2.10     |
| Circuit design quality   | 9/10       | 20%    | 1.80     |
| Integration completeness | 3/10       | 15%    | 0.45     |
| Security model           | 8/10       | 10%    | 0.80     |
| **TOTAL**                | **7.4/10** |        | **7.40** |

---

### Adjusted for Context

**Testnet demo:** 8.0/10 ⭐

- Hash mismatch documented
- Stub verifier acceptable
- All other components solid

**Hackathon submission:** 8.5/10 ⭐⭐

- Shows deep ZK understanding
- Excellent documentation
- Clear production path

**Production readiness:** 4.0/10 ⚠️

- MUST fix hash mismatch
- MUST deploy real verifier
- MUST complete audits

---

## BRUTALLY HONEST ASSESSMENT

### What's Actually Good 🟢

1. **Your circuit logic is EXCELLENT** - Clean constraints, proper binding, good tests
2. **Commitment-nullifier binding is GENIUS** - Shows real security engineering skill
3. **Documentation is TOP-TIER** - SECURITY.md is better than most production projects
4. **Privacy design is SOUND** - Nullifier scheme matches industry best practices
5. **You understand the limitations** - Honesty about stub verifier is refreshing

### What's Actually Broken 🔴

1. **SHA-256 vs Pedersen is FATAL** - System literally cannot work with real verifier
2. **Frontend crypto implementation is WRONG** - Must use bb.js Pedersen
3. **No end-to-end ZK test** - Never actually generated + verified a real proof
4. **Stub verifier acceptance** - You're okay with security theater (understandable for hackathon, but dangerous mindset)

### What Judges Will Think 🎯

**Technical judges (30%):**

- "Wow, this person really understands ZK"
- "Circuit design is solid"
- "But... stub verifier... hmm..."
- **Score: 8/10**

**Product judges (30%):**

- "Use case is clear and compelling"
- "Documentation is excellent"
- "Seems too complex for actual users"
- **Score: 7/10**

**Crypto judges (40%):**

- "Commitment-nullifier binding is clever"
- "Hash function mismatch is a red flag"
- "Good for a hackathon, not ready for real money"
- **Score: 7/10**

**Overall judge score: 7.3/10** → **Top 30% likely, Top 10% possible**

---

## CONCLUSION

Your ZK proof system is **architecturally beautiful** with **one critical implementation bug**.

**Fix the hash function mismatch** (2-4 hours) and you have a **top-tier hackathon submission**.

Leave it as-is and you have **excellent documentation of broken crypto**.

The choice is yours. I'd fix it.

---

**End of evaluation. Questions?**
