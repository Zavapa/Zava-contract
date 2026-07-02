#!/usr/bin/env bash
# Build everything Zava needs to deploy:
#   - 3 Noir circuits (zava_8w, zava_12w, zava_24w) → ACIR + VKs
#   - 3 Soroban contracts (savings, groth16, verifier) → WASM
#
# Requirements:
#   - nargo  (https://noir-lang.org/docs/getting_started/installation/)
#   - cargo with the wasm32-unknown-unknown target
#
# Run from the repo root: `./scripts/build.sh`

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

# ---------- Noir circuits --------------------------------------------------

if ! command -v nargo >/dev/null 2>&1; then
    echo "error: 'nargo' not found in PATH" >&2
    echo "Install via:  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup" >&2
    exit 1
fi

for tier in zava_8w zava_12w zava_24w; do
    step "Compiling circuit: $tier"
    (cd "circuits/$tier" && nargo check && nargo compile)
done

# ---------- Verification keys (UltraHonk via barretenberg) -----------------
#
# Flags MUST match the on-chain verifier (ultrahonk_soroban_verifier):
#   --scheme ultra_honk    : the proof scheme we verify
#   --oracle_hash keccak   : Fiat-Shamir transcript hash the verifier expects
#   --output_format bytes_and_fields : produces both target/vk (bytes) and
#                                      target/vk_fields.json for debugging
#
# `bb` versioning is strict: proof/VK byte layouts drift between majors.
# The reference verifier is tuned for bb v0.87.0 (Noir 1.0.0-beta.9). Any
# other version has a good chance of producing a VK the contract rejects
# at deploy time or a proof it rejects at verify time. See UPGRADE.md.

if command -v bb >/dev/null 2>&1; then
    for tier in zava_8w zava_12w zava_24w; do
        step "Writing VK: $tier"
        bb write_vk \
            --scheme ultra_honk \
            --oracle_hash keccak \
            --bytecode_path "circuits/$tier/target/$tier.json" \
            --output_path "circuits/$tier/target" \
            --output_format bytes_and_fields 2>&1 | tail -3
    done
else
    echo "WARNING: 'bb' not in PATH — skipping VK extraction." >&2
    echo "Install with:  curl -sL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash && bbup -v 0.87.0" >&2
fi

# ---------- Soroban contracts ---------------------------------------------

step "Building Soroban contracts (release WASM)"
(cd contracts && stellar contract build)

# ---------- Summary --------------------------------------------------------

step "Artifacts"
echo "Soroban WASM:"
ls -lh contracts/target/wasm32v1-none/release/*.wasm | awk '{print "  " $NF " (" $5 ")"}'

echo "Noir circuit outputs:"
for tier in zava_8w zava_12w zava_24w; do
    base="circuits/$tier/target"
    if [ -f "$base/$tier.json" ]; then
        echo "  $base/$tier.json"
    fi
    if [ -f "$base/vk/vk" ]; then
        size=$(stat -c %s "$base/vk/vk")
        echo "  $base/vk/vk (${size} bytes)"
    fi
done

echo
echo "Next: ./scripts/deploy.sh testnet"
