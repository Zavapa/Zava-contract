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

if command -v bb >/dev/null 2>&1; then
    for tier in zava_8w zava_12w zava_24w; do
        step "Writing VK: $tier"
        bb write_vk \
            -b "circuits/$tier/target/$tier.json" \
            -o "circuits/$tier/target/vk" \
            --verifier_target noir-recursive 2>&1 | tail -3
    done
else
    echo "WARNING: 'bb' not in PATH — skipping VK extraction." >&2
    echo "Install with:  curl -sL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash" >&2
fi

# ---------- Soroban contracts ---------------------------------------------

if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
    echo "Adding rust target wasm32-unknown-unknown"
    rustup target add wasm32-unknown-unknown
fi

step "Building Soroban contracts (release WASM)"
(cd contracts && cargo build --workspace --target wasm32-unknown-unknown --release)

# ---------- Summary --------------------------------------------------------

step "Artifacts"
echo "Soroban WASM:"
ls -lh contracts/target/wasm32-unknown-unknown/release/*.wasm | awk '{print "  " $NF " (" $5 ")"}'

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
