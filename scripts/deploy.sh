#!/usr/bin/env bash
# Deploy Zava to a Stellar network (default: testnet).
#
# Deploys 5 contract instances total:
#   - 1 savings
#   - 3 Honk verifiers (one per tier: 8 / 12 / 24 weeks)
#   - 1 credit verifier (wired to the 4 above)
#
# Writes contract IDs to .deploy.<network>.env for later use.
#
# Requirements:
#   - stellar CLI (`stellar --version`)
#   - A configured identity:  stellar keys generate --global default --network testnet --fund
#   - Run ./scripts/build.sh first
#
# Usage:  ./scripts/deploy.sh [testnet|mainnet]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NETWORK="${1:-testnet}"
SOURCE="${SOURCE:-default}"
WASM_DIR="contracts/target/wasm32v1-none/release"

if ! command -v stellar >/dev/null 2>&1; then
    echo "error: 'stellar' CLI not found in PATH" >&2
    echo "Install: https://developers.stellar.org/docs/tools/cli/install-cli" >&2
    exit 1
fi

for w in savings.wasm honk_verifier.wasm verifier.wasm; do
    if [ ! -f "$WASM_DIR/$w" ]; then
        echo "error: $WASM_DIR/$w not found — run ./scripts/build.sh first" >&2
        exit 1
    fi
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

deploy() {
    local wasm="$1"
    stellar contract deploy \
        --wasm "$wasm" \
        --source "$SOURCE" \
        --network "$NETWORK"
}

# ---------- savings --------------------------------------------------------

step "Deploying savings"
SAVINGS_ID=$(deploy "$WASM_DIR/savings.wasm")
echo "  SAVINGS=$SAVINGS_ID"

# ---------- 3 Honk verifiers ----------------------------------------------
#
# Each Honk verifier instance is initialised with the VK from its matching
# Noir circuit (zava_8w / 12w / 24w). VKs are extracted from compiled
# circuits with:
#
#   bb write_vk -b circuits/zava_8w/target/zava_8w.json -o circuits/zava_8w/target/vk
#
# Public input count is 2 + 2*N (min_amount + weeks + N commitments + N
# nullifiers).

deploy_honk() {
    local tier_weeks="$1"
    local vk_file="${2:-}"
    local public_input_count=$((2 + 2 * tier_weeks))

    if [ -z "$vk_file" ] || [ ! -f "$vk_file" ]; then
        # Fatal — the real verifier rejects placeholder VKs at initialize,
        # so silently continuing would waste an on-chain deploy.
        echo "error: VK file not found for ${tier_weeks}w tier at $vk_file" >&2
        echo "hint: run ./scripts/build.sh first (needs bb 0.87.0 + nargo 1.0.0-beta.9)" >&2
        exit 1
    fi

    local honk_id
    honk_id=$(deploy "$WASM_DIR/honk_verifier.wasm")

    local vk_hex
    vk_hex=$(xxd -p -c 99999 "$vk_file")
    # Log to stderr so command substitution captures only the contract ID.
    echo "  → initializing $honk_id with $vk_file ($(stat -c '%s' "$vk_file") B)" >&2
    stellar contract invoke \
        --id "$honk_id" \
        --source "$SOURCE" \
        --network "$NETWORK" \
        -- initialize \
        --vk_bytes "$vk_hex" \
        --num_public_inputs "$public_input_count" >/dev/null

    echo "$honk_id"
}

step "Deploying Honk verifier (8w tier)"
HONK_8W=$(deploy_honk 8 "circuits/zava_8w/target/vk")
echo "  HONK_8W=$HONK_8W"

step "Deploying Honk verifier (12w tier)"
HONK_12W=$(deploy_honk 12 "circuits/zava_12w/target/vk")
echo "  HONK_12W=$HONK_12W"

step "Deploying Honk verifier (24w tier)"
HONK_24W=$(deploy_honk 24 "circuits/zava_24w/target/vk")
echo "  HONK_24W=$HONK_24W"

# ---------- credit verifier ------------------------------------------------

step "Deploying credit verifier"
VERIFIER_ID=$(deploy "$WASM_DIR/verifier.wasm")
echo "  VERIFIER=$VERIFIER_ID"

step "Initialising credit verifier"
stellar contract invoke \
    --id "$VERIFIER_ID" \
    --source "$SOURCE" \
    --network "$NETWORK" \
    -- initialize \
    --savings_contract "$SAVINGS_ID" \
    --honk_8w "$HONK_8W" \
    --honk_12w "$HONK_12W" \
    --honk_24w "$HONK_24W"

# ---------- record IDs -----------------------------------------------------

ENV_FILE=".deploy.$NETWORK.env"
cat > "$ENV_FILE" <<EOF
ZAVA_NETWORK=$NETWORK
ZAVA_SAVINGS=$SAVINGS_ID
ZAVA_HONK_8W=$HONK_8W
ZAVA_HONK_12W=$HONK_12W
ZAVA_HONK_24W=$HONK_24W
ZAVA_VERIFIER=$VERIFIER_ID
EOF

step "Done"
echo "Contract IDs saved to $ENV_FILE"
cat "$ENV_FILE"
