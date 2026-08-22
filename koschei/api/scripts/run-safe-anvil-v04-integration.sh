#!/usr/bin/env bash
set -euo pipefail

for tool in anvil forge cast jq sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
API_DIR="$ROOT/koschei/api"
FIXTURE="$API_DIR/internal/executionproof/testdata/safe_anvil_v04/SafeHarness.sol"
RPC="http://127.0.0.1:18545"
OWNER="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
WORK="$(mktemp -d)"
ANVIL_LOG="$WORK/source-anvil.log"
SOURCE_PID=""

cleanup() {
  if [[ -n "$SOURCE_PID" ]]; then
    kill "$SOURCE_PID" >/dev/null 2>&1 || true
    wait "$SOURCE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/src"
cp "$FIXTURE" "$WORK/src/SafeHarness.sol"
cat > "$WORK/foundry.toml" <<'TOML'
[profile.default]
src = "src"
out = "out"
libs = []
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 200
TOML

anvil \
  --host 127.0.0.1 \
  --port 18545 \
  --chain-id 31337 \
  --block-base-fee-per-gas 0 \
  --gas-price 0 \
  --disable-min-priority-fee \
  --steps-tracing \
  --silent \
  >"$ANVIL_LOG" 2>&1 &
SOURCE_PID=$!

for _ in $(seq 1 100); do
  if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  cat "$ANVIL_LOG" >&2 || true
  echo "source Anvil did not become ready" >&2
  exit 1
fi

forge build --root "$WORK" >/dev/null

deploy_contract() {
  local contract="$1"
  shift
  local result address
  result="$(forge create "$contract" --root "$WORK" --rpc-url "$RPC" --from "$OWNER" --unlocked --broadcast --json "$@")"
  address="$(printf '%s' "$result" | jq -r '.deployedTo // .deployed_to // empty')"
  if [[ -z "$address" || "$address" == "null" ]]; then
    echo "$result" >&2
    echo "failed to resolve deployed address for $contract" >&2
    exit 1
  fi
  printf '%s' "$address"
}

ACCESSOR="$(deploy_contract src/SafeHarness.sol:SimulateTxAccessorV04)"
SAFE="$(deploy_contract src/SafeHarness.sol:SafeHarnessV04 --constructor-args "$OWNER")"
TARGET="$(deploy_contract src/SafeHarness.sol:NativeSinkV04)"

cast send "$SAFE" --value 10ether --rpc-url "$RPC" --from "$OWNER" --unlocked >/dev/null

BLOCK_NUMBER="$(cast block-number --rpc-url "$RPC")"
BLOCK_HASH="$(cast block "$BLOCK_NUMBER" --rpc-url "$RPC" --json | jq -r '.hash')"
ANVIL_PATH="$(command -v anvil)"
ANVIL_SHA256="$(sha256sum "$ANVIL_PATH" | awk '{print $1}')"

[[ "$BLOCK_NUMBER" =~ ^[0-9]+$ ]] || { echo "invalid source block number: $BLOCK_NUMBER" >&2; exit 1; }
[[ "$BLOCK_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "invalid source block hash: $BLOCK_HASH" >&2; exit 1; }
[[ "$ANVIL_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid Anvil digest" >&2; exit 1; }

export KOSCHEI_SAFE_ANVIL_INTEGRATION=1
export KOSCHEI_ANVIL_PATH="$ANVIL_PATH"
export KOSCHEI_SAFE_FORK_URL="$RPC"
export KOSCHEI_SAFE_ADDRESS="$SAFE"
export KOSCHEI_SAFE_ACCESSOR_ADDRESS="$ACCESSOR"
export KOSCHEI_SAFE_TARGET_ADDRESS="$TARGET"
export KOSCHEI_SAFE_BLOCK_NUMBER="$BLOCK_NUMBER"
export KOSCHEI_SAFE_BLOCK_HASH="$BLOCK_HASH"
export KOSCHEI_ANVIL_SHA256="$ANVIL_SHA256"
export KOSCHEI_SAFE_CHAIN_ID=31337

cd "$API_DIR"
go test ./internal/executionproof -run '^TestAnvilSafeSimulationEngineV04Integration$' -count=1 -v
go test ./internal/defensecollector -count=1
