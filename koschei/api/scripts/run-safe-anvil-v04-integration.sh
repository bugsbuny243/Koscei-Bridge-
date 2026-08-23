#!/usr/bin/env bash
set -euo pipefail

for tool in anvil forge cast jq sha256sum git xxd; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
API_DIR="$ROOT/koschei/api"
FIXTURE="$API_DIR/internal/executionproof/testdata/safe_anvil_v04/SafeHarness.sol"
APPROVED_RUNTIME_FILE="$API_DIR/internal/executionproof/testdata/safe_anvil_v04/approved-safe-harness-v04-runtime.sha256"
POLICY_FILE="$ROOT/WEB3_DEFENSE_VALIDATION_ENGINE.md"
RPC="http://127.0.0.1:18545"
OWNER="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
TARGET="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
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

hash_hex_bytes() {
  local value="$1"
  value="${value#0x}"
  printf '%s' "$value" | xxd -r -p | sha256sum | awk '{print $1}'
}

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

COMPILED_RUNTIME_HEX="$(jq -r '.deployedBytecode.object // empty' "$WORK/out/SafeHarness.sol/SafeHarnessV04.json")"
[[ "$COMPILED_RUNTIME_HEX" =~ ^0x[0-9a-fA-F]+$ ]] || { echo "compiled Safe runtime bytecode unavailable" >&2; exit 1; }
COMPILED_RUNTIME_SHA256="$(hash_hex_bytes "$COMPILED_RUNTIME_HEX")"
APPROVED_RUNTIME_SHA256="$(tr -d '[:space:]' < "$APPROVED_RUNTIME_FILE")"
if [[ ! "$APPROVED_RUNTIME_SHA256" =~ ^[0-9a-f]{64}$ || "$APPROVED_RUNTIME_SHA256" != "$COMPILED_RUNTIME_SHA256" ]]; then
  echo "approved Safe runtime digest mismatch" >&2
  echo "approved=$APPROVED_RUNTIME_SHA256" >&2
  echo "compiled=$COMPILED_RUNTIME_SHA256" >&2
  exit 1
fi

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

TARGET_CODE="$(cast code "$TARGET" --rpc-url "$RPC")"
[[ "$TARGET_CODE" == "0x" ]] || { echo "validated target must be code-less" >&2; exit 1; }
OBSERVED_RUNTIME_HEX="$(cast code "$SAFE" --rpc-url "$RPC")"
OBSERVED_RUNTIME_SHA256="$(hash_hex_bytes "$OBSERVED_RUNTIME_HEX")"
[[ "$OBSERVED_RUNTIME_SHA256" == "$APPROVED_RUNTIME_SHA256" ]] || {
  echo "deployed Safe runtime differs from independently approved artifact" >&2
  echo "approved=$APPROVED_RUNTIME_SHA256 observed=$OBSERVED_RUNTIME_SHA256" >&2
  exit 1
}

cast send "$SAFE" --value 10ether --rpc-url "$RPC" --from "$OWNER" --unlocked >/dev/null

BLOCK_NUMBER="$(cast block-number --rpc-url "$RPC")"
BLOCK_HASH="$(cast block "$BLOCK_NUMBER" --rpc-url "$RPC" --json | jq -r '.hash')"
ANVIL_PATH="$(command -v anvil)"
ANVIL_SHA256="$(sha256sum "$ANVIL_PATH" | awk '{print $1}')"
APPROVED_ANVIL_SHA256="${KOSCHEI_APPROVED_ANVIL_SHA256:-}"
[[ "$APPROVED_ANVIL_SHA256" =~ ^[0-9a-f]{64}$ && "$ANVIL_SHA256" == "$APPROVED_ANVIL_SHA256" ]] || {
  echo "Anvil binary is not independently approved" >&2
  echo "approved=$APPROVED_ANVIL_SHA256 observed=$ANVIL_SHA256" >&2
  exit 1
}

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
TOOLCHAIN_SHA256="$( { go version; forge --version; cast --version; anvil --version; } | sha256sum | awk '{print $1}')"
POLICY_SHA256="$(sha256sum "$POLICY_FILE" | awk '{print $1}')"
GENERATOR_SHA256="$(cat "$API_DIR/internal/executionproof/safe_anvil_engine_v04.go" "$API_DIR/internal/executionproof/safe_anvil_inert_target_v05.go" | sha256sum | awk '{print $1}')"

[[ "$BLOCK_NUMBER" =~ ^[0-9]+$ ]] || { echo "invalid source block number: $BLOCK_NUMBER" >&2; exit 1; }
[[ "$BLOCK_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "invalid source block hash: $BLOCK_HASH" >&2; exit 1; }
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ && "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid git provenance" >&2; exit 1; }

cd "$API_DIR"
go build -o "$WORK/defense-validation-alert-observer" ./cmd/defense-validation-alert-observer

export KOSCHEI_SAFE_ANVIL_INTEGRATION=1
export KOSCHEI_ANVIL_PATH="$ANVIL_PATH"
export KOSCHEI_SAFE_FORK_URL="$RPC"
export KOSCHEI_SAFE_ADDRESS="$SAFE"
export KOSCHEI_SAFE_ACCESSOR_ADDRESS="$ACCESSOR"
export KOSCHEI_SAFE_TARGET_ADDRESS="$TARGET"
export KOSCHEI_SAFE_BLOCK_NUMBER="$BLOCK_NUMBER"
export KOSCHEI_SAFE_BLOCK_HASH="$BLOCK_HASH"
export KOSCHEI_ANVIL_SHA256="$APPROVED_ANVIL_SHA256"
export KOSCHEI_SAFE_CHAIN_ID=31337
export KOSCHEI_SOURCE_COMMIT="$SOURCE_COMMIT"
export KOSCHEI_SOURCE_TREE="$SOURCE_TREE"
export KOSCHEI_TOOLCHAIN_SHA256="$TOOLCHAIN_SHA256"
export KOSCHEI_APPROVED_ARTIFACT_SHA256="$APPROVED_RUNTIME_SHA256"
export KOSCHEI_BUILT_ARTIFACT_SHA256="$COMPILED_RUNTIME_SHA256"
export KOSCHEI_OBSERVED_ARTIFACT_SHA256="$OBSERVED_RUNTIME_SHA256"
export KOSCHEI_POLICY_SHA256="$POLICY_SHA256"
export KOSCHEI_GENERATOR_SHA256="$GENERATOR_SHA256"
export KOSCHEI_ALERT_OBSERVER_PATH="$WORK/defense-validation-alert-observer"

go test ./internal/executionproof -run '^TestAnvilSafeSimulationEngineV04Integration$' -count=1 -v
go test ./internal/defensecollector -count=1
go test ./internal/defense -run '^TestRealAnvilSafeIntentMutationValidationV05$' -count=1 -v
