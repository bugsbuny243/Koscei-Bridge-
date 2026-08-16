#!/usr/bin/env bash
set -euo pipefail

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[ OK ] $*"; }
info() { echo "[INFO] $*"; }

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(id -u)" -eq 0 ]] || fail "run as root (sudo -E)"

: "${GITHUB_REPOSITORY:=bugsbuny243/Koschei-Web3-Hub}"
: "${EXPECTED_SHA:=}"

command -v gh >/dev/null 2>&1 || fail "GitHub CLI (gh) is required"
command -v git >/dev/null 2>&1 || fail "git is required"

# The host must already be authenticated with a principal allowed to create
# repository self-hosted runner registration tokens. Never embed PATs/tokens in
# the repository or pass them as command-line arguments.
if ! gh auth status >/dev/null 2>&1; then
  fail "gh is not authenticated; authenticate this dedicated proof host first"
fi

if [[ -n "$EXPECTED_SHA" ]]; then
  actual_sha="$(git rev-parse HEAD 2>/dev/null || true)"
  [[ "$actual_sha" == "$EXPECTED_SHA" ]] || fail "checkout head ${actual_sha:-unknown} does not match EXPECTED_SHA $EXPECTED_SHA"
  ok "exact PR head verified: $EXPECTED_SHA"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREPARE="${SCRIPT_DIR}/nodeshield-bpf-host-prepare.sh"
INSTALL="${SCRIPT_DIR}/nodeshield-runner-install.sh"
[[ -f "$PREPARE" ]] || fail "missing host preparation script"
[[ -f "$INSTALL" ]] || fail "missing runner install script"
chmod +x "$PREPARE" "$INSTALL"

info "validating dedicated proof host before runner registration"
EXPECTED_SHA="$EXPECTED_SHA" "$PREPARE"

info "requesting one-time repository runner registration token"
runner_token="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/runners/registration-token" --jq '.token')"
[[ -n "$runner_token" ]] || fail "GitHub returned an empty runner registration token"

# Export only for the installer subprocess. The short-lived token is never
# written to disk by this bootstrap script and is cleared from this shell after.
GITHUB_RUNNER_TOKEN="$runner_token" GITHUB_REPOSITORY="$GITHUB_REPOSITORY" "$INSTALL"
unset runner_token

ok "Node Shield self-hosted runner bootstrap complete"
info "next: remove and freshly re-add the nodeshield-kernel-proof label to PR #841 so the exact current head is authorized"
