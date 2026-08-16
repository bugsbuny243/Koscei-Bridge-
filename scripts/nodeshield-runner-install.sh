#!/usr/bin/env bash
set -euo pipefail

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[ OK ] $*"; }
info() { echo "[INFO] $*"; }

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(id -u)" -eq 0 ]] || fail "run as root (sudo)"

: "${GITHUB_RUNNER_TOKEN:?set GITHUB_RUNNER_TOKEN to a fresh repository runner registration token}"
: "${GITHUB_REPOSITORY:=bugsbuny243/Koschei-Web3-Hub}"
: "${RUNNER_VERSION:=2.328.0}"
: "${RUNNER_USER:=nodeshield-runner}"
: "${RUNNER_DIR:=/opt/nodeshield-runner}"
: "${RUNNER_NAME:=nodeshield-bpf-$(hostname -s)}"

case "$(uname -m)" in
  x86_64)
    runner_arch=x64
    expected_sha256=01066fad3a2893e63e6ca880ae3a1fad5bf9329d60e77ee15f2b97c148c3cd4e
    ;;
  aarch64|arm64)
    runner_arch=arm64
    expected_sha256=b801b9809c4d9301932bccadf57ca13533073b2aa9fa9b8e625a8db905b5d8eb
    ;;
  *) fail "unsupported runner architecture: $(uname -m)" ;;
esac

[[ "$RUNNER_VERSION" == "2.328.0" ]] || fail "RUNNER_VERSION override is not allowed without updating the pinned SHA-256 values"

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "$RUNNER_USER"
fi

install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0750 "$RUNNER_DIR"
cd "$RUNNER_DIR"

archive="actions-runner-linux-${runner_arch}-${RUNNER_VERSION}.tar.gz"
url="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${archive}"
info "downloading GitHub Actions runner ${RUNNER_VERSION} for ${runner_arch}"
curl --fail --location --proto '=https' --tlsv1.2 --output "$archive" "$url"
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum -c -
ok "runner package SHA-256 verified"

tar xzf "$archive"
rm -f "$archive"
chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"

repo_url="https://github.com/${GITHUB_REPOSITORY}"

# Registration tokens are short lived. Consume the token once, do not persist it.
sudo -u "$RUNNER_USER" ./config.sh \
  --unattended \
  --url "$repo_url" \
  --token "$GITHUB_RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "nodeshield-bpf" \
  --work "$RUNNER_DIR/_work" \
  --replace

unset GITHUB_RUNNER_TOKEN

# Install as a system service using the runner-provided service helper.
./svc.sh install "$RUNNER_USER"
./svc.sh start

ok "registered self-hosted runner ${RUNNER_NAME} for ${GITHUB_REPOSITORY}"
info "required workflow labels are: self-hosted, linux, nodeshield-bpf"
info "before authorizing a proof, run: sudo ./scripts/nodeshield-bpf-host-prepare.sh"
