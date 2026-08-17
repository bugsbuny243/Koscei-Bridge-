#!/usr/bin/env sh
set -eu

fail() {
  echo "Koschei Web3 policy violation: $1" >&2
  exit 1
}

# Next.js framework/runtime artifacts are permanently prohibited.
if find . -type f \( -name 'next-env.d.ts' -o -name 'next.config.js' -o -name 'next.config.mjs' -o -name 'next.config.cjs' -o -name 'next.config.ts' \) -print -quit | grep -q .; then
  fail "Next.js config/type artifact found"
fi

if find . -type d -name '.next' -print -quit | grep -q .; then
  fail ".next build output found"
fi

# Package manifests may exist for SDK/tooling, but the Next.js package may not.
find . -type f -name 'package.json' -not -path './node_modules/*' -print | while IFS= read -r manifest; do
  if grep -Eq '"next"[[:space:]]*:' "$manifest"; then
    echo "Koschei Web3 policy violation: Next.js dependency found in $manifest" >&2
    exit 1
  fi
done

# Runtime/config sources must not reintroduce browser-exposed NEXT_PUBLIC variables.
# Documentation that explains the prohibition is intentionally excluded.
find . -type f \
  \( -name '*.env' -o -name '.env' -o -name '.env.*' -o -name '*.go' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.tsx' -o -name '*.sh' -o -name 'Dockerfile*' \) \
  -not -path './node_modules/*' \
  -not -path './.git/*' \
  -print | while IFS= read -r source; do
    if grep -q 'NEXT_PUBLIC_' "$source"; then
      echo "Koschei Web3 policy violation: NEXT_PUBLIC_ runtime/config marker found in $source" >&2
      exit 1
    fi
  done

echo "Next.js prohibition guard: PASS"
