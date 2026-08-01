# Transaction Guard Enforcement Permit Verifier v1

Koschei enforcement permits are short-lived Ed25519 attestations issued only for complete `allow` or `warn` Transaction Guard decisions.

The permit verifier is designed for wallet adapters, browser extensions and wallet-native enforcement layers. It does not trust the public key returned in the same HTTP response. A trusted Koschei public key must be pinned out of band by key ID.

## Security contract

The verifier checks all of the following before a signing path may continue:

- permit status is `issued`, available and complete
- permit version is `koschei-enforcement-permit-v1`
- algorithm is Ed25519
- action is exactly `allow` or `warn`
- `guard_complete` is true
- WARN approval requirement matches the action
- canonical payload reconstructed from structured fields matches `canonical_payload`
- SHA-256 of the canonical payload matches `canonical_sha256`
- permit lifetime is positive and no longer than 120 seconds
- permit is currently valid within bounded clock skew
- transaction fingerprint, wallet, origin and network match the protected signing context
- request ID, Guard version, analysis version, risk level and risk index match the Guard response
- signed UI intent ID and UI summary hash match when present
- decision commitment hash is independently reconstructed from the Guard response
- response-advertised public key, when present, matches the pinned trusted key
- Ed25519 signature verifies against the pinned key

A missing, malformed, expired or mismatched permit is a fail-closed signing denial.

## Browser loading order

```html
<script src="/js/koschei-wallet-enforcement.js"></script>
<script src="/js/koschei-enforcement-permit-verifier.js"></script>
<script src="/js/koschei-wallet-enforcement-verified.js"></script>
```

## Verified wallet integration

```js
const guardedWallet = KoscheiVerifiedWalletEnforcement.createPermitVerifiedWallet(rawWallet, {
  endpoint: "/api/v1/shield/transaction",
  network: "solana-mainnet",
  origin: window.location.origin,

  // Trust anchor distributed independently from the Guard response.
  pinnedKeys: {
    "tgk_production_2026_01": "BASE64_RAW_32_BYTE_ED25519_PUBLIC_KEY"
  },

  policyProvider: async ({ transactionFingerprint }) => ({
    ui_summary: {
      title: "Swap 10 USDC",
      transaction_fingerprint: transactionFingerprint
    },
    expected_programs: ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"],
    required_programs: [],
    blocked_programs: [],
    accounts: []
  }),

  onWarn: async ({ transactionFingerprint, explanation }) => {
    const approved = await showExplicitKoscheiWarning(explanation);
    return { approved, fingerprint: transactionFingerprint };
  }
});
```

The verified wrapper delegates transaction serialization, mutation checks, signed UI intent and wallet message integrity to Wallet Enforcement v1. Before that SDK receives an `allow` or `warn` response, the wrapper independently verifies the enforcement permit.

## Key pinning

Supported trust-anchor inputs:

- `pinnedKeys`: object or `Map` keyed by permit `key_id`
- `pinnedKey` plus `expectedKeyID`: one explicitly pinned key
- `keyResolver(keyID)`: an application-controlled trusted key registry

The `verification_key` field returned by the server is bootstrap metadata only. It is never sufficient by itself.

Key rotation should use overlapping key IDs:

1. distribute the new public key to wallet or extension clients
2. allow both old and new key IDs during the transition
3. switch the server signing key
4. remove the old key only after the client rollout window closes

## Decision commitment

The permit contains `decision_hash`, a SHA-256 commitment over:

- action, risk level and risk index
- summary and findings
- program and account intent policies
- Threat History status and highest matched risk
- CPI asset-flow status
- authority-surface status

The verifier reconstructs this commitment from the parsed Guard response. Changing the response explanation or evidence after permit issuance causes verification failure even when the permit signature itself is valid.

## Runtime support

The verifier uses Web Crypto Ed25519 where supported. CommonJS/Node verification falls back to the native `node:crypto` Ed25519 implementation.

A runtime without a working Ed25519 verifier fails closed.

## CI contract

Required CI executes `scripts/verify-wallet-enforcement.js`, including:

- valid pinned-key permit verification
- response-key substitution rejection
- expired permit rejection
- decision-hash tampering rejection
- ALLOW without a permit never reaching the wallet
- valid permit enabling the protected wallet call
- WARN still requiring fingerprint-bound user approval
