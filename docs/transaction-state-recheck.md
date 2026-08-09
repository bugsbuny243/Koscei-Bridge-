# ARVIS Transaction State Recheck

Status: live authenticated developer API wired to bounded Solana account-state re-read with optional independent-provider corroboration.

## Purpose

A State Witness binds a Guard decision to one observed account-state root. A state-bound permit v2 signs that witness identity. Recheck determines whether the permit and issued witness are authentic, re-reads only the signed bounded account set, and compares current state before a wallet relies on the prior Guard decision.

This layer reduces the transaction-simulation TOCTOU window but does not claim that off-chain observation can freeze Solana state. Even after a successful recheck, state can change again before execution unless the invoked on-chain programs enforce the relevant invariants themselves.

## Developer API

```text
POST /api/v1/shield/state-recheck
```

The route uses the existing enterprise API-key plus live KOSCH-holder gate and Solana runtime feature gate. It is rate-limited but does not consume a second scan quota unit for the same Guard decision.

The request carries:

- the exact serialized transaction previously evaluated by Transaction Guard;
- the state-bound permit v2 token;
- the issued State Witness returned with that Guard decision;
- optional network, defaulting to `solana-mainnet`.

The handler verifies the permit and witness before making any RPC call. Invalid or forged requests therefore cannot use State Recheck as an unauthenticated RPC proxy.

## Trust rule

Recheck never trusts the public key carried in a client-supplied permit object.

The verifier derives the trusted Ed25519 public key from Koschei's configured enforcement signing key and requires:

- valid Ed25519 signature;
- `koschei-transaction-guard-permit-v2`;
- configured key ID match;
- `allow` action;
- current Transaction Guard version;
- exact network match;
- exact transaction fingerprint match;
- valid `issued_at` / `expires_at` interval;
- permit currently active and not expired;
- complete State Witness v1;
- exact witness slots and transaction identity;
- witness account count within the bounded Guard account limit;
- SHA-256-valid state hashes;
- no duplicate or empty witness addresses;
- recomputed witness account root equals both the witness and signed claims;
- recomputed witness binding hash equals both the witness and signed claims.

Legacy permit v1 is not accepted for state recheck because it contains no signed state witness.

## Live current-state re-read

Only after the trust checks pass, the handler:

1. extracts the signed witness account addresses;
2. calls bounded `getMultipleAccounts` using base64 account state and `processed` commitment;
3. requires the complete ordered witnessed account set;
4. canonicalizes each current account state using the same State Witness hashing contract;
5. recomputes the current account-state root;
6. compares the current provider slot against the signed simulation slot;
7. if the primary provider already reports changed or stale state, requires a fresh simulation immediately;
8. if the primary provider reports unchanged state and Evidence Court is enabled, requests the exact same bounded account set from independent providers and canonicalizes each response into the same State Witness root;
9. excludes the primary RPC provider identity from the Evidence Court witness pool before quorum evaluation;
10. returns only root/slot/quorum decision metadata, never raw account data or provider hostnames.

Provider failure or incomplete account evidence fails closed and requires a fresh simulation before signing.

## Evidence Court corroboration

Evidence Court remains configuration-controlled through `KOSCHEI_EVIDENCE_COURT_ENABLED`. When disabled, State Recheck preserves the original single-provider behavior. When enabled, an apparent primary-provider `state_unchanged` result is not sufficient by itself.

The corroboration gate requires all of the following:

- Evidence Court status is `verified`;
- the quorum-agreed canonical State Witness root exactly matches the primary recheck root;
- at least `KOSCHEI_EVIDENCE_COURT_REQUIRED_WITNESSES` independent matching providers observed that root at or after the signed simulation slot;
- none of those quorum votes comes from the primary RPC provider identity.

The required witness count defaults to 2 and remains bounded by Evidence Court's provider cap. Provider identities are deduplicated so multiple URLs from the same recognized provider do not count as independent witnesses. The primary provider identity is removed before this count is evaluated: if the primary read uses Helius, another Helius URL cannot count as a Court witness; for an unrecognized custom RPC, the exact normalized host identity is excluded.

If primary exclusion leaves fewer configured providers than the required Court threshold, corroboration is `insufficient` and fails closed. If quorum is insufficient, conflicting, stale, or disagrees with the primary provider, the final decision becomes `withhold` and `requires_resimulation=true`. An independent quorum can never turn a primary `state_changed` result back into `state_unchanged`.

## Current-state decision

The recheck evaluator has three states:

- `state_unchanged` — current account-state root exactly matches the signed issued root, the primary provider slot is at or after the signed simulation slot, and, when Evidence Court is enabled, a fresh independent provider quorum that excludes the primary provider corroborates that same root;
- `state_changed` — current account-state root differs, so a fresh simulation is required;
- `withhold` — current root/slot/quorum evidence is missing, incomplete, unavailable, conflicting, stale, or disagrees across required providers.

No arbitrary maximum slot-age threshold is introduced in this phase.

## Safety boundary

A successful `state_unchanged` response means only that the bounded signed account-state root still matched at the recheck observation slot and, when enabled, was independently corroborated. Koschei remains non-custodial: the route does not sign, submit, mutate, or custody the transaction.

The next hardening step is policy-scoped quorum activation using signed permit risk claims, allowing mandatory corroboration to be selected cryptographically for high-risk permits rather than only by deployment-wide Evidence Court configuration. A transaction-value threshold should be added only after Koschei has a separately verified value-evidence contract; this layer does not invent one from incomplete transaction context.
