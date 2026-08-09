# ARVIS Transaction State Recheck

Status: live authenticated developer API wired to bounded Solana account-state re-read.

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
2. calls bounded `getMultipleAccounts` using base64 account state;
3. requires the complete ordered witnessed account set;
4. canonicalizes each current account state using the same State Witness hashing contract;
5. recomputes the current account-state root;
6. compares the current provider slot against the signed simulation slot;
7. returns only root/slot decision metadata, never raw account data.

Provider failure or incomplete account evidence fails closed and requires a fresh simulation before signing.

## Current-state decision

The recheck evaluator has three states:

- `state_unchanged` — current account-state root exactly matches the signed issued root and the current provider slot is at or after the signed simulation slot;
- `state_changed` — current account-state root differs, so a fresh simulation is required;
- `withhold` — current root/slot evidence is missing, incomplete, unavailable, or the provider returned state older than the signed simulation slot.

No arbitrary maximum slot-age threshold is introduced in this phase.

## Safety boundary

A successful `state_unchanged` response means only that the bounded signed account-state root still matched at the recheck observation slot. Koschei remains non-custodial: the route does not sign, submit, mutate, or custody the transaction.

The next hardening step is selective Evidence Court corroboration for high-value or high-risk permits, so critical state can require independent provider agreement before `state_unchanged` is accepted.
