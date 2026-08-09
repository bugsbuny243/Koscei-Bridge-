# ARVIS Transaction State Recheck

Status: trust core implemented; API transport and live RPC re-read remain the next wiring step.

## Purpose

A State Witness binds a Guard decision to one observed account-state root. A state-bound permit v2 signs that witness identity. Recheck determines whether the permit and issued witness are authentic before any current-state comparison is trusted.

This layer reduces the transaction-simulation TOCTOU window but does not claim that off-chain observation can freeze Solana state. Even after a successful recheck, state can change again before execution unless the invoked on-chain programs enforce the relevant invariants themselves.

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

## Current-state decision

The pure recheck evaluator has three states:

- `state_unchanged` — current account-state root exactly matches the signed issued root and the current provider slot is at or after the signed simulation slot;
- `state_changed` — current account-state root differs, so a fresh simulation is required;
- `withhold` — current root/slot evidence is missing or the provider returned state older than the signed simulation slot.

No arbitrary maximum slot-age threshold is introduced in this phase.

## Next wiring step

The authenticated developer API should:

1. accept the exact serialized transaction, permit token and issued State Witness;
2. run the trust-core verification above;
3. re-read only the signed witness addresses with bounded `getMultipleAccounts`;
4. compute the current account-state root without exposing raw account data;
5. evaluate `state_unchanged`, `state_changed` or `withhold`;
6. require fresh simulation on state change, permit expiry, stale provider state or provider failure;
7. remain non-custodial and never sign or submit the transaction.

High-value policies may later require Evidence Court corroboration before returning `state_unchanged`.
