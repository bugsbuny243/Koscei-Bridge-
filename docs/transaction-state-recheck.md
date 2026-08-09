# ARVIS Transaction State Recheck

Status: live authenticated developer API with bounded Solana account-state re-read, independent-provider quorum and signed permit policy.

## Purpose

A State Witness binds a Guard decision to one observed account-state root. Current state-witness enforcement issues a policy-bound permit v3 that signs both that witness identity and the Guard risk policy snapshot used to decide whether independent corroboration is mandatory.

State Recheck verifies the permit and issued witness, re-reads only the signed bounded account set, and compares current state before a wallet relies on the prior Guard decision. It reduces the transaction-simulation TOCTOU window but does not claim that off-chain observation can freeze Solana state.

## Developer API

```text
POST /api/v1/shield/state-recheck
```

The route uses the existing enterprise API-key plus live KOSCH-holder gate and Solana runtime feature gate. It is rate-limited but does not consume a second scan quota unit for the same Guard decision.

The request carries the exact serialized transaction, the signed state-bound permit, the issued State Witness, and optional network (default `solana-mainnet`). Permit and witness trust checks happen before any RPC access.

## Response safety contract

A successful HTTP request and a safe signing decision are deliberately separate concepts.

- `ok=true` means the State Recheck request was processed successfully;
- `safe_to_proceed=true` is the only positive client-facing signal that the bounded signed state is still consistent after all effective recheck and Court requirements;
- `safe_to_proceed=false` means the prior Guard permit must not be relied on for signing without the action required by the returned decision;
- any `ok=false` response must also be treated as unsafe, regardless of whether a `safe_to_proceed` field is present.

`safe_to_proceed=true` is derived only from the final decision after Evidence Court processing. It requires the current and issued roots to match, a valid non-stale slot relationship, `state_unchanged`, `permit_state_consistent`, and no resimulation requirement. A primary `state_unchanged` result that is later downgraded by Court to `withhold` therefore cannot produce `safe_to_proceed=true`.

Clients should use a fail-closed rule:

```text
sign only if ok == true AND safe_to_proceed == true
```

The field does not mean Koschei signs or executes the transaction, and state can still change after the observation.

## Permit versions

Non-state-bound enforcement remains:

```text
koschei-transaction-guard-permit-v1
```

Legacy state-bound permits remain temporarily accepted for short-TTL migration compatibility:

```text
koschei-transaction-guard-permit-v2
```

New live state-witness issuance uses:

```text
koschei-transaction-guard-permit-v3
```

Permit v3 signs the v2 state binding plus:

- `state_recheck_policy_version`;
- final Guard `risk_level` snapshot;
- final Guard `risk_index` snapshot;
- the Court risk threshold used at issuance;
- whether Evidence Court is required;
- the signed independent-witness count when Court is required.

The verifier recomputes the policy relationship and rejects a correctly signed payload if `court_required` does not equal `risk_index >= signed_threshold`, if required witness counts are outside bounds, or if mandatory claims are missing. This semantic policy validation completes before the primary account-state RPC is allowed to run. Legacy v2 is accepted only when it contains no v3 policy claims. Permit v1 remains invalid for State Recheck because it has no State Witness.

## Selective Court policy

Runtime issuance policy:

```text
TRANSACTION_GUARD_STATE_RECHECK_COURT_RISK_THRESHOLD=25
```

The value is bounded to `0..100`. Current Transaction Guard permits are issued only for `allow` decisions, and the current base allow band is below risk index 25. Therefore the default threshold of 25 does not newly force Court for current allow permits.

Examples:

- threshold `25`: current allow-band permits do not force Court through signed risk policy;
- threshold `15`: allow permits with signed risk index `15..24` require Court;
- threshold `0`: every state-bound allow permit requires Court.

This is an issuance-time policy snapshot. Recheck does not recalculate the historic Guard score from mutable configuration.

## Global policy floor

`KOSCHEI_EVIDENCE_COURT_ENABLED=true` remains a deployment-wide floor. The effective recheck rule is:

```text
Court required = signed permit requires Court OR current global Court policy requires Court
```

The effective witness count is the stricter of the signed permit count and the current global Court count.

A signed v3 permit can therefore require Court even when the deployment-wide Evidence Court flag is currently off. This forced path does not bypass any Evidence Court safety rule: method allowlists, provider cap, timeouts, primary-provider exclusion, provider-identity deduplication and canonical-root quorum checks remain mandatory.

## Trust rule

State Recheck derives the trusted Ed25519 public key from Koschei's configured enforcement signing key and requires:

- valid Ed25519 signature and configured key ID;
- supported state-bound permit version and internally consistent policy claims;
- `allow` action and current Transaction Guard version;
- exact network and transaction fingerprint;
- active, non-expired TTL;
- complete State Witness v1;
- exact witness slots and transaction identity;
- bounded, duplicate-free witness account set;
- valid SHA-256 state hashes;
- recomputed witness root and binding hash matching signed claims.

The public key embedded in a client-supplied permit object is never trusted as the verification root.

## Live current-state re-read

Only after all permit, policy and witness checks pass, the handler:

1. extracts the signed witness account addresses;
2. calls bounded `getMultipleAccounts` using base64 account state and `processed` commitment;
3. requires the complete ordered witnessed account set;
4. canonicalizes each current account state with the same State Witness hash contract;
5. recomputes the current account-state root;
6. compares the primary provider slot with the signed simulation slot;
7. immediately requires fresh simulation when primary state is changed or stale;
8. resolves the effective signed/global Court requirement;
9. when Court is required, requests the same bounded state from independent providers even if the global Court feature flag is off;
10. excludes the primary RPC provider identity from Court voting;
11. requires the quorum root to equal the primary root and enough matching Court observations to be at or after the signed simulation slot;
12. derives `safe_to_proceed` from the final post-Court decision;
13. returns only safe root/slot/policy/quorum metadata, never raw account state or provider hostnames.

Provider failure, incomplete evidence, stale quorum, provider conflict, root disagreement or insufficient independent providers fail closed with `withhold` and `requires_resimulation=true`.

## Current-state decision

- `state_unchanged` — primary root exactly matches the signed root, primary state is not older than the simulation, and every effective Court requirement is satisfied by a fresh independent quorum;
- `state_changed` — primary current root differs, requiring a fresh simulation;
- `withhold` — current root/slot/policy/quorum evidence is unavailable, malformed, stale, conflicting or insufficient.

An independent quorum can never turn a primary `state_changed` result into `state_unchanged`.

## Safety boundary

A `safe_to_proceed=true` response means only that the bounded signed account-state root still matched at the recheck observation slot and all effective corroboration requirements passed. Koschei remains non-custodial and never signs, submits, mutates or holds the transaction.

No transaction-value threshold is defined here. A value-based policy should be added only after Koschei has a separately verified transaction-value evidence contract; incomplete transaction context is not converted into invented dollar or lamport exposure.