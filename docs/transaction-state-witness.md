# ARVIS Transaction State Witness

Status: live Guard collection, policy-bound permit issuance, bounded pre-sign recheck and optional/required independent-provider corroboration are implemented.

## Goal

Transaction simulation proves what a transaction would do against one observed Solana state. It does not prove that the same critical state still exists when a wallet signs moments later.

State Witness gives Transaction Guard a deterministic identity for the bounded account state used around simulation so an enforcement permit can be bound to more than serialized transaction bytes.

## Witness v1

The deterministic witness contains:

- exact transaction fingerprint;
- pre-state `getMultipleAccounts` context slot;
- simulation context slot;
- absolute slot spread as an observation, not a safety threshold;
- sorted bounded account addresses;
- whether each account was present;
- SHA-256 of each canonical account state;
- SHA-256 root over the sorted address/state-hash leaves;
- a binding hash over transaction fingerprint, both slots and the account root;
- explicit limitations when evidence is incomplete.

Account state hashing covers RPC-observed account data, lamports, owner, executable flag, rent epoch and space. Missing accounts receive a deterministic `present=false` hash rather than being silently dropped.

## Live Guard collection

Guard v3 builds the witness from the exact bounded account list already used for pre-state inspection and account-returning simulation:

```text
getMultipleAccounts(pre-state)
        │
        ├── context.slot
        ├── ordered addresses
        └── raw account states
                │
                ▼
simulateTransaction(accounts)
        │
        └── context.slot
                │
                ▼
Transaction State Witness
```

The response exposes `state_witness_complete` and `state_witness`. Missing bounded pre-state evidence or provider failure produces an explicit incomplete/unavailable witness rather than fabricated state evidence.

## Enforcement permit compatibility

Non-state-bound enforcement remains:

```text
koschei-transaction-guard-permit-v1
```

with opt-in state enforcement:

```text
TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT=true
TRANSACTION_GUARD_REQUIRE_STATE_WITNESS=true
```

When State Witness is required, permit issuance fails closed unless a complete live witness is available.

Legacy state-bound v2 claims bind:

- witness version;
- witness binding hash;
- account-state root;
- pre-state slot;
- simulation slot.

New live state-bound issuance uses:

```text
koschei-transaction-guard-permit-v3
```

which preserves the v2 state binding and additionally signs the State Recheck policy snapshot: Guard risk level/index, the configured Court risk threshold, whether Court is required and the independent witness count when required.

Legacy v2 remains accepted by State Recheck during the short permit-TTL migration window, but only if it contains no v3 policy fields. v1 remains invalid for State Recheck because it contains no signed State Witness.

`TRANSACTION_GUARD_REQUIRE_STATE_WITNESS=true` without signed permit enforcement remains invalid configuration.

## Signed selective corroboration

Issuance reads:

```text
TRANSACTION_GUARD_STATE_RECHECK_COURT_RISK_THRESHOLD
```

Default is 25 and the value is bounded to 0..100. Current permits are issued only for allow decisions, whose current base risk band is below 25, so the default threshold preserves current behavior. Lowering the threshold can require independent Court corroboration for elevated-risk decisions that are still inside the allow band.

The risk snapshot and threshold are signed into permit v3. Recheck validates that the signed Court decision matches `risk_index >= threshold`; it does not infer the historic issuance policy from mutable current configuration.

## Pre-sign recheck

State Recheck now:

1. verifies trusted Ed25519 signer, permit version, TTL, network and exact transaction fingerprint;
2. validates the signed State Witness and, for v3, the complete signed recheck-policy contract;
3. re-reads only the witnessed account addresses using the same account-state hash contract;
4. recomputes the current State Witness root;
5. requires fresh simulation on primary state change or stale primary evidence;
6. applies the effective Court requirement from signed permit policy OR current deployment-wide policy;
7. can force bounded Evidence Court collection from a signed v3 requirement even when the global Court flag is off;
8. excludes the primary RPC provider identity from Court votes;
9. requires fresh independent matching quorum evidence before returning `state_unchanged` when Court is required.

Any missing, stale, conflicting, insufficient or disagreeing evidence fails closed.

## Safety boundary

State Witness, policy-bound permits and pre-sign recheck reduce TOCTOU exposure but do not freeze Solana state. State can still change again after observation unless the invoked on-chain program enforces the relevant invariant.

Koschei does not sign, submit or custody the transaction. No transaction-value threshold is inferred until a separately verified value-evidence contract exists.