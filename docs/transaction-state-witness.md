# ARVIS Transaction State Witness

Status: live Guard collection and state-bound permit wiring implemented; pre-sign recheck remains the next enforcement phase.

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

Account state hashing covers the RPC-observed account data, lamports, owner, executable flag, rent epoch and space. Missing accounts receive a deterministic `present=false` hash rather than being silently dropped.

## Live Guard collection

Guard v3 now builds the witness from the exact bounded account list already used for pre-state inspection and account-returning simulation:

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

The response exposes:

- `state_witness_complete`
- `state_witness`

When Guard has no bounded pre-state account set, it still records the simulation slot but returns an explicit incomplete/not-collected witness. Provider failure similarly produces an unavailable witness rather than fabricating state evidence.

## Slot policy

State Witness records slot spread but does not invent a maximum safe spread. A later enforcement policy may define an acceptance window only with explicit Solana/runtime evidence and regression tests.

Missing pre-state or simulation context slots make the witness incomplete.

## Enforcement permit compatibility

Existing enforcement permits remain:

```text
koschei-transaction-guard-permit-v1
```

and are unchanged when state-witness enforcement is disabled.

The opt-in policy is:

```text
TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT=true
TRANSACTION_GUARD_REQUIRE_STATE_WITNESS=true
```

When State Witness is required, permit issuance fails closed unless a complete live witness is available. A complete witness produces:

```text
koschei-transaction-guard-permit-v2
```

whose signed claims include:

- state witness version;
- state witness binding hash;
- account-state root;
- pre-state slot;
- simulation slot.

The witness transaction fingerprint must exactly equal the permit transaction fingerprint.

`TRANSACTION_GUARD_REQUIRE_STATE_WITNESS=true` without signed permit enforcement is invalid configuration.

Compatibility rule: a complete witness may be present in a Guard response while state-witness enforcement is disabled, but the signed permit remains v1. This prevents the new observation layer from silently changing existing integration contracts.

## Current safety boundary

Live collection and permit binding are implemented, but the feature gate remains off by default. Koschei still does not sign or submit the transaction.

A state-bound permit proves what state the allow decision was bound to. It does **not** prove that state has remained unchanged after the response was issued.

That distinction is deliberate: TOCTOU resistance is complete only when the consumer performs a bounded pre-sign recheck.

## Next enforcement phase — bounded recheck

1. accept the signed state-bound permit and exact transaction fingerprint;
2. verify Ed25519 signature, key ID, expiry, guard version and witness claims;
3. re-read only the witnessed account addresses;
4. recompute the current account-state root;
5. compare it with the signed `state_account_root_sha256`;
6. return `state_unchanged` only on an exact match;
7. return `state_changed` / `recheck_required` on any mismatch, missing account evidence, expired permit or provider failure;
8. require a fresh simulation and permit after state change;
9. selectively corroborate hard-trigger state through Evidence Court when policy requires multi-provider proof.

The recheck layer is the component that converts state binding into practical TOCTOU resistance. A witness by itself remains evidence, not a future-state guarantee.
