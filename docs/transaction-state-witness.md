# ARVIS Transaction State Witness

Status: foundation implemented; live Guard collection/recheck wiring remains gated until the integration phase.

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

## Slot policy

State Witness records slot spread but this foundation does not invent a maximum safe spread. A later enforcement policy may define an acceptance window with explicit Solana/runtime evidence and tests.

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

When State Witness is required, permit issuance fails closed unless a complete witness is supplied. A complete witness produces:

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

## Current safety boundary

This foundation deliberately does not yet enable the policy in production. Existing Guard call paths continue using permit v1 unless the later integration path supplies a complete witness.

Until live collection is wired, enabling `TRANSACTION_GUARD_REQUIRE_STATE_WITNESS=true` causes otherwise-allowable enforcement to fail closed with `state_witness_unavailable`.

## Next integration phase

1. pass the preserved pre-state RPC context slot and simulation slot from Guard v3;
2. build the witness from the exact bounded account list already used by Guard;
3. expose the witness in the Guard response;
4. pass it to state-bound permit issuance;
5. add a bounded recheck path that re-reads the witnessed account states before relying on the permit;
6. require re-simulation when the account-state root changes or the permit expires;
7. selectively corroborate critical state through Evidence Court when policy requires multi-provider proof.

The recheck layer is the part that converts state binding into TOCTOU resistance. A witness by itself is evidence, not a guarantee that state has remained unchanged.
