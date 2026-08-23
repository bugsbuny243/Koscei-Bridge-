# Authority integrity component harness v0.1

This slice generalizes the **unauthorized source-account / principal-binding** failure class into Koschei Web3 Defense Validation without claiming that any production chain is already protected.

## Security question

A transaction can be correctly signed and its payload can remain byte-for-byte stable while the state transition is still unauthorized. The authority question is therefore independent of payload identity:

> Is the account that will actually be debited cryptographically or policy-bound to the caller principal, operation, asset and authorization context that approved this exact state transition?

The canonical invariant is:

`declared_source_account == authorized_source_for(caller_principal, operation, asset, authorization_context)`

An explicit delegation may satisfy the invariant only when evidence binds the exact principal, source account, operation and asset. A successful check against a different principal does not authorize the declared debit source.

## Implemented component path

The v0.1 component harness connects four existing/new deterministic boundaries:

1. `DefenseAuthorityBindingEvidenceV01` carries VERIFIED caller, declared source, authorized source, operation, asset, call-payload and state/effect digests.
2. `EvaluateDefenseAuthorityBindingV01` derives authority preservation from exact field equality. The caller cannot supply a free-standing `authority_preserved=true` verdict.
3. `ApplyDefenseAuthorityBindingToContainmentV01` feeds the derived result into the existing `executioncontainment` kernel. A mismatch produces `EC-005-AUTHORITY-CHANGED` and fails the invariant, so the receipt is `CONTAIN` even when approved/candidate intent and payload hashes are identical.
4. A separately identified Security Evidence producer binds its observation to both the authority-binding digest and containment receipt before Defense Validation v0.2 evaluates the matched attack/benign pair.

## Attack / benign pair

The component test intentionally keeps the approved intent hash and approved/candidate payload hash identical in both cases.

### Attack

- caller principal: authorized contract caller;
- declared debit source: victim account;
- authorized source: caller-bound account;
- operation and asset otherwise match;
- authority binding: **false**;
- containment: **CONTAIN**;
- expected reason includes `EC-005-AUTHORITY-CHANGED`;
- independent alert arrives before the declared impact deadline;
- Defense Validation outcome: `CAUGHT_IN_TIME`.

### Benign

- same caller, operation, asset, execution mode and observation window;
- declared debit source matches the authorized source (or can later be replaced by an exactly scoped verified delegation fixture);
- authority binding: **true**;
- containment: **RELEASE**;
- independent observation: `no_alert`;
- Defense Validation outcome: `CLEAN`.

The combined component report is `VALIDATED` only for this deterministic component harness.

## Historical motivation

The technique class was added after public reporting around the August 2026 BounceBit Chain incident described an authorization-path failure where a smart-contract caller could identify a different account as the funding source without the source account being correctly bound to the authorization check. The repository scenario treats that incident as **pattern motivation only**. It does not claim to reproduce BounceBit proprietary production code or its exact vulnerable implementation.

## Claim boundary

This harness is not production defense evidence. It does not:

- run the reported vulnerable Evmos/native authorization route;
- use any BounceBit production account, key, wallet or state;
- send a mainnet transaction;
- mutate a production control;
- prove a deployed Web3 API/runtime invokes the authority adapter;
- prove an operationally separate production collector observed a real attack;
- authorize an AI or UI to issue a validation verdict.

The scenario remains `planned` until an isolated Cosmos-EVM/native-module reproduction produces real pre/post state, debit-effect and authority-check trace evidence and the independent observation contract is satisfied.

## Next acceptance gate

The next slice should build a pinned isolated Cosmos-EVM/Evmos-style authorization fixture with one deliberately vulnerable source-account path and one corrected path. The exact same authority-binding adapter, Execution Containment receipt, independent evidence envelope and Defense Validation evaluator must consume those artifacts without weakening the ruleset.
