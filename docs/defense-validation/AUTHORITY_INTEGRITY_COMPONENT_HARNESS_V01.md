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

1. `DefenseAuthorityBindingEvidenceV01` carries caller, declared source, authorized source, module route, operation, asset, amount, call-payload and state/effect fields backed by two Ed25519-signed artifacts: principal-execution evidence and authorization-grant evidence.
2. `EvaluateDefenseAuthorityBindingV01` requires an external trust policy with distinct pinned producers and public keys, verifies both signatures, recomputes the artifact digests and binds every claimed field to the signed artifacts before deriving authority preservation. A caller-supplied `verified` label or arbitrary digest is insufficient.
3. `ApplyDefenseAuthorityBindingToContainmentV01` combines the derived result with the backend authority observation without overwriting an existing failure. A mismatch produces `EC-005-AUTHORITY-CHANGED` and fails the invariant, so the receipt is `CONTAIN` even when approved/candidate intent and payload hashes are identical.
4. `DefenseAuthorityNativeExecutionAttestationV01` must be signed by a separately pinned native-runner key and must attest the concrete isolated Cosmos-EVM backend, reproduced native authorization route, chain/block/runner identity, native authorization trace, call payload, state/effect hashes and exact containment receipt. Its producer and key are distinct from both authority-artifact producers and the independent observer. A caller-created deterministic receipt with `BackendAvailable=true` is insufficient.
5. `AdaptAuthorityIntegrityCaseV01` requires the receipt's chain ID, module route, approved/candidate payload, pre-state, post-state and effect-set hashes to match both the authenticated authority evidence and the native-runner attestation. Every scenario `matched_field` is compared with signed or receipt-backed execution evidence. This scenario's attack must contain only `source_account_mismatch`; an unrelated principal, operation or asset failure cannot stand in for the declared attack. Benign cases require an unqualified release.
6. A separately identified Security Evidence producer binds its observation to the authority-binding digest, native-runner attestation and containment receipt. Its identity and Ed25519 key must differ from the control and all evidence producers and pinned keys. Changing `producer` and recomputing the unkeyed event digest is insufficient. Its independently observed alert/no-alert status is preserved so Defense Validation can report misses and false positives. The signed chain label and receipt chain ID are carried through the observation and report boundary.
7. The evaluator receives the complete parsed scenario contract, recomputes its digest and requires every declared case for each tested control. Omitting an additional attack or benign case produces `INCOMPLETE`; a case outside the committed contract is rejected.

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
- independent alert arrives before the scenario's latest detection offset;
- Defense Validation outcome: `CAUGHT_IN_TIME`.

### Benign

- same caller, operation, asset, execution mode and observation window;
- declared debit source matches the authorized source (or can later be replaced by an exactly scoped verified delegation fixture);
- authority binding: **true**;
- containment: **RELEASE**;
- independent observation: `no_alert`;
- Defense Validation outcome: `CLEAN`.

The unit regression can assemble an authenticated native-attestation fixture and reach `VALIDATED` only to prove the adapter/evaluator contract. That fixture is not runtime evidence; without a trusted native-runner signature the adapter fails closed before emitting a verified case.

## Historical motivation

The technique class was added after public reporting around the August 2026 BounceBit Chain incident described an authorization-path failure where a smart-contract caller could identify a different account as the funding source without the source account being correctly bound to the authorization check. The repository scenario treats that incident as **pattern motivation only**. It does not claim to reproduce BounceBit proprietary production code or its exact vulnerable implementation.

## Claim boundary

This harness is not production defense evidence. It does not:

- run the reported vulnerable Evmos/native authorization route;
- supply a real native-runner attestation (the unit-test signer is fixture-only);
- use any BounceBit production account, key, wallet or state;
- send a mainnet transaction;
- mutate a production control;
- enable automatic intervention or arbitrary command execution;
- prove a deployed Web3 API/runtime invokes the authority adapter;
- prove an operationally separate production collector observed a real attack;
- authorize an AI or UI to issue a validation verdict.

The scenario remains `planned` until an isolated Cosmos-EVM/native-module reproduction produces real pre/post state, debit-effect and authority-check trace evidence and the independent observation contract is satisfied.

## Next acceptance gate

The next slice should build a pinned isolated Cosmos-EVM/Evmos-style authorization fixture with one deliberately vulnerable source-account path and one corrected path. The exact same authority-binding adapter, Execution Containment receipt, independent evidence envelope and Defense Validation evaluator must consume those artifacts without weakening the ruleset.
