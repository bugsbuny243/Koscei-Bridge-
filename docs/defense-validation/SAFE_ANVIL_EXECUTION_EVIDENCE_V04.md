# Safe Anvil Execution Evidence v0.4

Status: **component evidence / isolated validation substrate**

This slice replaces a purely in-memory Safe backend fixture with a concrete local EVM execution engine while preserving the product truth boundary around Execution Proof connectivity issue #864.

## What is real in v0.4

`AnvilSafeSimulationEngine` starts a child Anvil process bound to `127.0.0.1`, forks an explicitly pinned source block, verifies chain and block identity, hashes the exact Anvil runner binary, snapshots Safe state, traces the Safe simulation path, materializes the supported effect on the isolated fork, and returns bound post-state/effect evidence.

The dedicated `Defense Validation Anvil Evidence` workflow creates a deterministic local source chain, compiles and deploys the local Safe/accessor fixture, funds the fixture Safe, pins the resulting block, then makes the engine fork that source chain and execute the integration test. The acceptance therefore exercises real EVM bytecode, RPC, process spawning, fork state, `debug_traceCall`, receipt collection and state reads. It is not a mocked RPC acceptance.

## Safe execution semantics

The trace path must prove:

1. the Safe enters `simulateAndRevert(address,bytes)`;
2. the Safe context performs a `DELEGATECALL` into the configured `SimulateTxAccessor`;
3. the accessor performs the candidate `CALL` from Safe context to the exact target;
4. the canonical trace is complete and its digest recomputes;
5. the accessor calldata digest matches the locally encoded `simulate(address,uint256,bytes,uint8)` payload.

The trace execution is non-committing because `simulateAndRevert` always reverts the outer call. A second execution materializes the already-verified effect only on the child isolated fork so post-state and effect evidence can be collected.

## Deliberately narrow equivalence boundary

v0.4 accepts only:

- `operation = CALL`;
- native asset value movement;
- empty calldata.

Within that subset, the materialized effect is the same EVM `CALL` target/value/data that the verified accessor trace observed. Token calldata, arbitrary contract effects and `DELEGATECALL` are rejected fail-closed. They must not be promoted into validated evidence until dedicated effect collectors and equivalence tests exist.

## State and effect evidence

The Safe snapshot binds at minimum:

- owners;
- threshold;
- enabled modules;
- guard;
- fallback handler;
- implementation identity;
- implementation code hash;
- native balance;
- nonce.

The effect evidence binds:

- isolated transaction hash;
- transaction receipt digest;
- verified Safe trace digest;
- Safe balance before/after;
- target balance before/after;
- canonical native asset movement set.

No field supplied by a UI or model is verdict authority.

## Independent collector boundary

`internal/defensecollector` and `cmd/defense-validation-collector` form a separate observation process boundary. The collector receives the raw Execution Containment receipt and raw Execution Proof, recomputes both through the deterministic Defense Validation adapter, enforces a distinct collector identity, binds the completed observation window, and seals a Security Evidence Bus event.

The collector rejects:

- control self-attestation;
- tampered proof or containment artifacts;
- mainnet execution evidence;
- incomplete observation windows;
- a missing alert timestamp when recomputed control evidence signaled;
- an alert timestamp when recomputed evidence did not signal.

The command reads one bounded JSON request from stdin and emits one JSON result. It has no signing, custody, transaction submission, shell execution or network authority.

## What this does not prove

This slice does **not** prove that Koschei currently intercepts or authorizes a production Safe signing path.

It does not:

- send a mainnet transaction;
- use production private keys or production identities;
- mutate a production control;
- grant the validation collector signing authority;
- make a model or UI a verdict authority;
- close issue #864;
- establish a deployed caller -> handler/service -> route/worker -> signing-enforcement call chain.

The local Solidity fixture proves the mechanics of the evidence substrate. A validation claim for a particular production Safe deployment still requires a separately pinned real deployment/fork evidence run with deployment provenance and an operationally separate collector.

## Next gate

After this component is green, the next evidence slice is an end-to-end controlled scenario on the real Anvil substrate:

- approved native transfer -> `RELEASE` / `CLEAN`;
- mutated target outside the approved outflow policy -> `CONTAIN` / independently observed alert / `CAUGHT_IN_TIME`;
- both cases fed through the deterministic Defense Validation evaluator;
- signed dossier output with the exact runner, block, state, trace, receipt and collector digests.

Production signing enforcement remains blocked on the #864 connectivity audit even if that scenario validates.
