# Safe Anvil Execution Evidence v0.4

Status: **validated isolated component scenario / not production signing enforcement**

This slice replaces a purely in-memory Safe backend fixture with a concrete local EVM execution engine while preserving the product truth boundary around Execution Proof connectivity issue #864.

## What is real in v0.4

`AnvilSafeSimulationEngine` starts a child Anvil process bound to `127.0.0.1`, forks an explicitly pinned source block, verifies chain and block identity, hashes the exact Anvil runner binary, snapshots Safe state, traces the Safe simulation path, materializes the supported effect on the isolated fork, and returns bound post-state/effect evidence.

The dedicated `Defense Validation Anvil Evidence` workflow creates a deterministic local source chain, compiles and deploys the local Safe/accessor fixture, funds the fixture Safe, pins the resulting block, then makes the engine fork that source chain and execute the integration acceptance. The acceptance therefore exercises real EVM bytecode, RPC, process spawning, fork state, `debug_traceCall`, receipt collection and state reads. It is not a mocked RPC acceptance.

The same workflow now feeds real isolated execution artifacts through Execution Containment, Execution Proof artifact verification, the independent collector contract, Security Evidence Bus adaptation and the deterministic Defense Validation evaluator.

## Validated controlled scenario

The v0.4 acceptance runs two matched cases against fresh child forks of the same pinned source state:

1. **Benign control** — the approved 1 ETH Safe native transfer is executed exactly. The exact Safe intent matches, observed authority/code/trace/effect invariants hold, Execution Containment returns `RELEASE`, the independent observation is `NO_ALERT`, and Defense Validation returns `CLEAN`.
2. **Intent mutation attack** — the approved Safe transaction is mutated from 1 ETH to 2 ETH while keeping the same Safe and target. The locally recomputed Safe EIP-712 transaction identity changes. Execution Containment returns `CONTAIN` with `EC-004-INTENT-MISMATCH`, the independent collector binds the signaled control to the completed observation window, and Defense Validation returns `CAUGHT_IN_TIME`.

The matched benign + attack matrix produces the deterministic Defense Validation verdict `VALIDATED` under `koschei-defense-validation-rules-v0.2.0`.

This is a validation result for the isolated local fixture and the exact tested control configuration only. It is not evidence that Koschei currently protects a production Safe deployment.

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

`internal/defensecollector` and `cmd/defense-validation-collector` form a separate observation process boundary. The collector receives the raw Execution Containment receipt, raw Execution Proof and complete scenario contract, recomputes the execution evidence through the deterministic Defense Validation adapter, enforces a distinct collector identity, binds the completed observation window, and signs a sealed Security Evidence Bus event with Ed25519. The trusted collector public key is part of the exact control configuration hash.

The collector rejects:

- control self-attestation;
- a missing signing key or a signing key that does not match the control's pinned collector public key;
- tampered proof or containment artifacts;
- mainnet execution evidence;
- incomplete observation windows;
- a missing alert timestamp when recomputed control evidence signaled;
- an alert timestamp when recomputed evidence did not signal.

The command reads one bounded JSON request from stdin and emits one JSON result. Its test/runtime-specific evidence-signing key is supplied through `KOSCHEI_DEFENSE_COLLECTOR_ED25519_PRIVATE_KEY`; the corresponding public key must match the control configuration. This key authenticates evidence only: the command has no wallet custody, transaction-signing, transaction-submission, shell-execution or network authority.

## What this does not prove

This slice does **not** prove that Koschei currently intercepts or authorizes a production Safe signing path.

It does not:

- send a mainnet transaction;
- use production private keys or production identities;
- mutate a production control;
- grant the validation collector wallet or production transaction-signing authority;
- make a model or UI a verdict authority;
- close issue #864;
- establish a deployed caller -> handler/service -> route/worker -> signing-enforcement call chain.

The local Solidity fixture proves the mechanics of the evidence substrate and validates the exact isolated scenario above. A validation claim for a particular production Safe deployment still requires a separately pinned real deployment/fork evidence run with deployment provenance and an operationally separate collector.

## Next gate

The next evidence slice is a signed Defense Validation dossier that binds the exact scenario version, control configuration, Anvil binary identity, pinned block, pre/post state, Safe trace, materialized receipt/effect evidence, Execution Containment receipt, Execution Proof artifact, independent collector event and final deterministic report hash.

After that, the same harness can be pointed at a separately approved and pinned real Safe deployment for provenance-backed validation. Production signing enforcement remains blocked on the #864 connectivity audit even if those validations succeed.
