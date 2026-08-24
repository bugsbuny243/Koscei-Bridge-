# Safe intent-mutation component harness v0.2

This harness connects the Defense Validation v0.2 deterministic evaluator to the implemented Web3 execution-integrity primitives without claiming production enforcement.

## What is now exercised

The component test uses the real repository implementations for:

- local Safe EIP-712 `safeTxHash` recomputation (`executionproof.NativeSafeTxHashComputer`);
- canonical full Safe action hashing;
- Execution Proof deterministic `ALLOW` / `BLOCK` evaluation;
- Execution Containment deterministic `RELEASE` / `CONTAIN` recomputation and receipt verification;
- Security Evidence Bus event sealing, Ed25519 producer authentication and digest verification;
- independent-collector identity and source-digest binding;
- Defense Validation v0.2 attack/benign matrix evaluation.

The test runs two attack-control shapes against the same Safe intent-mutation scenario:

1. **Weak upstream binding** — the mutated candidate has already replaced the approved baseline before the control sees it. Execution Proof and Execution Containment therefore receive a self-consistent but wrong baseline. No control signal is produced; the independent observation is `no_alert`; the deterministic evaluator returns `MISSED` / `FAILED`.
2. **Exact approved binding** — the original approved Safe intent and calldata remain authoritative while the mutated candidate is separately recomputed. Execution Proof returns `BLOCK`, Execution Containment returns `CONTAIN`, the independently authenticated observation is bound to both artifact digests, and the attack is observed before the scenario's latest detection offset. The matched benign action remains `RELEASE` / `ALLOW` with `no_alert`, so the component evaluator returns `CAUGHT_IN_TIME` for attack and `CLEAN` for benign.

This proves why preserving the approved baseline is part of the security boundary. A control cannot detect a mutation if the attacker is allowed to redefine what "approved" meant before validation begins.

## Independent observation contract

A control cannot validate itself.

The observation adapter requires a `koschei.security-evidence/v1` event whose producer exactly matches the control's configured independent collector and is different from the control identity. The event must:

- verify its own event digest and Ed25519 signature against the collector public key pinned by the control configuration hash;
- identify the exact validation case;
- cover the full declared observation window;
- include both the Execution Proof digest and Execution Containment receipt digest as source digests;
- include exactly one `defense_validation_observation` finding;
- bind `control_ref`, `case_ref`, `status`, `execution_hash`, alert offset and completed observation offset into a canonical SHA-256 digest;
- use `VERIFIED` evidence state for that finding.

A self-produced or caller-resealed event, missing source digest, altered observation binding, incomplete window, or status that contradicts the verified control decisions is rejected before the deterministic evaluator sees it.

## Claim boundary

This is **component-level implementation evidence**, not production defense evidence.

The test intentionally does not:

- send a mainnet transaction;
- use a production wallet, key or Safe owner identity;
- prove a deployed API/runtime call path reaches Execution Proof;
- close connectivity issue #864;
- prove a separate production collector process observed a live attack;
- replace the planned pinned-fork / Anvil execution evidence required by `safe-intent-mutation-v1.json`.

The unit harness uses deterministic fixture state hashes and a deterministic test-only collector signing key whose public key is pinned in the control configuration. Therefore its `validated` evaluator result is scoped to the component harness only and MUST NOT be presented as a production control-validation claim.

## Next acceptance gate

The next slice is to replace fixture execution/state evidence with a pinned isolated EVM backend run and a collector process that is operationally separate from the control under test. The same adapters and evaluator should then consume those artifacts without changing verdict semantics.
