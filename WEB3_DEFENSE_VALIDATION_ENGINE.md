# Koschei Web3 — Defense Validation Plane

**Product contract — v0.2**  
**Ruleset:** `koschei-defense-validation-rules-v0.2.0`  
**Status:** canonical product direction; not a production-enforcement claim  
**Core:** chain-neutral; adapters preserve chain-specific execution semantics

## 0. Product boundary

Koschei Web3 answers one product-wide question:

> Does this exact Web3 defense configuration actually stop or detect this controlled attack before impact, while allowing the matched benign action?

Koschei Web3 is the product/control-plane layer. Koschei Sentinel remains the security-intelligence and adversarial-reasoning project. Koschei Lang remains the hardened language/runtime and authority project. Neither is a required production dependency of this repository today.

The legacy ARVIS/Radar/Actor stack remains a production security sensor. It can supply evidence and attack-pattern context, but it does not own defense-validation outcomes.

## 1. Why this layer exists

A code audit, monitoring alert, wallet warning, signer policy, node guard or bridge monitor can be implemented correctly and still fail at the real execution boundary. Koschei therefore validates the complete control configuration instead of trusting a dashboard, vendor self-attestation or serialized ALLOW value.

A validation run binds:

- exact scenario identity and version;
- exact control/adapter version and configuration hash;
- controlled fork/sandbox execution evidence;
- independent observation evidence;
- attack impact deadline;
- completed observation window;
- matched benign control;
- deterministic evaluation rules;
- immutable report identity.

## 2. Current repository substrate

The validation plane reuses existing Koschei components instead of replacing them.

| Component | Role in validation plane | Current authority status |
| --- | --- | --- |
| Security Evidence Bus | Canonical backend-generated evidence envelope and digest binding | Wired into trusted token-scan response path |
| Matrix Containment | Deterministic RELEASE / CONTAIN / UNAVAILABLE evaluation for exact action/state/effect evidence | Internal security kernel |
| Execution Proof | Intent/payload/invariant/Safe binding and forwarding boundary | Implemented internally; **not production-wired** until issue #864 closes |
| Defense OS | Immutable artifacts, reproduction, harness planning and isolated execution substrate | Present but default-off behind explicit feature gates |
| Node Shield | Runtime identity/capability containment and kernel evidence | PR #841; live compatible-kernel proof required before merge/production claim |
| ARVIS / Radar / Actor | Production security sensor and investigation evidence | Production-supported sensor; not validation authority |

No component becomes production-active merely because its package compiles or its tests pass. Production enforcement requires a verified runtime call chain and production evidence.

## 3. Validation topology

```text
versioned attack case ─┐
matched benign case ───┤
control configuration ─┤
                       ▼
              Validation Orchestrator
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     Defense OS    EVM/Safe      Node Shield
     / chain lab   execution      / runtime witness
          │            │            │
          └────────────┼────────────┘
                       ▼
              Security Evidence Bus
                       │
                       ▼
             deterministic evaluator
                       │
       caught_in_time / caught_late / missed
       false_positive / clean / incomplete
                       │
                       ▼
          validated / failed / incomplete
```

The evaluator is deterministic and I/O-free. It does not execute code, call a model, access a wallet, submit a transaction or mutate a production control.

## 4. Mandatory case matrix

Every validation target requires at least:

1. **Attack case** — controlled malicious action with a defined impact deadline.
2. **Benign control** — authorized/normal action matched to the same security surface closely enough to expose false positives.

Attack-only testing is incomplete. A control that alerts on everything is not validated.

### Case outcomes

| Outcome | Meaning |
| --- | --- |
| `CAUGHT_IN_TIME` | Verified alert reached the independent collector at or before the impact deadline |
| `CAUGHT_LATE` | Verified alert arrived after impact deadline |
| `MISSED` | Completed verified attack observation window contained no alert |
| `FALSE_POSITIVE` | Matched benign case produced an alert |
| `CLEAN` | Completed verified benign observation window produced no alert |
| `INCOMPLETE` | Execution, observation, timing or evidence chain could not be verified |

### Control verdict

- any `CAUGHT_LATE`, `MISSED` or `FALSE_POSITIVE` => `FAILED`;
- no failure but any `INCOMPLETE`, or missing attack/benign coverage => `INCOMPLETE`;
- all mandatory attacks caught in time and benign controls clean => `VALIDATED`.

`VALIDATED` is scoped only to the exact control version, configuration hash, scenario version, evidence set and observation window in the report. It is never a general claim that a protocol, wallet or vendor is safe.

## 5. Ruleset v0.2

| Rule | Requirement |
| --- | --- |
| `DV-R01` | Missing/unverified fork or sandbox execution cannot validate |
| `DV-R02` | Missing/unverified independent observation cannot validate |
| `DV-R03` | Alert after impact deadline is `CAUGHT_LATE` |
| `DV-R04` | Completed attack window with no alert is `MISSED` |
| `DV-R05` | Benign alert is `FALSE_POSITIVE` |
| `DV-R06` | Missing attack + benign matrix or incomplete observation is `INCOMPLETE` |
| `DV-R07` | Mainnet transaction evidence in a controlled validation case is rejected |
| `DV-R08` | Control cannot be its own independent collector |
| `DV-R09` | Report identity binds evidence content hashes, not run-local references |
| `DV-R10` | AI, UI and vendor self-attestation have no verdict authority |

No weighted security formula, probability or 0–100 aggregate security score exists in this ruleset. Detection time, lead time, miss count and false-positive count are direct measurements.

## 6. Evidence requirements

A `VALIDATED` result requires verified evidence for:

- scenario and case identity;
- fork/sandbox execution;
- pre-state and post-state;
- exact control configuration;
- independent collector observation;
- complete observation window;
- alert evidence when an alert exists;
- impact deadline for attacks;
- ruleset identity.

Missing, malformed, stale, contradictory or unverified evidence fails closed to `INCOMPLETE` or input rejection. Koschei does not synthesize successful evidence.

## 7. Authority and safety boundary

Validation work must preserve all of the following:

```text
wallet_custody=false
mainnet_transaction_sent=false
production_control_mutation=false
automatic_intervention=false
arbitrary_command_execution=false
ai_verdict_authority=false
ui_verdict_authority=false
```

Controlled execution must remain inside approved fork/sandbox/isolated runtime boundaries. Production signing/forwarding must not be wired to experimental packages merely to demonstrate the feature.

## 8. First machine-evaluable slice

The first mergeable slice consists only of:

- chain-neutral deterministic evaluator;
- exact control configuration identity;
- verified attack + benign matrix;
- independent collector requirement;
- impact/deadline and observation-window timing;
- fail-closed verdict aggregation;
- order-independent report hashing;
- unit tests for late detection, miss, false positive, incomplete evidence, matrix completeness and no-mainnet rejection.

It adds no route, migration, worker action, signing authority or production feature activation.

## 9. First planned flagship scenario: Safe intent mutation

The first cross-chain flagship validation scenario should model the class of failure where a human/operator intends one privileged Safe action while a compromised presentation/build path presents different executable bytes.

The scenario must bind and independently verify:

```text
human/approved intent
        ↓
canonical Safe transaction
        ↓
locally recomputed safeTxHash
        ↓
exact full action bytes
        ↓
pinned EVM state
        ↓
actual isolated execution
        ↓
authority + asset + code + trace invariants
        ↓
independent observation
        ↓
validation verdict
```

Attack and benign cases must use matched treasury/security surfaces. The attack case must not be called validated until a concrete isolated EVM backend and independent observation evidence exist. The current `internal/executionproof` package remains non-production-wired until the #864 connectivity gate is satisfied.

## 10. Expansion sequence

After the evaluator is accepted:

1. define versioned scenario schema and planned Safe intent-mutation fixture;
2. add one-way adapters from existing immutable Defense OS / isolated EVM evidence into the evaluator;
3. add independent collector contracts;
4. prove a weak configuration `FAILED` and a corrected configuration `VALIDATED` using the same immutable scenario;
5. add vendor-neutral control adapter interface;
6. add value-at-risk / blast-radius evidence as measurements, never as fabricated precision;
7. add continuous regression campaigns only behind explicit opt-in gates;
8. later integrate Sentinel for scenario generation/correlation without giving model output deterministic authority.

## 11. Product truth rule

Customer-facing copy must distinguish:

- **implemented core**;
- **integration pending**;
- **in validation**;
- **production-wired/proven**.

A package existing in `main` is not sufficient evidence for a production claim. This rule is especially binding for Execution Proof and Node Shield.
