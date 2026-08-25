# Koschei Defense Validation API v1

Koschei Defense Validation answers a different question from transaction scanning:

> Did the declared defense actually catch the isolated attack case in time, while leaving the matched benign case clean?

The first production API slice exposes the existing execution-integrity validation substrate through the Enterprise developer API. It evaluates already-collected fork/sandbox evidence. It does **not** execute arbitrary customer commands, submit mainnet transactions, mutate production controls, hold wallet keys, or treat AI output as verdict authority.

## Route

`POST /api/v1/defense/validation`

Access: Enterprise API key plus active Enterprise SaaS entitlement. The route uses the existing developer API rate/accounting middleware.

## Evidence contract

A request contains:

- `run_ref`: caller correlation identifier.
- `scenario`: the complete `koschei-defense-validation-scenario/v0.2` JSON contract. The server reparses and hashes the complete contract; duplicate keys, unsafe execution flags, missing safety fields, unsupported control classes, or a mutated contract are rejected.
- `controls`: execution-integrity controls, each with a distinct `control_ref`, independent `collector_ref`, and trusted Ed25519 collector public key.
- `cases`: zero or more isolated attack/benign execution evidence bundles.

Each submitted case contains:

- case identity, kind, technique, execution mode, timing and observation window;
- a recomputable `executioncontainment.Receipt`;
- a recomputable `executionproof.Proof`;
- exact approved and candidate canonical Safe action bytes, encoded as standard base64;
- optionally, an observation binding and an Ed25519-authenticated `securityevidence.Event` from the independent collector.

The server does not accept caller-asserted `verified` case or observation states. It reconstructs those states through the existing adapters:

1. `NewExecutionIntegrityControlV02`
2. `AdaptExecutionIntegrityCaseV02`
3. `AdaptSecurityEvidenceObservationV02`
4. `EvaluateDefenseValidationV02`

## Decision model

Per attack case, the deterministic evaluator can produce:

- `caught_in_time`
- `caught_late`
- `missed`
- `incomplete`

Per matched benign case it can produce:

- `clean`
- `false_positive`
- `incomplete`

The control/report verdict is one of:

- `validated`
- `failed`
- `incomplete`

A missing case or missing independent observation is not converted into a pass. Coverage gaps remain `incomplete`.

## Independent witness requirement

The collector identity must be different from the control identity. Observation events must verify against the trusted Ed25519 public key supplied in the control configuration. A caller-resealed event, an unsigned event, a forged signature, a mismatched case/control binding, or a different execution hash is rejected.

The trusted public key is configuration input; it is never accepted from the signed event itself.

## Execution integrity requirement

Submitted execution evidence is accepted only when the existing adapter can bind the exact scenario, control configuration, containment receipt, execution proof, approved Safe action, candidate Safe action, pre-state, post-state and timing into one execution hash.

The adapter rejects evidence when, among other conditions:

- the containment receipt cannot be recomputed;
- isolated backend evidence is unavailable;
- the execution proof cannot be recomputed;
- approved/candidate action bytes do not match their bound hashes;
- the case does not match the scenario-declared security difference;
- an unrelated containment reason is presented as the declared attack;
- the execution mode is not fork/sandbox;
- mainnet transaction evidence is claimed.

## Request limits

The first API version deliberately stays bounded:

- maximum scenario JSON: 256 KiB;
- maximum controls: 8;
- maximum cases: 64;
- maximum decoded canonical action: 128 KiB per action;
- global JSON request-body limit remains 1 MiB through the common API decoder.

These bounds reduce memory/CPU abuse and keep the endpoint an evidence evaluator rather than an arbitrary execution surface.

## Response

A successful response includes:

- `product: "Koschei Defense Validation"`;
- the recomputed scenario contract hash;
- number of verified execution bundles;
- number of independently authenticated observations;
- the deterministic `DefenseValidationReportV02`, including per-case outcomes, evidence references/hashes, rule hits and report hash;
- explicit `mainnet_transaction_sent: false`;
- explicit `execution_authority: false`;
- explicit `production_control_mutation: false`.

No numeric safety score is added by this API.

## Current scope

The production route currently exposes the existing `pre_signing_execution_integrity` / `koschei_execution_proof` validation adapter and its Safe-oriented isolated execution evidence. It does not yet claim generic validation of every third-party Web3 security product.

The next expansion should add provider-neutral control adapters that preserve the same independent-witness contract, so Blockaid/Hypernative/custom policy engines or protocol monitors can be tested without weakening evidence authenticity.

## Product boundary

This API is separate from the owner-only Defense OS harness routes. Defense OS may prepare/reproduce isolated evidence when explicitly enabled. The Enterprise API only verifies and evaluates submitted evidence; it does not expose arbitrary harness execution to customers.

A `validated` result therefore means:

> For this exact scenario contract, control configuration, isolated execution evidence and independently signed observation set, the evaluated attack/benign matrix satisfied the deterministic validation rules.

It does not mean that every possible attack is covered, that production infrastructure cannot be compromised, or that Koschei submitted or blocked a mainnet transaction.
