# ARVIS Evidence-Backed Decision v1

## Purpose

This bridge closes the chain-neutral ARVIS investigation contract without creating a second verdict engine.

The authoritative grade remains the existing deterministic `UnifiedRadarVerdict`. The bridge only projects that signed verdict into `IntelligenceInvestigation.Decision` when every grade-determining rule can be traced back to canonical evidence already present in the investigation.

The intended product path is:

`Address → Entity → Transaction → Behavior → Threat Hypothesis → Attack Path → Evidence → Decision`

## Evidence authority

The decision bridge accepts only canonical evidence with status `verified` or `observed`.

A grade-determining rule may be linked through an existing evidence transaction hash/signature or through explicit evidence metadata such as `rule_id`, `evidence_key`, `evidence_keys`, or `signatures`.

The bridge does not infer missing evidence and does not manufacture relationships to make a verdict look complete.

## Fail-closed behavior

If a signed grade exists but one or more grade-determining rules cannot be linked to canonical evidence, the chain-neutral decision remains withheld:

- `status = unverified`
- `action = investigate`
- `confidence = 0`
- missing rule IDs are included in the reasons

A signed `no_grade_trigger` result is not converted into an approval or safety claim. It remains the investigation contract's default `unverified / investigate` state.

## Successful projection

When every grade-determining rule is linked:

- all verified rule/evidence inputs produce `status = verified`
- any observed determining input produces `status = observed`
- `action = review_signed_verdict`
- evidence IDs are attached as canonical `evidence_refs`
- `confidence = 1`

`confidence = 1` means the projection is completely provenance-linked. It is not a probability of maliciousness, rug probability, exploit likelihood, or safety score.

## Rule selection

For `hard_trigger` verdicts, hard-trigger or hard-cap rules are grade determining.

For `compounding_rule` and `severe_compounding_rule` verdicts, compounding-tier rules are grade determining.

Supporting rules are intentionally excluded from the completeness gate when they did not determine the final grade. This prevents non-authoritative supporting evidence gaps from invalidating an otherwise fully evidenced deterministic grade.

## Current scope

v1 projects Solana investigations because Solana is the current production-live ARVIS evidence source. The intelligence contract itself remains chain-neutral.

Adding another chain requires a real chain adapter that produces canonical evidence and relationships matching the common intelligence contract. Do not copy Solana-specific assumptions into core intelligence.

## Security invariants

1. The bridge never re-grades the target.
2. The bridge never predicts intent.
3. Missing evidence is never treated as safe evidence.
4. A no-grade result is never an approval.
5. Evidence references must resolve to evidence already present in the canonical investigation.
6. Numeric risk/rug probability is not introduced by this bridge.
7. The existing signed deterministic verdict remains the sole grade authority.

## Test coverage

Handler-level tests cover:

- verified hard-trigger evidence linkage
- fail-closed behavior for missing canonical evidence
- isolation of non-grade-determining supporting rules
- observed compounding evidence
- no-grade behavior
