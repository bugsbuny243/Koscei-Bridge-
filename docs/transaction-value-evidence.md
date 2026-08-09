# ARVIS Transaction Value Evidence v1

Status: read-only evidence surface for Transaction Guard. It is intentionally not used by Guard scoring, verdicts or permit policy in v1.

## Purpose

A single scalar called "transaction value" is unsafe when evidence mixes explicit transfers, wallet net balance changes, fees, rent/account creation, token raw amounts and unresolved CPI behavior. Value Evidence v1 keeps those surfaces separate and deterministic so later policy can be built only on verified semantics.

Schema version:

```text
koschei-transaction-value-evidence-v1
```

The Guard v3 response exposes:

```text
transaction_value_evidence_complete
transaction_value_evidence
```

## SOL evidence

Value Evidence records explicit System Program SOL movements from decoded outer instructions plus CPI SOL movements only when the CPI collector marks them `inner_only=true`. This prevents an outer instruction and its matching inner observation from being counted twice.

It exposes:

- `explicit_sol_lamports`: total explicit decoded SOL movement across the transaction;
- `wallet_explicit_sol_outflow_lamports`: explicit movement whose source is the requested wallet;
- individual `sol_movements` with origin, kind, source, destination, lamports and wallet-origin identity;
- observed wallet SOL delta/spent/received from automatic simulation balance evidence as a separate surface.

Observed wallet net spend is not relabeled as transfer value. It may contain effects such as account creation/rent or fees that are not separately decomposed by this contract.

## Token evidence

Outer SPL Token / Token-2022 `transfer`, `transfer_checked`, `burn` and `burn_checked` operations are recorded. CPI token movements are added only when `inner_only=true`, preventing duplicate outer/inner counting.

Token amounts remain raw integers. Mint identity comes from the decoded instruction when present or from verified automatic-balance token-account metadata. If a token movement cannot be scoped to a mint, the movement remains visible but is excluded from mint aggregates and the overall Value Evidence becomes partial.

Mint aggregates keep transfer and burn totals separate and expose wallet-origin raw totals. A mint aggregate reports decimals only as observed metadata; `decimals_consistent=true` requires decimals to be known and equal across every aggregated movement. Raw integer aggregation does not depend on decimals.

## Wallet-origin semantics

SOL movement is wallet-origin when its decoded source equals the requested wallet.

Outer token movement is wallet-origin only when the decoded authority/source/account is the requested wallet or verified automatic-balance token-account owner metadata identifies the requested wallet as the source owner. CPI movement uses the existing CPI flow's verified `wallet_origin` classification.

No wallet relation is inferred from address similarity or transaction position.

## Coverage and fail-closed status

`complete=true` requires:

- automatic transaction decode complete;
- CPI value-flow coverage complete when requested;
- automatic balance coverage complete when requested;
- no invalid raw integer movement amounts;
- no token movement with unresolved mint identity.

Missing instructions, unresolved CPI, invalid raw amounts or unscoped token movement are not treated as zero value. The evidence becomes `partial` with explicit limitations.

## Fee and price boundary

Value Evidence v1 does not independently verify transaction fee lamports, so:

```text
fee_status = unavailable_no_verified_fee_evidence
```

It does not subtract an estimated fee from wallet net spend.

It also performs no SOL/token-to-USD conversion:

```text
price_status = not_requested_v1
```

Price evidence must remain a separate contemporaneous evidence contract before dollar-denominated policy is considered.

## Deterministic evidence identity

The evidence object carries `evidence_hash_sha256`, computed from the full normalized Value Evidence object with the hash field blanked before canonical JSON encoding. There is no clock read or provider request in this builder, so identical decoded/simulation/CPI inputs produce the same hash.

## Policy boundary

Value Evidence v1 explicitly returns:

```text
policy_use_status = evidence_only_not_enforced
```

It does not change `risk_index`, action, `guard_complete`, State Witness, enforcement permit issuance or State Recheck policy. A future value-based policy must first define which verified evidence surface is policy-relevant and how fee, token price, CPI coverage and wallet ownership are handled without inference.