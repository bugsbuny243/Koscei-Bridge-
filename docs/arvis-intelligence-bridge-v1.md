# ARVIS Intelligence Bridge v1

ARVIS remains the production Solana evidence and verdict engine. The chain-neutral intelligence contract is an additive projection layer, not a replacement.

## Current bridge

The bridge projects already-collected ARVIS evidence into `koschei-intelligence-contract-v1`:

- token/mint subject
- existing transaction evidence (`signature`, `slot`, `trader`, `direction`, `block_time`, `source`)
- canonical creator/deployer subject when ARVIS has a creator→mint evidence record
- creator/deployer entity attribution scoped to `onchain_role_only`
- creator→mint `created_token` relationship

## Verification boundary

A canonical creator→mint relationship is `verified` only when the existing ARVIS evidence record is itself marked verified and contains both:

- transaction signature
- slot

If those fields are incomplete, the relationship remains `observed`. Missing evidence never becomes a verified relationship.

## Non-goals

This bridge does not:

- replace or re-grade the ARVIS final verdict
- create a new customer safety decision
- claim real-world creator identity
- promote observed creator relations to verified
- attach Solana evidence to EVM subjects
- introduce live EVM collection

## Next bridge targets

The next production-safe projections are evidence-backed funding relationships and existing typed ARVIS attack-path evidence. Both must preserve the same no-evidence-no-claim rule.
