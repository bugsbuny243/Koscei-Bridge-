# Pump Address Integrity Checkpoint

## CURRENT STATE

- Production main before this branch: `c0a6c41533e9b857efc07a43e9685f33d02b59bf` (PR #985).
- Selective canonical Pump scheduling is live in Railway production with broad Solana RPC workers still paused under saver mode.
- Production selective bounds are explicit: 24h USD threshold `500000`, poll interval `5m`, maximum one canonical Pump job per cycle, six-hour report cooldown, thirty-minute attempt cooldown, shared Solana RPC budget enabled at 220 requests/hour.

## CHANGED

- Active branch: `fix/pump-solana-address-integrity`.
- Canonical Pump candidate identity now uses exact Solana mint equality instead of `lower(...)` case folding.
- Candidate pagination uses byte-stable `C` collation for the mint tie-break.
- Canonical attempt cooldown now matches the exact mint only.
- The dormant legacy inline Pump worker was not re-enabled or expanded.

## VERIFIED

- Repository diff is limited to the canonical scheduler, exact Solana identity helper, PostgreSQL regression, and this checkpoint.
- PostgreSQL regression inserts two mints whose lowercase forms collide and requires both to remain distinct candidates.
- The regression also proves an attempt recorded for one mint does not suppress its case-variant mint.
- Permanent CI is pending until the PR is opened; do not merge until exact-head, merge-candidate and target-freshness gates pass.

## BROKEN / MISSING

- Legacy dormant Pump helper paths still contain historical case-folded queries. They are not production canonical scheduling authority and should not be revived without the same exact-address treatment.
- A production DB read through the Neon connector could not be completed because the connector rejected its own documented argument naming; no SQL mutation occurred.

## NEXT

1. Run exact branch head through permanent CI and PostgreSQL 17 tests.
2. Merge only after exact candidate and target freshness pass.
3. Verify Railway deploy and confirm selective scheduler remains active while broad RPC workers stay paused.
4. Observe production scheduler cycles for provider/RPC errors before changing any throughput bound.

## RISKS

- Solana base58 addresses are case-sensitive; case folding can merge unrelated token identities, corrupt cooldown state, or skip a valid investigation.
- Selective Pump remains intentionally bounded; do not raise threshold throughput or enable broad RPC streams as part of this integrity repair.
