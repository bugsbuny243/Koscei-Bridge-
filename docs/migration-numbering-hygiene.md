# Migration numbering hygiene

Date: 2026-08-02

This document records the applied migration history exactly as it exists. The
migration runner keys `schema_migrations` by the complete filename, so every file
listed below has its own applied identity even when two files share a numeric
prefix. **Do not rename, renumber, delete, or edit an already-applied migration to
repair the numbering.** Any schema correction must be a new forward migration.

The machine-readable source of truth is
`koschei/api/migrations/migration-numbering-baseline.json`. CI compares the
current directory with that exact baseline and rejects:

- a newly added file that reuses any existing numeric prefix;
- a newly introduced numeric gap;
- renaming, removing, or replacing any accepted duplicate-history filename;
- silently filling an accepted historical gap with a newly numbered migration.

## Accepted duplicate prefixes

| Prefix | Applied filenames |
| --- | --- |
| 029 | `029_unified_reports.sql`, `029_zero_free_entitlements.sql` |
| 033 | `033_entity_access_policy.sql`, `033_security_radar_live_feed.sql` |
| 034 | `034_security_radar_seen_signatures_nullable_target.sql`, `034_wallet_ownership.sql` |
| 035 | `035_arvis_stream_processing.sql`, `035_token_access_snapshots.sql` |
| 040 | `040_arvis_exhausted_job_state.sql`, `040_customer_feedback.sql` |
| 041 | `041_arvis_processing_reconciliation.sql`, `041_raydium_live_program_source.sql` |
| 042 | `042_owner_ai_chat.sql`, `042_paddle_webhook_events.sql` |
| 043 | `043_billing_cleanup.sql`, `043_radar_queue_capacity_and_pump_source.sql` |
| 060 | `060_api_key_tier_caps.sql`, `060_kosch_daily_quota_ledger_index.sql` |
| 078 | `078_defense_harness_execution_gate.sql`, `078_defense_safe_execution_policies.sql` |
| 081 | `081_actor_transaction_evidence_idempotency.sql`, `081_defense_litesvm_execution_attempts.sql` |

These duplicates are accepted historical facts, not reusable slots.

### Prefix 078 dependency review

`078_defense_harness_execution_gate.sql` extends
`defense_toolchain_attestations` and creates
`defense_harness_execution_profiles`.
`078_defense_safe_execution_policies.sql` creates
`defense_toolchain_policies` and `defense_safe_execution_manifests`, then widens
the allowed tool names on `defense_toolchain_attestations`.

Neither migration references an object created by the other. Both depend only on
objects created by earlier migrations, including `defense_harness_plans`,
`defense_program_artifacts`, `defense_toolchain_attestations`, and
`reject_defense_runtime_mutation()`. Therefore the pair has **no ordering
dependency between its two files**. Alphabetical ordering is still recorded and
must not be changed because both filenames may already be applied.

### Prefix 081 dependency review

`081_actor_transaction_evidence_idempotency.sql` adjusts the actor transaction
evidence idempotency contract. `081_defense_litesvm_execution_attempts.sql`
creates the LiteSVM execution-attempt evidence surface. They operate on separate
schema areas and neither references an object created by the other. Therefore
the pair has **no ordering dependency between its two files**.

No forward repair migration is required for either 078 or 081 because no hidden
cross-file ordering dependency was found.

## Accepted historical gaps

The exact accepted missing prefixes are:

`026`, `027`, `032`, `048`, `049`, `050`, `051`, `052`, `061`, `082`, `085`.

The briefing specifically identified the `085` gap. It is real and accepted, but
it must remain empty: the next migration must use the next unused sequential
prefix after the current maximum, not backfill `085`. The same rule applies to
all older gaps above.

## Verification

Run from `koschei/api`:

```text
python3 scripts/check_migration_numbering.py
python3 -m unittest scripts/test_migration_numbering.py
```

The unit suite contains deliberate temporary cases proving that a new duplicate
prefix and a new skipped prefix are rejected.
