# Koschei Web3 Hub — Consolidation Pass, July 26, 2026

Scope: code-side audit against `docs/final-release-checklist.md` and closure of the
two P0 gates that were blocked on code rather than on infrastructure.

**Release state after this pass: Production Candidate.** Not Final GA. Section 14
of the checklist requires production evidence for every P0 field, and two gates
still have no code path at all (#698, section 11).

---

## 1. What the audit found

The codebase is large (537 Go files, 84 migrations, 8 CI workflows) and the
evidence product is coherent. Three findings were release-blocking.

### Finding A — no worker was event-driven (#697)

There was no `LISTEN`/`NOTIFY` anywhere in the repository, and three workers ran
fixed high-frequency tickers regardless of queue depth:

| Worker | Interval | Empty queries/day |
| --- | --- | --- |
| `handlers.canonicalInvestigationJobWorker` | 2s | ~43,200 |
| `webhooks.StartDeliveryWorker` | 4s | ~21,600 |
| `alerts.StartDeliveryWorker` | 4s | ~21,600 |

That is roughly 86,000 empty claim queries per day against an idle database. A
Neon compute cannot enter its idle window under that load, so #698 was
unreachable and the section 10 cold-wake sequence could never have passed — step
3 ("confirm the production compute enters suspended state") would fail every
time.

The other twelve tickers in the codebase are gated behind
`KOSCHEI_AUTOMATIC_SCANNING_ENABLED` (via `AutomaticBackgroundScanningEnabled`
and `watchlistMonitorEnabled`), so in the section 3 required production
configuration they are already off. These three were the entire always-on
footprint.

### Finding B — retention deleted without archiving (#699)

`securityRadarRetentionWorker.runOnce` issued bare `DELETE` statements against
five tables — verdicts, events, seen signatures, stream events and trade events —
with no archive, no checksum and no run record.

Checklist section 6 states plainly: *production deletion is forbidden until
archive record counts and checksums match the selected source data.* This was
live, unbounded-in-consequence data loss on a 12-hour timer, and it was the most
serious issue in the audit — worse than #697, because polling wastes money while
this destroys evidence.

### Finding C — no OpenAPI document exists

Section 11 requires a validated OpenAPI 3.1 document. No file in the repository
matches `openapi` or `swagger`. This is unstarted, not merely incomplete.

---

## 2. What this pass changed

### #697 — event-driven wake-up: code complete

New package `koschei/api/internal/workerwake`.

Design note worth recording, because the obvious answer is wrong here:
**PostgreSQL `LISTEN`/`NOTIFY` was rejected deliberately.** A listener holds an
open connection, and an open connection is itself activity — it would suppress
compute suspend exactly as effectively as the polling it replaced. On a
scale-to-zero control plane, `LISTEN` is not an optimization.

Every producer and consumer runs in one process (`main.go` starts all three
workers with the same `appCtx` and `*sql.DB`), so the wake is in-process:

- `workerwake.Signal(name)` fires after the enqueue commits;
- the consumer sleeps until a signal, the next scheduled retry, or a bounded
  ceiling;
- `NextDueSleep` asks the database once, on the transition into idle, how long
  until the next `pending`/`retry` row is claimable — instead of asking every
  four seconds.

Idle cost falls from ~86,000 queries/day to at most 96 (one per 15-minute
ceiling), and delivery latency for a real enqueue improves, because the signal
arrives immediately rather than at the next tick.

The ceiling is the safety net for wakes that cannot arrive in-process: another
Railway instance enqueued the row, or the process restarted mid-flight. It is
clamped to [60s, 3600s] — the floor exists so a misconfiguration cannot quietly
recreate a high-frequency poll.

Producers signalling after commit:

- `jobs.Store.Create` and `jobs.Store.CreateUniqueActive` (the latter after
  `tx.Commit`, since a signal before the row is visible would be coalesced away
  and the job would then wait for the full ceiling);
- `handlers` webhook test delivery;
- `alerts.Emit` when a system channel row is actually queued, plus explicit webhook retry/test enqueue paths.

Claim failures now back off for five seconds rather than either spinning or
parking for the full ceiling, so a transient database error cannot strand a
queued job for minutes.

Files: `internal/workerwake/workerwake.go` (new),
`internal/workerwake/workerwake_test.go` (new, 18 cases),
`internal/webhooks/worker.go`, `internal/alerts/worker.go`, `internal/alerts/alerts.go`,
`internal/jobs/store.go`, `internal/handlers/webhooks.go`,
`internal/handlers/canonical_investigation_job_worker.go`.

Additional audit corrections made before publication:

- webhook retry scheduling excludes paused endpoints, preventing a due paused row
  from causing a zero-sleep claim loop;
- manual webhook retries and newly queued system alerts signal their workers;
- generic job creation signals the canonical worker only for the two job types it
  can actually claim, avoiding unrelated job traffic waking an empty consumer;
- retention query errors now halt and record the run instead of being logged as a
  successful pass.

### #699 — archive before delete: code complete

New migration `084_radar_retention_archive.sql` adds
`radar_retention_archive` (with a `UNIQUE (source_table, source_id)` constraint,
a SHA-256 `row_checksum`, the full row as `jsonb`, and `exported_at`/`export_ref`)
plus `radar_retention_runs` as a per-run ledger.

The retention worker was rewritten so the guarantee is structural rather than
procedural. Archive, payload/checksum verification and deletion share one
statement. The `DELETE` is enabled only when the complete selected batch has an
exact archive match:

```sql
WITH expiring AS (SELECT row id, to_jsonb(t) ... FOR UPDATE SKIP LOCKED),
     archived AS (INSERT INTO radar_retention_archive ... RETURNING source_id, checksum, payload),
     verified AS (SELECT exact payload/checksum matches),
     batch_ok AS (SELECT 1 only when selected = archived = verified),
     removed  AS (DELETE ... WHERE id IN verified AND EXISTS (SELECT 1 FROM batch_ok))
SELECT selected, archived, verified, deleted counts
```

Deleting an unarchived or checksum-mismatched row is not expressible in that
shape. `ON CONFLICT DO UPDATE` keeps a resumed run idempotent, while the existing
payload and checksum must still match before the source batch can be deleted.
`arvis_stream_processing` is archived before its parent stream event, and parent
deletion is blocked while any processing row remains, so the foreign-key cascade
cannot bypass the archive contract.

The worker fails closed on four conditions, each leaving the hot tables intact:

1. archive tables absent (migration 084 not applied);
2. a batch where `selected != archived` or `archived != deleted`;
3. any row whose recomputed checksum does not match the stored value;
4. unexported archive backlog above `KOSCHEI_RADAR_ARCHIVE_BACKLOG_MAX`.

Condition 4 is the honest part of the design. An archive in the same database
does not by itself reduce hot storage — it relocates it. So the archive is a
staging ledger: an export step must move rows out of the control plane and stamp
`exported_at`, and only exported rows may be pruned. Until that export is wired,
the backlog ceiling halts deletion rather than trading one table's growth for
another's.

**This means #699 is not closed by this pass.** The deletion contract is now
correct and safe, but the export sink does not exist yet. See section 3.

---

## 3. What remains before Final GA

Ordered by what blocks what.

1. **Wire the archive export sink.** Until something stamps `exported_at`, the
   archive accumulates and — by design — eventually halts retention. #699 needs
   an export target (object storage or an external warehouse), a writer that
   verifies checksums at the destination, and evidence that counts match. This is
   the single most important remaining item, because the current state is safe but
   not sustainable.

2. **#698 — Neon control-plane limits.** Now unblocked. Enable scale-to-zero, cap
   max compute to the approved value, configure spending alerts. Set
   `KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS` above the configured idle window, or
   the compute still never suspends.

3. **Run the section 10 cold-wake sequence.** This is the acceptance test for
   items 1–2 and cannot be substituted with reasoning. Expected observable: the
   compute suspends during the idle window, a manual Safe Check wakes it, the scan
   completes, and no high-frequency empty-query pattern returns.

4. **OpenAPI 3.1 document plus CI validation** (section 11). Unstarted.

5. **Section 9 asynchronous acceptance** — seven production tests, none of which
   the code changes here can satisfy on their own.

6. **`pg_stat_statements`**, storage/latency/connection alerts, stale-lease
   recovery evidence, job payload retention policy (section 6 open boxes).

7. **#653** and the G703/G704 CI exclusion (section 5), before any
   enterprise/public GA announcement.

8. **#662** stays closed as the execution-plane gate. Nothing here touches it, and
   public copy must continue to not describe the sandbox plane as
   production-ready.

---

## 4. Verification status of this pass — completed August 2, 2026

The July 26 consolidation was re-verified in GitHub Actions on the repository's
required toolchain, `go version go1.25.12 linux/amd64`, against PostgreSQL 17.10.
The first strict run correctly failed because `gofmt -l .` exposed repository-wide
formatting debt. The complete Go tree was normalized with `gofmt -w koschei/api`,
and the permanent verification run then passed every gate without weakening any
check.

Commands and results from `Release Gates Verification` run 6:

```text
go version
# go version go1.25.12 linux/amd64

gofmt -l .
# no output

for migration in $(find migrations -maxdepth 1 -type f -name '*.sql' | sort); do
  psql --set=ON_ERROR_STOP=1 --file="$migration"
done
# all migrations passed on PostgreSQL 17.10

SELECT encode(sha256(convert_to('{}','UTF8')),'hex');
# 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a

go test -v ./internal/services -run '^TestRetentionArchiveDeletePostgres17$' -count=1
# PASS: initial archive/delete, resumed ON CONFLICT path, checksum-mismatch fail-closed path

go test ./...
# PASS

go test -race ./internal/handlers ./internal/services ./internal/defense
# PASS

go vet ./...
# PASS

CGO_ENABLED=0 GOOS=linux go build ./...
# PASS
```

The transaction-guard v3 authority, CPI-flow and threat-history collectors are
also protected by a reachability/fail-closed test anchored in the registered v2
evidence-first handler. The test requires all three collectors and the final
assessment/response functions to remain called from that endpoint, and confirms
that incomplete required evidence produces `withhold` with unknown risk rather
than an allow/deny decision.

**Task 5 verification gate is closed.** This result verifies the repository tree
and the July 26 consolidation mechanics; it does not close the separate archive
export, OpenAPI, funding-origin bounded-state or migration-hygiene gates listed
in the August 2 release briefing.

---

## 5. Hygiene note, not a blocker

`koschei/api/migrations/` has duplicate numeric prefixes — two `078_` files and
two `081_` files — and no `082_`. The runner keys `schema_migrations` on the full
filename (`filepath.Base`), so this is not a correctness bug and both files in
each pair apply. But ordering within a duplicated prefix falls to alphabetical
sort, which is chance rather than intent. If either pair has a dependency, that
should be made explicit before the numbering gap is inherited by future
migrations.
