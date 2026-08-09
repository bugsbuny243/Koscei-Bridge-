# Koschei Sovereign Ingest Plane

Status: implemented behind a safe runtime gate.

## Purpose

The stream listener must never silently discard a recognized Solana observation merely because an in-process analysis queue is full. Intake, persistence, enrichment and verdict production are separate responsibilities.

This layer is intentionally evidence-first. It improves transport reliability; it does not make a risk claim stronger and it does not grant any new verdict authority.

## Runtime modes

```env
# Safe compatibility default.
KOSCHEI_STREAM_INGEST_MODE=legacy

# Durable-first journal path.
KOSCHEI_STREAM_INGEST_MODE=journal
KOSCHEI_STREAM_JOURNAL_WRITERS=4
KOSCHEI_STREAM_ENRICHMENT_BATCH=25
RADAR_EVENT_BUFFER_SIZE=5000
```

`legacy` preserves the pre-existing SBX-1 collector.

`journal` uses this pipeline:

```text
Solana WSS
  -> bounded decode only
  -> blocking backpressure queue
  -> retry-until-persisted Postgres raw-event journal
  -> independent transaction enrichment loop
  -> existing ARVIS stream verdict worker
  -> evidence/verdict tables
```

## Reliability contract

Journal mode currently guarantees the following inside a live process:

1. Queue saturation no longer has a `default` branch that silently drops the incoming event.
2. Intake applies backpressure until capacity returns or the process context is cancelled.
3. Once a persistence worker dequeues an event, a transient database write error is retried with bounded exponential backoff until the insert succeeds or the process is shutting down.
4. Heavy transaction enrichment is not performed by the WSS reader.
5. Enrichment work is claimed from the persisted journal with PostgreSQL `FOR UPDATE SKIP LOCKED` semantics.
6. Enrichment attempts are bounded and recorded in the event metadata.
7. The existing database uniqueness contract remains the duplicate-event boundary.
8. The existing ARVIS stream verdict worker remains responsible for evidence qualification and verdict persistence.

## What this does NOT guarantee yet

Journal mode is not described as globally lossless yet.

A process, host or WSS connection can disappear after Solana produced an event but before Koschei committed that observation. Closing that class of gap requires an independent chain gap-healing/replay subsystem.

Therefore the next reliability gate is:

```text
persisted high-water mark
  + reconnect boundary
  + program-specific signature backfill
  + canonical RPC verification
  + idempotent replay into security_radar_stream_events
```

Only after that gate passes under failure injection should Koschei claim replay-complete ingestion.

## Rollout gates

Journal mode should remain opt-in until all of these are demonstrated:

- required CI test/vet/build is green;
- Railway build and startup are healthy;
- production database migrations are current;
- stream-event insert latency and backlog are observable;
- WSS disconnect/reconnect tests do not create unreported gaps;
- enrichment retries and exhaustion are visible to the owner plane;
- no customer verdict is emitted solely because an event was transported successfully.

## Relationship to the ARVIS war architecture

This is the first sovereign reliability step and does not require Redis to be correct.

Postgres is currently the durable raw-event journal already used by the deployed system. A later Redis Streams/NATS/Kafka-class transport may be introduced for horizontal throughput, consumer groups and large burst absorption, but it must preserve the same invariants:

```text
capture != verdict
transport success != evidence verification
ack only after durable handoff
replay must be idempotent
provider disagreement must remain visible
```

## Next gate: Slot Gap Healer

The next implementation phase should add a deterministic replay worker with explicit evidence provenance:

1. Record per-program observed high-water slots and signatures.
2. Detect reconnect boundaries and suspicious slot discontinuities.
3. Backfill bounded program histories through canonical Solana RPC.
4. Corroborate critical recovered state through Evidence Court when policy requires it.
5. Insert recovered observations through the same dedupe contract as live observations.
6. Mark every recovered event with `source=replay`, replay window and provider provenance.
7. Expose `live`, `replayed`, `gap_pending` and `gap_conflict` counters.
8. Never fabricate a recovered event when RPC history is unavailable.

That closes the remaining gap between "does not drop under local pressure" and a genuinely replayable sovereign observation plane.
