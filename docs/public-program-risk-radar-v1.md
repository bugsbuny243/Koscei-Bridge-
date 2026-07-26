# Koschei ARVIS — Public Program Risk Radar v2

Audit date: 2026-07-26

This contract connects Defense OS Program Sentinel evidence to the public ARVIS product without exposing private scans, binary artifacts or internal worker details.

## Product access

Program Sentinel is available to authenticated users and API accounts through `GET|POST /api/v1/defense/sentinel`. A single on-chain monitor may be shared safely by multiple subscribers, but each subscription remains independently owned. A later subscriber cannot take over another subscriber's manifest or publication rights.

Owner endpoints remain for operations and moderation; they are not the only product path.

## Explicit publication

Program snapshots and change events are private by default. They enter public APIs only when an authorized monitor subscriber or owner moderator creates a `program_risk_publications` row with `status=public`.

Visibility changes are recorded in immutable `program_risk_publication_events` rows.

## Published evidence

Two immutable evidence families may appear:

1. `program_control_risk_observed`
   - only the latest immutable `KDS1-...` snapshot for the program and network;
   - open upgrade authority;
   - independently evaluated source-manifest versus deployed-bytecode mismatch;
   - a current program account that is not executable.

2. `program_deployment_changed`
   - immutable `KDCE1-...` Program Sentinel event;
   - bytecode, loader or ProgramData address change;
   - upgrade authority opened or changed;
   - current open-authority, executable and source-mismatch controls merged into the event so deduplication cannot hide ongoing risk.

Only HIGH and CRITICAL evidence is eligible.

Configuration-only changes such as removing an optional manifest are not published as verified on-chain transitions.

## Public surfaces

- `GET /api/public/program-risks`
- `GET /api/public/program-risks/<KDS1-or-KDCE1-ref>`
- `GET /program-risk/<KDS1-or-KDCE1-ref>`
- `GET /api/public/soc/feed`
- `/live`

Visibility surface:

- `POST /api/v1/program-risks/publications`

## Decision and action contract

Every public risk carries:

- `decision`: `WARN` or `BLOCK`;
- `recommended_action`;
- severity and lifecycle status;
- actual inspectable evidence references and count;
- current and previous public deployment state;
- a canonical public `verification_payload`;
- a reproducible SHA-256 `verification_hash`.

The public page explains what happened, why it matters and what the user should do. It does not merely dump hashes or worker state.

## Privacy and truth boundaries

- Private snapshots never appear without explicit publication.
- Only the latest snapshot may describe a control as current. Superseded snapshots return not found from current-risk routes.
- Open upgrade authority proves technical changeability, not malicious intent.
- A source mismatch is published only after an independently supplied manifest contradicts deployed bytes.
- `not_requested`, `invalid_manifest`, `not_evaluated` and missing-source states are not mismatch claims.
- A baseline with `executable=false` is described as currently non-executable, not as a proven loss of executability.
- Evidence counts equal the number of public inspectable evidence references; synthetic counts are forbidden.
- Binary artifact bytes and internal `artifact:` references are excluded from the public projection.
- Program evidence has `verdict_authority=false`; it does not silently alter a signed ARVIS letter grade.
- No actor identity, intent, exploitation or wrongdoing claim is made without separate evidence.

## Performance contract

The public change feed uses a partial index over HIGH/CRITICAL event creation time. Public requests must not scan and sort the entire immutable Program Sentinel history every 15 seconds.

## Next analyzer layer

Instruction-level sBPF/source findings remain a separate evidence family. Before public release they require explicit creator publication, redacted source locations, versioned rule IDs, reproducible analyzer versions, false-positive boundaries and no exploitation claim without runtime or transaction evidence.
