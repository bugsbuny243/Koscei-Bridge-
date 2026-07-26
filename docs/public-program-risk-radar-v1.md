# Koschei ARVIS — Public Program Risk Radar v1

Audit date: 2026-07-26

This contract publishes evidence-backed Solana program control risks through the public ARVIS SOC without exposing private scans, binary artifacts or internal worker details.

## Published evidence

Two immutable evidence families may appear:

1. `program_control_risk_observed`
   - latest immutable `KDS1-...` deployment snapshot;
   - open upgrade authority;
   - verified source-manifest versus deployed-bytecode mismatch;
   - a monitored program account no longer observed as executable.

2. `program_deployment_changed`
   - immutable `KDCE1-...` Program Sentinel event;
   - bytecode, loader or ProgramData address change;
   - upgrade authority opened or changed;
   - an independently established source match was lost.

Only `high` and `critical` program evidence is included in the public feed.

## Public surfaces

- `GET /api/public/program-risks`
- `GET /api/public/program-risks/<KDS1-or-KDCE1-ref>`
- `GET /program-risk/<KDS1-or-KDCE1-ref>`
- `GET /api/public/soc/feed`
- `/live`

The public detail projection includes program ID, network, immutable evidence reference/hash, snapshot references, canonical binary hashes, loader state, ProgramData state, upgrade authority state and source-match status.

It deliberately excludes stored program binary bytes and internal artifact references.

## Truth boundaries

- Open upgrade authority proves that the observed program remains changeable. It does not prove malicious intent.
- A source mismatch is published only when an independently supplied manifest was evaluated and the deployed binary contradicted it.
- `not_requested`, `invalid_manifest`, `not_evaluated` and other missing-source states are not converted into mismatch claims.
- A deployment change proves a technical state transition. It does not establish actor identity, intent, exploitation or wrongdoing.
- Program risk evidence has `verdict_authority=false`; it cannot silently issue a deterministic ARVIS letter grade.
- No private customer scan, secret, owner-only worker state or binary artifact is exposed.

## Next analyzer layer

This v1 contract covers on-chain deployment and control-plane risk. Instruction-level sBPF vulnerability analysis must remain a separate evidence family with explicit rule IDs, reproducible analyzer versions, false-positive boundaries and no claim of exploitation without transaction evidence.
