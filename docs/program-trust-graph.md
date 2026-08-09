# ARVIS Program Trust Graph v1

Status: Transaction Guard evidence bridge to persisted Defense OS deployment snapshots.

Schema version:

```text
koschei-program-trust-graph-v1
```

## Purpose

Transaction simulation can show which programs a transaction invokes, including inner CPI programs and Token-2022 TransferHook targets. It does not by itself prove which deployed bytecode, source commit or upgrade authority those program IDs were previously bound to.

Program Trust Graph joins the live Guard program surface to immutable, previously collected Defense OS deployment snapshots. It is a read-only evidence bridge. The Guard request does not trigger program RPC inspection, source import, compilation, sandbox execution or repair.

## Observed program surface

The graph combines and de-duplicates program IDs observed through:

- decoded outer transaction instructions;
- resolved CPI / inner instructions;
- TransferHook program IDs resolved by the authority surface.

Each node preserves the exact `observed_in` sources. Program IDs are sorted before graph construction so identical evidence produces an identical graph identity.

## Defense snapshot evidence

When an immutable `defense_program_deployments` snapshot exists for the invoked program and network, the graph may expose:

- Defense snapshot reference and snapshot hash;
- loader kind and ProgramData address;
- observed account slot and deployment slot;
- whether an upgrade authority remained open, plus the observed authority address;
- executable state;
- canonical deployed binary SHA-256;
- exact source commit when a manifest supplied one;
- source/binary match status and evidence status.

The latest persisted snapshot is selected deterministically per program/network. Snapshot retrieval is bounded to 64 unique program IDs.

## Built-in programs

The System Program, Address Lookup Table Program and Compute Budget Program are marked `builtin_not_applicable`; their absence from Defense OS deployment snapshots is not treated as a missing BPF provenance record.

Other invoked programs without a persisted snapshot are marked `snapshot_unavailable`. This is an evidence limitation, not a claim that the program is malicious or unverified in the real world.

## Deterministic identity

The graph carries `evidence_hash_sha256`, computed from the normalized ordered graph with the hash field blanked before canonical JSON encoding. There is no clock read, network call or mutable external lookup in the graph builder itself.

## Guard response

Transaction Guard exposes:

```text
program_trust_graph_complete
program_trust_graph
```

`complete=true` requires every non-builtin observed program to have a persisted Defense OS deployment snapshot and every observed program ID to be a valid Solana public key.

A missing database or lookup failure returns a partial graph with an explicit limitation. Raw database errors are not returned to the client.

## Authority boundary

Program Trust Graph v1 is evidence-only:

```text
verdict_authority = false
```

It does not change `risk_index`, `risk_level`, `action`, `guard_complete`, State Witness, enforcement permit issuance or State Recheck policy. Defense OS remains a separate read-only verification system and cannot silently become Transaction Guard verdict authority through this bridge.

A later enforcement policy may use exact program provenance only after it defines which snapshot states are mandatory, how snapshot freshness is proven, which native/protocol programs are exempt, and how missing evidence fails closed without inventing source trust.
