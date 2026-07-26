# Koschei Defense Lab — Customer Program Security v1

Audit date: 2026-07-26

## Product purpose

Koschei Defense Lab is an authenticated Solana program-security product for users, development teams and API integrations. It is not limited to owner operations.

A customer can upload a private source bundle, Anchor IDL or build manifest and run the existing deterministic Koschei Program Security (`KPS`) detectors. The result is returned as a decision, finding list, source location, limitation, immutable run reference and report hash.

Public page:

- `GET /program-audit`

Authenticated API:

- `GET|POST /api/v1/defense/artifacts`
- `GET|POST /api/v1/defense/lab`
- `GET|POST /api/v1/defense/sentinel`

## Artifact ownership

Artifacts are content-addressed. Two customers may submit byte-identical content and therefore receive the same immutable artifact reference. Ownership is consequently represented by the many-to-many `defense_artifact_subscriptions` table, not by the artifact row's single historical `created_by` field.

The customer API never returns artifact content, original creator identity, source URI, source commit or metadata. A customer can load and analyze an artifact only when an exact subscription exists for its authenticated subject.

Customer submissions cannot self-assert verified evidence. The service forces:

```text
verified=false
trust_level=unverified
private_by_default=true
```

Supported customer artifact types:

- `source_bundle`
- `anchor_idl`
- `source_manifest`
- `sbpf_manifest`

Executable bytecode, synthetic benchmark bundles, knowledge documents and command artifacts are not accepted by the customer upload route.

## Deterministic analysis

The customer endpoint reuses the existing Defense OS detector implementation and version. It does not create a second simplified scanner.

Current source-bundle rules include:

- `KPS-S001` — `UncheckedAccount` without explicit CHECK rationale;
- `KPS-S002` — unsafe Rust block;
- `KPS-S003` — `invoke_unchecked`;
- `KPS-S004` — dynamic `remaining_accounts`;
- `KPS-S005` — `init_if_needed` review surface;
- `KPS-S006` — realloc review surface;
- `KPS-S007` — Token-2022 control extensions;
- `KPS-S008` — panic-prone unwrap/expect.

Anchor IDL analysis produces the deterministic instruction/account graph used by the existing Program Lab.

## Customer decision projection

The static report is summarized without granting verdict authority:

- one or more HIGH/CRITICAL findings → `block`;
- one or more MEDIUM findings → `warn`;
- LOW-only findings → `review`;
- no static trigger → `no_static_trigger`.

`no_static_trigger` is not a safety guarantee. Every result retains `static_only=true` and `verdict_authority=false`.

## Immutable run ledger

Migration `086_customer_program_lab.sql` adds immutable `defense_lab_runs` records containing:

- `KDLR1-...` run reference;
- artifact and authenticated subject;
- detector version;
- decision and severity counts;
- deterministic report hash;
- creation time.

The same artifact analyzed by two customers produces the same report hash but different customer-bound run references. Run rows reject update and delete operations.

## Safety boundary

The customer Program Lab endpoint:

- does not execute artifact code;
- does not invoke shell commands;
- does not compile or deploy a Solana program;
- does not sign or send a transaction;
- does not access mainnet execution paths;
- does not publish private source automatically;
- does not claim exploitability, asset loss, identity, intent or wrongdoing from a static match.

Runtime reproduction, LiteSVM execution, patch approval and production changes remain separate gated workflows.

## Abuse controls

Artifact uploads and static analyses require an authenticated user session or API key and are subject-scoped rate limited. Request bodies remain bounded by the existing JSON body limit and the Defense OS artifact-size contract.

## Verification gates

Release acceptance requires:

- PostgreSQL 17 migration 086;
- identical artifact subscription by two independent subjects;
- access rejection for a third subject;
- deterministic KPS-S003 HIGH finding and `block` projection;
- equal report hashes and distinct customer run references;
- immutable run update/delete rejection;
- customer response redaction of creator/source/metadata fields;
- full Go tests, vet/build and security scans;
- JavaScript syntax and static page contract checks.
