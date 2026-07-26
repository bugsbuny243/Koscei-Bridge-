# Koschei Public Security SOC v2

Audit date: 2026-07-26

## Purpose

Koschei ARVIS is a public Solana security product, not an owner-only operations console. Public users, registered customers, developers and API integrations can create investigations, produce immutable dossiers, monitor programs and control the visibility of the evidence they created.

Owner access is limited to moderation, featuring, emergency hiding and infrastructure operations. It is not the product's only creation or publication path.

Public surfaces:

- `GET /api/public/cases`
- `GET /api/public/soc/feed`
- `GET /api/public/program-risks`
- `GET /api/public/program-risks/<ref>`
- `GET /case/<case-ref>`
- `GET /dossier/<case-ref>`
- `GET /program-risk/<ref>`
- `GET /cases`
- `GET /live`

Authenticated creation and visibility surfaces:

- `POST /api/v1/dossier/<target>`
- `POST /api/v1/dossier/publications`
- `GET|POST /api/v1/defense/sentinel`
- `POST /api/v1/program-risks/publications`

## Ownership and publication boundary

Every dossier, program monitor and program-risk publication is private by default.

The authenticated principal that created the dossier or subscribed to the program monitor controls whether its eligible evidence is `draft`, `public` or `hidden`. Principals are represented as stable user or API-key subjects. One customer cannot publish another customer's dossier, manifest or monitor evidence.

Owner moderation may feature, hide or restore eligible evidence without changing the immutable dossier, deployment snapshot, change event, signature or verification hash.

Every visibility change appends an immutable audit event.

## Customer-facing result contract

Public product pages show:

1. a direct user decision such as `BLOKLA`, `YÜKSEK DİKKAT`, `İŞLEMİ BEKLET` or `KANITLA DEVAM`;
2. the verified or observed finding;
3. why the finding matters;
4. the action the user should take;
5. inspectable evidence references and transaction links;
6. an immutable bundle hash or reproducible public verification hash.

Public pages do not show internal worker ownership, acceptance job queues, collector retry state or synthetic progress lists. Those are operational telemetry, not customer results.

Repeated instances of one rule are collapsed into one explanation with the verified total. They are not rendered as dozens of duplicate findings.

## Case truth boundary

The API selects the latest public dossier for each target before applying the response limit. Historical immutable revisions remain available through their dossier URLs, but do not crowd unrelated targets out of the case registry.

A letter grade is not shown as valid when the signed deterministic decision contract is withheld. `WITHHOLD` means no transaction approval was issued; it is not a safe or unsafe percentage score.

## Program-risk truth boundary

Program risk evidence is public only after explicit publication by an authorized monitor subscriber or owner moderator.

Eligible public evidence is limited to current HIGH/CRITICAL technical states and immutable on-chain changes:

- executable bytecode changed;
- loader changed;
- ProgramData address changed;
- upgrade authority opened or changed;
- current upgrade authority remains open;
- current program account is not executable;
- an independently supplied source/build manifest contradicts the deployed binary.

Missing source evidence, an invalid manifest or removal of an optional manifest is not described as an on-chain deployment change.

Historical snapshots cannot be presented as current after a newer snapshot resolves the condition.

## Public response boundary

Public responses may include:

- immutable case, snapshot or change-event reference;
- program, target kind and network;
- public title and summary;
- decision and recommended action;
- current and previous public deployment state;
- redacted inspectable evidence references;
- actual evidence count;
- reproducible `verification_payload` and SHA-256 `verification_hash`;
- bundle hash, ruleset and timestamps.

Public responses never expose:

- credentials, API keys or secrets;
- private customer identity or scan history;
- binary artifact bytes or private artifact references;
- internal worker topology, retry state or queue details;
- unpublished evidence;
- real-world identity, intent or wrongdoing claims.

## Live behavior

`/live` polls the public feed every 15 seconds and combines current user-published cases with explicitly published HIGH/CRITICAL program risks. It does not synthesize activity or treat an empty feed as proof of safety.
