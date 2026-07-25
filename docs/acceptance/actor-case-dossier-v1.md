# Public Actor-Case Dossier v1

Status: implementation branch; production reference export pending deployment  
Canonical contract: `ACTOR_INVESTIGATION_ENGINE.md` v1.0  
Actor acceptance: `koschei-actor-acceptance-v1`  
Dossier envelope: `koschei-dossier-v1`

## Purpose

A completed wallet-first investigation can be frozen into one immutable JSON bundle and one public, self-contained HTML page. Creating the export requires owner, Enterprise session or Enterprise API credentials. Reading the permanent HTML page requires no account, KOSCH balance or API key.

The export is technical evidence. It contains no marketing language, wrongdoing accusation, identity assertion or investment recommendation.

## Reference sequence

Run the actor acceptance first so a signed immutable wallet snapshot exists:

```bash
cd koschei/api
KOSCHEI_OWNER_SECRET='...' \
KOSCHEI_BASE_URL='https://tradepigloball.co' \
node scripts/run-actor-acceptance.mjs \
  yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe \
  actor-engine-v1-yHCx.json
```

Create or retrieve the immutable dossier JSON:

```bash
curl --fail-with-body --silent --show-error \
  -X POST \
  -H "x-koschei-secret: ${KOSCHEI_OWNER_SECRET}" \
  "${KOSCHEI_BASE_URL:-https://tradepigloball.co}/api/v1/dossier/yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe" \
  --dump-header actor-dossier.headers \
  --output actor-dossier.json
```

The response includes:

- `X-Koschei-Case-Ref`
- `X-Koschei-Public-Dossier: /dossier/<case-ref>`
- `Content-Location: /dossier/<case-ref>`
- an immutable bundle `ETag`

The public page is then:

```text
https://tradepigloball.co/dossier/<case-ref>
```

## Actor-case contents

The bundle contains:

1. resolved wallet target and on-chain-only identity scope;
2. deterministic final verdict, triggered rule identifiers and exact ruleset;
3. all ten acceptance items in fixed `AC-01` through `AC-10` order;
4. actor profile and created-token history;
5. funding origin;
6. cross-token recurrence and relationship evidence;
7. the complete persisted actor evidence log;
8. section-local limitations;
9. source snapshot hash, bundle hash and independent verifier command;
10. the full frozen technical report.

## Verdict signature and snapshot identity

The deterministic verdict signature and the immutable case snapshot identity are retained separately.

- `verification.verdict_signature` is the unchanged Unified Radar verdict identity.
- `verification.snapshot_identity` binds that verdict identity to the actor acceptance hash.
- the `KD1-...` case reference binds the resolved wallet to `snapshot_identity`.

This prevents a later acceptance/evidence change from being hidden behind an unchanged grade or verdict signature. Token dossiers retain their existing behavior because their snapshot identity remains the verdict signature.

## Evidence-state rule

Every acceptance claim shows both:

- acceptance outcome: `pass`, `fail`, or `not_investigated`;
- evidence state: `verified`, `observed`, `inferred`, `not_verified`, `not_investigated`, or `unavailable`.

Every created-token relation is also projected with a visible `verification_status`. A creator-role observation without a complete creator-to-mint evidence line remains `unverified` and carries its limitation beside the row.

`Direct creator → dominant-holder relation: NOT VERIFIED` is an explicit withheld result. It carries no fabricated signature or transaction row.

## Public-page behavior

`GET /dossier/<case-ref>` is public and renders a single HTML response with inline CSS and no external rendering dependency. Actor-case sections display their relevant limitations inside the same section. The immutable bundle hash is returned as the page ETag and the page may be cached publicly as immutable content.

## Fail-closed conditions

Export is rejected when:

- no immutable signed source snapshot exists;
- the source snapshot hash does not match its canonical bytes;
- actor acceptance is missing;
- acceptance does not contain exactly ten ordered items;
- an acceptance status is unknown;
- a VERIFIED or OBSERVED acceptance row lacks evidence references;
- canonical bundle storage cannot be verified after insert.

Export never starts a new RPC scan to repair missing evidence.

## Independent verification

```bash
node oss/verifier/typescript/verify-dossier.mjs ./actor-dossier.json
```

The verifier checks the bundle hash, target-plus-snapshot case reference, ten-item actor row contract, evidence references, actor evidence log and section-local limitations.

## Production record

The reference case is complete only after:

1. required CI is green;
2. the merged route is deployed;
3. actor acceptance succeeds twice with stable identity;
4. the dossier export succeeds;
5. the public URL opens without authentication;
6. the downloaded JSON passes the independent verifier;
7. all failures and not-investigated states remain visible.

Current production record: `not_run`.
