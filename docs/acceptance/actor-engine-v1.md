# Actor Investigation Engine v1 Acceptance

Status: implementation complete; production reference run pending deployment  
Canonical contract: `ACTOR_INVESTIGATION_ENGINE.md` v1.0  
Acceptance schema: `koschei-actor-acceptance-v1`  
Actor ruleset: `koschei-actor-defense-rules-v1.0.0`

## Reference actor

```text
yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe
```

The acceptance route evaluates the ten criteria in `ACTOR_INVESTIGATION_ENGINE.md` section 8 independently. Every criterion is returned as:

- `pass`
- `fail`
- `not_investigated`

A criterion never disappears because evidence is missing. `not_investigated`, `not_verified` and `unavailable` remain separate through the `evidence_state`, summary and limitations fields.

## Owner-only route

```text
POST /api/owner/defense/actor-acceptance
```

The route uses the existing wallet-first actor collectors and deterministic actor rules. It does not add a numeric score, crawl recipient-wide wallet history, alter the verdict, use AI as verdict authority or broaden the first-slice scope.

## One-command reference run

Run from `koschei/api` after the route is deployed:

```bash
KOSCHEI_OWNER_SECRET='...' \
KOSCHEI_BASE_URL='https://tradepigloball.co' \
node scripts/run-actor-acceptance.mjs \
  yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe \
  actor-engine-v1-yHCx.json
```

The runner calls the owner route twice, validates all ten ordered items and rejects a changed `acceptance_hash`. The same persisted dossier, funding evidence and deterministic verdict projection must produce the same identity. Collection changes may legitimately produce a new hash because the evidence set changed; timestamps created only by the acceptance evaluator are excluded.

## Ten acceptance items

| ID | Required result |
|---|---|
| `AC-01` | Owner route accepts one wallet target. |
| `AC-02` | Target classification resolves a wallet or a token account with a resolved owner wallet. |
| `AC-03` | Created mints have complete creator-to-mint evidence lines. |
| `AC-04` | Funding origin has a complete evidence line; CEX identity remains opaque unless a separately verified entity label exists. |
| `AC-05` | Creator token exits and recipients come only from mint-specific ATA history. |
| `AC-06` | Recipient-to-top-holder comparison is materialized, including valid zero-match results. |
| `AC-07` | Liquidity add/remove claims require complete signature-backed evidence; otherwise this item remains `not_investigated`. |
| `AC-08` | Creator recurrence and holder/related-actor recurrence both require complete cross-token evidence lines. |
| `AC-09` | Direct creator-to-dominant-holder relation is either VERIFIED or exactly `Direct creator → dominant-holder relation: NOT VERIFIED`. Explicit withholding satisfies the acceptance behavior without creating a chain claim. |
| `AC-10` | One numberless deterministic verdict includes grade, triggered rule IDs, ruleset version and evidence references. |

## Canonical chain evidence line

A chain claim can pass only when its evidence line contains:

- `signature`
- `slot`
- `timestamp`
- `source_wallet`
- `destination_wallet`
- `amount` or explicit `not_applicable`
- `program`
- `verification_status`
- `evidence_key`
- `evidence_source`

Control-plane checks such as route input and target classification are labelled `kind=control`; they are never presented as transaction evidence. An explicit `NOT VERIFIED` result carries no fabricated transaction row.

## Narrow-slice boundary

The first acceptance slice remains:

```text
one wallet
→ created mints
→ funding origin
→ first 20 recipients per mint through mint-specific ATA history
```

Cross-token and liquidity capabilities are evaluated from already persisted evidence but are not expanded by this PR. Missing evidence remains visible rather than triggering new unbounded collection.

## Live result record

The first production result must be appended here only after:

1. the branch passes complete Go test, vet and build gates;
2. the route is deployed;
3. the two-run verifier above succeeds;
4. both responses have the same `acceptance_hash` when the underlying evidence set is unchanged;
5. every failing or not-investigated item is retained with its reason.

Current reference-run state: `not_run`.
