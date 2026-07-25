# Koschei Public SOC v1

## Purpose

Public SOC is the account-free evidence window for Koschei ARVIS. It is not a mirror of owner operations and it never exposes every stored investigation.

The first vertical slice provides:

- `GET /api/public/cases`
- `GET /api/public/soc/feed`
- `GET /cases`
- `GET /live`
- owner-only `POST /api/owner/dossier/publications`

## Publication boundary

An immutable dossier is private by default. A row in `dossier_exports` does not make a case discoverable.

An owner must explicitly create or update `dossier_publications` with `status=public`. Publication state can be hidden or featured without modifying the canonical dossier bundle, verdict, evidence rows, signature, source snapshot or bundle hash.

Every publication-state change appends an immutable row to `dossier_publication_events`.

## Public response boundary

Public discovery responses include only a bounded projection:

- immutable case reference and public URL
- shortened target display plus target kind and network
- public title and summary
- dossier and ruleset versions when present
- bundle hash and timestamps
- evidence-state counts
- actor acceptance pass/fail/not-investigated counts
- created-token history count
- independent verifier command

The canonical `/dossier/<case-ref>` page remains the evidence source of truth.

Public discovery responses do not expose:

- owner credentials or internal endpoints
- customer identity or private scan history
- provider keys, worker topology or retry internals
- unpublished dossiers
- real-world identity, intent or wrongdoing claims

## Live behavior

`/live` polls the public feed every 15 seconds. It does not synthesize activity. When no new owner-published immutable case exists, it says so explicitly.

## Owner publication request

Example body:

```json
{
  "case_ref": "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "status": "public",
  "public_title": "ARVIS Actor Evidence Case",
  "public_summary": "Evidence-bounded actor investigation.",
  "featured": true,
  "redaction_profile": "public-onchain-v1"
}
```

Allowed states are `draft`, `public` and `hidden`. Only public cases may be featured.
