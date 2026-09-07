# Koschei Web3 Project State

## CURRENT STATE

- The production Go runtime is intentionally stateless with respect to Koschei application PostgreSQL persistence. `main.go` does not initialize the application database and does not start database-backed job, watchlist, alert, telemetry or webhook workers.
- Neon remains the authentication boundary. `/api/me` can verify the authenticated identity without application persistence.
- Customer Panel is being aligned to this runtime truth: it must not call persistence-backed features and present their `503` responses as live customer state.
- Solana remains the live chain evidence core. Missing evidence remains unknown.
- The public case registry is still unavailable in production because the stateless process does not open the database and the optional Drive registry backend is not fully configured.
- `scan.html` remains a legacy third customer-facing product surface and still carries the old CSS/script stack. It is the next major two-surface migration target.

## CHANGED

On branch `cleanup/serious-surface-hardening` / PR #1064:

- Retired dormant Jito transaction-relay MEV code, request-controlled liquidity webhook automation, placeholder DAO Guardian KPI code, stale KOSCH payment-health handlers, legacy unauthenticated jobs, generic metadata generation and obsolete plan/credit/entitlement wrappers.
- Extracted the genuinely shared `firstNonEmpty` primitive rather than restoring the retired payment module.
- Retired standalone `feedback.html`, `exposure-report.html`, stale `security-ecosystem.html` and legacy `token-vesting.html`.
- Integrated feedback into Customer Panel using the existing `/api/analytics/event` path and added a client-side secret-language guard.
- Removed the non-working interactive Exposure control from Customer Panel because `/api/v1/radar/exposure` requires persistence-backed Professional access in the current architecture. Legacy Exposure URLs now land on the truthful capability-boundary section.
- Reworked Customer Panel runtime state so it reads only `/api/me` for authenticated account identity and `/health` for service status. Durable investigation history, continuous monitoring and persisted alerts are explicitly marked `NOT LIVE / PERSISTENCE OFF`.
- Added regression contracts forbidding the stateless workspace from calling `/api/auth/premium-access`, `/api/v1/radar/jobs/`, `/api/watchlist`, `/api/watchlist/alerts` or `/api/v1/radar/exposure`.
- Preserved the canonical durable-history backend contract for a future real persistence plane; only the current Customer Panel projection changed.
- Preserved the no-custody boundary: Koschei analyzes and simulates but does not sign, submit, relay or broadcast customer transactions.

## VERIFIED

- Customer Workspace V2 Acceptance passes with the new stateless workspace contract.
- Canonical Investigation History V1 Acceptance passes after separating the preserved backend contract from the current stateless panel projection.
- Auth Freeze Guard passes on PR #1064; no authentication runtime/test file is changed there.
- OpenAPI Contract passes.
- The updated Go hardening files were run through the actual `gofmt` binary before being committed back to the repair branch.
- Earlier security, secret and supply-chain checks on this repair line passed; the latest full matrix is being re-run after the format fix.

## BROKEN / MISSING

- `/api/public/cases?limit=100` still returns `503` in production. The outer API readiness gate returns `{"error":"database unavailable"}` before the registry handler can serve data.
- The database registry cannot work in the stateless process because `main.go` intentionally supplies no DB handle.
- The Drive registry alternative cannot be enabled truthfully until its service-account credential is configured; the folder ID alone is insufficient.
- Durable customer jobs/history, watchlists and stored alerts remain intentionally unavailable until a real persistence + worker plane is restored.
- `scan.html` is still a third customer-facing product page, uses the legacy `koschei.css`, inline CSS and many compatibility scripts. Token/deep Professional execution also conflicts with the current stateless entitlement/persistence boundary.
- The full Go Release Gate can still encounter the pre-existing Neon issuer test/runtime contradiction after formatting is clean. Auth is frozen; do not bypass the guard to hide this.
- TradePI agent routes and migrations still share the Web3 repository/deployment, increasing cross-product blast radius.

## NEXT

1. Finish PR #1064 CI. Fix only failures caused by this branch; do not weaken production smoke or authentication guards.
2. Migrate the genuinely stateless read-only transaction simulation from the legacy `/scan` surface into Customer Panel.
3. Retire `/scan` as a separate product page and redirect legacy scan/shield routes to the appropriate Customer Panel section or capability boundary.
4. After scan migration, restrict public HTML serving so legacy files cannot become accidental product surfaces through the generic FileServer fallback.
5. Design a separate read-only evidence persistence/registry plane for public case discovery, or fully configure the existing verified Drive snapshot backend. Do not return a fake healthy empty registry.
6. Isolate TradePI routes/migrations into their own deployment/repository boundary rather than deleting them blindly from Koschei Web3.

## RISKS

- Re-enabling the existing application `DATABASE_URL` globally in the stateless Web3 process could accidentally resurrect old DB-backed workers, jobs, telemetry or automation; persistence restoration must be deliberately scoped.
- Treating unavailable durable history as an empty history would misrepresent evidence. The panel must continue to distinguish unavailable from empty.
- Treating registry unavailability as an empty healthy publication set would violate the evidence-first contract.
- Keeping `/scan` as a legacy third surface preserves CSS/JS drift and contradicts the explicit two-primary-page product boundary.
- Branch protection is not enabled on `main`; exact target freshness and CI status must be checked before merge.

## WORK-IN-PROGRESS POLICY

1. Keep one active Web3 repair branch for this cleanup line.
2. Do not reintroduce fake database state, fake jobs, fake evidence or parallel verdict authority.
3. Preserve Solana exact identity and fail-closed evidence semantics.
4. Keep secrets in environment configuration only.
5. Do not add Koschei Lang or Sentinel implementation work to this repository.
