# Koschei Web3 Project State

This is the authoritative checkpoint for the uploaded working snapshot. The archive does not contain Git metadata, so repository commit identity must be verified again before opening or merging a pull request.

## CURRENT STATE

- The Go runtime is intentionally stateless: `main.go` does not initialize the application database and does not start the canonical investigation job worker.
- Live token evidence collection remains available through the synchronous `/api/token/scan`, `/api/owner/arvis/scan`, and `/api/owner/radar/unified` routes.
- The owner page had replaced its working synchronous scan with `/api/owner/radar/jobs`. That durable route correctly returns `503` without its database and worker, so the button could not start a scan.
- The public token page aborted `/api/token/scan` after 45 seconds even though bounded launch forensics alone may run for 120 seconds.
- This working snapshot contains the scan-runtime recovery described below. It has not been deployed.
- Koschei Sentinel is cancelled. Koschei Lang remains separate and is not part of this repository change.

## CHANGED

- `owner-court-ui.js` now attempts the durable canonical job first and falls back to the existing live synchronous owner scan only when the job capability is unavailable (`404`, `405`, `501`, or `503`) or returns no poll URL.
- Authentication, invalid-target, and other application errors are not swallowed by the fallback.
- `requiresDB` now treats the exact `databaseOptionalAPIPaths` allowlist consistently with `apiReadiness`; these routes no longer depend on the legacy `KOSCHEI_NEON_AUTH_ONLY` flag to reach their own degraded-mode handling.
- `/api/owner/radar/jobs` remains database-required and fail-closed. No fake durable job or persistence result is created.
- The public token-scan browser timeout is now 210 seconds and its cache key is incremented.
- Owner and public cache keys, Go surface expectations, CI routing, and a new executable regression verifier were updated.
- The release gate exposed a pre-existing `gofmt` alignment error in `internal/archive/google_drive.go`; it was formatted without changing behavior so the full Go gate can run.

## VERIFIED

- All `public/js/*.js` files pass `node --check`.
- The four browser-side unit suites pass: 17 tests, 0 failures.
- The required public scan, evidence-card, customer/owner UI, trust-consistency, and dossier contract checks pass.
- The new runtime-recovery check proves that a `503` job response invokes the direct scan exactly once, while a `422` invalid target does not fall back.
- Canonical product, deep-scan navigation, owner evidence explorer, and production RPC-isolation contracts pass.
- Railway production deployment `e57c529d-dacf-4e4e-80aa-060a9ee01418` is healthy on `main` commit `c114aac`. Its startup log explicitly confirms the stateless Web3 runtime.
- A live production full-scan acceptance request returned `200` and passed its response-contract checks in 152,610 ms. This directly reproduces why the old 45-second browser timeout discarded otherwise valid results.
- A clean archive comparison shows only the documented recovery files plus the release-gate formatting repair changed.

## BROKEN / MISSING

- Go is not installed in this execution environment. `go test ./...`, `go vet ./...`, and `go build ./...` could not be run here and remain mandatory CI gates.
- Durable canonical jobs, history, watchlists, and database-backed actor dossiers remain unavailable while the runtime intentionally has no application database/worker.
- Token-mint scans are the recovered stateless path. Wallet dossier scans still require the retired persistence layer and fail closed without it.

## NEXT

1. Apply this working snapshot on a Git branch and run required Go tests, vet, build, security checks, and exact merge-candidate verification.
2. Deploy only after the exact branch head passes CI.
3. Smoke-test one public token mint and one owner token mint in production; confirm the owner network trace falls back from `/api/owner/radar/jobs` to `/api/owner/arvis/scan` when persistence is absent.
4. Decide separately whether durable jobs and wallet dossiers should be restored with an application database/worker or removed from the current product contract.

## RISKS

- Synchronous full scans can keep a browser request open for several minutes; losing the tab loses the response even though no false result is created.
- Restoring only the job route without restoring its worker would create permanently queued work. The database-required boundary must remain until both storage and processing are real.
- The stateless token route can return partial or withheld evidence when RPC or market providers are unavailable; missing evidence must never be converted into a safe result.
- Browser caches require the updated `v=4` owner and `v=12` public script URLs to receive this fix.
- The repository has no branch protection guarantee; verify exact target freshness before merge.

## WORK-IN-PROGRESS POLICY

1. Keep one active repair branch and repair CI failures on that branch.
2. Do not reintroduce fake database state, fake jobs, fake evidence, or parallel verdict authority.
3. Preserve Solana exact-case identity and fail-closed evidence semantics.
4. Keep secrets in environment configuration only.
5. Do not add Sentinel or Lang work to this Web3 recovery.
