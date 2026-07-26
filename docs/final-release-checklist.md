# Koschei Web3 Hub — Final GA Release Checklist

Audit baseline: **July 26, 2026**  
Canonical tracking issue: **#701 — Koschei Final GA Gate**

This document defines the acceptance contract for the final generally available Koschei ARVIS release.

Koschei is an evidence-first, read-only Solana security product. A release is not final merely because the site loads or one scan completes. Final GA requires correctness, public-product availability, deterministic evidence contracts, bounded production cost, recoverable data operations and explicit security boundaries.

## 1. Release states

### Production Candidate

Use this state when the evidence product is live and verified, but one or more final cost, data, security or release-management gates remain open.

```text
Production Candidate — evidence product live; final cost/data/security gates in progress.
```

### Final GA

Use this state only when every P0 item in #701 is closed with production evidence and the complete cold-wake acceptance sequence passes.

Final GA does **not** mean:

- guaranteed safety;
- guaranteed scam detection;
- investment advice;
- real-world identity attribution;
- AI authority over the signed deterministic verdict;
- production authorization for the isolated execution plane.

## 2. Product boundaries

The production core may:

- inspect Solana token, wallet, program and transaction evidence;
- classify verified account types before choosing an investigation lane;
- publish immutable dossiers after explicit owner publication;
- present deterministic rules, signatures, limitations and evidence gaps;
- provide manual Safe Check, scan, dossier, SOC and API-key-protected tools;
- retain INFERRED observations as watch-only context;
- label possible dust or address-poisoning candidates without claiming intent.

The production core must not:

- treat an unknown account as a token mint;
- treat ProgramData or loader-buffer accounts as ordinary wallets;
- manufacture repeated activity from multiple instruction rows in one transaction;
- let one rule ID become multiple compounding rules merely because it has several evidence groups;
- turn missing evidence into an A or safe verdict;
- delete or rewrite an immutable published dossier;
- expose owner secrets, provider credentials, private scans or customer data in public responses;
- submit transactions, hold keys or enable sandbox execution without the separately approved execution-plane policy.

## 3. Required production configuration

Required secrets and endpoints:

```env
APP_ENV=production
DATABASE_URL=
SOLANA_RPC_URL=
OWNER_SECRET=
API_KEY_PEPPER=
USER_SESSION_SECRET=
NEON_AUTH_JWKS_URL=
CORS_ORIGIN=https://tradepigloball.co,https://www.tradepigloball.co
```

Cost-safe connection defaults:

```env
DB_MAX_OPEN_CONNS=5
DB_MAX_IDLE_CONNS=0
DB_CONN_MAX_LIFETIME_SECONDS=300
DB_CONN_MAX_IDLE_TIME_SECONDS=60
DB_APPLICATION_NAME=koschei-api
DATABASE_URL_ALLOW_POOLER=0
```

Background Solana scanning must remain explicit:

```env
KOSCHEI_AUTOMATIC_SCANNING_ENABLED=false
SOLANA_RPC_LIMIT_SAVER_ENABLED=true
SOLANA_RPC_BUDGET_ENABLED=true
```

Automatic scanning may be enabled only when the provider quota, worker architecture and production budget are approved. Manual user-triggered security tools must remain usable when automatic scanning is disabled.

## 4. P0 final gates

The release is not Final GA until all are closed:

- [ ] **#697 — Event-driven worker wake-up**  
  Canonical jobs, webhooks and alerts must not rely on high-frequency empty database polling. Existing asynchronous features must remain functional.

- [ ] **#698 — Neon control-plane cost limits**  
  Scale-to-zero must be enabled, max compute capped to the approved value and spending alerts/limits configured.

- [ ] **#699 — Hot-data reduction and archive**  
  High-volume radar history must be checksummed and archived before bounded retention reduces the hot production database.

No P0 may be waived with documentation alone. Each requires production evidence.

## 5. Security acceptance

Mandatory CI gates:

- PostgreSQL 17 migration validation;
- immutable dossier validation;
- complete Go test suite;
- `go vet`;
- Linux production build;
- committed-secret scan;
- reachable dependency vulnerability scan;
- high-confidence static security scan;
- public JavaScript syntax and Turkish-copy checks;
- TypeScript SDK/normalizer check, test and package dry-run.

Before enterprise/public GA announcement:

- [ ] Close **#653** and remove the G703/G704 CI exclusion.
- [ ] Classify every outbound URL as fixed, trusted operator configuration or validated user input.
- [ ] Reject private, loopback, link-local and redirect-to-private destinations where arbitrary endpoints are supported.
- [ ] Restrict file-based credentials to explicit trusted paths or secret-content configuration.
- [ ] Confirm production does not expose secrets in HTML, JavaScript, JSON, logs or downloadable artifacts.

## 6. Database and migration acceptance

- [x] Migration SQL and its `schema_migrations` row commit in one transaction.
- [x] Migration search paths support local, container and configured directories.
- [x] Full required-schema verification remains active.
- [x] Canonical plan synchronization remains active.
- [x] Connections carry deterministic `application_name` metadata.
- [x] Idle application connections default to zero.
- [ ] `pg_stat_statements` or an equivalent query-observability mechanism is enabled.
- [ ] Storage size, row age, latency, error and connection alerts are configured.
- [ ] Stale processing leases are recovered or explicitly marked failed.
- [ ] Completed/failed job result payload retention is defined.
- [ ] Archive and hot-retention jobs are resumable, bounded and observable.

Production deletion is forbidden until archive record counts and checksums match the selected source data.

## 7. Public availability acceptance

### Transport smoke

The `koschei/public-api-transport` status must verify:

- `/api/version` reaches the application;
- `/api/config` returns the expected application contract;
- `/health` returns within its bounded readiness window;
- database dependency degradation is distinguished from proxy/application failure.

### Product smoke

The `koschei/public-product` status must verify:

- `/cases`;
- `/live`;
- `/login`;
- `/register`;
- `/api/public/cases?limit=100`;
- `/api/public/soc/feed`;
- the current dynamically discovered `/case/<KD1-ref>` page;
- the matching immutable `/dossier/<KD1-ref>` page.

The smoke must not hard-code an obsolete case reference.

### Public-copy boundaries

- Green or withheld states are not guarantees of safety.
- Empty feeds do not mean no activity occurred.
- INFERRED evidence is clearly separated from VERIFIED/OBSERVED evidence.
- Vanity/address similarity never claims shared identity, ownership, intent or common control.
- Possible dust remains visible but grade-ineligible.
- Public pages never expose owner-only operational secrets.

## 8. Actor-reference acceptance

The canonical actor workflow must:

1. accept the exact reference wallet;
2. run the ten ordered acceptance items;
3. preserve `pass`, `fail` and `not_investigated` separately;
4. bind grade-changing rules to canonical evidence references;
5. produce deterministic acceptance identity for an unchanged evidence set;
6. export a new immutable dossier without rewriting older versions;
7. keep C004 groups internally consistent:
   - `count`;
   - `facts.distinct_signature_count`;
   - unique `signatures` length;
8. count several C004 evidence groups as one compounding rule ID;
9. retain possible dust and vanity candidates only within their published evidence boundaries.

Current audit reference dossier:

```text
KD1-24deszdy5n3tls2dljt2adxddkc7tj66
```

A later successful workflow may replace this as the current reference, but older immutable dossiers remain historical records.

## 9. Asynchronous feature acceptance

Before Final GA, run one real production test for each:

- [ ] canonical async investigation job;
- [ ] webhook test delivery;
- [ ] security-alert delivery;
- [ ] retry/backoff behavior;
- [ ] stale lease recovery;
- [ ] multi-instance `SKIP LOCKED` safety;
- [ ] missed-wakeup recovery fallback.

An API must not promise `201 job created` when no worker plane can execute it. Worker unavailability must be visible and must not silently consume customer credit.

## 10. Neon cold-wake acceptance

After #697 and #698:

1. stop all test traffic;
2. observe the configured idle window;
3. confirm the production compute enters suspended state;
4. run a manual Safe Check;
5. record wake-up latency;
6. confirm the scan completes;
7. rerun transport and product smokes;
8. run the actor-reference workflow;
9. verify no high-frequency empty-query pattern returns.

The release fails this gate if compute never suspends or required features fail after wake-up.

## 11. Developer/enterprise release acceptance

- [ ] Publish an OpenAPI **3.1** document for the supported public and API-key routes.
- [ ] Validate the OpenAPI document in CI.
- [ ] Generate or verify example requests and responses against production-safe fixtures.
- [ ] Publish `@koschei/arvis-sdk`.
- [ ] Publish `@koschei/solana-event-normalizer`.
- [ ] Verify public package listings, provenance, package contents and installation from a clean project.
- [ ] Ensure package versions match the release notes and compatibility policy.

Package dry-run success alone is not publication.

## 12. Execution-plane boundary

Issue **#662** remains the approval gate for isolated LiteSVM execution.

Until it is closed:

- production execution stays disabled;
- no network fallback or dependency fetch is allowed;
- no wallet material or transaction submission enters the execution worker;
- read-only evidence and dossier features may still reach Final GA;
- public claims must not describe the sandbox execution plane as production-ready.

## 13. Release management

Before declaring Final GA:

- [ ] every P0 issue is closed with production evidence;
- [ ] no open release-blocking PR remains;
- [ ] main CI and all production smokes are green;
- [ ] the release commit is recorded;
- [ ] a signed/versioned tag is created;
- [ ] a changelog summarizes behavior, migrations, ruleset versions and known limits;
- [ ] rollback instructions identify the previous deployable commit and database-safety constraints;
- [ ] the current public dossier reference is recorded;
- [ ] operational owners know how to disable automatic scanning without disabling manual security tools;
- [ ] legal/product copy has been reviewed for evidence and attribution boundaries.

## 14. Final declaration

A final release declaration must include:

```text
Release commit:
Release tag:
Railway deployment:
Public API transport status:
Public product status:
Actor-reference run:
Current immutable dossier:
Neon suspend/wake evidence:
Archive/retention evidence:
OpenAPI version:
SDK versions:
Rollback commit:
Known limitations:
```

If any P0 field is missing, the correct state remains **Production Candidate**, not Final GA.
