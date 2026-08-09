# ARVIS v1 — Final Security Baseline

Status: **code feature-complete candidate**.

This document defines the end of the ARVIS v1 feature-building phase. It does not declare commercial adoption, production latency, operational cost controls or external integration evidence that has not been measured.

## Final product identity

ARVIS v1 is a Solana-native, evidence-first pre-signing security control plane.

Its core path is:

```text
transaction / wallet / token / program target
        ↓
canonical Solana evidence collection
        ↓
Transaction Guard + actor/liquidity/program evidence
        ↓
deterministic allow / warn / block / withhold decision
        ↓
State Witness + signed permit v3
        ↓
pre-sign State Recheck
        ↓
independent Evidence Court quorum when policy requires it
        ↓
safe_to_proceed
```

The final v1 intelligence/provenance layers include:

- Transaction Guard v3 decode, simulation, balance, CPI and authority analysis;
- State Witness bound to transaction fingerprint, account-state root and observation slots;
- signed permit v3 with immutable State Recheck policy snapshot;
- pre-sign State Recheck with explicit `safe_to_proceed` semantics;
- independent-provider Evidence Court with primary-provider identity exclusion;
- Token-2022 extension and authority evidence;
- Exit Impact / liquidity evidence with exact Jupiter route-address attribution;
- read-only Jupiter Swap V2 quote transport with trusted-host secret isolation;
- deterministic Transaction Value Evidence v1 without invented fees or USD value;
- Program Trust Graph v1 linking direct/CPI/TransferHook programs to immutable Defense OS deployment/source snapshots;
- persistent Actor Defense evidence graph and deterministic rules;
- Technical Campaign Genome v1 for cross-wallet technical pattern recurrence without real-world identity attribution;
- immutable dossiers, signed verdicts, watchlists, alerts, webhooks and authenticated developer APIs;
- Defense OS read-only verification plane, still separated from Transaction Guard verdict authority.

## Final security invariant manifest

The machine-readable release contract is:

```text
koschei/api/final_security_invariants.json
```

The manifest is itself validated by:

```text
koschei/api/internal/finalgate/manifest_test.go
```

The validator fails when:

- a required crown-jewel invariant disappears;
- two invariant IDs or test targets collide;
- an invariant points outside the internal Go test surface;
- a referenced exact test no longer exists;
- the baseline starts claiming production GA or latency without evidence;
- the no-identity, no-AI-verdict-authority or no-custody constitution is weakened.

Because the existing Release Gate executes `go test ./...`, the referenced tests are not presence-only declarations: they execute under the normal required test suite, and the manifest validator additionally proves that the release contract still points to those exact executable tests.

## Crown-jewel invariants

The final manifest locks, at minimum:

1. State Witness deterministic ordering;
2. State Witness sensitivity to account-state mutation;
3. rejection of untrusted permits before State Recheck RPC access;
4. fail-closed `safe_to_proceed` semantics;
5. stale Evidence Court quorum rejection;
6. primary/quorum root disagreement rejection;
7. exclusion of the primary provider identity from independent Court voting;
8. semantic validation of signed permit-v3 policy;
9. deterministic Transaction Value Evidence identity;
10. outer/CPI token movement de-duplication;
11. transaction/network binding of Program Trust Graph evidence;
12. Program Trust / Defense OS verdict-authority isolation;
13. cross-wallet Technical Campaign Genome pattern determinism with distinct audit evidence identities;
14. dust/inferred/unverified Campaign Genome boundaries.

These are release-blocking code invariants. Normal full tests, race tests, vet, Linux build, migrations, secret scanning, vulnerability scanning, static security scanning, CodeQL, supply-chain checks, public product smoke, Auth Freeze and exact-head corpus acceptance remain separate mandatory gates.

## Feature freeze

After this baseline merges, ARVIS v1 enters feature freeze.

A new code change should be accepted only when it is one of:

- a security or correctness fix;
- a measured performance/reliability improvement;
- a real customer/integration requirement;
- an operational production requirement;
- a new verified threat class backed by reproducible evidence;
- a separately approved Defense OS phase.

Do not restart feature accumulation merely to increase module count.

## What “finished” means

For the code/product architecture, v1 is feature-complete when the final invariant-gate PR is green and merged.

That means the intended Solana security architecture exists, is wired into canonical product paths and is protected by reproducible CI contracts.

It does **not** mean:

- guaranteed safety or exploit prevention;
- guaranteed rug/scam detection;
- real-world actor identity attribution;
- investment advice;
- production p50/p95/p99 latency has been measured if no production telemetry was supplied;
- paid customer adoption exists if no signed customer evidence exists;
- the isolated Defense execution plane is production-authorized;
- external infrastructure cost/cold-wake/retention controls have passed when their production evidence is unavailable.

## Production GA boundary

The existing `docs/final-release-checklist.md` remains the operational GA contract for external production evidence.

Code feature-complete status must not be used to auto-check production-only gates such as customer adoption, Neon control-plane configuration, cold-wake behavior, external delivery reliability or deployment-specific cost limits.

Until those external gates are evidenced, the honest release class is:

```text
ARVIS v1 — Code Feature Complete / Production Candidate
```

not an evidence-free Final GA claim.

## Next phase

The next phase is not another internal feature sprint. It is external proof:

- wallet / launchpad / dApp integration pilots;
- protected transaction volume;
- measured decision completion and withhold rates;
- reviewed false-positive / false-negative cases;
- measured production latency and provider recovery;
- first paid B2B contracts and ARR;
- published technical case replays with exact evidence references.

Those metrics determine commercial maturity. They are deliberately not fabricated by this code baseline.
