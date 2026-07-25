# Koschei — Solana Security Market-Gap Integration

Status: strategic execution contract  
Baseline: `main@7e31b5d8fbe3feb2d55f854a93675f4dfe01f722`  
Canonical investigation contract: `ACTOR_INVESTIGATION_ENGINE.md` v1.0  
Unified Radar ruleset: `koschei-unified-radar-rules-v1.0.0`

This document incorporates the market-gap report received on 2026-07-24 into Koschei without replacing or weakening the existing evidence engine.

External market sizes, competitor claims, pricing figures, legal conclusions and incident totals are strategic inputs, not Koschei technical evidence. They must be independently revalidated before public marketing, contracting or legal reliance.

## 1. Product-positioning decision

Koschei will not attempt to imitate premium general-purpose audit firms immediately.

The bounded initial position is:

> Solana-native, evidence-first, affordable and transparent security laboratory for small teams, token launches, MVPs and emerging protocols, backed by ARVIS continuous evidence and Defense OS reproducible program analysis.

The product has five mutually reinforcing surfaces:

1. **ARVIS / Unified Radar** — token, actor, holder, funding, liquidity, transaction-intent and pre-signing evidence;
2. **Defense OS** — source, IDL, deployed-bytecode, harness, reproducibility and human-reviewed program-security evidence;
3. **Public technical dossiers** — immutable, self-contained evidence exports and research reports;
4. **Continuous monitoring** — deployment, authority, liquidity, actor and signed-verdict alerts;
5. **Regional education** — Turkish-first Solana security training, safe fixtures and public research.

Maximum strength means exact evidence, visible collection limits, deterministic outcomes, reproducibility and honest unavailable states. It does not mean more provider calls, automatic accusations or an unsupported safety certificate.

## 2. Constitutional boundaries

All existing Koschei boundaries remain authoritative.

- No numeric 0–100 final score.
- Letter grade, triggered rule identifiers and exact ruleset version remain canonical.
- `INFERRED` is watch-only. `UNVERIFIED` cannot alter a grade.
- Missing evidence, provider failure or malformed evidence fails closed.
- Serious claims require exact evidence references.
- AI may explain or propose; it cannot create evidence, grade a target, approve a fix or claim proof-of-fix.
- Defense OS always preserves `verdict_authority=false`.
- No wallet material, custody, transaction signing, mainnet submission or automatic production patching.
- No recipient-wide or holder-wide unbounded wallet-history scans.
- New product tiers may change capacity and access, never the technical truth of a result.
- No product or service may market “audited”, “safe”, “rug-proof”, “exploit-proof” or equivalent language unless the exact reviewed scope and limitations are displayed beside the claim.

## 3. Separation of engine work and business work

`ACTOR_INVESTIGATION_ENGINE.md` §1 remains the gate for investigation-engine features.

A proposed runtime feature must identify which canonical investigation question it answers and which evidence row proves the answer. If it answers none, it is rejected from the engine roadmap.

Business packaging, public research, education and service operations are allowed outside the engine roadmap, but they may not silently change evidence, verdict or signing semantics.

## 4. Market-gap execution tracks

### M-01 — Affordable Solana Security Review Pack

Purpose: serve memecoin teams, MVPs, small dApps and early protocols that cannot purchase a premium audit.

Initial package:

- fixed-scope intake and threat-model questionnaire;
- exact commit, build inputs, IDL and deployed-program references;
- automated ARVIS and Defense OS evidence collection;
- human review of account validation, signer/writable constraints, CPI boundaries, authority controls and token flows;
- reproducible finding evidence where supported;
- one fix-review round;
- immutable public or private technical dossier chosen by the customer;
- explicit investigated / not-investigated / unavailable matrix.

The service will use bounded tiers based on program count, nSLOC, Anchor/native/Pinocchio model, CPI surface, Token-2022 use and requested turnaround. Prices are commercial configuration, not hardcoded runtime policy.

Acceptance gate:

- one real reference project completed end to end;
- scope hash, source hash, deployed-bytecode reference and limitations retained;
- every finding has reproducible evidence or is labelled as an observation;
- no finding is generated solely by AI;
- report survives independent verification from the exported dossier.

Non-claim:

A review is a bounded technical assessment, not a guarantee against all future vulnerabilities, governance changes, stolen keys or social engineering.

### M-02 — Token-2022 Extension Risk Laboratory

Purpose: close a clear Solana-native tool gap without duplicating generic fuzzers.

Evidence modules:

- transfer-hook configuration and invoked-program boundaries;
- permanent delegate and delegated-transfer authority;
- transfer fees and withheld-fee authority;
- confidential-transfer configuration where supported;
- default account state and frozen-account implications;
- metadata/group/member pointer authority;
- close authority, mint authority and freeze authority;
- CPI guard and re-entrancy-like callback surfaces;
- extension compatibility and account-length validation;
- Token versus Token-2022 owner-program verification.

Canonical question mapping:

- who controls the asset or state;
- which authority can change behavior;
- which program is invoked;
- what verified relationship exists between the target and the invoked program;
- what evidence is missing or unavailable.

Acceptance gate:

- byte-level and parsed-account fixtures for each supported extension;
- wrong owner, malformed length, stale context and contradictory parsed/raw data rejected;
- exact program, account, slot and evidence-key references;
- no extension presence alone changes a grade;
- transaction intent returns `withhold` when required account evidence is incomplete.

### M-03 — Native and Pinocchio Program Analysis

Purpose: build differentiated static and structural evidence for non-Anchor Solana programs.

Initial detector families:

- missing signer and writable validation;
- account-owner and executable-program validation;
- unchecked account substitution;
- PDA seed, bump and canonical-derivation mistakes;
- unsafe duplicate-account assumptions;
- arbitrary or insufficiently constrained CPI;
- incorrect sysvar/instruction-sysvar handling;
- unchecked arithmetic, rounding and precision boundaries;
- unsafe realloc, close and lamport-balance transitions;
- Token/Token-2022 account-layout confusion;
- deserialization length/discriminator mistakes;
- upgrade-authority and deployment-control exposure.

Output rules:

- static matches are observations until a concrete reachable instruction path is established;
- no detector result alone claims exploitability or asset impact;
- source spans, artifact hashes and detector version are mandatory;
- deployed-bytecode correspondence remains a separate evidence question.

Acceptance gate:

- vulnerable and corrected fixture corpus;
- false-positive regression tests;
- exact source spans and rule identifiers;
- fail-closed behavior on unsupported code shapes;
- deterministic output over the same source bundle.

### M-04 — Continuous Solana Defense SaaS

Purpose: convert one-time review evidence into ongoing protection.

Monitored changes:

- deployed program data or upgrade authority;
- source/deployed-bytecode correspondence;
- mint/freeze/permanent-delegate and Token-2022 extension authorities;
- LP burn, permanent custody, locker schedule and liquidity movement;
- creator, funding, dominant-holder and recurring actor relations;
- transaction-guard decisions;
- evidence or ruleset invalidation after a deployment change.

Delivery surfaces:

- dashboard;
- signed technical dossier;
- tenant-scoped alerts;
- existing webhook delivery pipeline;
- API and SDK verification.

Acceptance gate:

- duplicate events cannot double-sign or double-deliver a verdict;
- worker restarts and stale leases preserve idempotency;
- provider failure produces unavailable/withhold rather than safe;
- deployment change invalidates inherited assumptions;
- alerts transport an existing deterministic result and never create the grade.

### M-05 — Operational Security and Access-Control Review

Purpose: cover the increasing risk surface outside program logic while staying within Koschei’s evidence discipline.

Review areas:

- upgrade-authority custody and rotation;
- multisig threshold and signer concentration;
- deploy/release separation of duties;
- CI/CD secret exposure and artifact provenance;
- emergency pause and recovery controls;
- privileged service accounts and API keys;
- incident response, contact tree and disclosure runbook;
- dependency and release-signing policy.

Boundary:

Koschei will not claim that an on-chain address identifies a real person. Off-chain controls require customer-provided documents or verifiable system evidence and retain their provenance separately from chain evidence.

Acceptance gate:

- separate on-chain and customer-supplied evidence classes;
- explicit reviewed/not-reviewed control matrix;
- no secret values persisted in reports;
- no legal/compliance certification language.

### M-06 — Turkish and Regional Solana Security Academy

Purpose: fill the Turkish-language education gap and create a durable researcher pipeline.

Initial curriculum:

1. Solana account model and runtime;
2. Anchor constraints and common validation failures;
3. native Rust and Pinocchio security;
4. SPL Token and Token-2022 extensions;
5. CPI, PDA, signer and authority security;
6. fuzzing and deterministic harness design;
7. source/deployed-bytecode verification;
8. incident evidence and responsible disclosure;
9. ARVIS actor/flow evidence interpretation;
10. Defense OS safe reproduction boundaries.

Delivery model:

- Turkish-first written modules;
- English terminology retained beside Turkish terms;
- intentionally vulnerable local fixtures;
- CTF exercises with no live-target exploitation;
- public solution write-ups after an embargo;
- completion based on reproducible evidence, not attendance alone.

Boundary:

Education fixtures may never contain production secrets, current private targets or instructions for unauthorized mainnet exploitation.

## 5. Research and reputation track

Koschei will build credibility through verifiable output rather than unsupported market claims.

- maintain a public technical-report repository or public dossier index;
- publish detector methodology and limitations;
- participate selectively in Rust/Solana contests and responsible bug bounties;
- publish postmortems only from public information or authorized evidence;
- use coordinated disclosure for live vulnerabilities;
- preserve exact commit, target scope, tool version and evidence references in every report;
- never advertise customer TVL “protected” without an auditable calculation method.

Contest earnings are not treated as the primary business model. Contest participation is a reputation, training and fixture-acquisition path.

## 6. Immediate implementation order

This market-gap plan must not derail active correctness and execution work.

1. Complete the wallet-first actor acceptance contract (T-01).
2. Extend the existing dossier export for the actor acceptance case (T-02).
3. Complete Defense OS Phase 12C and immutable offline dependency review with all production gates disabled.
4. Produce the first public, independently verifiable Koschei technical case file.
5. Define the fixed-scope affordable review intake and report template (M-01).
6. Implement Token-2022 extension evidence in bounded PRs (M-02).
7. Build the native/Pinocchio fixture corpus before adding detectors (M-03).
8. Productize existing deployment, alert and webhook capabilities as continuous monitoring (M-04).
9. Add operational-security review templates without mixing off-chain evidence into chain verdicts (M-05).
10. Publish the first Turkish security module only after its fixtures and answers are reviewed (M-06).

## 7. PR discipline

Each implementation PR must contain:

- canonical question/contract mapping;
- exact in-scope and out-of-scope sections;
- no unrelated refactor;
- default-off gate for new automation, execution or provider-cost paths;
- deterministic identity tests where reproducibility is claimed;
- negative and fail-closed tests;
- exact evidence-state tests;
- no production enablement;
- complete repository CI and security gates.

A business or education PR may contain documentation and fixtures only. It may not alter verdict semantics incidentally.

## 8. Success metrics

Technical success:

- one wallet-first actor acceptance case with ten explicit states;
- one public immutable actor/program dossier independently verified;
- one deterministic Defense OS harness rerun with matching result identity;
- one Token-2022 evidence module with raw/parsed agreement tests;
- one native/Pinocchio detector family with fixture-backed false-positive tests;
- one deployment change alert that invalidates stale evidence correctly.

Commercial success:

- a repeatable fixed-scope review process;
- first paid small-team review with public or customer-approved reference;
- recurring monitoring customer;
- inbound request attributable to a public technical report;
- first Turkish-language cohort completing reproducible security exercises.

Commercial metrics never override technical truth or evidence status.

## 9. Explicitly deferred

- premium major-DeFi positioning before a public reference corpus exists;
- automatic exploitability or proof-of-fix claims;
- broad EVM audit expansion;
- Firedancer/validator-client auditing without dedicated C expertise;
- cross-chain criminal-pattern claims without verified bridge and entity evidence;
- legal conclusions about Turkish or foreign licensing without qualified counsel;
- public competitor comparisons based solely on marketing claims.
