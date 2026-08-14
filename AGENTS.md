# Repository agent contract

All Codex and automated implementation work in this repository must begin by selecting and reading the applicable canonical contract:

- product-wide Web3 defense-validation work: [`WEB3_DEFENSE_VALIDATION_ENGINE.md`](./WEB3_DEFENSE_VALIDATION_ENGINE.md);
- actor/token investigation work: [`ACTOR_INVESTIGATION_ENGINE.md`](./ACTOR_INVESTIGATION_ENGINE.md).

Work that crosses both surfaces must reference both documents and keep their verdicts separate.

## Non-negotiable product rules

1. Koschei Web3 is an evidence-first, vendor-neutral defense-validation product: it proves whether a specific Web3 defense configuration catches a controlled attack before impact without crossing mainnet, custody or signing boundaries.
2. The Actor Investigation Engine remains an active evidence subsystem. New actor/token investigation work must answer at least one question from its canonical ten-question filter.
3. Defense-validation outcomes and actor/unified Radar verdicts use separate, versioned deterministic rulesets. Neither result may silently change the other.
4. Weighted formulas, probabilities and `0–100` final security scores are prohibited. Exact timing, miss and false-positive counts are measurements, not scores.
5. A defense cannot self-attest `VALIDATED`. A validated result requires verified fork/sandbox execution, an independent observation record, a complete observation window and both attack and benign-control coverage.
6. `VALIDATED` applies only to the exact control version, configuration hash, scenario version, evidence set and observation window in the report. It is never a general safety guarantee.
7. The owner-facing primary Radar remains one manual pipeline: 14 legacy ARVIS arms + actor investigation + market/holder behavior rules + one letter-only final verdict.
8. The unified behavior ruleset includes explicit, versioned rules for volume/liquidity gap, dominant-holder position/liquidity pressure, creator sell acceleration and dominant-holder first observed exit.
9. `INFERRED` evidence is watch-only. `UNVERIFIED` evidence cannot affect a grade, produce `VALIDATED` or appear as a verified claim.
10. AI may explain deterministic rules and outcomes but may not generate, raise, lower or override a Radar grade or defense-validation result.
11. Serious on-chain actor claims require evidence rows with signature, slot, timestamp, source, destination, amount, program and verification status. Serious defense-validation claims require immutable execution, state, observation and alert evidence hashes.
12. Initial-distribution and holder follow-up must be mint-specific/ATA-based; recipient-wide full wallet history scans are prohibited in broad pipelines.
13. Actor index history is persistent. Raw-event retention must not delete durable actor memory.
14. Quota-consuming automatic scanning or validation is opt-in and disabled by default. Manual owner actions must never silently enable background workers.
15. Do not introduce demo, beta, placeholder, synthetic or fabricated production outputs. Safe fixtures are permitted only when backed by real fork/sandbox execution evidence and clearly labeled.
16. Defense-validation work must not store wallet material, submit mainnet transactions, mutate the tested production control, accept arbitrary commands or enable autonomous intervention.
17. Do not modify auth, Neon Auth, sessions, owner cookies, KOSCH entitlement or verified-wallet implementation unless the user explicitly requests that exact work.
18. Do not delete a legacy production path until its replacement has proven behavioral parity and rollback safety.
19. Koschei Sentinel and Koschei Lang remain separate incubation projects and must not become Web3 production dependencies without their own approved integration gates.

Every task description and pull request must name its applicable canonical contract and ruleset. Actor work must also name the actor ruleset and unified Radar ruleset. Defense-validation work must state whether it changes execution, observation, evaluation or publication authority and must list all default-off safety gates it preserves.
