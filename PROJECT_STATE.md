# Koschei Web3 Project State

This file is the repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Repository state wins over conversational assumptions.

## CURRENT STATE

- Active product PR: **none**.
- Open pull requests: **none** at this checkpoint.
- Transaction Preflight v1 was merged through PR **#960**.
- Product behavior: Professional users can use `/scan?mode=transaction` to obtain the real pre-sign Transaction Guard result.
- The client does not sign or broadcast the transaction and does not persist the raw transaction.
- The legacy numeric risk score is not the decision authority for Transaction Preflight.
- `openapi.yaml` has been regenerated from the final merged route inventory after the PR #960/main race.
- Canonical generated OpenAPI blob at this checkpoint: `200ecfadec6153880ed53317b49269d6af5e8ae6` (155 registered API paths).
- Last code-affecting verification head: `e2a2995cf10c477db94dda16c35da4c3c3151b20`.

## CHANGED

- PR #960 merged the customer Transaction Preflight UI plus the generated API contract and formatting-only Agent Go cleanup present in that final PR head.
- The final merge exposed four Agent routes that had landed on `main` after PR-head validation:
  - `/api/agents/admin/onboard`
  - `/api/agents/admin/pilots`
  - `/api/agents/admin/pilots/status`
  - `/api/agents/pilot`
- `openapi.yaml` was synchronized on final `main` only; no Agent behavior was reverted to repair the drift.
- Stale PR #959 was closed because its Agent diff was no longer formatting-only and would have reverted account-aware WhatsApp/provenance behavior.
- Stale PR #942 was closed unmerged. It was 140 commits behind current `main`, its complete diff was only two standalone defense-validation files, and it was not wired into the live route/customer response. Current Transaction Guard V3 is the authoritative live path for further evidence-first validation work.
- The OpenAPI drift test message now explicitly requires regeneration from the exact current target head before merge.

## VERIFIED

- PR #960 head `c605228cdf37a3d9c9d1eec1e88cbaf3608d8331` passed its permanent PR-head gates before merge.
- Actual merge commit `99a7b1e85febf4a852ef9c795da84dc9807c67df` exposed one repository invariant failure expressed by two checks: committed OpenAPI was stale relative to the final registered boot-chain routes.
- The failing API test was `TestCommittedOpenAPIMatchesRegisteredAPIRoutes`; migrations and the other observed API/security checks were not the root blocker.
- Final OpenAPI synchronization commit: `06c2a15f23112229f8175cfc8640996b524ebf11`.
- That synchronization commit changes only `koschei/api/openapi.yaml` and adds exactly the four missing Agent route contracts; existing 151 path objects were not modified.
- On code-affecting head `e2a2995cf10c477db94dda16c35da4c3c3151b20`, all **7 workflows triggered by the changed path completed successfully**:
  - API Required CI
  - OpenAPI Contract
  - Security CI
  - Supply Chain Security
  - CodeQL
  - Public Product Smoke
  - Public API Transport Smoke
- API Required CI completed migrations, tests, vet and build successfully, and its secret/vulnerability/static-security job also succeeded.
- OpenAPI Contract succeeded on the same exact code head.

## BROKEN / MISSING

- `main` is currently **not branch-protected**. Parallel direct pushes can move the merge base after a PR's synthetic merge candidate has passed CI.
- No Transaction Preflight product blocker is currently known from the verified head.

## WORK-IN-PROGRESS POLICY

1. Keep **one active product PR** at a time.
2. A CI failure does **not** justify a new branch or PR by itself.
3. If CI is broken by unrelated `main` drift, classify the failure first and repair the smallest safe invariant on the current work line.
4. Open a new branch only for a real scope split, required security isolation, or an unrecoverably polluted branch.
5. New ideas go to backlog; they do not interrupt the active product change.
6. Do not merge stale cleanup or product branches whose final diff no longer matches the current product architecture or stated scope.
7. Before merge, validate against the current target head; after merge, verify the actual merged `main` head.
8. A stale feature PR that is far behind `main` must not be kept alive merely to preserve old work; first prove that its capability is still missing from the current live path.

## NEXT

1. Do **not** open another product branch yet.
2. Enforce or configure protected-main / current-head merge discipline so parallel work cannot invalidate Web3 PR evidence after CI.
3. After the merge discipline is fixed, inspect the current live Transaction Guard V3 and select exactly one next customer-useful Web3 slice from current-main evidence, not from a stale PR or old chat idea.

## RISKS

- The principal process risk is an unprotected `main`, not Transaction Preflight behavior.
- A green PR is insufficient evidence when `main` can move between synthetic merge validation and the real merge.
- Repeated temporary branches/workflows for generated-contract drift create repository noise; route registration and generated OpenAPI should travel atomically with the change that introduces the route.
- Parallel decision contracts are a product/security risk: evidence-first validation must evolve through the current live Transaction Guard path, not through disconnected legacy builders.
