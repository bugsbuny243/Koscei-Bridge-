# Koschei Execution Proof

## Current integration status

Execution Proof is a substantial internal security subsystem. One narrow main-product integration is now explicitly wired into the API boot chain: Enterprise `POST /api/v1/execution-assurance/safe/verify` imports this package through the HTTP handler and performs read-only Safe signing verification.

That endpoint recomputes the complete Safe EIP-712 `safeTxHash`, recomputes the Execution Proof envelope decision/hash, and requires exact identity between the raw Safe transaction and the approved signing request before it can return `ALLOW`.

This closes the repository connectivity gap for the **verification-only** boundary. It does **not** mean Koschei Web3 holds signing authority, forwards Safe transactions, submits mainnet transactions, or mutates production controls. Side-effecting forwarder paths in this package remain internal/experimental unless separately wired and proven.

A registered route is still not by itself proof that a deployed environment has served the path. Production-active claims require deployment/runtime evidence in addition to repository wiring and CI.

## Intended authority rule

`NO VALID EXECUTION PROOF = NO SIGNING FORWARD`

Any signer or forwarding integration must never trust a serialized `ALLOW`, a Transaction Service supplied Safe hash, or a runtime-provided artifact identity as authoritative by itself.

## Evidence chain

The implemented model is:

`source -> build -> runtime -> payload -> invariant -> signing request`

Mandatory edges are designed to fail closed. Decisions are deterministic `ALLOW` or `BLOCK` reason-code outputs rather than a score or grade.

## Safe boundary implemented in this package

For Safe transactions, the package recomputes `safeTxHash` locally from the complete raw Safe transaction using Safe EIP-712 semantics. The presented service hash is comparison-only evidence; mismatches block the authorization boundary.

`AuthorizeSafeForward` is reused by the production-wired verification handler, but the HTTP path supplies no `SafeForwarder` and performs no side effect. `VerifyAndForwardSafeTransaction` and other forwarding functions remain non-production until a separately authorized integration proves their need, caller chain, configuration, tests, and deployed runtime evidence.

Within the package, a `BLOCK` decision is enforced before any side-effecting `SafeForwarder` interface. The forwarder must not be called for invalid evidence, proof tampering, Safe hash mismatch, request mismatch, or a cancelled context. A downstream forward transport failure is returned as failed/BLOCK, never as ALLOW.

## Safe upstream conformance

The Safe EIP-712 schema tests are pinned to `safe-fndn/safe-smart-account` commit `37a8215a8f2a10e275650cfce0059dbfb480030e` (`contracts/Safe.sol` and `src/utils/execution.ts`). The upstream domain and `SafeTx` schema strings are independently Keccak-hashed and compared with Koschei's typehash constants; a full transaction golden-hash test separately locks the final digest.

No static Safe-owned golden JSON fixture is claimed by this package.

## Validation status

Package/unit/integration validation proves implementation behavior and repository connectivity, but it does **not** prove a deployed environment has served the route.

The old `Dockerfile.execution-proof-validator` / dedicated external Railway validator path was removed from `main` by PR #853 and must not be referenced as a current validation dependency.

Current acceptance for any additional production wiring includes all of the following:

1. a non-test deployed caller outside `internal/executionproof`;
2. caller -> handler/service/worker -> route/startup wiring trace;
3. explicit config/feature-gate ownership where applicable;
4. tests covering the actual integration boundary;
5. production evidence proving the call path executes;
6. no bypass path that can forward/sign without the required proof boundary.

## Non-goals / production claim boundary

The verification API does not make Koschei Web3 a custody system. No claim is made that Koschei routes production signing, Safe Transaction Service writes, custody, or user funds through this package.

Generic EVM/fork evidence and side-effecting Safe-aware contracts present in this package remain implementation evidence until their own connectivity and production-evidence requirements are met.

See issue #864 for the original connectivity-audit finding and resolution rules.