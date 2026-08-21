# Koschei Execution Proof

## Current integration status

Execution Proof is a substantial internal security subsystem, but it is **not currently wired into the deployed Koschei Web3 API/runtime path**. Repository-level callers for its signing/forwarding entrypoints remain inside `internal/executionproof` and its tests. Until an explicit handler/service/worker call chain and production evidence exist, this package must not be described as production-active enforcement.

The package is therefore classified as **internal/experimental security control-plane code under connectivity audit**.

## Intended authority rule

`NO VALID EXECUTION PROOF = NO SIGNING FORWARD`

If/when this subsystem is connected to a real signing path, that path must never trust a serialized `ALLOW`, a Transaction Service supplied Safe hash, or a runtime-provided artifact identity as authoritative by itself.

## Evidence chain

The implemented model is:

`source -> build -> runtime -> payload -> invariant -> signing request`

Mandatory edges are designed to fail closed. Decisions are deterministic `ALLOW` or `BLOCK` reason-code outputs rather than a score or grade.

## Safe boundary implemented in this package

For Safe transactions, the package recomputes `safeTxHash` locally from the complete raw Safe transaction using Safe EIP-712 semantics. The presented service hash is comparison-only evidence; mismatches block the package forwarding boundary.

`VerifyAndForwardSafeTransaction` is the package's native Safe hash/forwarding boundary. It is **not a deployed production boundary merely because the function exists**. Production status requires a verified non-test caller from the deployed product plus runtime evidence that the path executes.

Within the package, a `BLOCK` decision is enforced before the side-effecting `SafeForwarder` interface. The forwarder must not be called for invalid evidence, proof tampering, Safe hash mismatch, request mismatch, or a cancelled context. A downstream forward transport failure is returned as failed/BLOCK, never as ALLOW.

## Safe upstream conformance

The Safe EIP-712 schema tests are pinned to `safe-fndn/safe-smart-account` commit `37a8215a8f2a10e275650cfce0059dbfb480030e` (`contracts/Safe.sol` and `src/utils/execution.ts`). The upstream domain and `SafeTx` schema strings are independently Keccak-hashed and compared with Koschei's typehash constants; a full transaction golden-hash test separately locks the final digest.

No static Safe-owned golden JSON fixture is claimed by this package.

## Validation status

Package/unit/integration validation can prove implementation behavior, but it does **not** prove deployed reachability.

The old `Dockerfile.execution-proof-validator` / dedicated external Railway validator path was removed from `main` by PR #853 and must not be referenced as a current validation dependency.

Current acceptance for production wiring must include all of the following:

1. a non-test deployed caller outside `internal/executionproof`;
2. caller -> handler/service/worker -> route/startup wiring trace;
3. explicit config/feature-gate ownership where applicable;
4. tests covering the actual integration boundary;
5. production evidence proving the call path executes;
6. no bypass path that can forward/sign without the required proof boundary.

## Non-goals / no current production claim

No claim is made here that Koschei Web3 currently routes production signing, Safe Transaction Service writes, custody, or user funds through this package. Generic EVM/fork evidence and Safe-aware contracts present in this package remain implementation evidence until the connectivity audit closes.

See issue #864 for the connectivity audit and classification work.
