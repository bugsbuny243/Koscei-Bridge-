# Koschei Execution Proof

## Current integration status

Execution Proof is a substantial internal security subsystem. One narrow main-product integration is now explicitly wired into the API boot chain: Enterprise `POST /api/v1/execution-assurance/safe/verify` imports this package through the HTTP handler and performs read-only Safe signing verification.

That endpoint recomputes the complete Safe EIP-712 `safeTxHash`, recomputes the Execution Proof envelope decision/hash, and requires exact identity between the raw Safe transaction and the approved signing request before it can return `ALLOW`.

Internal consistency alone is not trusted provenance. The HTTP boundary also requires a fresh `securityevidence.Event` signed by the server-configured trusted Ed25519 producer. The signed event must bind the exact recomputed Execution Proof SHA-256 and Safe transaction hash. Caller-supplied/self-signed trust material cannot authorize the request.

This closes the repository connectivity gap for the **verification-only** boundary. It does **not** mean Koschei Web3 holds signing authority, forwards Safe transactions, submits mainnet transactions, or mutates production controls. Side-effecting forwarder paths in this package remain internal/experimental unless separately wired and proven.

A registered route is still not by itself proof that a deployed environment has served the path or that an independent attestation producer has been deployed. Production-active claims require deployment/runtime evidence in addition to repository wiring and CI.

## Intended authority rule

`NO VALID EXECUTION PROOF + TRUSTED FRESH ATTESTATION = NO SIGNING FORWARD`

Any signer or forwarding integration must never trust a serialized `ALLOW`, a Transaction Service supplied Safe hash, caller-selected producer key, or runtime-provided artifact identity as authoritative by itself.

## Evidence chain

The implemented model is:

`source -> build -> runtime -> payload -> invariant -> signing request -> authenticated independent attestation`

Mandatory edges are designed to fail closed. Decisions are deterministic `ALLOW` or `BLOCK` reason-code outputs rather than a score or grade.

## Safe boundary implemented in this package

For Safe transactions, the package recomputes `safeTxHash` locally from the complete raw Safe transaction using Safe EIP-712 semantics. The presented service hash is comparison-only evidence; mismatches block the authorization boundary.

`SafeExecutionAttestationBindingV1` binds the EIP-155 chain, Safe address, recomputed `safeTxHash`, and recomputed Execution Proof SHA-256. `VerifySafeExecutionAttestationV1` authenticates a `securityevidence.Event` against producer identity/public-key trust supplied out of band by the server configuration, verifies the exact binding, and applies a bounded freshness window. Untrusted provenance is `EP-010`; stale authenticated evidence is `EP-011`.

`AuthorizeSafeForward` is reused by the production-wired verification handler, but the HTTP path supplies no `SafeForwarder` and performs no side effect. `VerifyAndForwardSafeTransaction` and other forwarding functions remain non-production until a separately authorized integration proves their need, caller chain, configuration, tests, and deployed runtime evidence.

Within the package, a `BLOCK` decision is enforced before any side-effecting `SafeForwarder` interface. The forwarder must not be called for invalid evidence, proof tampering, Safe hash mismatch, request mismatch, untrusted/stale provenance, or a cancelled context. A downstream forward transport failure is returned as failed/BLOCK, never as ALLOW.

## Safe upstream conformance

The Safe EIP-712 schema tests are pinned to `safe-fndn/safe-smart-account` commit `37a8215a8f2a10e275650cfce0059dbfb480030e` (`contracts/Safe.sol` and `src/utils/execution.ts`). The upstream domain and `SafeTx` schema strings are independently Keccak-hashed and compared with Koschei's typehash constants; a full transaction golden-hash test separately locks the final digest.

No static Safe-owned golden JSON fixture is claimed by this package.

## Trusted attestation boundary

The production-wired verification handler reads only these trust-anchor values from server configuration:

- `KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_PRODUCER`
- `KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_ED25519_PUBLIC_KEY`

The API request does not carry an authoritative trust key. The verification server does not require the producer private key. Private signing material belongs to the independent producer/collector trust domain and must not be embedded in the API server or browser bundle.

The current HTTP policy requires the signed observation to be no older than five minutes and rejects timestamps more than 30 seconds into the future. Missing trust configuration fails closed before evaluation.

## Validation status

Package/unit/integration validation proves implementation behavior and repository connectivity, but it does **not** prove a deployed environment has served the route.

The old `Dockerfile.execution-proof-validator` / dedicated external Railway validator path was removed from `main` by PR #853 and must not be referenced as a current validation dependency.

Current acceptance for any additional production wiring includes all of the following:

1. a non-test deployed caller outside `internal/executionproof`;
2. caller -> handler/service/worker -> route/startup wiring trace;
3. explicit config/feature-gate ownership where applicable;
4. tests covering the actual integration boundary;
5. production evidence proving the call path executes;
6. authenticated independent evidence provenance where `ALLOW` depends on externally produced facts;
7. no bypass path that can forward/sign without the required proof boundary.

## Non-goals / production claim boundary

The verification API does not make Koschei Web3 a custody system. No claim is made that Koschei routes production signing, Safe Transaction Service writes, custody, or user funds through this package.

Generic EVM/fork evidence and side-effecting Safe-aware contracts present in this package remain implementation evidence until their own connectivity and production-evidence requirements are met.

See issue #864 for the original connectivity-audit finding and resolution rules.
