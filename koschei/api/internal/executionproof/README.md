# Koschei Execution Proof v0.1

Execution Proof is a Security Control Plane boundary, separate from actor/Radar investigation behavior.

## Authority rule

`NO VALID EXECUTION PROOF = NO SIGNING FORWARD`

The signing path must never trust a serialized `ALLOW`, a Transaction Service supplied Safe hash, or a runtime-provided artifact identity as authoritative by itself.

## v0.1 evidence chain

`source -> build -> runtime -> payload -> invariant -> signing request`

Every mandatory edge fails closed. The final decision is only `ALLOW` or `BLOCK` with deterministic reason codes.

## Safe boundary

For Safe transactions, Koschei recomputes `safeTxHash` locally from the complete raw Safe transaction using Safe EIP-712 semantics. The presented service hash is comparison-only evidence. Any mismatch blocks forwarding.

The production `VerifyAndForwardSafeTransaction` boundary owns the native Safe hash authority; callers cannot inject a Transaction Service supplied or pass-through hash implementation there.

A `BLOCK` decision is enforced before the side-effecting `SafeForwarder` boundary. The forwarder must not be called for invalid evidence, proof tampering, Safe hash mismatch, request mismatch, or a cancelled context. A downstream forward transport failure is returned as a failed/BLOCK result, never as ALLOW.

## Safe upstream conformance

The Safe EIP-712 schema tests are pinned to `safe-fndn/safe-smart-account` commit `37a8215a8f2a10e275650cfce0059dbfb480030e` (`contracts/Safe.sol` and `src/utils/execution.ts`). The upstream domain and `SafeTx` schema strings are independently Keccak-hashed and compared with Koschei's typehash constants; a full transaction golden-hash test separately locks the final digest.

No static Safe-owned golden JSON fixture is claimed by this package.

## Validation

The dedicated Railway validator is source-bound to `feat/execution-proof-v0.1`, builds `Dockerfile.execution-proof-validator` from the full repository snapshot, and requires:

```text
go mod download
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/koschei-api .
```

Exact-head deployment metadata must match the PR head before a PASS is accepted. An older green deployment is not accepted after the branch head changes.

## Non-goals

No direct production Safe Transaction Service write adapter, mainnet-fork invariant runner, numeric score, letter grade, AI-generated decision, custody replacement, or fabricated production proof output is part of v0.1.
