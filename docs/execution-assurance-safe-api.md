# Safe Execution Assurance API

## Purpose

`POST /api/v1/execution-assurance/safe/verify` is the first production-wired HTTP boundary for Koschei Execution Proof.

It answers one narrow question before signing:

> Does this complete raw Safe transaction resolve to the exact signing request approved by a fresh, independently authenticated Execution Proof observation?

The endpoint is verification-only. It does not sign, forward, submit, replace, or execute a transaction.

## Authentication

Developer API key + active Enterprise SaaS entitlement.

The route uses the same API-key authentication, Enterprise entitlement, rate-limit, and database-availability boundary as other Enterprise developer APIs.

## Independent trust anchor

An internally consistent Execution Proof is not enough to authorize `ALLOW`. A caller could otherwise fabricate matching evidence, set the simulation result to `PASS`, and create a proof that is self-consistent but has no trusted provenance.

The endpoint therefore requires a signed `proof_attestation` produced by an independently trusted collector or assurance producer.

Trust material is server-owned configuration:

- `KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_PRODUCER`
- `KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_ED25519_PUBLIC_KEY`

The request cannot select or replace the trusted producer or public key. The trusted Ed25519 private key is not required by this API server and must not be stored in the frontend, request payload, repository, or API-server logs.

If the trusted producer/public-key configuration is absent, the endpoint fails closed with HTTP `503` and `execution_assurance_unconfigured`.

## Trust model

The caller supplies:

1. the Execution Proof;
2. a signed independent `proof_attestation`;
3. the complete Safe transaction fields used by `getTransactionHash`;
4. the Safe hash presented by the caller's UI/service/integration.

Koschei then independently:

1. recomputes the Execution Proof decision and envelope SHA-256 instead of trusting serialized `evaluation`;
2. recomputes `safeTxHash` using native Safe v1.3+ EIP-712 semantics from all transaction fields;
3. compares the recomputed Safe hash with `presented_safe_tx_hash`;
4. hashes the actual calldata and compares chain, target, calldata digest, and Safe signing-request identity with the proof;
5. authenticates the attestation with the server-configured Ed25519 public key and exact producer identity;
6. requires the signed attestation to bind the exact EIP-155 chain, recomputed Safe transaction hash, recomputed Execution Proof SHA-256, and canonical binding digest;
7. requires the signed observation to be fresh: older than five minutes fails closed, and timestamps more than 30 seconds into the future fail closed;
8. returns deterministic `ALLOW` or `BLOCK` plus reason codes.

A caller-selected `ALLOW`, caller-selected public key, self-signed event, stale event, or valid signature over a different Safe transaction/proof cannot override the verification result.

## Attestation binding

The signed event authenticates this canonical binding:

```json
{
  "version": "koschei.safe-execution-attestation/v1",
  "chain_id": 1,
  "safe": "0x1111111111111111111111111111111111111111",
  "safe_tx_hash": "0x...",
  "execution_proof_sha256": "..."
}
```

The `securityevidence.Event` must also carry:

- `subject.chain = eip155:<chain_id>`;
- `subject.type = safe_execution_assurance`;
- `subject.id = <recomputed safeTxHash>`;
- exactly one `source_digests_sha256` entry equal to the recomputed Execution Proof SHA-256;
- a `VERIFIED` finding with id `safe-execution-binding`, kind `safe_execution_binding`, and `evidence_sha256` equal to the canonical binding digest;
- valid Ed25519 producer authentication and a valid sealed event digest.

## Request

```json
{
  "execution_proof": {
    "envelope": {},
    "evaluation": {
      "decision": "ALLOW",
      "reasons": []
    },
    "envelope_sha256": "..."
  },
  "proof_attestation": {
    "schema_version": "koschei.security-evidence/v1",
    "producer": "independent-collector-a",
    "subject": {
      "chain": "eip155:1",
      "type": "safe_execution_assurance",
      "id": "0x..."
    },
    "window": {
      "from_unix_ms": 0,
      "to_unix_ms": 0
    },
    "source_digests_sha256": ["..."],
    "findings": [
      {
        "id": "safe-execution-binding",
        "kind": "safe_execution_binding",
        "state": "VERIFIED",
        "evidence_sha256": "..."
      }
    ],
    "authentication": {
      "algorithm": "ed25519",
      "signature": "..."
    },
    "event_sha256": "..."
  },
  "transaction": {
    "chain_id": 1,
    "safe": "0x1111111111111111111111111111111111111111",
    "to": "0x2222222222222222222222222222222222222222",
    "value": "0",
    "data": "0x1234",
    "operation": 0,
    "safe_tx_gas": "0",
    "base_gas": "0",
    "gas_price": "0",
    "gas_token": "0x0000000000000000000000000000000000000000",
    "refund_receiver": "0x0000000000000000000000000000000000000000",
    "nonce": "7"
  },
  "presented_safe_tx_hash": "0x..."
}
```

The zero timestamps above are shape placeholders only; a real attestation must contain its actual signed observation window and must satisfy the freshness policy.

`value`, gas fields, and `nonce` are strings so the API never depends on JSON floating-point handling for uint256 values. Decimal and `0x`-prefixed hexadecimal forms are accepted. Negative values and values wider than uint256 are rejected.

`data` must be `0x`-prefixed hex and is bounded to 128 KiB decoded. The shared HTTP JSON body limit remains 1 MiB.

## Successful evaluation response

A validly formed request returns HTTP `200` whether the security decision is `ALLOW` or `BLOCK`.

```json
{
  "ok": true,
  "product": "Koschei Execution Assurance",
  "decision": "BLOCK",
  "reason_codes": ["EP-009-SAFE-HASH-MISMATCH"],
  "evidence_model": "trusted_ed25519_attestation_plus_recomputed_execution_proof_plus_native_safe_eip712_hash",
  "computed_safe_tx_hash": "0x...",
  "presented_safe_tx_hash": "0x...",
  "presented_envelope_sha256": "...",
  "recomputed_envelope_sha256": "...",
  "attestation_verified": true,
  "attestation_producer": "independent-collector-a",
  "attestation_event_sha256": "...",
  "attestation_binding_sha256": "...",
  "mainnet_transaction_sent": false,
  "signing_authority": false,
  "forwarding_authority": false,
  "production_control_mutation": false,
  "limitations": []
}
```

Malformed transaction fields or malformed hashes return HTTP `400` and are not treated as a completed security evaluation.

## Relevant reason codes

The endpoint preserves Execution Proof reason codes. Important signing-boundary examples include:

- `EP-001-INVALID-EVIDENCE`
- `EP-002-ARTIFACT-MISMATCH`
- `EP-003-RUNTIME-ARTIFACT-MISMATCH`
- `EP-004-PAYLOAD-MISMATCH`
- `EP-005-INVARIANT-NOT-PASS`
- `EP-006-PROOF-HASH-MISMATCH`
- `EP-007-SIGNING-REQUEST-MISMATCH`
- `EP-008-INVALID-SIGNING-REQUEST`
- `EP-009-SAFE-HASH-MISMATCH`
- `EP-010-UNTRUSTED-ATTESTATION`
- `EP-011-STALE-ATTESTATION`

`EP-010` covers missing/invalid producer authentication, wrong trusted key, wrong event binding, a signature over a different Safe transaction/proof, or other provenance failures. `EP-011` means the correctly authenticated event is outside the allowed observation freshness window.

## Authority boundary

This endpoint deliberately has no:

- private key or seed material;
- Safe signer;
- Safe Transaction Service write client;
- transaction broadcaster;
- mainnet submission path;
- production-control mutation capability.

It is therefore suitable as an independent pre-sign verification service without turning Koschei Web3 into a custody product.

The external assurance producer/collector owns its own Ed25519 private key and is a separate trust domain. This verification API needs only the trusted public key.

## Production claim boundary

Repository wiring and CI prove that the handler is part of the server boot chain. They do not by themselves prove a deployed environment has served the route, nor do they prove an external attestation producer has been deployed and configured. Production-active claims require runtime/deployment evidence for both the API verification path and the trusted producer path after release.
