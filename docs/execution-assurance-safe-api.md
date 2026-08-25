# Safe Execution Assurance API

## Purpose

`POST /api/v1/execution-assurance/safe/verify` is the first production-wired HTTP boundary for Koschei Execution Proof.

It answers one narrow question before signing:

> Does this complete raw Safe transaction resolve to the exact signing request approved by the supplied Execution Proof?

The endpoint is verification-only. It does not sign, forward, submit, replace, or execute a transaction.

## Authentication

Developer API key + active Enterprise SaaS entitlement.

The route uses the same API-key authentication, Enterprise entitlement, rate-limit, and database-availability boundary as other Enterprise developer APIs.

## Trust model

The caller supplies:

1. the Execution Proof envelope;
2. the complete Safe transaction fields used by `getTransactionHash`;
3. the Safe hash presented by the caller's UI/service/integration.

Koschei then independently:

1. recomputes the Execution Proof decision and envelope SHA-256 instead of trusting serialized `evaluation`;
2. recomputes `safeTxHash` using native Safe v1.3+ EIP-712 semantics from all transaction fields;
3. compares the recomputed Safe hash with `presented_safe_tx_hash`;
4. hashes the actual calldata and compares chain, target, calldata digest, and Safe signing-request identity with the proof;
5. returns deterministic `ALLOW` or `BLOCK` plus reason codes.

A caller-selected `ALLOW` field cannot override the recomputed proof result.

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
  "evidence_model": "recomputed_execution_proof_plus_native_safe_eip712_hash",
  "computed_safe_tx_hash": "0x...",
  "presented_safe_tx_hash": "0x...",
  "presented_envelope_sha256": "...",
  "recomputed_envelope_sha256": "...",
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

## Authority boundary

This endpoint deliberately has no:

- private key or seed material;
- Safe signer;
- Safe Transaction Service write client;
- transaction broadcaster;
- mainnet submission path;
- production-control mutation capability.

It is therefore suitable as an independent pre-sign verification service without turning Koschei Web3 into a custody product.

## Production claim boundary

Repository wiring and CI prove that the handler is part of the server boot chain. They do not by themselves prove a deployed environment has served the route. Production-active claims require runtime/deployment evidence after release.
