# Koschei Evidence Court

Status: foundation implemented, production verdict integration disabled by default.

## Purpose

Normal Solana RPC failover answers an availability question: if the preferred endpoint fails, can another endpoint provide the requested data?

Evidence Court answers a different question: when a fact is important enough to support a hard security claim, do independent providers return the same canonical state?

The first implementation is intentionally bounded and read-only.

## Runtime gate

```text
KOSCHEI_EVIDENCE_COURT_ENABLED=false
KOSCHEI_EVIDENCE_COURT_REQUIRED_WITNESSES=2
```

The feature is off unless explicitly enabled. No existing Radar or Transaction Guard path calls Evidence Court in this foundation release, so adding the engine creates no new production RPC spend by itself.

## Allowed RPC methods

The foundation permits only bounded state queries:

- `getAccountInfo`
- `getMultipleAccounts`
- `getTokenSupply`

History scans, signatures-for-address, program-wide scans and other potentially unbounded methods are rejected by the Evidence Court client.

## Independent witnesses

Configured RPC endpoints are deduplicated by provider identity where Koschei recognizes the provider. Multiple Helius, Alchemy, QuickNode or public-Solana endpoints cannot create multiple votes for the same provider. Unknown/private RPC services fall back to hostname identity.

Candidate witnesses can come from the existing Koschei Solana provider configuration, including configured Alchemy, Helius, QuickNode and public Solana RPC endpoints.

Customer output contains only safe provider labels and hostnames. Endpoint paths, API keys and query credentials are not part of the witness object.

## Canonical comparison

For context-bearing Solana responses, Evidence Court records the provider context slot but hashes the canonical `value` object rather than the full response envelope. This prevents harmless context-slot differences from becoming false state conflicts.

Object key order does not affect the canonical SHA-256 hash.

The deterministic quorum states are:

- `verified` — at least the configured witness threshold returned the same canonical value hash;
- `conflict` — enough providers responded, but no value reached the configured quorum;
- `insufficient` — too few providers returned usable canonical evidence;
- `unsupported_method` — the requested RPC method is outside the bounded allowlist;
- `disabled` — the feature gate is off.

A conflict never selects an authoritative value. Insufficient evidence never becomes a positive safety signal.

## Constitutional boundary

Evidence Court corroborates evidence. It does not:

- create a Radar grade;
- let an AI model change a verdict;
- turn an inferred relation into verified identity;
- sign or submit transactions;
- bypass the existing evidence-state rules;
- expose raw provider URLs or credentials.

The next integration phase should use quorum only for high-value evidence such as hard-trigger authority state, publication/court artifacts and State Witness issuance. Running every ordinary scan through several providers would add cost without proportional security value.

## Acceptance properties

The foundation is considered correct only when tests prove:

1. identical state with different context slots and JSON key order hashes identically;
2. two-of-three agreement can verify while preserving the dissenting witness;
3. conflicting providers produce `conflict` with no selected value hash;
4. missing provider evidence produces `insufficient`;
5. the feature is default-off;
6. unbounded RPC methods are rejected;
7. known providers cannot gain extra quorum votes through multiple hostnames or credentials;
8. witness metadata contains only safe provider identities/hosts and no credential material.
