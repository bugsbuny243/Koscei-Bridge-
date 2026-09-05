# Compact Intelligence Index

Koschei Web3 does not persist the raw blockchain/event firehose as product memory.

When the application database is unavailable but a real cache is configured, unified token and wallet verdicts may retain one bounded TTL index record per exact target. The record exists only to recognize repeated technical states cheaply; it is not an evidence archive and never replaces live chain/provider verification.

## Stored

- hashed target identity for the cache key
- network and target kind
- deterministic verdict fingerprint
- grade/verdict and ruleset versions
- signed/not-signed flag
- bounded triggered-rule and watch-flag summaries
- bounded decision path and behavior-signal summaries
- first seen, last seen and scan count

## Not stored

- serialized transactions
- raw transaction history
- raw event streams
- full actor dossiers
- complete evidence bundles
- private keys, secrets or provider credentials

Default TTL is 7 days. `KOSCHEI_COMPACT_INDEX_TTL_HOURS` may shorten or extend retention, but code clamps it to a maximum of 30 days.

If cache is disabled/Noop, the runtime reports no compact persistence. With in-process memory cache, the index is process-local and disappears on restart. With Redis, the same bounded TTL contract applies across requests.

Evidence remains request-scoped in stateless mode. When a prior compact fingerprint matters, Koschei must rehydrate the underlying proof from chain/providers before making a current evidence claim.
