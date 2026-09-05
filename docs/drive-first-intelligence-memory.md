# Drive-first intelligence memory

## Architecture boundary

Koschei Web3 treats Neon as authentication infrastructure only. ARVIS/radar/evidence/intelligence memory must not use Neon/PostgreSQL as a durable product-data store.

### Neon

Allowed:
- authentication provider state managed by Neon Auth,
- JWT/JWKS/login/register/session identity flows owned by the existing auth subsystem.

Not allowed:
- blockchain events,
- radar events or verdict history,
- wallet/actor dossiers,
- behavior or trajectory memory,
- evidence bundles,
- attack paths,
- incident/campaign corpus,
- raw transaction history,
- watchlist/alert history.

Auth code, auth schema and Auth Freeze contracts are outside this migration and must not be modified by intelligence-memory work.

### Google Drive

Google Drive is the durable archive for evidence-oriented ARVIS memory. Objects are JSON evidence envelopes with:
- schema version,
- memory kind,
- network,
- captured timestamp,
- SHA-256 target identity,
- evidence payload,
- Drive object SHA-256 metadata from the existing archive client.

Plaintext target addresses are not used in archive filenames. Solana target hashing remains exact and case-sensitive.

Before serialization, secret-like fields including private keys, seed phrases, API keys, access/refresh tokens, authorization values and passwords are redacted recursively.

### Blockchain / providers

The chain/provider remains the source of truth for raw historical state. Google Drive stores ARVIS evidence/results needed for durable investigation memory; it is not a second blockchain database.

### Redis / process memory

Redis may hold bounded TTL indexes/caches. Process memory is request-scoped and must not become an unbounded intelligence archive.

## Migration rule

Never delete historical application data from the old PostgreSQL tables until the corresponding export has been written to Drive and integrity/readback has been verified. After verified export, PostgreSQL application tables may be retired while the Neon Auth schema remains untouched.
