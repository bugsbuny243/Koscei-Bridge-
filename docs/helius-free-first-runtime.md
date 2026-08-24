# Helius free-first runtime policy

Koschei Web3 treats Helius as a Solana evidence provider, not as the intelligence or verdict authority.

## Default behavior

Three provider-specific or paid-plan paths are disabled by default even when `HELIUS_API_KEY` is configured:

- Holder-cluster Enhanced Transactions history: `KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=false`
- Created-mint `getTransactionsForAddress` archival discovery: `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=false`
- Helius Wallet Identity enrichment: `HELIUS_WALLET_IDENTITY_ENABLED=false`

Default holder history uses standard Solana RPC (`getSignaturesForAddress` plus bounded `getTransaction` sampling).

Default created-mint discovery uses a provider-portable bounded Solana RPC window. Its default limits are:

- `CREATED_MINT_RPC_SIGNATURE_LIMIT=100`
- `CREATED_MINT_RPC_TRANSACTION_LIMIT=40`

The transaction sample is spread across the observed signature window instead of taking only the newest transactions. If older or unsampled history remains, the result is reported as `bounded`; absence of a created mint in that window is not treated as clean evidence.

## Explicit provider modes

Set `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=true` only when the deployment intentionally uses Helius `getTransactionsForAddress` archival history and its provider-plan/credit requirements have been accepted.

Set `KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=true` only when the deployment intentionally uses Helius Enhanced Transactions for holder history.

Set `HELIUS_WALLET_IDENTITY_ENABLED=true` only on a deployment whose Helius plan provides Wallet Identity. Helius currently documents `GET /v1/wallet/{wallet}/identity` as paid-plan-only and returns `403 Forbidden` on Free. Koschei therefore makes no Wallet Identity request by default. If an explicitly enabled deployment receives `401` or `403`, a process-level capability circuit prevents the same unavailable feature from being retried for every holder address in that process.

A missing Helius key, provider error, or unavailable paid capability is not cached as proof that an address is unlabeled. Only definitive `404`, a successful empty identity response, or a successful positive identity response is address-cached.

These switches do not disable normal Helius-backed Solana RPC, DAS metadata, or other provider-key uses.

## Evidence boundary

Provider discovery produces OBSERVED candidates. A created-mint candidate becomes VERIFIED only after Koschei re-reads the candidate transaction from the canonical Solana RPC and confirms the actor signer plus explicit Pump/SPL/Token-2022 mint-creation instruction.

Wallet Identity labels are third-party attribution metadata. A positive label may enrich entity context; a missing label, disabled capability, `403`, timeout, or provider failure must never become a clean-wallet or safety claim.

Provider availability, plan level, cache state, or missing history must never be converted into a safety claim.

## Secret handling

`HELIUS_API_KEY` and RPC URLs containing provider keys are deployment secrets. Do not commit them, expose them to the browser bundle, or log complete credential-bearing URLs.
