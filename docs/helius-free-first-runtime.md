# Helius free-first runtime policy

Koschei Web3 treats Helius as a Solana evidence provider, not as the intelligence or verdict authority.

## Provider cost and plan boundaries

Helius provider methods do not all have the same plan or credit model. The runtime must keep those boundaries explicit instead of assuming that a configured API key makes every Helius capability safe to call.

Current Helius documentation states:

- Standard Solana RPC methods are the low-cost default path; ordinary RPC calls are charged separately from high-cost product APIs.
- Helius bills classic `getProgramAccounts` at 10 credits and the paginated `getProgramAccountsV2` method at 1 credit per request.
- `getProgramAccountsV2` supports the existing program-account filters plus cursor pagination, `withContext`, `minContextSlot`, `dataSlice`, and `changedSinceSlot`.
- DAS requests are provider-specific enrichment and must stay bounded.
- Enhanced Transactions are high-credit provider calls and are not the default holder-history collector.
- `getTransactionsForAddress` is a paid-plan archival method and costs 100 credits per call.
- `getTransfersByAddress` is a paid-plan archival method and costs 10 credits per call.
- Every Wallet API request costs 100 credits.
- Wallet API `balances`, `balance-at`, `history`, and `transfers` are available on Free.
- Wallet API `identity`, `batch-identity`, and `funded-by` require a paid plan; Free-plan requests return `403 Forbidden`.
- `batch-identity` accepts up to 100 addresses/domains in one 100-credit request and is the required Koschei path when paid Identity enrichment is intentionally enabled.

## Default behavior

Three provider-specific paid/high-credit paths stay disabled by default even when `HELIUS_API_KEY` is configured:

- Holder-cluster Enhanced Transactions history: `KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=false`
- Created-mint `getTransactionsForAddress` archival discovery: `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=false`
- Helius Wallet Identity enrichment: `HELIUS_WALLET_IDENTITY_ENABLED=false`

Default holder history uses standard Solana RPC (`getSignaturesForAddress` plus bounded `getTransaction` sampling).

Default created-mint discovery uses a provider-portable bounded Solana RPC window. Its default limits are:

- `CREATED_MINT_RPC_SIGNATURE_LIMIT=100`
- `CREATED_MINT_RPC_TRANSACTION_LIMIT=40`

The transaction sample is spread across the observed signature window instead of taking only the newest transactions. If older or unsampled history remains, the result is reported as `bounded`; absence of a created mint in that window is not treated as clean evidence.

Token-metadata creator resolution follows the same free-first rule. Helius DAS `getAsset` may provide a verified metadata creator candidate, but the default path does **not** make a second `getTransactionsForAddress` archival call merely to find the mint-creation signature. Instead it reads a bounded standard Solana mint-signature window and inspects the oldest successful transaction details inside that window. Defaults are `TOKEN_METADATA_CREATION_SIGNATURE_LIMIT=100` and `TOKEN_METADATA_CREATION_TRANSACTION_LIMIT=16`.

The token-metadata result exposes `creation_history_source`, `creation_history_bounded`, signatures seen, transaction details requested, and transaction details parsed. If the signature window boundary is reached or no exact create instruction is observed, that limitation is retained and the creator relation stays OBSERVED unless a concrete create transaction can be canonically verified. Setting `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=true` explicitly opts both created-mint archival discovery and token-metadata creation-history discovery back into Helius `getTransactionsForAddress`.

## Helius program-account pagination

When the canonical Solana RPC host is Helius, handler-level `getProgramAccounts` reads are automatically routed through `getProgramAccountsV2` and normalized back into the standard Solana response shape expected by existing Koschei collectors. Non-Helius providers continue to receive ordinary `getProgramAccounts`, so core evidence logic remains provider-portable.

Koschei uses a bounded page size and follows `paginationKey` until Helius returns a null cursor. A short page is not treated as completion. Repeated cursors, an excessive page chain, a missing context slot, or a context-slot change across pages fails closed rather than exposing a partial program-account set as complete evidence.

`HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED=false` is an emergency compatibility switch that restores the classic `getProgramAccounts` path on Helius. It should not be the normal setting because the classic Helius method carries the higher provider credit cost.

The current production consumer is the Raydium CLMM Burn & Earn lock-state query. Its existing program ID, account-size, pool memcmp, `dataSlice`, commitment, and `minContextSlot` restrictions are preserved by the V2 adapter; only the Helius transport method and pagination shape change.

## Explicit provider modes

Set `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=true` only when the deployment intentionally uses Helius `getTransactionsForAddress` archival history and its provider-plan/credit requirements have been accepted.

Set `KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=true` only when the deployment intentionally uses Helius Enhanced Transactions for holder history.

Set `HELIUS_WALLET_IDENTITY_ENABLED=true` only on a deployment whose Helius plan provides Wallet Identity. Koschei then resolves bounded address sets through `POST /v1/wallet/batch-identity` instead of issuing one Identity request per holder or flow endpoint. A `401` or `403` opens a process-level capability circuit so the same unavailable feature is not retried for every address in that process.

A missing Helius key, provider error, unavailable paid capability, or short batch response is not cached as proof that an address is unlabeled. Only a successful positive identity or a successful resolved-unknown batch entry is address-cached.

These switches do not disable normal Helius-backed Solana RPC, DAS metadata, or the Free-plan Wallet API endpoints that may be integrated separately with their own evidence and credit budgets.

## Evidence boundary

Provider discovery produces OBSERVED candidates. A created-mint candidate becomes VERIFIED only after Koschei re-reads the candidate transaction from the canonical Solana RPC and confirms the actor signer plus explicit Pump/SPL/Token-2022 mint-creation instruction.

Wallet Identity labels are third-party attribution metadata. A positive label may enrich entity context; a missing label, disabled capability, `403`, timeout, or provider failure must never become a clean-wallet or safety claim.

Provider availability, plan level, cache state, or missing history must never be converted into a safety claim.

## Free-plan opportunities

Helius Wallet API `balances`, `balance-at`, `history`, and `transfers` are available on the Free plan but each request costs 100 credits. Koschei should add them only where they replace more expensive or lower-quality evidence collection, and each integration must preserve source, timestamp, transaction signature/slot where available, coverage bounds, and an explicit distinction between provider-observed and canonically verified evidence.

## Secret handling

`HELIUS_API_KEY` and RPC URLs containing provider keys are deployment secrets. Do not commit them, expose them to the browser bundle, or log complete credential-bearing URLs. Prefer the `X-Api-Key` header for Wallet API requests where supported.
