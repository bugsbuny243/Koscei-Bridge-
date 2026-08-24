# Helius free-first runtime policy

Koschei Web3 treats Helius as a Solana evidence provider, not as the intelligence or verdict authority.

## Default behavior

Two expensive/provider-specific historical paths are disabled by default even when `HELIUS_API_KEY` is configured:

- Holder-cluster Enhanced Transactions history: `KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=false`
- Created-mint `getTransactionsForAddress` archival discovery: `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=false`

Default holder history uses standard Solana RPC (`getSignaturesForAddress` plus bounded `getTransaction` sampling).

Default created-mint discovery uses a provider-portable bounded Solana RPC window. Its default limits are:

- `CREATED_MINT_RPC_SIGNATURE_LIMIT=100`
- `CREATED_MINT_RPC_TRANSACTION_LIMIT=40`

The transaction sample is spread across the observed signature window instead of taking only the newest transactions. If older or unsampled history remains, the result is reported as `bounded`; absence of a created mint in that window is not treated as clean evidence.

## Explicit archival mode

Set `HELIUS_CREATED_MINT_ARCHIVAL_ENABLED=true` only when the deployment intentionally uses Helius `getTransactionsForAddress` archival history and its provider-plan/credit requirements have been accepted.

Set `KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=true` only when the deployment intentionally uses Helius Enhanced Transactions for holder history.

These switches do not disable normal Helius-backed Solana RPC, DAS metadata, or other provider-key uses.

## Evidence boundary

Provider discovery produces OBSERVED candidates. A created-mint candidate becomes VERIFIED only after Koschei re-reads the candidate transaction from the canonical Solana RPC and confirms the actor signer plus explicit Pump/SPL/Token-2022 mint-creation instruction.

Provider availability, plan level, cache state, or missing history must never be converted into a safety claim.

## Secret handling

`HELIUS_API_KEY` and RPC URLs containing provider keys are deployment secrets. Do not commit them, expose them to the browser bundle, or log complete credential-bearing URLs.
