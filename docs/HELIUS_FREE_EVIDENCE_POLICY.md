# Helius Free Evidence Policy

Operational snapshot: 2026-08-24. Helius billing and plan limits can change; provider documentation and the account usage dashboard remain the billing authority.

## Principle

Helius is a Solana evidence provider, not Koschei Web3's verdict engine. Provider-specific convenience endpoints must not silently become mandatory for canonical ARVIS evidence when equivalent bounded evidence can be collected through standard Solana RPC.

## Current provider-cost snapshot

According to Helius billing documentation reviewed on 2026-08-24:

- standard RPC calls: 1 credit per call unless separately listed;
- DAS API calls: 10 credits;
- Enhanced Transactions: 100 credits;
- `getTransactionsForAddress`: 50 credits and Developer plan or above;
- `getTransfersByAddress`: 10 credits and Developer plan or above;
- Free plan: 1,000,000 monthly credits.

Do not hard-code these billing weights into verdict logic. They are operational planning inputs only.

## ARVIS defaults

### Holder history

The default holder-cluster history path is standard Solana RPC (`getSignaturesForAddress` plus bounded `getTransaction`). Helius Enhanced Transactions is available only after explicit operator opt-in:

`KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED=true`

Disabling Enhanced Transactions does not disable the shared Helius provider key used by DAS or ordinary Helius-backed RPC.

### Actor created-mint discovery

The default actor created-mint discovery path is standard Solana RPC so it works with Helius Free and with non-Helius Solana RPC providers.

Default bounded collection:

- `SOLANA_CREATED_MINT_MAX_PAGES=2`
- `SOLANA_CREATED_MINT_PAGE_LIMIT=250`
- `SOLANA_CREATED_MINT_TX_LIMIT=40`

The signature window is sampled deterministically across its newest-to-oldest span. If the history or decoded transaction set is incomplete, the result is explicitly reported as bounded. No observed mint creation in a bounded window is not evidence that the actor never created a mint.

Helius `getTransactionsForAddress` remains an optional paid-plan optimization and is disabled by default:

`KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED=true`

When explicitly enabled, a failed or unavailable gTFA request falls back to the standard RPC collector and preserves the provider failure in `limitations`.

## Evidence boundary

Created-mint discovery remains OBSERVED evidence until the candidate transaction is re-read through the canonical Solana RPC verification path and the actor signer plus explicit Pump/SPL/Token-2022 mint-creation instruction are confirmed.

Provider errors, missing transactions, truncated history, and sampling are limitations. They must never be converted into a clean or safe verdict.
