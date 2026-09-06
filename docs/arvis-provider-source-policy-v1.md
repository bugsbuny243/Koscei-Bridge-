# ARVIS Solana Provider Source Policy v1

Koschei Web3 keeps provider roles explicit so a missing source is never converted into a safe finding and no market-data provider can issue a verdict by itself.

## Source ownership

- **Helius / on-chain RPC:** historical and on-chain transaction truth, balances, transfers, decoded transaction evidence and holder/account state.
- **Jupiter:** primary execution and market-price context when trusted read-only evidence is available; swapability, route context, quote slot and exit-liquidity estimates.
- **PumpPortal:** Pump.fun realtime event intelligence.
- **DexScreener:** temporary fallback/reference source and pair/DEX discovery used by existing LP-control evidence until canonical on-chain pool discovery replaces that dependency.

## Price selection

`jupiter_market_context.primary_market_price` is the customer-facing provider-priority projection:

1. use trusted Jupiter price evidence when available;
2. otherwise use DexScreener only as an explicitly labelled fallback;
3. if neither source has price evidence, return unavailable — never infer safety or synthesize a price.

DexScreener pair discovery remains available to LP-control logic independently of the selected primary price. The price-selection projection does not mutate deterministic ARVIS verdict semantics.

## Security boundary

`JUPITER_API_KEY` is sent only by the existing trusted Jupiter client to validated `api.jup.ag` endpoints. This change does not introduce another Jupiter client or another secret-handling path.
