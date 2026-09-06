# ARVIS PumpPortal → Helius Trade Correlation v1

## Purpose

ARVIS already receives Pump.fun/PumpSwap trade observations through the PumpPortal live ledger. This change adds a bounded independent reread of those signatures from canonical Solana transaction history, preferring the configured Helius RPC endpoint.

The correlation does **not** create a second scanner and does not change the deterministic ARVIS verdict.

## Evidence states

- `observed_unverified`: PumpPortal emitted the event but the canonical transaction could not be reread.
- `observed_mismatch`: a canonical transaction was returned, but slot, Pump/PumpSwap program, trader token delta, or trade direction did not match the live observation.
- `verified_correlated`: the same signature independently confirms the target mint, trader direction, compatible slot, and Pump/PumpSwap program.

Unknown or unavailable evidence is never treated as safe.

## Provider responsibility

- **PumpPortal:** realtime Pump trade observation.
- **Helius RPC:** preferred historical/on-chain transaction verification source.
- **Canonical Solana RPC fallback:** used only when the explicit Helius RPC endpoint is unavailable; provenance stays labelled as fallback.

No provider can issue an ARVIS verdict by itself.

## Bounded verification

`ARVIS_PUMP_CORRELATION_LIMIT` controls the maximum number of earliest PumpPortal signatures reread in one investigation. The accepted range is 1–50 and the default is 12. The live ledger itself is not rewritten or upgraded; correlation is an additive investigation projection.

The structured report is exposed under:

`source_context.pump_helius_trade_correlation`

This keeps the original PumpPortal observation and the independent verification result separately inspectable.
