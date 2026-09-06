# ARVIS Pump Discovery Correlation v1

ARVIS already subscribes to PumpPortal `subscribeNewToken` and `subscribeMigration` events and persists those discovery observations through the existing durable inbox. This feature does not create another Pump stream.

For a source-reported PumpPortal new-token or migration event with a signature, ARVIS now independently rereads that exact Solana transaction through the same Helius-preferred canonical RPC path used by Pump trade correlation.

A result may become `signature_correlated` only when the exact transaction is available, the requested mint is referenced by transaction accounts or token balances, a Pump.fun/PumpSwap program is observed, and the observed slot matches when both sides provide one.

This does **not** independently decode or prove the `create` or `migration` instruction semantic. The event semantic remains `source_reported_not_independently_decoded` until a dedicated instruction decoder proves it. This prevents a matching Pump transaction from being promoted into a stronger migration/create claim than the evidence supports.

The additive result is exposed at `source_context.pump_discovery_correlation`. Unknown, unavailable, or mismatching correlation remains unverified and is never treated as safe. No provider or correlation result can issue or modify the deterministic ARVIS verdict.
