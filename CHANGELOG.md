# Changelog

## Unreleased — Scan runtime recovery

- Owner scans now fall back from unavailable database-backed canonical jobs to the live stateless ARVIS scan.
- Explicitly stateless API routes no longer depend on the legacy auth-only environment flag to pass the database gate.
- Public token scans now allow the full bounded evidence pipeline to finish instead of aborting after 45 seconds.
- Regression checks preserve the fallback, timeout budget, and browser cache-version contract.

## 0.1.0 — Early Live MVP

- Live Koschei Web3 Hub
- Authentication
- Admin analytics
- Credit system
- Metadata Studio
- Risk Scanner
- Chain Health
- Watchlist
- Wallet Score
- TX Decoder
- Public docs and impact pages
