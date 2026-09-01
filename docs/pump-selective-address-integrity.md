# Selective Pump Solana Address Integrity

The production canonical Pump scheduler treats Solana mint addresses as exact, case-sensitive base58 identifiers.

- Candidate dedupe never lowercases a mint.
- Candidate cursor tie-break uses byte-stable PostgreSQL `C` collation.
- Attempt cooldown applies only to the exact mint.
- Canonical completed-report cooldown already matches the exact mint in the canonical job ledger.
- Broad RPC workers remain outside this selective path and stay paused under RPC saver policy.

This rule exists because case folding can collapse distinct Solana addresses and suppress or misattribute an investigation.
