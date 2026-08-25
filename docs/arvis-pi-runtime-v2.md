# ARVIS Pi Runtime v2

## Purpose

ARVIS treats Pi as a first-class chain adapter. Pi targets are never passed through Solana account, SPL-token, Pump.fun or Raydium semantics.

## Network selection

Customer Pi targets default to `pi-mainnet`.

Supported canonical networks:

- `pi-mainnet` — production Pi evidence, default for detected Pi targets.
- `pi-testnet` — explicit test/testing evidence only.

Accepted aliases are normalized by the backend. A Pi target submitted with a non-Pi network fails closed instead of being reinterpreted on another chain.

## Horizon endpoints

Production defaults:

- Mainnet: `https://api.mainnet.minepi.com`
- Testnet: `https://api.testnet.minepi.com`

Optional runtime overrides:

- `PI_MAINNET_HORIZON_URL` — Pi mainnet Horizon override.
- `PI_TESTNET_HORIZON_URL` — Pi testnet Horizon override.
- `PI_HORIZON_URL` — legacy compatibility override for **testnet only**.

The mainnet collector deliberately never falls back to `PI_HORIZON_URL`; this prevents a legacy testnet setting from silently contaminating mainnet evidence.

Public HTTP endpoints are rejected. HTTP is accepted only for loopback test infrastructure.

## Target contract

ARVIS currently accepts public Pi targets in two forms:

- Account: a valid public `G...` address.
- Asset: `CODE:G...ISSUER` where the asset code is 1–12 alphanumeric characters and the issuer is a valid public Pi/Stellar-style account key.

The server performs strict public-key checksum validation. Browser-side detection is only a routing hint and is never verdict authority.

## Evidence currently collected

The bounded Pi Horizon adapter can collect:

- account / issuer state
- signer weights and thresholds
- exact asset lookup
- trustline holder balances with explicit pagination completeness
- exact-asset issuer payment observations
- bounded issuer operation and transaction windows
- current liquidity-pool state
- issuer control interpretation
- liquidity-history evidence where available
- issuer `home_domain` and exact `/.well-known/pi.toml` asset-domain provenance
- Pi intelligence-graph relations derived from collected evidence

Every relation retains its evidence boundary. Issuer/domain provenance is not represented as real-world identity proof.

## Deliberately not claimed yet

ARVIS does **not** currently issue a signed Pi risk grade. The Pi evidence result remains `unknown` until a Pi-specific deterministic ruleset has an independent regression corpus.

Pi-native transaction preflight is also not implemented yet. The existing serialized-transaction simulation surface is Solana-specific and is labeled accordingly. A future Pi preflight must decode and validate Pi/Stellar transaction envelopes and operations instead of reusing Solana semantics.

## Safety invariants

- no private key or recovery phrase collection
- no custody
- no server-side Pi transaction signing or submission
- missing evidence never becomes a safe finding
- Pi and Solana evidence are not cross-interpreted
- bounded/incomplete holder history remains explicitly bounded/incomplete
