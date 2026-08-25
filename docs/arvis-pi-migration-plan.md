# ARVIS Pi migration — implementation contract

ARVIS is currently Solana-heavy in live evidence collection. The migration target is **Pi-first, chain-decoupled ARVIS**, not deletion of the working Solana collector.

Koschei Web3 core intelligence must remain chain-independent. Pi transport, Horizon objects, trustlines, issuer controls and liquidity pools belong to a Pi adapter; Solana RPC, SPL mint accounts, Pump and Raydium belong to a Solana adapter.

## Pi Testnet evidence source

Official Pi token documentation identifies Pi Testnet Horizon at:

`https://api.testnet.minepi.com`

Pi assets are identified by `asset_code + issuer public G-address`, not by a Solana mint address. ARVIS Pi asset targets therefore use the canonical form:

`CODE:G...ISSUER`

Wallet targets use the public `G...` account address.

## Phase 1

- strict Pi target parsing and StrKey public-address verification;
- bounded read-only Pi Horizon client;
- issuer account, asset, trustline-holder, transaction and operation evidence;
- Pi-specific ARVIS 14-arm evidence assembly;
- Pi grade remains unsigned/unknown until a Pi deterministic ruleset is separately validated;
- auto-detect Pi targets when network is omitted;
- preserve Solana behavior for Solana targets;
- never request private keys/passphrases;
- no Pi transaction signing or submission.

## Evidence mapping

Pi evidence is not renamed Solana evidence.

- Token Authority Scanner -> issuer signer/threshold/authorization state.
- Holder Concentration -> trustline account balances with bounded pagination disclosed.
- Liquidity Movement -> current Pi liquidity-pool state only; movement remains pending until transaction-backed deltas exist.
- Creator Link Analysis -> issuer account is protocol-level issuer, not an identity claim.
- Launch Distribution -> issuer-originated payment operations for this exact asset.
- Repeat Actor / Funding Cluster -> pending until Pi-specific durable evidence exists.
- Program Relation -> not applicable on Pi's Stellar-derived asset model.
- Pump/Raydium arms -> not applicable on Pi.

## Security boundary

- Unknown/incomplete Horizon responses remain UNKNOWN.
- Bounded holder windows are never described as complete.
- No risk grade is signed from Pi evidence in Phase 1.
- No server-side wallet secrets.
- No Mainnet transaction submission.

## Phase 2

- Pi-specific deterministic ruleset with regression corpus;
- Pi liquidity add/remove transaction parsing and reserve-delta evidence;
- issuer lock/max-supply verification;
- home-domain + `/.well-known/pi.toml` verifier with SSRF-safe fetch rules;
- Pi Sign-in identity binding through backend `/v2/me` verification;
- durable Pi actor/issuer memory;
- customer UI accepting `CODE:ISSUER` and Pi `G...` targets natively.
