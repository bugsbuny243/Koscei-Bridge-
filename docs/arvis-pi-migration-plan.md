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
- Liquidity Movement -> current pool state plus separately collected transaction-backed deposit/withdraw operations when available.
- Creator Link Analysis -> issuer account is protocol-level issuer, not an identity claim.
- Launch Distribution -> issuer-originated payment operations for this exact asset.
- Repeat Actor / Funding Cluster -> pending until Pi-specific durable evidence exists.
- Program Relation -> not applicable on Pi's Stellar-derived asset model.
- Pump/Raydium arms -> not applicable on Pi.

## Security boundary

- Unknown/incomplete Horizon responses remain UNKNOWN.
- Bounded holder and liquidity-operation windows are never described as complete history.
- No risk grade is signed from Pi evidence in Phase 1 or the evidence-only Phase 2/3 slices.
- No server-side wallet secrets.
- No Mainnet transaction submission.

## Phase 2 — provenance and issuer control

- issuer authorization interpretation from current signer-weight + medium/high threshold evidence;
- future classic issuance is described as locked only when neither payment authorization nor Set Options authorization is currently possible;
- exact historical maximum supply is **not** inferred from issuer lock state;
- issuer `home_domain` is normalized as a bare public DNS name;
- `https://<home_domain>/.well-known/pi.toml` is fetched with strict HTTPS, no redirects, bounded size/time and a public-IP-only dial policy;
- the `[[CURRENCIES]]` entry must exactly match `CODE:ISSUER` and contain the Pi token metadata fields used by the official token guide;
- verified domain binding remains protocol provenance and never becomes a real-world identity claim;
- verified domain relation may be added to the ARVIS intelligence graph with its source URL and verification status.

## Phase 3 — liquidity movement evidence

The current pool snapshot is not treated as historical movement. ARVIS separately queries successful operations related to the exact native/target-asset liquidity pool and accepts only `liquidity_pool_deposit` and `liquidity_pool_withdraw` records.

Each structured movement row preserves:

- liquidity pool id;
- Horizon operation id;
- transaction hash;
- source account;
- timestamp;
- exact target asset and amount;
- native reserve amount when present;
- received/redeemed pool shares;
- verification status and evidence source.

Collection is bounded by pool and operation limits. Hitting a bound marks the history incomplete; no observed withdrawal/deposit is never translated into a SAFE claim.

## Still required

- Pi-specific deterministic ruleset with regression corpus;
- complete issuance-history proof before any exact maximum-supply statement;
- Pi Sign-in identity binding through backend `/v2/me` verification;
- durable Pi actor/issuer memory;
- customer UI accepting `CODE:ISSUER` and Pi `G...` targets natively.
