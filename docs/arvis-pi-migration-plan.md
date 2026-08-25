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
- Funding Cluster -> bounded top-holder account-creation/native-funding provenance and repeated funding-source groups.
- Repeat Actor -> pending until Pi-specific durable issuer/actor memory exists.
- Program Relation -> not applicable on Pi's Stellar-derived asset model.
- Pump/Raydium arms -> not applicable on Pi.

## Security boundary

- Unknown/incomplete Horizon responses remain UNKNOWN.
- Bounded holder, funding and liquidity-operation windows are never described as complete history.
- A shared on-chain funding source is not proof of common control, legal identity or wrongdoing.
- No risk grade is signed from Pi evidence in Phase 1 or the evidence-only Phase 2/3/4/5 slices.
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

## Phase 4 — customer Pi target surface

The canonical customer scan accepts Pi targets without sending them through Solana collectors:

- Pi assets matching the public `CODE:G...ISSUER` shape are detected as Pi token targets;
- Pi public `G...` accounts are detected as Pi account targets;
- Pi targets are sent to the existing authenticated `/api/security/radar/check` route with `network=pi-testnet`;
- the backend remains the authority for checksum/target validation; browser detection is routing assistance only;
- Pi results render an evidence file with observed/pending/not-applicable arms instead of borrowing the signed Solana verdict card;
- the UI explicitly withholds a Pi grade and preserves `UNKNOWN != SAFE`;
- Solana token investigations, preflight and transaction simulation keep their existing routes.

The legacy filename `public-solana-scan.js` now contains chain-aware customer routing. Renaming that asset is cleanup work only and must not create a second scan runtime.

## Phase 5 — holder funding provenance

Funding Cluster uses a separately bounded evidence pass over the largest observed Pi trustline holders. For each candidate account ARVIS reads the oldest Horizon operation window and accepts only:

- `create_account` where the scanned holder is the created account; or
- the earliest native `payment` into the holder account when creation funding is not present in the observed window.

Each funding row preserves holder account, source account, relation type, operation id, transaction hash, amount, timestamp, verification status and evidence source. Repeated source accounts are grouped as **shared funding-source evidence only**. They are never upgraded into a common-controller or real-world identity claim.

Funding collection is bounded to eight holder candidates and one oldest-operation page per account. Candidate truncation, operation-page saturation or provider failures remain explicit limitations. No repeated funding source in the bounded set is not evidence that holders are unrelated.

## Still required

- Pi-specific deterministic ruleset with regression corpus;
- complete issuance-history proof before any exact maximum-supply statement;
- Pi Sign-in identity binding through backend `/v2/me` verification;
- durable Pi actor/issuer memory;
- Pi transaction/claim preflight semantics before any Pi MEV or claim-shield verdict is enabled.
