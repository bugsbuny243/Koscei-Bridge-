# Koschei Forge — Pi Secure Launchpad Foundation

Status: **Pi Testnet launch-preflight foundation**

Koschei Forge is not a generic Pump.fun clone and it is not a replacement for Pi Network's official Launchpad. Its product role is to make token-launch preparation evidence-first: validate the public launch configuration, surface blocking conditions before signing, and preserve a deterministic reference to what was reviewed.

## Market and protocol boundary

As of 2026-08-25, Pi Network's official Launchpad remains a Testnet product and Pi continues to describe its Testnet launches as inputs toward a future Mainnet version. Pi's DEX/AMM/token-creation features are also documented as Testnet-first, with the corresponding Mainnet functionality restricted while testing continues.

Official references:

- https://minepi.com/blog/pi-launchpad/
- https://minepi.com/blog/launchpad-liquidity-pool/
- https://minepi.com/blog/dex-amm-token-creation/
- https://github.com/pi-apps/pi-platform-docs/blob/master/tokens.md

This repository therefore must not claim that Koschei can issue Pi Mainnet ecosystem tokens today.

## Current production slice

### Domain proof

The Pi Developer Portal expects the app-domain validation key at:

```text
https://tradepigloball.co/validation-key.txt
```

The running Go service serves static assets from `koschei/api/public`, so the validation file must exist in that directory. A repository-root copy by itself is not enough to make the HTTP path available.

### Public launch preflight

Registered route:

```text
POST /api/pi/testnet/launch/preflight
```

The route accepts public launch-plan fields only:

- asset code;
- initial supply;
- issuer public G-address;
- distributor public G-address;
- issuer/project name;
- description;
- HTTPS image URL;
- home domain;
- concrete product utility.

It validates:

- Pi/Stellar asset-code shape;
- positive supply and seven-decimal precision boundary;
- StrKey checksum for issuer/distributor public G-addresses;
- issuer/distributor separation;
- metadata needed for a future Pi Wallet token record;
- home-domain shape;
- presence of a concrete utility statement.

The response includes a deterministic SHA-256 `plan_hash`, per-rule findings, a ruleset version, explicit limitations and one of:

```text
blocked
testnet_preflight_passed_with_warnings
testnet_preflight_passed
```

A preflight pass is not a safety guarantee, investment recommendation, liquidity guarantee or Mainnet-eligibility claim.

### Customer surface

`/pi-launchpad` resolves to `koschei/api/public/pi-launchpad.html` through the existing static alias behavior.

The page intentionally contains no private-key field and no fake Mint button. It can:

- run the real Testnet launch preflight;
- render blocking/warning/pass evidence;
- expose the exact plan hash;
- verify that the public domain-proof file is being served;
- direct users to the existing ARVIS Deep Scan for existing Solana assets without pretending that ARVIS already has Pi on-chain intelligence.

## Non-custodial security invariant

Koschei Web3 must never ask for, receive, store, log or transmit a Pi wallet passphrase/private key.

Pi's current token-creation documentation demonstrates raw Stellar SDK signing with private keys. That is useful protocol documentation, but it is **not** an acceptable custody model for Koschei Forge.

The server therefore has no token-minting authority in this phase.

Current response contract states:

```json
{
  "can_mint": false,
  "mainnet_supported": false,
  "requires_wallet_secrets": false
}
```

These fields must not be changed merely to make the UI look more complete.

## Target architecture

```text
Pi Browser
    |
    | public launch plan
    v
Koschei Forge
    |
    +--> Pi Testnet launch preflight
    |       - asset/supply validation
    |       - issuer/distributor integrity
    |       - metadata/home-domain readiness
    |       - deterministic plan hash
    |
    +--> Pi chain evidence adapter           [NEXT]
    |       - issuer/distributor account state
    |       - trustline evidence
    |       - token supply/distribution
    |       - transaction provenance
    |
    +--> ARVIS common evidence model         [NEXT]
    |       - Entity
    |       - Transaction
    |       - Behavior
    |       - Attack Path
    |       - Evidence
    |
    +--> Safe wallet authorization adapter   [BLOCKED ON SAFE INTEGRATION]
            - user-authorized signing
            - no server-side wallet secret
            - exact transaction binding
```

Chain-specific Pi transport belongs in a Pi adapter. Solana RPC structures must not be renamed or copied into Pi intelligence as if they were chain-neutral.

## Launch Passport direction

The useful moat is not “anyone can create a token.” The useful moat is a launch that carries an auditable security record.

A future Launch Passport can bind:

- launch-plan hash;
- creator/account provenance;
- issuer/distributor configuration;
- token metadata and domain evidence;
- trustline state;
- issuance transaction hash;
- supply/distribution state;
- liquidity setup;
- ARVIS findings;
- evidence sources, timestamps and confidence;
- post-launch monitoring history.

Unknown evidence must stay unknown. A missing Pi provider response must never turn into a green badge.

## Safe issuance gate

A real `Launch` / `Mint` action is allowed only after all of these are true:

1. Pi exposes or documents an integration path that lets the user's wallet authorize the required token operations without Koschei receiving the private key/passphrase.
2. Koschei can bind the user's approved launch plan to the exact transaction payload presented for signing.
3. The Testnet transaction can be independently re-read and verified after submission.
4. Failure or incomplete evidence fails closed rather than being presented as success.
5. Mainnet support is enabled only after Pi officially enables the corresponding Mainnet ecosystem-token path and Koschei validates it separately.

Until then, Koschei Forge is a real launch-security/preparation product, not a custody-based token factory.

## Next engineering increments

1. Pi Sign-in backend verification and app-session binding.
2. Pi Testnet Horizon read-only adapter for account/trustline/token evidence.
3. Pre-sign transaction-intent contract for token operations.
4. Safe wallet-authorized transaction handoff when an official non-custodial path is available.
5. Launch Passport persistence and post-launch monitoring.
6. Pi-specific ARVIS evidence arms, kept separate from Solana provider code.
