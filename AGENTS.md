# Koschei Web3 repository contract

This repository's primary product domain is **Koschei Web3**, and the Koschei Web3 security core must remain isolated and intact.

A single deployed TradePI service may also host explicitly isolated TradePI product modules under their own namespaces (for example `/agents`, `/api/agents/*`, and dedicated internal packages) when this avoids unnecessary duplicate infrastructure. These modules must not be presented as Koschei Web3 capabilities and must not import or copy ARVIS or Koschei Lang internals.

- ARVIS is a core intelligence and evidence engine inside Koschei Web3.
- Matrix belongs to Koschei Lang, not Koschei Web3.
- Koschei Sentinel is cancelled and is not an active integration target for this repository.
- Koschei Lang is a separate, early-stage project and is not ready for Web3 runtime integration; no production dependency on it may be introduced here.
- Koschei Web3 is a Web3 Security Validation & Risk Intelligence Platform. It must not collapse into a generic wallet, token, honeypot, rug, contract scanner, or generic business-automation product.
- Non-Web3 TradePI modules must stay in isolated route/package namespaces and must not alter Koschei Web3 evidence, security, entitlement, or customer-decision contracts.
- Chain-specific evidence collection belongs behind adapters. Core intelligence, evidence policy, attack-path reasoning, and customer decision contracts must remain chain-independent.
- ARVIS must preserve provenance and explainability. Missing evidence stays UNKNOWN and must never be converted into SAFE.
- Do not request, store, log, or commit private keys, seed phrases, passphrases, provider secrets, bot tokens, or webhook secrets.
- Do not fabricate on-chain data, risk evidence, production capability, enterprise features, inventory, price, appointment availability, or revenue attribution. Test fixtures and mocks must be explicit.

## Single-service product boundary

TradePI product modules may share the same Railway/HTTP service for cost and operational simplicity, but they must remain logically separated:

- Koschei Web3 routes and packages remain the security product.
- TradePI AI Agents use `/agents`, `/api/agents/*`, `/webhooks/telegram`, and future `/webhooks/whatsapp` namespaces.
- Shared infrastructure is limited to generic transport, configuration, database connectivity, observability, and deployment plumbing.
- Cross-product calls must use explicit interfaces/contracts rather than direct access to security internals.

## Chain architecture

Chain adapters are evidence transports, not product identities. The existing working Solana collector remains isolated behind its adapter boundary. Future chain support must not couple core intelligence to one chain's account, token, program, or transaction model.
