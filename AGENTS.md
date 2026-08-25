# Koschei Web3 repository contract

This repository is **Koschei Web3** only.

- ARVIS is a core intelligence and evidence engine inside Koschei Web3.
- Matrix belongs to Koschei Lang, not Koschei Web3.
- Koschei Sentinel and Koschei Lang are external systems from this repository's point of view; integrations must use explicit contracts instead of copying their internals here.
- Koschei Web3 is a Web3 Security Validation & Risk Intelligence Platform. It must not collapse into a generic wallet, token, honeypot, rug, or contract scanner.
- Chain-specific evidence collection belongs behind adapters. Core intelligence, evidence policy, attack-path reasoning, and customer decision contracts must remain chain-independent.
- ARVIS must preserve provenance and explainability. Missing evidence stays UNKNOWN and must never be converted into SAFE.
- Do not request, store, log, or commit private keys, seed phrases, passphrases, or provider secrets.
- Do not fabricate on-chain data, risk evidence, production capability, or enterprise features. Test fixtures and mocks must be explicit.

## Chain architecture

Solana and Pi are evidence adapters, not product identities. Existing working Solana collectors may remain while Pi becomes first-class. New chain work must not couple core intelligence to one chain's account, token, program, or transaction model.

## Pi boundary

Pi analysis is read-only unless a separately reviewed product flow explicitly requires a write. ARVIS Pi evidence must use public account/asset identifiers and must not require wallet secrets. A Pi final risk grade must remain withheld until a Pi-specific deterministic ruleset and regression corpus are validated.
