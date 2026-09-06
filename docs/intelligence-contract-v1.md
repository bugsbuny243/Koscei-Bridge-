# Koschei Intelligence Contract v1

## Purpose

This contract is the first chain-neutral foundation for evolving ARVIS from a target scanner into the Koschei Web3 intelligence pipeline:

`Subject -> Entity -> Transaction/Evidence -> Relationship -> Behavior -> Attack Path -> Decision`

It does not replace the working Solana collectors or the unified deterministic verdict engine. It gives future chain adapters a common evidence and investigation model without coupling core intelligence to Solana accounts, EVM contracts, or any provider-specific response shape.

## Current production boundary

Version `koschei-intelligence-contract-v1` currently provides:

- deterministic subject identity and canonical references;
- syntactic EVM-address classification;
- syntactic Solana-address classification;
- explicit chain family, chain and network separation;
- chain-neutral entity, evidence, relationship, behavior, attack-path and decision records;
- a fail-closed investigation constructor whose initial decision is `unverified / investigate`;
- a relationship constructor that cannot mark a relationship verified without at least one concrete evidence reference.

This version does **not** claim that EVM collection, EVM simulation, cross-chain attribution, bridge correlation or entity attribution is live. Those capabilities require adapters and evidence collectors in later changes.

## Evidence rules

A security-relevant relationship must not be presented as verified merely because two targets look similar, share timing, or were supplied in the same request. A verified relationship requires concrete evidence references such as transaction hashes/signatures, block/slot observations, provider-backed provenance or another independently inspectable record.

`inferred` is not `verified`. `unverified` is not `safe`. Missing evidence remains unknown.

## Chain adapter boundary

Chain adapters are evidence transports. They may decode chain-native concepts, but must normalize their output into this contract before core behavior, attack-path or customer-decision logic consumes it.

Examples:

- Solana adapter: account/program ownership, signatures, slots, parsed instructions, token authorities, account deltas.
- EVM adapter: accounts/contracts, transaction hashes, blocks, calldata, logs, storage/state deltas, proxy/implementation relations.

The core contract must not import RPC-provider SDKs or encode provider-specific payloads.

## Canonical subject identity

Canonical references include chain family, resolved chain, network and raw target. Therefore an identical hexadecimal address observed on Ethereum and Base is represented as two distinct subjects until evidence proves a cross-chain entity relationship.

This prevents accidental cross-chain conflation.

## Next integration step

The next production step is to attach an `IntelligenceSubject` to the existing ARVIS investigation output without changing grading, then adapt existing Solana evidence into `IntelligenceEvidence` records. Only after that boundary is verified should an EVM evidence adapter be introduced.
