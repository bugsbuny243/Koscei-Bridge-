# Koschei Web3 product boundary

Status: canonical repository boundary.

## Koschei Web3

Koschei Web3 is the market-facing Web3 product. In this repository, its implemented intelligence/evidence engine is ARVIS.

This repository owns ARVIS investigation and evidence capabilities: live radar, token and wallet investigation, actor/deployer/creator relations, funding and flow evidence, liquidity and launch evidence, transaction evidence, source-aware collection, persistent actor memory and operator investigation workflows.

The repository must not grow unrelated execution runtimes or duplicate the responsibilities of Koschei Lang or Koschei Sentinel merely because those capabilities may eventually strengthen Koschei Web3.

## ARVIS

ARVIS is a first-class intelligence and evidence engine **inside Koschei Web3**. It is not a retired subsystem, compatibility layer or separate product family.

ARVIS evidence must remain source-aware and truth-preserving. Deterministic investigation rules own final grades/verdicts; explanation layers do not manufacture evidence.

Solana is the current production domain and adapter surface. It is not the definition of the entire future Koschei Web3 universe. Future chain support should preserve chain-specific semantics behind explicit adapters rather than hard-coding a single chain into new core investigation concepts.

## Removed Web3-internal expansions

Defense OS, Defense Validation, Execution Proof, Node Shield and Web3-native execution-containment runtimes are outside the current repository boundary and must not be silently restored through handlers, routes, workers, migrations, Dockerfiles, workflows or documentation.

If execution/authorization capabilities are needed later, their ownership must first be decided explicitly across Web3, Lang and Sentinel rather than being recreated opportunistically in this repository.

## Matrix

Matrix is **not a Koschei Web3 component**. Matrix belongs to Koschei Lang. This repository must not introduce Matrix as a Web3 product module, architecture layer, customer-facing capability, containment engine or namespace.

## Sentinel and Lang integration

Koschei Sentinel and Koschei Lang remain separate projects. Future integration must use explicit interfaces and evidence contracts. A connected Sentinel model must not silently become deterministic verdict authority, and a Lang runtime must not be relabeled as a native ARVIS subsystem.

## Naming rules

1. `Koschei Web3` is the product umbrella.
2. `ARVIS` is the Web3 intelligence/evidence engine implemented in this repository.
3. `Matrix` is reserved for Koschei Lang.
4. Do not use removed Defense OS / Execution Proof / execution-containment names as active Web3 architecture.
5. Product copy must match real production wiring and evidence quality.
