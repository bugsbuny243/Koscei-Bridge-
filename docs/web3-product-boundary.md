# Koschei Web3 product boundary

Status: canonical product architecture boundary for this repository.

## Koschei Web3

Koschei Web3 is the product and the repository-level system boundary. Web3-facing investigation, evidence, monitoring, transaction defense, defense validation, execution verification, runtime defense and operator workflows belong under Koschei Web3.

## ARVIS

ARVIS is a core intelligence and evidence engine **inside Koschei Web3**. It is not a retired subsystem, a legacy product, or a separate product family.

ARVIS owns and/or feeds Web3-native observation and intelligence capabilities such as live radar, token and wallet investigation, actor/deployer/creator relations, funding and flow evidence, liquidity and launch evidence, transaction evidence, source-aware collection and related on-chain intelligence.

Public product language may use names such as `Koschei Web3 · ARVIS Intelligence` or `ARVIS Security Radar`, but must not present ARVIS as a product separate from Koschei Web3.

## Matrix

Matrix is **not a Koschei Web3 component**. The Matrix concept belongs to the Koschei Lang project. This repository must not introduce Matrix as a Web3 product module, architecture layer, customer-facing capability, containment engine, or namespace.

Web3-native deterministic execution containment uses the `executioncontainment` namespace.

## Sentinel and Lang integration

Koschei Sentinel and Koschei Lang may integrate with Koschei Web3 through explicit contracts, but they remain separate projects. Sentinel must not become verdict authority merely by being connected. Koschei Lang/Matrix must not be represented as a native Web3 module merely because Web3 consumes a Lang-provided runtime or authority service in the future.

## Naming rules

1. `Koschei Web3` is the product umbrella in this repository.
2. `ARVIS` is a first-class Web3 intelligence/evidence engine inside that umbrella.
3. `Matrix` is reserved for Koschei Lang and is forbidden as a Web3 product/module namespace.
4. Internal Web3 containment terminology uses `execution containment`, not Matrix.
5. Product copy must preserve real implementation boundaries and must not invent production wiring.
