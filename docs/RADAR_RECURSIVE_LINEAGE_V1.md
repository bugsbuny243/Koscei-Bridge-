# Radar Recursive Lineage v1

## Purpose

A token investigation must expand beyond the current mint into the bounded, evidence-backed operational history of the wallets that matter to the case. This is investigation context, not identity attribution and not an independent verdict engine.

## Default seed set

For a token target, build a deterministic, deduplicated seed set in this order:

1. resolved creator/deployer wallet;
2. primary funding source only when the funding-origin evidence is VERIFIED;
3. up to 20 owner-resolved, risk-bearing holder wallets ranked by holder rank and operational relevance.

The same wallet may carry multiple roles but appears only once in the seed set. Its complete role set must be preserved.

A holder is eligible for bounded lineage expansion only when it is owner-resolved, risk-bearing and has at least one meaningful operational signal such as parsed transaction evidence, common-exit evidence, repeat-dominant-holder history, launch creator linkage, or an observed funding source. Protocol/program accounts and unresolved token accounts are excluded.

## Historical token lineage

For every seed wallet, read the persistent actor dossier first. Historical token lineage is the union of:

- tokens created/deployed by the wallet;
- tokens where the wallet was a dominant holder;
- tokens traded by the wallet.

Creator lifecycle memory may add creation signature, creation slot and active/inactive/dead observation provenance. Lifecycle fate alone never means rug.

The current target mint is deduplicated from historical related-token output while its role evidence remains visible.

## Operational graph

Use the Actor Constellation engine as the wallet-relationship graph primitive. Do not build a second graph traversal implementation.

Default constellation bounds remain:

- depth: 2;
- fanout: 8;
- node cap: 25.

Hard maximums remain depth 3, fanout 20 and node cap 50.

Only evidence-supported expansion classes may traverse. A serious edge requires stable evidence containing signature, slot, timestamp, source wallet, destination wallet, amount/asset, program, relation and verification status. Single weak OBSERVED links do not expand transitively.

## Global investigation budgets

Recursive lineage is bounded across all seeds. v1 defaults:

- maximum seed wallets: creator + verified funder + 20 critical holders;
- maximum unique wallet dossiers materialized in the synchronous report: 25;
- maximum unique related token mints returned synchronously: 100;
- maximum historical token observations retained per seed wallet: 20;
- no unbounded synchronous RPC fan-out.

Persistent memory is read synchronously. Missing or incomplete actor history should enqueue deduplicated enrichment work rather than launching an RPC storm inside the customer request.

Any budget or corpus boundary makes the lineage result explicitly `complete=false` and adds a limitation. Missing data never becomes a safe/clean claim.

## Output contract

The unified investigation report should expose an `actor_investigation.recursive_lineage` block containing at least:

- version;
- status and complete;
- seed wallets with roles and evidence status;
- wallet dossier summaries;
- related token lineage with wallet roles and provenance;
- creator lifecycle provenance where available;
- actor constellation summary;
- truncation/budget counters;
- limitations;
- policy.

The investigation policy must stop claiming that recipient investigation is mint-specific once recursive lineage is enabled. The new scope should be explicitly bounded persistent actor history.

## Authority boundaries

Recursive lineage has no grade, verdict, guard-block or real-world identity authority.

It may provide evidence to the existing canonical unified Radar evaluator only through the normal evidence-policy boundary. It must never create a second signed final verdict.

Required policy assertions:

- `real_world_identity_claim=false`;
- `same_operator_claim=false`;
- `wrongdoing_claim=false`;
- `transitive_identity_claim=false`;
- `verdict_authority=false`;
- `grade_authority=false`;
- `guard_block_authority=false`;
- `no_evidence_no_claim=true`;
- `bounded_graph=true`.

## Acceptance requirements

v1 is not merge-ready until tests prove:

1. creator is always the first valid seed when resolved;
2. an OBSERVED/unverified funding source is not promoted into the primary-funder seed slot;
3. a VERIFIED funding source is included with provenance;
4. holder candidates exclude unresolved and protocol accounts;
5. no more than 20 holder seeds are selected;
6. duplicate creator/funder/holder wallets collapse into one wallet with all roles retained;
7. persistent dossier lineage includes created, dominant-holder and traded token relations;
8. current mint is deduplicated from related-token output;
9. constellation remains bounded and serious edges retain evidence rows;
10. hitting any seed, wallet, token, graph or corpus budget yields `complete=false`;
11. missing persistent history queues enrichment rather than performing unbounded synchronous RPC traversal;
12. recursive lineage cannot directly change grade or sign a final verdict;
13. unified report policy advertises bounded persistent actor history instead of mint-only recipient scope.
