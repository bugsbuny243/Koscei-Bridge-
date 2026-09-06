# ARVIS Threat Hypothesis Contract v1

Threat hypotheses are an additive projection over the existing deterministic ARVIS `ThreatAnticipation` pathways. They do not replace ARVIS, create a second scanner, assign rug probability, predict intent, or change the signed verdict.

A pathway is exposed as an intelligence-contract hypothesis only when the existing attack-path projection has concrete linked evidence for that pathway and the corresponding ARVIS composite evidence row is present. Target-only references, untyped maps, missing evidence and source-only claims cannot create a hypothesis.

The chain-neutral hypothesis shape preserves the existing pathway title, status, basis and required evidence. `confidence` remains `0` in v1 because no calibrated hypothesis probability model exists. The classification is explicitly `capability_exposure_hypothesis`: capability is not intent.

This is the first contract step toward the longer ARVIS flow:

`Address → Entity → Funding → Behavior → Threat Hypothesis → Attack Path → Defense Validation → Evidence-backed Decision`

Future correlation may combine funding, relationship, behavior, transaction, authority and exit evidence, but only after each source has a concrete provenance/evidence reference in the canonical intelligence contract.
