# ARVIS Technical Campaign Genome v1

Status: deterministic evidence-only technical pattern contract for wallet actor investigations.

Schema version:

```text
koschei-technical-campaign-genome-v1
```

## Purpose

Actor Defense already persists transaction-backed wallet relations and exposes an evidence graph with VERIFIED, OBSERVED, INFERRED and UNVERIFIED classes. Campaign Genome does not build a second identity graph and does not attempt to identify a human operator.

It projects that existing evidence into a reusable technical behavior fingerprint so separate wallet investigations can be compared by exact on-chain behavior pattern without claiming common ownership, common control, intent or wrongdoing.

## Two identities

Campaign Genome deliberately carries two different hashes.

### Evidence hash

`evidence_hash_sha256` is wallet/evidence-specific. It commits to the full normalized genome response, including evidence keys and signatures. Two different wallets with different transaction evidence should not share this audit identity.

### Pattern hash and genome ID

`pattern_hash_sha256` contains only normalized technical descriptors that are eligible for campaign-pattern comparison. Counterpart wallet addresses, token mint addresses, transaction signatures and evidence keys are deliberately excluded from this pattern identity.

A verified-supported pattern receives a short display identifier:

```text
KCG1-<16 uppercase hex chars>
```

The same `genome_id` means only that two investigations produced the same normalized technical descriptor set under this version. It does **not** mean the wallets are the same person, the same organization, under common control, malicious, or engaged in the same real-world campaign.

## Descriptor sources

Descriptors are derived from persisted Actor Defense evidence and may include:

- relation kind;
- relation plus observed program;
- actor role plus relation;
- counterpart kind plus relation;
- native-SOL versus token behavior class plus relation;
- multi-token creator/deployer recurrence;
- multi-token dominant-holder recurrence;
- cross-token related-actor recurrence already established by the Actor Defense track.

The descriptor set does not contain exact counterpart addresses or token mint addresses.

## Verification boundary

UNVERIFIED evidence is excluded.

INFERRED evidence is watch-only and cannot contribute to a campaign genome ID.

Possible dust and address-poisoning candidates remain watch-only even when persisted.

A VERIFIED row can anchor a genome ID only when its canonical Actor Defense evidence line is complete and has signature, slot and timestamp evidence. Incomplete VERIFIED rows remain visible as watch descriptors and cannot anchor the technical campaign fingerprint.

OBSERVED descriptors may support a pattern, but a genome ID is issued only when at least one active descriptor is VERIFIED and signature-backed. Fewer than two distinct active technical descriptors are insufficient.

## Determinism

Descriptor keys, evidence keys and signatures are sorted before output. Pattern descriptors are sorted again before hashing. The builder performs no RPC call, clock read, database query or AI inference. Identical dossiers produce byte-equivalent logical genome content and the same pattern/evidence hashes.

## Authority boundary

Campaign Genome v1 is evidence-only. It does not change:

- Actor Defense grade or deterministic rule verdict;
- Unified Radar verdict;
- token or transaction risk index;
- Transaction Guard action;
- signed verdict state;
- State Witness or permit policy.

AI may explain an already-produced genome but cannot create descriptors, upgrade evidence status, issue a genome ID, claim real-world identity or change a verdict.
