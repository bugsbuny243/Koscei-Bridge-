# Defense-validation scenario definitions

Applicable canonical contract: [`WEB3_DEFENSE_VALIDATION_ENGINE.md`](../../../WEB3_DEFENSE_VALIDATION_ENGINE.md)  
Ruleset: `koschei-defense-validation-rules-v0.1.0`

This directory contains **planned scenario definitions**, not validation runs. A definition describes what a future owner-approved isolated run must execute, what its matched benign control is, which evidence it must collect, and which safety boundaries it must preserve.

A definition cannot contain `run_ref`, execution/state hashes, observations, outcomes, verdicts or report hashes. Those fields belong to a later immutable run record. Until real sandbox execution and independent observation exist, Koschei must not say that a defense was validated, failed or tested.

## First Solana pair

`solana-compromised-privileged-signer-v1.json` defines one controlled pair:

| Dimension | Attack case | Benign control |
| --- | --- | --- |
| Program, instruction, asset, amount | Identical fixture withdrawal | Identical fixture withdrawal |
| Signer | Ephemeral privileged fixture identity | Ephemeral privileged fixture identity |
| Approval | Absent | Approved |
| Destination policy | Not allowlisted | Allowlisted |
| Expected control behavior | Alert no later than the impact deadline | Remain silent |

“Expected control behavior” is the predeclared acceptance oracle, not an observed result. Only independently collected run evidence may later determine `CAUGHT_IN_TIME`, `MISSED`, `FALSE_POSITIVE` or another evaluator outcome.

The primary taxonomy mapping is MITRE AADAPT `ADT1552.004` because the planned threat model is unauthorized use of compromised private-key authority. The manifest never includes or imports a real key; all future identities must be generated ephemerally inside the isolated harness. This mapping describes the scenario and is not evidence that a real incident occurred.

## Locked safety profile

The v0.1 Solana profile requires:

- LiteSVM sandbox execution with no network or mainnet RPC access;
- owner approval and a default-off execution gate;
- signature verification left enabled;
- no arbitrary account writes used to manufacture the tested transition;
- no production identity, wallet custody, control mutation or automatic intervention;
- an independent collector and a complete attack + benign observation window.

LiteSVM supports test conveniences such as disabling signature verification and overwriting accounts. This profile deliberately rejects both for a defense-validation claim; otherwise the fixture could prove behavior that a realistic signed transition never exercised.

## Local verification

From the repository root:

```bash
node --check oss/verifier/typescript/verify-defense-scenario.mjs
node --test oss/verifier/typescript/verify-defense-scenario.test.mjs
node oss/verifier/typescript/verify-defense-scenario.mjs \
  docs/defense-validation/scenarios/solana-compromised-privileged-signer-v1.json
```

The verifier is dependency-free, reads local JSON only and performs no network, execution or write operation.

## Not implemented in this slice

- fixture Solana program and state pack;
- LiteSVM execution adapter;
- tested-control adapter;
- independent observation collector;
- immutable execution evidence or evaluator input;
- any production route, worker, database record or public validation claim.

External methodology and taxonomy references:

- [MITRE AADAPT ADT1552.004](https://aadapt.mitre.org/techniques/ADT1552.004/)
- [Security Alliance drill template](https://github.com/security-alliance/drill-template)
- [LiteSVM](https://github.com/LiteSVM/litesvm)
