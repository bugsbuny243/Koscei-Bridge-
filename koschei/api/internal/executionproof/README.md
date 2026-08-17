# Koschei Execution Proof v0.1

Execution Proof is a Security Control Plane boundary, separate from actor/Radar investigation behavior.

## Authority rule

`NO VALID EXECUTION PROOF = NO SIGNING FORWARD`

The signing path must never trust a serialized `ALLOW`, a Transaction Service supplied Safe hash, or a runtime-provided artifact identity as authoritative by itself.

## v0.1 evidence chain

`source -> build -> runtime -> payload -> invariant -> signing request`

Every mandatory edge fails closed. The final decision is only `ALLOW` or `BLOCK` with deterministic reason codes.

## Safe boundary

For Safe transactions, Koschei recomputes `safeTxHash` locally from the complete raw Safe transaction using Safe EIP-712 semantics. The presented service hash is comparison-only evidence. Any mismatch blocks forwarding.

## Non-goals

No numeric score, letter grade, AI-generated decision, custody replacement, or fabricated production proof output.
