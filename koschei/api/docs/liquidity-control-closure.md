# Liquidity Control Closure

Koschei collects protocol-specific pool evidence during full token investigations. This collector is informational and cannot change a grade, verdict signature, rule threshold or caller entitlement.

## Supported pool layouts

| Protocol | Pool identity | Vault reserves | Control model | Lock / burn evidence |
|---|---|---|---|---|
| Raydium CPMM | Pinned program owner and decoded pool account | Direct token-account balances | Fungible LP token | LP supply, resolved largest LP holders, burn-address share, creator-observed share, pinned Burn & Earn custody share, supported time-lock programs |
| Raydium CLMM | Pinned Anchor `PoolState` owner/discriminator and decoded mints/vaults | Direct token-account balances | Position NFT | Pool-filtered Burn & Earn lock states, linked personal-position accounts, and program-authority custody of the original position NFT |
| Raydium AMM v4 | Pinned program owner and fixed LiquidityStateV4 fields | Direct token-account balances | Fungible LP token | LP supply, resolved largest LP holders, burn-address share, creator-observed share, supported time-lock programs; Burn & Earn permanent-lock status is not asserted for this model |
| PumpSwap | Official Pool account layout and canonical pool index | Direct base/quote vault balances plus separately labelled virtual quote reserve | Fungible LP token | LP supply, resolved largest LP holders, burn-address share, creator-observed share |
| Meteora DAMM v2 | Official Pool account layout | Direct token A/B vault balances | Position NFT | Pool liquidity and permanent-locked liquidity are read from the pool account; no LP mint is invented |
| Meteora DLMM | Official bytemuck `LbPair` layout | Direct reserve X/Y token-account balances | Position account | Pool and reserve evidence is collected; position-owner enumeration remains withheld |

An unsupported program, account-owner mismatch, short account payload or mint mismatch remains `insufficient_evidence` or `source_unavailable`. A pool address alone never completes the collector.

## Raydium CPMM fungible-LP permanent lock evidence

For Raydium CPMM pools, Koschei reports `permanently_locked` only when all of the following are observed together:

1. the pool account is owned by the pinned Raydium CPMM program;
2. the pool exposes a decoded fungible LP mint;
3. an LP token account is returned by the bounded `getTokenLargestAccounts` request;
4. that token account's authority wallet is resolved from parsed SPL-token account data;
5. the authority account itself is owned by the pinned Raydium Burn & Earn program;
6. the LP amount is positive and does not exceed the observed LP mint supply;
7. the observed LP mint supply is available.

The report stores the summed `locked_lp_amount`, `locked_lp_share_pct`, contributing LP token accounts, every resolved Burn & Earn authority account, pinned program and slot-bound evidence keys. An arbitrary label, transaction signer, market-provider locker label or account owned by another program cannot satisfy this rule.

Burn-address share and Burn & Earn custody share remain separate evidence. When both are observed, both numeric fields are retained; the overall control status reports the verified permanent custody surface. The percentage is explicitly bounded to LP token accounts returned by the largest-account RPC and is not a claim that every LP account was enumerated.

Raydium AMM v4 is deliberately excluded from this permanent-lock rule. Streamflow remains a separate time-lock model. A Streamflow-owned authority is reported as `locked_until` only when its schedule account yields a conservatively decoded future unlock time; it is never promoted through the Raydium CPMM permanent-lock rule.

## Raydium CLMM position-NFT permanent lock evidence

Raydium CLMM does not expose a fungible LP mint. Koschei therefore uses a separate position-NFT proof chain and reports one position as `VERIFIED` only when all of the following match:

1. the pool account is owned by the pinned Raydium CLMM program and matches the Anchor `PoolState` discriminator;
2. the pool contains the investigated mint and exposes decoded token/quote vaults;
3. a current account owned by the pinned Raydium Burn & Earn program matches the exact locked-position account size, discriminator and pool field;
4. the lock state references a personal-position account owned by the pinned Raydium CLMM program;
5. that personal-position account matches the exact `PersonalPositionState` layout and the same pool;
6. the linked locked NFT token account is owned by SPL Token or Token-2022;
7. the token account contains exactly one zero-decimal token whose mint equals the personal position's NFT mint;
8. the token-account authority equals the pinned Raydium CLMM lock-authority account;
9. the tick range is ordered and the position liquidity integer is positive.

The current lock-state query is bounded in three ways: exact program, exact account size and pool-ID memcmp filter. A data slice returns only the fields needed for verification. More than 200 matching records causes fail-closed `limit_exceeded`; results are never silently truncated. Linked accounts are fetched in batches of at most 100.

The report stores each verified lock-state account, original position owner, personal-position account, position NFT mint, custody token account, program authority, fee NFT mint, tick range, raw position-liquidity integer and evidence keys. Invalid linked records are excluded and make enumeration `verified_partial_bounded_filter` rather than being treated as verified.

`PoolState.liquidity` is active-tick liquidity, not total liquidity across every CLMM position. Koschei therefore reports pool active-liquidity raw and summed verified locked-position liquidity raw as separate integers. It does **not** calculate or display a locked-liquidity percentage for CLMM.

No current matching lock state means only that no current Burn & Earn lock account was observed for that pool at the reported RPC context. It is not a historical unlock statement.

## Recent liquidity movement window

A full scan inspects at most:

- 50 recent successful pool signatures;
- 20 parsed transactions.

A movement row requires all of the following:

1. The transaction references the decoded pool and its pinned program.
2. The transaction contains an explicit add, deposit, initialize-pool, remove, withdraw or lock instruction/log trace.
3. The decoded pool vault deltas are compatible with that trace.
4. The signature and slot are present.

Opposing token and quote reserve deltas are treated as a swap and are never reported as add/remove liquidity. Same-direction reserve changes without an explicit liquidity trace are also rejected.

Each accepted row contains:

- movement kind;
- signature and slot;
- observed block time;
- signer wallet when available;
- deterministic creator relation (`verified_pool_creator_signer`, `verified_investigated_creator_signer`, `verified_creator_lp_holder_signer`, or `not_observed`);
- source and destination accounts derived from the verified movement direction;
- pool and program;
- token and quote vault deltas;
- instruction types;
- evidence key;
- verification status (`VERIFIED`).

For fungible-LP pools the report also exposes the largest resolved LP-token account, its owner wallet, observed supply share and classification (holder, creator, burn address or supported locker). Raydium CPMM decodes the pool creator and quote mint from the pinned pool layout, so quote-vault reserve deltas and creator-signer relations are evaluated against actual pool accounts rather than a market label. Burn and owner shares remain explicitly bounded to the LP token accounts returned by Solana's largest-account RPC.

No observed row means only that no qualifying trace was found in the bounded window. It is not a claim about older activity.

## Position-based ownership boundary

Raydium CLMM, Meteora DAMM v2 and Meteora DLMM do not use a fungible LP mint as the ownership source. Koschei therefore does not display LP supply, burn percentage or creator LP share for these models.

DAMM v2 permanent-lock liquidity is a pool-level field and can be reported directly. Raydium CLMM current locked positions are queried through the narrowly filtered Burn & Earn account index described above. Meteora DAMM v2 and DLMM current owner enumeration remains withheld because no equivalent bounded index is used during a user scan.

Recent add/remove transaction signers are still shown as observed transaction actors. They are not asserted to be the current owner of every position.

## Product invariants

- Capability is not intent.
- No identity attribution beyond observed on-chain wallet relations.
- No BLOCK/ALLOW or buy/sell recommendation.
- No numeric risk score or rug probability.
- Safe Check and preflight perform no new pool-history calls.
- Public, owner and API full scans use the same technical evidence path.
- Tiers affect access and capacity, not the technical result.
