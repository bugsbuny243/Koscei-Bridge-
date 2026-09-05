# ARVIS Address History v1

ARVIS wallet investigation now includes a provider-portable Solana address-history report inside `actor_investigation.external_discovery.address_history`.

The collector uses paginated `getSignaturesForAddress`. It does not copy raw transaction bodies into a new database and it does not claim a real-world owner identity from an address alone.

## Output contract

The report exposes:

- exact case-sensitive address and network
- first and last observed block time when available
- newest and oldest observed transaction signatures
- successful and failed signature counts
- chronological evidence entries containing signature, slot, status and block time
- pages fetched and signatures observed
- `history_complete` when the RPC history was actually exhausted
- `next_cursor` when the scan stops at the configured page/time budget
- explicit limitations for uninspected older history

## Cost boundary

Defaults are 250 signatures per page and 8 pages. Runtime controls:

- `ARVIS_ADDRESS_HISTORY_PAGE_SIZE`
- `ARVIS_ADDRESS_HISTORY_MAX_PAGES`

The page size is capped at 1000 and page count at 20. A bounded result must never be presented as a clean or complete history.

## Identity policy

Address history is on-chain evidence, not a legal-person attribution. Real-world ownership must remain `unknown` unless a separate public and verifiable attribution source supports the claim.
