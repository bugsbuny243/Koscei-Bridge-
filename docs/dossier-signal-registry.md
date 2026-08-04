# Dossier signal registry and deterministic autopublish

The customer-facing dossier card is defined once in `dossier_signal_registry.go`.
It contains 25 stable rows and a canonical nine-state vocabulary:

- evidence: `verified`, `observed`
- watch-only: `inferred`
- open work: `window_open`, `pending`, `not_investigated`
- closed: `not_applicable`
- blocked: `unavailable`, `unknown`

Unknown engine states fail closed. Module lookup is exact, and field selectors use
real report paths such as `signals.mint_authority_present`.

The ten priority detectors all own a customer row. Four rows are deliberately
`not_investigated` until their detector reports are wired:
`authority-change`, `supply-change`, `concentration-change`, and
`exploit-attempts`.

Autopublish remains disabled by default. Initial production thresholds:

```text
KOSCHEI_AUTOPUBLISH_ENABLED=false
KOSCHEI_AUTOPUBLISH_MIN_SIGNAL_ROWS=6
KOSCHEI_AUTOPUBLISH_MIN_VERIFIED_ROWS=3
KOSCHEI_AUTOPUBLISH_MAX_OPEN_ROWS=8
KOSCHEI_AUTOPUBLISH_MAX_BLOCKED_ROWS=2
KOSCHEI_AUTOPUBLISH_MAX_UNKNOWN_ROWS=0
KOSCHEI_AUTOPUBLISH_MAX_BUNDLE_AGE_HOURS=72
```

Thresholds are fingerprinted into `policy_version`; changing a gate creates a
new deterministic decision identity. Owner draft/hidden/public rows are never
touched because the worker considers only exports with no publication row.

Feedback query:

```sql
SELECT reason, count(*)
FROM dossier_autopublish_decisions d
CROSS JOIN LATERAL jsonb_array_elements_text(d.reasons) AS reason
WHERE NOT d.published
GROUP BY reason
ORDER BY count(*) DESC, reason;
```
