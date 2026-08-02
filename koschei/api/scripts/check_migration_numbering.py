#!/usr/bin/env python3
"""Reject migration numbering drift without renaming applied history."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MIGRATION_RE = re.compile(r"^(?P<prefix>\d{3})_.+\.sql$")


def inventory(directory: Path) -> tuple[dict[str, list[str]], list[str]]:
    groups: dict[str, list[str]] = {}
    for path in sorted(directory.glob("*.sql")):
        match = MIGRATION_RE.match(path.name)
        if not match:
            raise ValueError(f"migration filename does not match NNN_name.sql: {path.name}")
        groups.setdefault(match.group("prefix"), []).append(path.name)
    if not groups:
        raise ValueError("no migrations found")
    values = sorted(int(prefix) for prefix in groups)
    missing = [f"{value:03d}" for value in range(values[0], values[-1] + 1) if f"{value:03d}" not in groups]
    return groups, missing


def baseline_for(directory: Path) -> dict[str, object]:
    groups, missing = inventory(directory)
    duplicates = {prefix: names for prefix, names in groups.items() if len(names) > 1}
    return {
        "schema_version": 1,
        "known_duplicate_prefixes": duplicates,
        "known_missing_prefixes": missing,
    }


def validate(directory: Path, baseline_path: Path) -> list[str]:
    groups, missing = inventory(directory)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    known_duplicates = {
        str(prefix): sorted(str(name) for name in names)
        for prefix, names in baseline.get("known_duplicate_prefixes", {}).items()
    }
    known_missing = sorted(str(value) for value in baseline.get("known_missing_prefixes", []))

    errors: list[str] = []
    current_duplicates = {prefix: sorted(names) for prefix, names in groups.items() if len(names) > 1}
    for prefix, names in current_duplicates.items():
        accepted = known_duplicates.get(prefix)
        if accepted is None:
            errors.append(f"new duplicate migration prefix {prefix}: {', '.join(names)}")
        elif names != accepted:
            errors.append(
                f"accepted duplicate prefix {prefix} changed: expected {accepted}, found {names}"
            )
    for prefix, accepted in known_duplicates.items():
        if current_duplicates.get(prefix) != accepted:
            errors.append(
                f"known duplicate history {prefix} was renamed, removed or reordered: expected {accepted}, "
                f"found {current_duplicates.get(prefix, [])}"
            )

    if missing != known_missing:
        added = sorted(set(missing) - set(known_missing))
        removed = sorted(set(known_missing) - set(missing))
        if added:
            errors.append(f"new skipped migration prefix(es): {', '.join(added)}")
        if removed:
            errors.append(
                "historical accepted gap(s) were filled or numbering baseline changed: " + ", ".join(removed)
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--migrations", default="migrations", type=Path)
    parser.add_argument(
        "--baseline", default="migrations/migration-numbering-baseline.json", type=Path
    )
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    if args.write_baseline:
        baseline = baseline_for(args.migrations)
        args.baseline.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.baseline}")
        return 0

    try:
        errors = validate(args.migrations, args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"migration numbering check failed: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"migration numbering check failed: {error}", file=sys.stderr)
        return 1
    groups, missing = inventory(args.migrations)
    duplicates = sorted(prefix for prefix, names in groups.items() if len(names) > 1)
    print(
        "migration numbering check passed: "
        f"{sum(len(names) for names in groups.values())} files, "
        f"known duplicates={duplicates}, known gaps={missing}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
