#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_migration_numbering import baseline_for, validate


class MigrationNumberingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.migrations = self.root / "migrations"
        self.migrations.mkdir()
        for name in [
            "001_first.sql",
            "002_second.sql",
            "003_legacy_a.sql",
            "003_legacy_b.sql",
            "005_fifth.sql",
        ]:
            (self.migrations / name).write_text("SELECT 1;\n", encoding="utf-8")
        self.baseline = self.root / "baseline.json"
        self.baseline.write_text(
            json.dumps(baseline_for(self.migrations), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_known_history_passes(self) -> None:
        self.assertEqual(validate(self.migrations, self.baseline), [])

    def test_new_duplicate_prefix_fails(self) -> None:
        (self.migrations / "005_duplicate.sql").write_text("SELECT 1;\n", encoding="utf-8")
        errors = validate(self.migrations, self.baseline)
        self.assertTrue(any("new duplicate migration prefix 005" in error for error in errors), errors)

    def test_new_skipped_prefix_fails(self) -> None:
        (self.migrations / "007_seventh.sql").write_text("SELECT 1;\n", encoding="utf-8")
        errors = validate(self.migrations, self.baseline)
        self.assertTrue(any("new skipped migration prefix(es): 006" in error for error in errors), errors)

    def test_renaming_applied_duplicate_history_fails(self) -> None:
        (self.migrations / "003_legacy_b.sql").unlink()
        (self.migrations / "003_replacement.sql").write_text("SELECT 1;\n", encoding="utf-8")
        errors = validate(self.migrations, self.baseline)
        self.assertTrue(any("accepted duplicate prefix 003 changed" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
