"""Tests for rule pack management through the command-line interface."""

import json
import tempfile
import unittest
from pathlib import Path

from ire_zero.rules import load_rules, validate_rules_file


class RuleManagementTests(unittest.TestCase):
    def test_packaged_rules_load_by_default(self) -> None:
        rules = load_rules(None)
        ids = {rule.id for rule in rules}

        self.assertIn("rule.private.lsworkspace", ids)
        self.assertIn("rule.instrumentation.frida", ids)

    def test_validate_rules_file_reports_regex_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(
                json.dumps([
                    {"id": "bad", "pattern": "[", "severity": "high", "regex": True},
                ]),
                encoding="utf-8",
            )

            errors = validate_rules_file(path)

        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
