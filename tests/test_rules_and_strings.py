"""Tests for string extraction and YARA-like rule behavior."""

import tempfile
import unittest
from pathlib import Path

from ire_zero.rules import BUILTIN_RULES, scan_rules
from ire_zero.string_scan import analyze_strings, extract_strings_from_file


class RuleAndStringTests(unittest.TestCase):
    def test_builtin_rules_match_case_insensitively(self) -> None:
        matches = scan_rules(["Using FRIDA gadget", "nothing"], BUILTIN_RULES)

        self.assertIn("rule.jailbreak.frida", matches)

    def test_string_analysis_extracts_indicators(self) -> None:
        indicators = analyze_strings(
            [
                "http://example.test/api",
                "10.20.30.40",
                "client_secret=abc12345",
                "clientSecret",
                "check pasteboard",
            ],
            BUILTIN_RULES,
        )

        self.assertEqual(indicators.urls, ["http://example.test/api"])
        self.assertEqual(indicators.ips, ["10.20.30.40"])
        self.assertEqual(indicators.secrets, ["client_secret=abc12345"])
        self.assertIn("pasteboard", indicators.suspicious_keywords)

    def test_extract_strings_from_file_reads_ascii_and_utf16le(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bin"
            path.write_bytes(b"\x00hello-world\x00" + "wide-token".encode("utf-16le"))

            strings = extract_strings_from_file(path)

        self.assertIn("hello-world", strings)
        self.assertIn("wide-token", strings)


if __name__ == "__main__":
    unittest.main()
