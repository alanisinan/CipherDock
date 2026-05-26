"""Tests for Info.plist loading and selected metadata normalization."""

import plistlib
import tempfile
import unittest
from pathlib import Path

from ire_zero.plist_parser import load_info_plist, parse_info_plist


class PlistParserTests(unittest.TestCase):
    def test_parse_selected_info_plist_values(self) -> None:
        parsed = parse_info_plist(
            {
                "CFBundleIdentifier": "com.example.app",
                "CFBundleName": "Example",
                "CFBundleExecutable": "ExampleBin",
                "CFBundleURLTypes": [
                    {"CFBundleURLName": "auth", "CFBundleURLSchemes": ["example"]},
                    "not-a-dict",
                ],
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                "LSApplicationQueriesSchemes": ["cydia", "fb"],
            }
        )

        self.assertEqual(parsed.bundle_identifier, "com.example.app")
        self.assertEqual(parsed.bundle_name, "Example")
        self.assertEqual(parsed.bundle_executable, "ExampleBin")
        self.assertEqual(parsed.url_types, [{"CFBundleURLName": "auth", "CFBundleURLSchemes": ["example"]}])
        self.assertEqual(parsed.app_transport_security, {"NSAllowsArbitraryLoads": True})
        self.assertEqual(parsed.query_schemes, ["cydia", "fb"])
        self.assertIn("CFBundleIdentifier", parsed.raw_subset)

    def test_load_binary_plist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Info.plist"
            with path.open("wb") as handle:
                plistlib.dump({"CFBundleIdentifier": "com.example.binary"}, handle, fmt=plistlib.FMT_BINARY)

            parsed = load_info_plist(path)

        self.assertEqual(parsed.bundle_identifier, "com.example.binary")


if __name__ == "__main__":
    unittest.main()
