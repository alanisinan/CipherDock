"""Tests for symbol extraction and security category classification."""

import unittest

from ire_zero.binary import _parse_nm_symbols
from ire_zero.symbols import classify_symbols


class SymbolClassificationTests(unittest.TestCase):
    def test_classifies_core_ios_security_categories(self) -> None:
        categories = classify_symbols(
            [
                "_OBJC_CLASS_$_LSApplicationWorkspace",
                "_SecItemCopyMatching",
                "_NSURLSessionTaskResume",
                "_CCCrypt",
                "_UIPasteboardNameGeneral",
                "_FirebaseAnalyticsLogEvent",
                "_$s8Mastodon5ThingV",
            ]
        )

        self.assertIn("private_api", categories)
        self.assertIn("storage_keychain", categories)
        self.assertIn("networking", categories)
        self.assertIn("crypto", categories)
        self.assertIn("pasteboard", categories)
        self.assertIn("analytics_tracking", categories)
        self.assertIn("swift", categories)

    def test_nm_parser_retains_symbol_not_origin_library(self) -> None:
        symbols = _parse_nm_symbols(
            "                 (undefined) external _SecItemAdd (from Security)\n"
            "0000000100004000 (__TEXT,__text) external _$s8Mastodon4mainyyF\n"
        )

        self.assertEqual(symbols, ["_SecItemAdd", "_$s8Mastodon4mainyyF"])

    def test_ui_segmented_control_is_not_tracking_sdk_evidence(self) -> None:
        categories = classify_symbols(["_OBJC_CLASS_$_UISegmentedControl", "segmentedControlValueChanged:"])

        self.assertNotIn("analytics_tracking", categories)


if __name__ == "__main__":
    unittest.main()
