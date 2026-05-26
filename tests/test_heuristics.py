"""Tests for deterministic security heuristics and score assembly."""

import unittest

from ire_zero.heuristics import (
    detect_hardcoded_secrets,
    detect_jailbreak_logic,
    detect_private_api_usage,
    detect_sensitive_entitlements,
    detect_suspicious_endpoints,
    detect_transport_security,
    evaluate_heuristics,
)
from ire_zero.models import BinaryArtifacts, PlistInfo, StringIndicators


class HeuristicTests(unittest.TestCase):
    def test_transport_security_flags_arbitrary_loads(self) -> None:
        plist = PlistInfo(app_transport_security={"NSAllowsArbitraryLoads": True})

        findings = detect_transport_security(plist)

        self.assertEqual(findings[0].id, "ats.arbitrary_loads")
        self.assertEqual(findings[0].severity, "high")

    def test_secret_detector_uses_strings_and_rules(self) -> None:
        indicators = StringIndicators(
            secrets=["api_key=abc123"],
            rule_matches={"rule.secret.aws": ["AKIA1234567890ABCDEF"]},
        )

        findings = detect_hardcoded_secrets(indicators)

        self.assertEqual(len(findings), 1)
        self.assertIn("api_key=abc123", findings[0].evidence)
        self.assertIn("AKIA1234567890ABCDEF", findings[0].evidence)

    def test_private_api_detector_uses_symbols_and_rules(self) -> None:
        binary = BinaryArtifacts(
            executable_path="/tmp/App",
            symbols=["_OBJC_CLASS_$_LSApplicationWorkspace"],
        )
        indicators = StringIndicators()

        findings = detect_private_api_usage(binary, indicators)

        self.assertEqual(findings[0].id, "binary.private_api_usage")

    def test_jailbreak_detector_groups_keywords(self) -> None:
        indicators = StringIndicators(suspicious_keywords={"frida": ["frida-server"], "cydia": ["/Applications/Cydia.app"]})

        findings = detect_jailbreak_logic(indicators)

        self.assertEqual(findings[0].category, "anti-analysis")
        self.assertEqual(len(findings[0].evidence), 2)

    def test_suspicious_endpoints_flags_http_and_ips(self) -> None:
        indicators = StringIndicators(
            urls=[
                "http://example.test/path",
                "https://safe.test",
                "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
                "http://ocsp.apple.com/ocsp03-test",
            ],
            ips=["10.0.0.5"],
        )

        findings = detect_suspicious_endpoints(indicators)

        self.assertEqual({finding.id for finding in findings}, {"network.cleartext_urls", "network.hardcoded_ips"})
        cleartext = next(finding for finding in findings if finding.id == "network.cleartext_urls")
        self.assertEqual(cleartext.evidence, ["http://example.test/path"])

    def test_sensitive_entitlements_flags_private_entitlements(self) -> None:
        findings = detect_sensitive_entitlements({"com.apple.private.security.no-container": True})

        self.assertEqual(findings[0].severity, "high")

    def test_evaluate_heuristics_returns_score_and_sorted_findings(self) -> None:
        plist = PlistInfo(app_transport_security={"NSAllowsArbitraryLoads": True})
        binary = BinaryArtifacts(executable_path="/tmp/App", symbols=["_LSApplicationWorkspace"])
        indicators = StringIndicators(
            urls=["http://example.test"],
            suspicious_keywords={"frida": ["frida"]},
            secrets=["token=abc"],
        )

        findings, score, breakdown = evaluate_heuristics(
            plist,
            {"com.apple.private.foo": True},
            binary,
            indicators,
        )

        self.assertGreater(score, 0)
        self.assertIn("hardcoded_secrets", breakdown)
        self.assertEqual(findings[0].severity, "high")


if __name__ == "__main__":
    unittest.main()
