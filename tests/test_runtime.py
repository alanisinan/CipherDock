"""Tests for runtime trace parsing, correlation, campaigns, and findings."""

import json
import tempfile
import unittest
from pathlib import Path

from ire_zero.models import BinaryArtifacts, DynamicCapture, PlistInfo, RuntimeEvent, RuntimeProbe, StringIndicators
from ire_zero.runtime import correlate_runtime_events, generate_runtime_campaigns, load_runtime_capture, measure_campaign_coverage, runtime_findings, runtime_observation_findings


class RuntimeCaptureTests(unittest.TestCase):
    def test_imports_runtime_events_and_confirms_keychain_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "capture.json"
            trace.write_text(
                json.dumps(
                    {
                        "session": "authorized-device-run",
                        "events": [
                            {
                                "timestamp": "00:03.801",
                                "layer": "keychain",
                                "operation": "SecItemAdd",
                                "value": "access=kSecAttrAccessibleAlways",
                                "severity": "high",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            capture = load_runtime_capture(trace)
            findings = runtime_findings(capture)

        self.assertEqual(capture.status, "captured")
        self.assertEqual(capture.session, "authorized-device-run")
        self.assertEqual(findings[0].id, "dynamic.keychain_accessibility")

    def test_no_trace_is_not_misrepresented_as_execution(self) -> None:
        capture = load_runtime_capture(None)

        self.assertEqual(capture.status, "not_captured")
        self.assertEqual(capture.events, [])

    def test_imports_generated_frida_log_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "frida.log"
            trace.write_text(
                "[Local::App ]-> IRE_ZERO_EVENT "
                '{"timestamp":"now","layer":"network","operation":"NSURLSession","value":"https://example.test"}\n',
                encoding="utf-8",
            )
            capture = load_runtime_capture(trace)

        self.assertEqual(capture.status, "captured")
        self.assertEqual(capture.events[0].layer, "network")

    def test_imports_single_jsonl_event_written_by_live_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime-capture.jsonl"
            trace.write_text(
                '{"timestamp":"now","layer":"process","operation":"instrumentation attached","value":"capture started"}\n',
                encoding="utf-8",
            )

            capture = load_runtime_capture(trace)

        self.assertEqual(capture.status, "captured")
        self.assertEqual(len(capture.events), 1)
        self.assertEqual(capture.events[0].operation, "instrumentation attached")

    def test_simulator_companion_capture_preserves_observed_events_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime-capture.jsonl"
            trace.write_text(
                '{"layer":"process","operation":"instrumentation attached","value":"started"}\n'
                '{"layer":"network","operation":"NSURLSession dataTaskWithRequest","value":"https://api.example.test/new"}\n',
                encoding="utf-8",
            )
            capture = load_runtime_capture(trace, capture_mode="companion_build")
        correlate_runtime_events(
            capture,
            PlistInfo(),
            BinaryArtifacts(executable_path="Payload/App.app/App"),
            StringIndicators(urls=["https://other.different.test/known"]),
        )
        observations = runtime_observation_findings(capture)

        self.assertEqual(capture.status, "captured (companion build)")
        self.assertEqual(capture.capture_mode, "companion_build")
        self.assertEqual(capture.evidence_source, "Frida Simulator live capture")
        self.assertEqual(capture.events[1].correlation_status, "DYNAMIC_ONLY")
        self.assertEqual(capture.cross_layer["summary"]["DYNAMIC_ONLY"], 2)
        self.assertEqual(len(observations), 2)
        self.assertIn("Source: Frida Simulator live capture", observations[1].evidence)

    def test_campaign_coverage_marks_only_observed_behaviors(self) -> None:
        probes = [
            RuntimeProbe(
                id="probe-network",
                layer="network",
                operation="URLSessionTask.resume",
                target="api.example.test",
                rationale="Observe network use.",
            ),
            RuntimeProbe(
                id="probe-pasteboard",
                layer="process",
                operation="UIPasteboard reads and writes",
                target="clipboard",
                rationale="Observe clipboard access.",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "capture.json"
            trace.write_text(
                json.dumps(
                    [
                        {"layer": "process", "operation": "instrumentation attached", "value": "started"},
                        {"layer": "network", "operation": "NSURLSession dataTaskWithRequest", "value": "https://api.example.test"},
                    ]
                ),
                encoding="utf-8",
            )
            capture = load_runtime_capture(trace)
        campaigns = generate_runtime_campaigns(probes)
        coverage = measure_campaign_coverage(campaigns, capture.events)

        self.assertEqual(coverage["observed"], 2)
        privacy = next(item for item in coverage["campaigns"] if item["id"] == "campaign-privacy")
        self.assertEqual(privacy["status"], "not_observed")

    def test_runtime_privacy_and_tamper_events_become_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "capture.json"
            trace.write_text(
                json.dumps(
                    [
                        {"layer": "process", "operation": "UIPasteboard - string", "value": "contents redacted"},
                        {"layer": "process", "operation": "fileExistsAtPath", "value": "/Applications/Cydia.app"},
                    ]
                ),
                encoding="utf-8",
            )
            capture = load_runtime_capture(trace)
        ids = {finding.id for finding in runtime_findings(capture)}

        self.assertIn("dynamic.pasteboard_read", ids)
        self.assertIn("dynamic.anti_analysis_probe", ids)

    def test_runtime_events_link_to_related_static_evidence(self) -> None:
        capture = DynamicCapture(
            status="captured",
            events=[
                RuntimeEvent(
                    id="network",
                    timestamp="now",
                    layer="network",
                    operation="NSURLSession dataTaskWithRequest",
                    value="https://api.example.test/feed",
                ),
                RuntimeEvent(
                    id="scheme",
                    timestamp="later",
                    layer="process",
                    operation="UIApplication.canOpenURL",
                    value="mailto://compose",
                ),
            ],
        )
        plist = PlistInfo(query_schemes=["mailto"])
        binary = BinaryArtifacts(
            executable_path="Payload/App.app/App",
            platform="IOS",
            symbol_categories={"networking": ["_NSURLSession_dataTask"]},
        )
        indicators = StringIndicators(urls=["https://www.example.test/privacy"])

        correlate_runtime_events(capture, plist, binary, indicators)

        self.assertIn("Related recovered domain string: https://www.example.test/privacy", capture.events[0].static_evidence)
        self.assertEqual(capture.events[0].correlation_status, "DOMAIN_MATCH")
        self.assertIn("Recovered networking artifact: _NSURLSession_dataTask", capture.events[0].static_evidence)
        self.assertIn("Declared LSApplicationQueriesSchemes value: mailto", capture.events[1].static_evidence)

    def test_exact_recovered_runtime_url_is_confirmed(self) -> None:
        capture = DynamicCapture(
            status="captured",
            capture_mode="exact_ipa",
            events=[
                RuntimeEvent(
                    id="network",
                    timestamp="now",
                    layer="network",
                    operation="NSURLSession",
                    value="https://api.example.test/v1",
                )
            ],
        )
        correlate_runtime_events(
            capture,
            PlistInfo(),
            BinaryArtifacts(executable_path="Payload/App.app/App"),
            StringIndicators(urls=["https://api.example.test/v1"]),
        )

        self.assertEqual(capture.events[0].correlation_status, "CONFIRMED")
        self.assertEqual(capture.events[0].verdict, "CONFIRMED")
        self.assertEqual(capture.cross_layer["events"][0]["label"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
