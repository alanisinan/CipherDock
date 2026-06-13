"""Tests for corpus generation, scoring, and evaluation reporting."""

import csv
import json
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from eval.common import load_labels, sample_candidates, upsert_label_rows
from eval.generate_abstract import generate_abstract
from eval.metrics import ScoredExample, bootstrap_f1, compute_metrics, main as metrics_main, read_labeled_scores, split_examples
from eval.paper_numbers import _dynamic_numbers
from eval.run_all import main as run_all_main, mann_whitney_u
from eval.run_corpus import discover_ipas, main as run_corpus_main
from eval.synthetic_builder import main as synthetic_builder_main
from eval.verify_corpus import main as verify_corpus_main
from eval.run_corpus import sha256_file
from ire_zero.analyzer import analyze_ipa
from ire_zero.rules import load_rules


def write_test_ipa(path: Path, bundle_identifier: str = "org.irezero.syntheticrisk") -> None:
    """Create a tiny IPA fixture for static-analysis and corpus tests."""
    path.parent.mkdir(parents=True, exist_ok=True)
    info_plist = {
        "CFBundleIdentifier": bundle_identifier,
        "CFBundleName": "SyntheticRisk",
        "CFBundleExecutable": "SyntheticRisk",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["syntheticrisk"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False},
        "LSApplicationQueriesSchemes": ["https"],
    }
    executable = (
        b"IREZero SyntheticRisk fixture\n"
        b"https://api.synthetic-risk.example.invalid/v1/status\n"
        b"http://insecure.synthetic-risk.example.invalid/debug\n"
        b"NSURLSession Keychain UIPasteboard\n"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/SyntheticRisk.app/Info.plist", plistlib.dumps(info_plist, fmt=plistlib.FMT_XML))
        archive.writestr("Payload/SyntheticRisk.app/SyntheticRisk", executable)


class EvaluationTests(unittest.TestCase):
    def test_labels_match_filename_and_binary_forms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            labels_path = Path(tmp) / "labels.csv"
            labels_path.write_text("ipa_file,label\nOne.ipa,positive\nTwo.ipa,clean\n", encoding="utf-8")
            labels = load_labels(labels_path)

            one = labels.match(sample_candidates(filename="One.ipa"))
            two = labels.match(sample_candidates(filename="Two.ipa"))

            self.assertIsNotNone(one)
            self.assertIsNotNone(two)
            self.assertEqual(one.label, 1)
            self.assertEqual(two.label, 0)

    def test_computes_threshold_metrics(self) -> None:
        row = compute_metrics([(92, 1), (75, 0), (60, 1), (20, 0)], 70)

        self.assertEqual(row["true_positive"], "1")
        self.assertEqual(row["false_positive"], "1")
        self.assertEqual(row["true_negative"], "1")
        self.assertEqual(row["false_negative"], "1")
        self.assertEqual(row["precision"], "0.5000")
        self.assertEqual(row["recall"], "0.5000")
        self.assertEqual(row["f1"], "0.5000")

    def test_stratified_held_out_split_and_bootstrap_interval(self) -> None:
        examples = [
            ScoredExample(20, 0, "b1", "real_benign"),
            ScoredExample(60, 0, "b2", "real_benign"),
            *[ScoredExample(84, 1, f"o{index}", "obvious") for index in range(5)],
            *[ScoredExample(18, 1, f"s{index}", "subtle") for index in range(4)],
        ]
        calibration, held_out = split_examples(examples, 0.3, 1337)
        mean, low, high = bootstrap_f1(held_out, 70, 100, 1337)

        self.assertLess(len(held_out), len(examples))
        self.assertTrue(any(item.variant_type == "subtle" for item in held_out))
        self.assertTrue(any(item.variant_type == "obvious" for item in held_out))
        self.assertTrue(any(item.label == 0 for item in held_out))
        self.assertGreaterEqual(mean, low)
        self.assertLessEqual(mean, high)
        self.assertTrue(calibration)

    def test_mann_whitney_detects_separated_category_counts(self) -> None:
        statistic, p_value = mann_whitney_u([0, 0, 1, 0, 0], [2, 2, 2, 3, 2])

        self.assertEqual(statistic, 0.0)
        self.assertLess(p_value, 0.05)

    def test_abstract_is_filled_from_paper_numbers(self) -> None:
        abstract = generate_abstract(
            {
                "corpus_total": 35,
                "corpus_benign_real": 5,
                "corpus_malicious": 30,
                "best_threshold": 50,
                "best_f1": 0.9474,
                "precision_at_best": 0.9,
                "recall_at_best": 1.0,
                "f1_confidence_interval": "0.95 +/- 0.09 (95% CI [0.82, 1.00])",
                "avg_score_benign": 41,
                "avg_score_malicious": 78.67,
                "dynamic_events_captured": 2,
                "dynamic_network_calls": 1,
                "dynamic_endpoint_captured": "https://api.joinmastodon.org/default-servers",
                "dynamic_endpoint_correlation": "DOMAIN_MATCH",
                "simulator_target": "iPhone 17 Pro Simulator",
            }
        )

        self.assertIn("controlled corpus of 35 IPAs", abstract)
        self.assertIn("F1 0.9474", abstract)
        self.assertIn("DOMAIN_MATCH", abstract)

    def test_synthetic_builder_injects_detectable_static_behaviors_and_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            labels = root / "corpus" / "labels.csv"
            variants = root / "corpus" / "synthetic"
            source = root / "fixtures" / "SyntheticRisk.ipa"
            write_test_ipa(source)

            exit_code = synthetic_builder_main(
                [
                    str(source),
                    "--all",
                    "--count",
                    "2",
                    "--output-dir",
                    str(variants),
                    "--update-labels",
                    str(labels),
                ]
            )
            variant = sorted(variants.glob("*.ipa"))[0]
            result = analyze_ipa(variant, load_rules(None))
            with labels.open("r", encoding="utf-8", newline="") as handle:
                label_rows = list(csv.DictReader(handle))
            manifest = json.loads((variants / "manifest.json").read_text(encoding="utf-8"))
            finding_ids = {finding.id for finding in result.findings}

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(label_rows), 2)
            self.assertEqual(label_rows[0]["label"], "positive")
            self.assertEqual(len(manifest["variants"]), 2)
            self.assertIn(".irez.eval001", result.info_plist.bundle_identifier)
            self.assertIn("ats.arbitrary_loads", finding_ids)
            self.assertIn("strings.hardcoded_secret", finding_ids)
            self.assertIn("strings.jailbreak_detection", finding_ids)
            self.assertIn("network.cleartext_urls", finding_ids)

    def test_subtle_builder_uses_single_low_signal_behavior_and_records_variant_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            labels = root / "corpus" / "labels.csv"
            variants = root / "corpus" / "subtle"
            source = root / "fixtures" / "SyntheticRisk.ipa"
            write_test_ipa(source)

            exit_code = synthetic_builder_main(
                [
                    str(source),
                    "--subtle",
                    "--count",
                    "3",
                    "--output-dir",
                    str(variants),
                    "--update-labels",
                    str(labels),
                ]
            )
            manifest = json.loads((variants / "manifest.json").read_text(encoding="utf-8"))
            with labels.open("r", encoding="utf-8", newline="") as handle:
                label_rows = list(csv.DictReader(handle))

            self.assertEqual(exit_code, 0)
            self.assertEqual(manifest["variant_type"], "subtle")
            self.assertEqual(
                [row["behaviors"] for row in manifest["variants"]],
                [["encoded_secret"], ["misspelled_jailbreak"], ["plausible_endpoint"]],
            )
            self.assertTrue(all(row["variant_type"] == "subtle" for row in label_rows))
            self.assertTrue(all("__irez.subtle" in row["ipa_file"] for row in label_rows))

    def test_run_corpus_and_read_metrics_from_static_cli_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            corpus.mkdir()
            ipa = corpus / "SyntheticRisk.ipa"
            write_test_ipa(ipa)
            labels = root / "labels.csv"
            labels.write_text("ipa_file,label\nSyntheticRisk.ipa,vulnerable\n", encoding="utf-8")
            output = root / "results.csv"
            reports = root / "reports"
            metrics_output = root / "metrics.csv"

            exit_code = run_corpus_main(
                [str(corpus), str(labels), "--output", str(output), "--reports-dir", str(reports)]
            )
            with output.open("r", encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            examples = read_labeled_scores(output, labels)
            metrics_exit_code = metrics_main([str(output), str(labels), "--output", str(metrics_output)])
            with metrics_output.open("r", encoding="utf-8", newline="") as handle:
                metric_rows = list(csv.DictReader(handle))

            self.assertEqual(exit_code, 0)
            self.assertEqual(metrics_exit_code, 0)
            self.assertEqual(row["status"], "ok")
            self.assertEqual(row["label"], "1")
            self.assertGreater(int(row["score"]), 0)
            self.assertGreater(int(row["findings_count"]), 0)
            self.assertGreater(int(row["probe_plan_count"]), 0)
            self.assertEqual(len(examples), 1)
            self.assertEqual(
                [row["threshold"] for row in metric_rows if row["scope"] == "all"],
                ["50", "70", "90"],
            )

    def test_corpus_discovery_excludes_build_artifacts_and_duplicate_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp)
            original = corpus / "benign" / "control.ipa"
            duplicate = corpus / "synthetic" / "duplicate.ipa"
            built = corpus / "sources" / "project" / "build" / "control.ipa"
            original.parent.mkdir()
            duplicate.parent.mkdir()
            built.parent.mkdir(parents=True)
            original.write_bytes(b"same IPA bytes")
            duplicate.write_bytes(original.read_bytes())
            built.write_bytes(b"separate generated build output")

            self.assertEqual(discover_ipas(corpus), [original])
            self.assertEqual(discover_ipas(corpus, include_build_artifacts=True), [original, built])

    def test_verify_corpus_checks_label_and_real_build_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            benign = corpus / "benign"
            synthetic = corpus / "synthetic"
            benign.mkdir(parents=True)
            synthetic.mkdir()
            control = benign / "control.ipa"
            injected = synthetic / "variant.ipa"
            control.write_bytes(b"benign bytes")
            injected.write_bytes(b"synthetic bytes")
            control_sha = sha256_file(control)
            injected_sha = sha256_file(injected)
            labels = corpus / "labels.csv"
            upsert_label_rows(
                labels,
                [
                    {
                        "app_id": "control",
                        "relative_path": "benign/control.ipa",
                        "ipa_file": "control.ipa",
                        "sha256": control_sha,
                        "label": "negative",
                        "benchmark_role": "non-injected open-source control",
                        "status": "ready",
                    },
                    {
                        "app_id": "variant",
                        "relative_path": "synthetic/variant.ipa",
                        "ipa_file": "variant.ipa",
                        "sha256": injected_sha,
                        "label": "positive",
                        "benchmark_role": "controlled injected positive",
                        "status": "ready",
                    },
                ],
            )
            build_md = corpus / "BUILD.md"
            build_md.write_text(f"Control SHA-256 `{control_sha}`.\n", encoding="utf-8")

            self.assertEqual(
                verify_corpus_main(["--corpus-dir", str(corpus), "--labels", str(labels), "--build-md", str(build_md)]),
                0,
            )
            control.write_bytes(b"changed bytes")
            self.assertEqual(
                verify_corpus_main(["--corpus-dir", str(corpus), "--labels", str(labels), "--build-md", str(build_md)]),
                1,
            )

    def test_run_all_writes_paper_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            benign = corpus / "benign"
            benign.mkdir(parents=True)
            base = benign / "base.ipa"
            write_test_ipa(base)
            labels = corpus / "labels.csv"
            upsert_label_rows(
                labels,
                [
                    {
                        "app_id": "base",
                        "relative_path": "benign/base.ipa",
                        "ipa_file": "base.ipa",
                        "sha256": "",
                        "label": "negative",
                        "benchmark_role": "test control",
                        "source": "generated test fixture",
                        "status": "ready",
                    }
                ],
            )
            synthetic_builder_main(
                [
                    str(base),
                    "--all",
                    "--output-dir",
                    str(corpus / "synthetic"),
                    "--update-labels",
                    str(labels),
                ]
            )
            results = root / "results.csv"
            metrics = root / "metrics.csv"
            threshold_curve = root / "threshold_curve.csv"
            category_delta = root / "category_delta.csv"
            table = root / "RESULTS.md"
            paper_json = root / "paper_numbers.json"
            status = run_all_main(
                [
                    "--corpus-dir",
                    str(corpus),
                    "--labels",
                    str(labels),
                    "--results",
                    str(results),
                    "--metrics",
                    str(metrics),
                    "--threshold-curve",
                    str(threshold_curve),
                    "--category-delta",
                    str(category_delta),
                    "--reports-dir",
                    str(root / "reports"),
                    "--paper-table",
                    str(table),
                    "--paper-json",
                    str(paper_json),
                    "--paper-numbers-md",
                    str(root / "paper_numbers.md"),
                    "--vt-results",
                    str(root / "missing-vt.csv"),
                    "--dynamic-report",
                    str(root / "missing-dynamic-report"),
                    "--runtime-bindings",
                    str(root / "missing-runtime-bindings.json"),
                ]
            )
            numbers = json.loads(paper_json.read_text(encoding="utf-8"))

            self.assertEqual(status, 0)
            self.assertEqual(numbers["corpus_total"], 2)
            self.assertEqual(numbers["corpus_benign"], 1)
            self.assertEqual(numbers["corpus_malicious"], 1)
            self.assertIn("Held-Out Detection Performance", table.read_text(encoding="utf-8"))
            self.assertIn("Table 4 - Findings by Category", table.read_text(encoding="utf-8"))
            self.assertTrue(numbers["top_finding_category"])
            self.assertEqual(len(numbers["threshold_curve"]), 18)
            self.assertTrue(threshold_curve.exists())
            self.assertTrue(numbers["category_stats"])
            self.assertTrue(category_delta.exists())

    def test_companion_dynamic_numbers_preserve_live_runtime_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            bindings = root / "bindings.json"
            report.write_text(
                json.dumps(
                    {
                        "strings": {"urls": ["https://joinmastodon.org/ios/privacy"]},
                        "dynamic": {
                            "status": "captured (companion build)",
                            "capture_mode": "companion_build",
                            "events": [
                                {"layer": "process", "operation": "instrumentation attached", "value": "started"},
                                {
                                    "layer": "network",
                                    "operation": "NSURLSession dataTaskWithRequest",
                                    "value": "https://api.joinmastodon.org/default-servers",
                                },
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            bindings.write_text(
                json.dumps({"org.joinmastodon.app": {"environment": "simulator", "device_name": "iPhone 17 Pro"}}),
                encoding="utf-8",
            )

            numbers = _dynamic_numbers(report, bindings)

            self.assertEqual(numbers["dynamic_status"], "captured_companion_build")
            self.assertEqual(numbers["dynamic_events_captured"], 2)
            self.assertEqual(numbers["dynamic_network_calls"], 1)
            self.assertEqual(numbers["dynamic_endpoint_correlation"], "DOMAIN_MATCH")
            self.assertEqual(numbers["simulator_target"], "iPhone 17 Pro Simulator")


if __name__ == "__main__":
    unittest.main()
