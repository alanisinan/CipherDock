"""End-to-end static pipeline and report artifact tests."""

import plistlib
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path

from ire_zero.analyzer import analyze_ipa
from ire_zero.reporting import render_pdf, write_reports
from ire_zero.rules import load_rules


class PipelineTests(unittest.TestCase):
    def test_analyze_synthetic_ipa_and_write_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ipa = _make_synthetic_ipa(root)

            result = analyze_ipa(ipa, load_rules(None))
            report_dir = root / "reports"
            write_reports(result, report_dir, sarif=True, html_report=True, pdf_report=True)

            finding_ids = {finding.id for finding in result.findings}
            self.assertEqual(result.info_plist.bundle_identifier, "com.example.pipeline")
            self.assertIn("ats.arbitrary_loads", finding_ids)
            self.assertIn("strings.hardcoded_secret", finding_ids)
            self.assertIn("strings.jailbreak_detection", finding_ids)
            self.assertGreater(result.score, 0)
            self.assertEqual(result.dynamic.status, "not_captured")
            self.assertTrue(result.dynamic.probes)
            self.assertTrue(result.dynamic.campaigns)
            self.assertEqual(result.dynamic.campaign_coverage["observed"], 0)
            self.assertTrue(any(probe.layer == "network" for probe in result.dynamic.probes))
            self.assertTrue(result.binary.evidence)
            self.assertTrue(result.ai_notes)
            self.assertTrue((report_dir / "report.json").exists())
            self.assertTrue((report_dir / "report.md").exists())
            self.assertTrue((report_dir / "report.sarif").exists())
            self.assertTrue((report_dir / "report.html").exists())
            self.assertTrue((report_dir / "report.pdf").exists())
            self.assertTrue((report_dir / "runtime-plan.md").exists())
            self.assertTrue((report_dir / "frida-hooks.js").exists())
            self.assertTrue((report_dir / "report.pdf").read_bytes().startswith(b"%PDF-1.4"))
            hooks = (report_dir / "frida-hooks.js").read_text(encoding="utf-8")
            plan = (report_dir / "runtime-plan.md").read_text(encoding="utf-8")
            self.assertIn("SecTrustEvaluateWithError", hooks)
            self.assertIn("Assessment Campaigns", plan)

    def test_render_pdf_produces_downloadable_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ipa = _make_synthetic_ipa(root)
            result = analyze_ipa(ipa, load_rules(None))

            pdf = render_pdf(result)

        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"trailer", pdf)


def _make_synthetic_ipa(root: Path) -> Path:
    app = root / "Payload" / "Pipeline.app"
    app.mkdir(parents=True)
    with (app / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.example.pipeline",
                "CFBundleName": "Pipeline",
                "CFBundleExecutable": "Pipeline",
                "CFBundleURLTypes": [
                    {"CFBundleURLName": "pipeline", "GeneratedAt": datetime(2026, 1, 1), "OpaqueData": b"\x01\x02"}
                ],
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            },
            handle,
        )
    executable = app / "Pipeline"
    executable.write_bytes(
        b"placeholder\n"
        b"http://insecure.example.test\n"
        b"client_secret=abc12345\n"
        b"/Applications/Cydia.app\n"
        b"LSApplicationWorkspace\n"
    )
    ipa = root / "Pipeline.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        for path in (root / "Payload").rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(root))
    return ipa


if __name__ == "__main__":
    unittest.main()
