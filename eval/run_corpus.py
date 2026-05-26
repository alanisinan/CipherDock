#!/usr/bin/env python3
"""Run the static CLI over a labeled corpus and emit normalized CSV rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from .common import LabelIndex, load_labels, sample_candidates
except ImportError:
    from common import LabelIndex, load_labels, sample_candidates

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SEVERITIES = ("critical", "high", "medium", "low", "info")
GENERATED_DIRECTORY_NAMES = {"build", "sources", "DerivedData", ".git"}
RESULT_FIELDS = (
    "ipa_file",
    "ipa_relative_path",
    "sha256",
    "label",
    "matched_label_key",
    "benchmark_role",
    "variant_type",
    "app_name",
    "bundle_identifier",
    "score",
    "findings_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "info_count",
    "probe_plan_count",
    "category_counts_json",
    "report_json",
    "status",
    "error",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the iRE-Zero static CLI over a labeled IPA corpus and emit evaluation results."
    )
    parser.add_argument("ipa_folder", type=Path, help="Folder containing IPA files, searched recursively")
    parser.add_argument("labels_csv", type=Path, help="CSV file with a sample identifier and binary label")
    parser.add_argument("--output", type=Path, default=Path("eval/results.csv"), help="Results CSV path")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("eval/reports"),
        help="Directory for per-app CLI report artifacts",
    )
    parser.add_argument("--rules", type=Path, help="Optional iRE-Zero JSON string-rule file")
    parser.add_argument("--ghidra-headless", type=Path, help="Optional path to Ghidra analyzeHeadless")
    parser.add_argument("--sarif", action="store_true", help="Ask the CLI to produce SARIF alongside reports")
    parser.add_argument("--html", action="store_true", help="Ask the CLI to produce HTML alongside reports")
    parser.add_argument(
        "--allow-unlabeled",
        action="store_true",
        help="Complete successfully when analyzed IPA files have no labels; those rows are excluded by metrics.",
    )
    parser.add_argument("--fail-fast", action="store_true", help="Stop after the first analyzer failure")
    parser.add_argument(
        "--reuse-reports",
        action="store_true",
        help="Reuse an existing report for the same SHA-specific report directory when available.",
    )
    parser.add_argument(
        "--include-build-artifacts",
        action="store_true",
        help="Include IPAs stored below source/build directories; exact SHA-256 duplicates remain excluded.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    folder = args.ipa_folder.resolve()
    if not folder.is_dir():
        print(f"IPA folder does not exist: {folder}", file=sys.stderr)
        return 2
    try:
        labels = load_labels(args.labels_csv.resolve())
    except (OSError, ValueError) as exc:
        print(f"Unable to read labels: {exc}", file=sys.stderr)
        return 2
    ipas = discover_ipas(folder, args.include_build_artifacts)
    if not ipas:
        print(f"No IPA files found: {folder}", file=sys.stderr)
        return 2

    output = args.output.resolve()
    reports_dir = args.reports_dir.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, str]] = []
    failures = 0
    unlabeled = 0
    for index, ipa in enumerate(ipas, start=1):
        print(f"[analyze {index}/{len(ipas)}] {ipa.relative_to(folder).as_posix()}", flush=True)
        row = analyze_sample(ipa, folder, labels, reports_dir, args)
        rows.append(row)
        if row["status"] == "ok":
            print(
                f"[scored {index}/{len(ipas)}] score={row['score']} findings={row['findings_count']} "
                f"probes={row['probe_plan_count']}",
                flush=True,
            )
        else:
            print(f"[failed {index}/{len(ipas)}] {row['error']}", file=sys.stderr, flush=True)
        if row["status"] != "ok":
            failures += 1
            if args.fail_fast:
                break
        if row["label"] == "":
            unlabeled += 1
    write_results(output, rows)
    print(f"[results] {output} ({len(rows)} app(s), {failures} analysis failure(s), {unlabeled} unlabeled)")
    if failures or (unlabeled and not args.allow_unlabeled):
        return 1
    return 0


def discover_ipas(folder: Path, include_build_artifacts: bool = False) -> List[Path]:
    candidates = sorted(path for path in folder.rglob("*.ipa") if path.is_file())
    unique: List[Path] = []
    seen_sha256: Dict[str, Path] = {}
    for path in candidates:
        parts = set(path.relative_to(folder).parts[:-1])
        if not include_build_artifacts and parts.intersection(GENERATED_DIRECTORY_NAMES):
            continue
        digest = sha256_file(path)
        if digest in seen_sha256:
            print(
                f"[skip duplicate] {path.relative_to(folder).as_posix()} has the same SHA-256 as "
                f"{seen_sha256[digest].relative_to(folder).as_posix()}",
                flush=True,
            )
            continue
        seen_sha256[digest] = path
        unique.append(path)
    return unique


def analyze_sample(
    ipa: Path,
    folder: Path,
    labels: LabelIndex,
    reports_dir: Path,
    args: argparse.Namespace,
) -> Dict[str, str]:
    relative = ipa.relative_to(folder).as_posix()
    digest = sha256_file(ipa)
    match = labels.match(
        sample_candidates(sha256=digest, relative_path=relative, filename=ipa.name)
    )
    row = empty_row(ipa, relative, digest, match.label if match else None, match.key if match else "")
    job_dir = reports_dir / f"{safe_name(ipa.stem)}-{digest[:12]}"
    before = set(job_dir.rglob("report.json")) if job_dir.exists() else set()
    if args.reuse_reports and before:
        try:
            existing = max(before, key=lambda path: path.stat().st_mtime)
            report = json.loads(existing.read_text(encoding="utf-8"))
            populate_report_fields(row, report, existing)
            if match is None:
                match = labels.match(
                    sample_candidates(
                        sha256=digest,
                        relative_path=relative,
                        filename=ipa.name,
                        bundle_identifier=row["bundle_identifier"],
                    )
                )
                if match is not None:
                    row["label"] = str(match.label)
                    row["matched_label_key"] = match.key
            assign_evaluation_role(row)
            return row
        except (OSError, ValueError, TypeError):
            pass
    command = [sys.executable, "-m", "ire_zero", str(ipa), "-o", str(job_dir)]
    for option in ("rules", "ghidra_headless"):
        path = getattr(args, option)
        if path:
            command.extend(["--" + option.replace("_", "-"), str(path.resolve())])
    if args.sarif:
        command.append("--sarif")
    if args.html:
        command.append("--html")
    completed = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    report_paths = sorted(set(job_dir.rglob("report.json")) - before, key=lambda path: path.stat().st_mtime)
    if completed.returncode != 0 or not report_paths:
        row["status"] = "error"
        row["error"] = _failure_message(completed, report_paths)
        assign_evaluation_role(row)
        return row
    try:
        report = json.loads(report_paths[-1].read_text(encoding="utf-8"))
        populate_report_fields(row, report, report_paths[-1])
        if match is None:
            match = labels.match(
                sample_candidates(
                    sha256=digest,
                    relative_path=relative,
                    filename=ipa.name,
                    bundle_identifier=row["bundle_identifier"],
                )
            )
            if match is not None:
                row["label"] = str(match.label)
                row["matched_label_key"] = match.key
    except (OSError, ValueError, TypeError) as exc:
        row["status"] = "error"
        row["error"] = f"Could not parse report JSON: {exc}"
    assign_evaluation_role(row)
    return row


def populate_report_fields(row: Dict[str, str], report: Dict[str, Any], report_path: Path) -> None:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("findings is not a list")
    severity_counts = {
        severity: sum(
            1 for finding in findings
            if isinstance(finding, dict) and str(finding.get("severity", "")).lower() == severity
        )
        for severity in SEVERITIES
    }
    category_counts: Dict[str, int] = {}
    for finding in findings:
        if isinstance(finding, dict):
            category = str(finding.get("category", "unknown")).strip() or "unknown"
            category_counts[category] = category_counts.get(category, 0) + 1
    dynamic = report.get("dynamic", {})
    probes = dynamic.get("probes", []) if isinstance(dynamic, dict) else []
    plist = report.get("info_plist", {})
    row.update(
        {
            "app_name": str(report.get("app_name", "")),
            "bundle_identifier": str(plist.get("bundle_identifier", "")) if isinstance(plist, dict) else "",
            "score": str(int(report.get("score", 0))),
            "findings_count": str(len(findings)),
            "probe_plan_count": str(len(probes) if isinstance(probes, list) else 0),
            "category_counts_json": json.dumps(category_counts, sort_keys=True, separators=(",", ":")),
            "report_json": str(report_path),
            "status": "ok",
            "error": "",
        }
    )
    for severity, count in severity_counts.items():
        row[f"{severity}_count"] = str(count)


def empty_row(
    ipa: Path,
    relative: str,
    digest: str,
    label: Optional[int],
    matched_label_key: str,
) -> Dict[str, str]:
    row = {field: "" for field in RESULT_FIELDS}
    row.update(
        {
            "ipa_file": ipa.name,
            "ipa_relative_path": relative,
            "sha256": digest,
            "label": "" if label is None else str(label),
            "matched_label_key": matched_label_key,
            "status": "pending",
        }
    )
    return row


def write_results(output: Path, rows: List[Dict[str, str]]) -> None:
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def assign_evaluation_role(row: Dict[str, str]) -> None:
    if row["label"] == "1":
        row["benchmark_role"] = "controlled injected positive"
        row["variant_type"] = "subtle" if "__irez.subtle" in row["ipa_file"] else "obvious"
    elif row["label"] == "0":
        row["benchmark_role"] = "non-injected open-source control"
        row["variant_type"] = "real_benign"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_." else "_" for character in value) or "app"


def _failure_message(completed: subprocess.CompletedProcess[str], report_paths: List[Path]) -> str:
    output = (completed.stderr or completed.stdout).strip().replace("\n", " ")
    if completed.returncode != 0:
        return f"CLI exited {completed.returncode}: {output[:400]}"
    return "CLI completed without generating report.json" if not report_paths else output[:400]


if __name__ == "__main__":
    raise SystemExit(main())
