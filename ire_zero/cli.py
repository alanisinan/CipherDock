"""Command-line interface for single-IPA and batch iRE-Zero analysis."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, List

from .analyzer import analyze_ipa
from .doctor import doctor_exit_code, render_doctor, run_doctor
from .models import result_dir_name
from .reporting import write_index_report, write_reports
from .rules import load_rules, validate_rules_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ire-zero",
        description="Hybrid iOS IPA analyzer that writes evidence-backed security reports.",
    )
    parser.add_argument("input", type=Path, help="One .ipa file or a folder containing .ipa files")
    parser.add_argument("-o", "--output", type=Path, default=Path("ire-zero-reports"), help="Report output directory")
    parser.add_argument("--rules", type=Path, help="Optional JSON rule file for YARA-like string patterns")
    parser.add_argument("--ghidra-headless", type=Path, help="Path to Ghidra analyzeHeadless")
    parser.add_argument("--ghidra-script", type=Path, help="Optional extra Ghidra postScript to run")
    parser.add_argument("--sarif", action="store_true", help="Also write report.sarif")
    parser.add_argument("--html", action="store_true", help="Also write report.html")
    parser.add_argument("--runtime-trace", type=Path, help="Optional authorized runtime event JSON or JSONL capture for one IPA")
    parser.add_argument(
        "--runtime-capture-mode",
        choices=("exact_ipa", "companion_build"),
        default="exact_ipa",
        help="Fidelity boundary for an imported trace; use companion_build for Simulator evidence.",
    )
    parser.add_argument("--runtime-source", help="Human-readable source label for an imported runtime trace")
    parser.add_argument("--fail-fast", action="store_true", help="Stop batch mode after the first failed IPA")
    return parser


def build_doctor_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ire-zero doctor",
        description="Check local iRE-Zero analysis dependencies.",
    )
    parser.add_argument("--ghidra-headless", type=Path, help="Path to Ghidra analyzeHeadless")
    return parser


def build_rules_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ire-zero rules",
        description="Inspect or validate iRE-Zero string rule packs.",
    )
    subparsers = parser.add_subparsers(dest="rules_command", required=True)
    list_parser = subparsers.add_parser("list", help="List loaded built-in and custom rules")
    list_parser.add_argument("--rules", type=Path, help="Optional JSON rule file to include")
    validate_parser = subparsers.add_parser("validate", help="Validate a JSON rule file")
    validate_parser.add_argument("rules", type=Path, help="Rule file to validate")
    return parser


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "analyze":
        argv = argv[1:]
    if argv and argv[0] == "doctor":
        args = build_doctor_parser().parse_args(argv[1:])
        checks = run_doctor(args.ghidra_headless)
        print(render_doctor(checks))
        return doctor_exit_code(checks)
    if argv and argv[0] == "rules":
        args = build_rules_parser().parse_args(argv[1:])
        if args.rules_command == "list":
            try:
                rules = load_rules(args.rules)
            except Exception as exc:
                print(f"Failed to load rules: {exc}", file=sys.stderr)
                return 2
            for rule in rules:
                print(f"{rule.id}\t{rule.severity}\t{rule.category}\t{rule.description}")
            return 0
        if args.rules_command == "validate":
            errors = validate_rules_file(args.rules)
            if errors:
                for error in errors:
                    print(f"[error] {error}", file=sys.stderr)
                return 1
            print(f"[ok] {args.rules}")
            return 0

    args = build_parser().parse_args(argv)
    ipa_paths = list(_collect_ipa_paths(args.input))
    if not ipa_paths:
        print(f"No IPA files found: {args.input}", file=sys.stderr)
        return 2
    if args.runtime_trace is not None and len(ipa_paths) != 1:
        print("--runtime-trace may only be used when analyzing one IPA", file=sys.stderr)
        return 2

    try:
        rules = load_rules(args.rules)
    except Exception as exc:
        print(f"Failed to load rules: {exc}", file=sys.stderr)
        return 2

    failures = 0
    completed = []
    args.output.mkdir(parents=True, exist_ok=True)
    for ipa_path in ipa_paths:
        try:
            result = analyze_ipa(
                ipa_path=ipa_path,
                rules=rules,
                ghidra_headless=args.ghidra_headless,
                ghidra_script=args.ghidra_script,
                runtime_trace=args.runtime_trace,
                runtime_capture_mode=args.runtime_capture_mode,
                runtime_source=args.runtime_source,
            )
            report_dir = _unique_report_dir(args.output, result_dir_name(ipa_path, result.app_name))
            write_reports(result, report_dir, sarif=args.sarif, html_report=args.html)
            completed.append((result, report_dir))
            print(f"[ok] {ipa_path} -> {report_dir}")
        except Exception as exc:
            failures += 1
            print(f"[error] {ipa_path}: {exc}", file=sys.stderr)
            if args.fail_fast:
                return 1
    if completed:
        write_index_report(completed, args.output)
        print(f"[index] {args.output / 'index.html'}")
    return 1 if failures else 0


def _collect_ipa_paths(path: Path) -> Iterable[Path]:
    if path.is_file():
        if path.suffix.lower() == ".ipa":
            yield path
        return
    if path.is_dir():
        yield from sorted(item for item in path.rglob("*.ipa") if item.is_file())


def _unique_report_dir(output: Path, name: str) -> Path:
    candidate = output / name
    if not candidate.exists():
        return candidate
    index = 2
    while True:
        alternative = output / f"{name}-{index}"
        if not alternative.exists():
            return alternative
        index += 1
