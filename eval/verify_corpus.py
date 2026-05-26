#!/usr/bin/env python3
"""Verify evaluated IPA hashes against the corpus manifest and build provenance log."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

try:
    from .common import read_label_rows
    from .run_corpus import discover_ipas, sha256_file
except ImportError:
    from common import read_label_rows
    from run_corpus import discover_ipas, sha256_file

SHA_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify analyzed corpus IPA hashes and documented provenance.")
    parser.add_argument("--corpus-dir", type=Path, default=Path("eval/corpus"))
    parser.add_argument("--labels", type=Path, default=Path("eval/corpus/labels.csv"))
    parser.add_argument("--build-md", type=Path, default=Path("eval/corpus/BUILD.md"))
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rows = verify_corpus(args.corpus_dir.resolve(), args.labels.resolve(), args.build_md.resolve())
    except OSError as exc:
        print(f"Unable to verify corpus: {exc}", file=sys.stderr)
        return 2
    print_table(rows)
    failures = [row for row in rows if row["status"] != "PASS"]
    print(f"\nCorpus verification: {'PASS' if not failures else 'FAIL'} ({len(rows) - len(failures)}/{len(rows)} IPA hashes valid)")
    return 1 if failures else 0


def verify_corpus(corpus_dir: Path, labels_path: Path, build_md_path: Path) -> List[Dict[str, str]]:
    """Return SHA verification rows for all evaluation IPAs outside source build trees."""
    label_rows = {
        str(row.get("relative_path", "")).replace("\\", "/"): row
        for row in read_label_rows(labels_path)
        if str(row.get("relative_path", "")).strip()
    }
    documented_hashes = {
        digest.lower()
        for digest in SHA_PATTERN.findall(build_md_path.read_text(encoding="utf-8"))
    }
    results: List[Dict[str, str]] = []
    for ipa in discover_ipas(corpus_dir):
        relative = ipa.relative_to(corpus_dir).as_posix()
        label_row = label_rows.get(relative)
        actual = sha256_file(ipa)
        expected = str((label_row or {}).get("sha256", "")).lower()
        label_status = "PASS" if expected and expected == actual else "FAIL"
        role = str((label_row or {}).get("benchmark_role", ""))
        if role == "non-injected open-source control":
            build_status = "PASS" if actual in documented_hashes else "FAIL"
        else:
            build_status = "N/A synthetic"
        status = "PASS" if label_status == "PASS" and build_status != "FAIL" else "FAIL"
        results.append(
            {
                "ipa": relative,
                "sha256": actual,
                "labels.csv": label_status,
                "BUILD.md": build_status,
                "status": status,
            }
        )
    return results


def print_table(rows: List[Dict[str, str]]) -> None:
    """Print a compact, review-friendly verification table."""
    headers = ("IPA", "SHA-256", "labels.csv", "BUILD.md", "Status")
    values = [
        (row["ipa"], row["sha256"][:12] + "...", row["labels.csv"], row["BUILD.md"], row["status"])
        for row in rows
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in values))
        for index in range(len(headers))
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in values:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


if __name__ == "__main__":
    raise SystemExit(main())
