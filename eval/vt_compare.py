#!/usr/bin/env python3
"""Compare CipherDock corpus scores with VirusTotal hash lookups."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Sequence

FIELDS = (
    "ipa_file",
    "sha256",
    "label",
    "cipherdock_score",
    "cipherdock_findings",
    "vt_detections",
    "vt_undetected",
    "vt_status",
    "error",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare iRE-Zero results to VirusTotal using SHA-256 lookups only; no IPA files are uploaded."
    )
    parser.add_argument("results_csv", type=Path, nargs="?", default=Path("eval/results.csv"))
    parser.add_argument("--output", type=Path, default=Path("eval/vt_results.csv"))
    parser.add_argument("--delay", type=float, default=15.5, help="Delay between API requests for public API quotas")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        print("VT_API_KEY is not set; skipping VirusTotal hash comparison.")
        return 0
    try:
        rows = read_results(args.results_csv.resolve())
    except OSError as exc:
        print(f"Unable to read results: {exc}", file=sys.stderr)
        return 2
    output_rows: List[Dict[str, str]] = []
    for index, row in enumerate(rows):
        if index and args.delay:
            time.sleep(args.delay)
        output_rows.append(lookup_hash(row, api_key))
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(output_rows)
    print(f"[virustotal] {output} ({len(output_rows)} SHA-256 lookup(s); no files uploaded)")
    return 0


def read_results(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [
            dict(row)
            for row in csv.DictReader(handle)
            if row.get("status", "").lower() == "ok" and row.get("sha256")
        ]


def lookup_hash(row: Dict[str, str], api_key: str) -> Dict[str, str]:
    output = {
        "ipa_file": row.get("ipa_file", ""),
        "sha256": row.get("sha256", ""),
        "label": row.get("label", ""),
        "cipherdock_score": row.get("score", ""),
        "cipherdock_findings": row.get("findings_count", ""),
        "vt_detections": "",
        "vt_undetected": "",
        "vt_status": "error",
        "error": "",
    }
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{output['sha256']}",
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        output["vt_detections"] = str(int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)))
        output["vt_undetected"] = str(int(stats.get("undetected", 0)) + int(stats.get("harmless", 0)))
        output["vt_status"] = "found"
    except urllib.error.HTTPError as exc:
        output["vt_status"] = "not_found" if exc.code == 404 else "error"
        output["error"] = f"HTTP {exc.code}"
    except (KeyError, TypeError, ValueError, OSError) as exc:
        output["error"] = str(exc)
    return output


if __name__ == "__main__":
    raise SystemExit(main())
