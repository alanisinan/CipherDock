#!/usr/bin/env python3
"""Extract reproducible paper statistics from evaluation and runtime artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export the single source of truth for iRE-Zero paper statistics.")
    parser.add_argument("results_csv", type=Path, nargs="?", default=Path("eval/results.csv"))
    parser.add_argument("metrics_csv", type=Path, nargs="?", default=Path("eval/metrics.csv"))
    parser.add_argument("--vt-results", type=Path, default=Path("eval/vt_results.csv"))
    parser.add_argument("--labels", type=Path, default=Path("eval/corpus/labels.csv"))
    parser.add_argument("--dynamic-report", type=Path, default=Path("workbench-data/reports"))
    parser.add_argument("--runtime-bindings", type=Path, default=Path("workbench-data/runtime-target-bindings.json"))
    parser.add_argument("--threshold-curve", type=Path, default=Path("eval/threshold_curve.csv"))
    parser.add_argument("--category-delta", type=Path, default=Path("eval/category_delta.csv"))
    parser.add_argument("--json-output", type=Path, default=Path("eval/paper_numbers.json"))
    parser.add_argument("--markdown-output", type=Path, default=Path("eval/paper_numbers.md"))
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results = read_results(args.results_csv.resolve())
        metrics = read_csv(args.metrics_csv.resolve())
        numbers = compute_paper_numbers(
            results,
            metrics,
            args.vt_results.resolve(),
            args.labels.resolve(),
            args.dynamic_report.resolve(),
            args.runtime_bindings.resolve(),
            args.threshold_curve.resolve(),
            args.category_delta.resolve(),
        )
    except (OSError, ValueError) as exc:
        print(f"Unable to extract paper numbers: {exc}", file=sys.stderr)
        return 2
    json_output = args.json_output.resolve()
    markdown_output = args.markdown_output.resolve()
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(numbers, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_output.write_text(render_markdown(numbers), encoding="utf-8")
    print(json.dumps(numbers, indent=2, sort_keys=True))
    print(f"[paper] {json_output}")
    print(f"[paper] {markdown_output}")
    return 0


def read_results(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for row in read_csv(path):
        if row.get("status", "").lower() != "ok" or row.get("label", "") not in {"0", "1"}:
            continue
        try:
            counts = json.loads(row.get("category_counts_json", "{}") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid category_counts_json for {row.get('ipa_file', 'sample')}") from exc
        rows.append(
            {
                **row,
                "label": int(row["label"]),
                "score": int(row["score"]),
                "findings_count": int(row["findings_count"]),
                "category_counts": counts if isinstance(counts, dict) else {},
            }
        )
    if not rows:
        raise ValueError("No successful labeled results found")
    return rows


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def compute_paper_numbers(
    results: List[Dict[str, Any]],
    metrics: List[Dict[str, str]],
    vt_results_path: Path,
    labels_path: Optional[Path] = None,
    dynamic_report_path: Optional[Path] = None,
    runtime_bindings_path: Optional[Path] = None,
    threshold_curve_path: Optional[Path] = None,
    category_delta_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if not metrics:
        raise ValueError("metrics.csv contains no thresholds")
    all_metrics = [row for row in metrics if row.get("scope", "all") == "all"]
    selected = [row for row in all_metrics if row.get("selected_from_calibration") == "true"]
    best = selected[0] if selected else max(all_metrics, key=lambda row: (float(row["f1"]), -int(row["threshold"])))
    benign = [row for row in results if row["label"] == 0]
    malicious = [row for row in results if row["label"] == 1]
    categories = category_averages(results)
    malicious_totals = {
        row["category"]: float(row["malicious_total"])
        for row in categories
    }
    top_category = max(malicious_totals, key=malicious_totals.get) if malicious_totals else None
    vt_missed = vt_missed_caught(results, int(best["threshold"]), vt_results_path)
    subtle = _scope_metric(metrics, "subtle", int(best["threshold"]))
    obvious = _scope_metric(metrics, "obvious", int(best["threshold"]))
    margin = float(best.get("f1_ci_margin", "0") or 0)
    low = float(best.get("f1_ci_low", best["f1"]))
    high = float(best.get("f1_ci_high", best["f1"]))
    numbers = {
        "eval_note": "Controlled synthetic evaluation. Official open-source builds pending.",
        "corpus_total": len(results),
        "corpus_benign": len(benign),
        "corpus_benign_real": len(benign),
        "corpus_benign_pending": _pending_benign_count(labels_path),
        "corpus_malicious": len(malicious),
        "best_f1": round(float(best["f1"]), 4),
        "best_threshold": int(best["threshold"]),
        "precision_at_best": round(float(best["precision"]), 4),
        "recall_at_best": round(float(best["recall"]), 4),
        "f1_confidence_interval": f"{float(best['f1']):.2f} +/- {margin:.2f} (95% CI [{low:.2f}, {high:.2f}])",
        "subtle_variant_f1": None if subtle is None else round(float(subtle["f1"]), 4),
        "obvious_variant_f1": None if obvious is None else round(float(obvious["f1"]), 4),
        "avg_score_benign": _mean([row["score"] for row in benign]),
        "avg_score_malicious": _mean([row["score"] for row in malicious]),
        "score_delta": round(_mean([row["score"] for row in malicious]) - _mean([row["score"] for row in benign]), 2),
        "findings_per_malicious_avg": _mean([row["findings_count"] for row in malicious]),
        "findings_per_benign_avg": _mean([row["findings_count"] for row in benign]),
        "top_finding_category": top_category,
        "vt_missed_caught_by_cipherdock": vt_missed,
        "vt_available": vt_missed is not None,
    }
    numbers.update(_dynamic_numbers(dynamic_report_path, runtime_bindings_path))
    numbers["threshold_curve"] = _threshold_curve(threshold_curve_path)
    numbers["category_stats"] = _category_stats(category_delta_path)
    return numbers


def _scope_metric(metrics: List[Dict[str, str]], scope: str, threshold: int) -> Optional[Dict[str, str]]:
    return next(
        (row for row in metrics if row.get("scope") == scope and int(row["threshold"]) == threshold),
        None,
    )


def _threshold_curve(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None or not path.exists():
        return []
    curve: List[Dict[str, Any]] = []
    for row in read_csv(path):
        curve.append(
            {
                "threshold": int(row["threshold"]),
                "precision": float(row["precision"]),
                "recall": float(row["recall"]),
                "f1": float(row["f1"]),
                "evaluated_apps": int(row["evaluated_apps"]),
            }
        )
    return curve


def _category_stats(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None or not path.exists():
        return []
    statistics_rows: List[Dict[str, Any]] = []
    for row in read_csv(path):
        statistics_rows.append(
            {
                "category": row["category"],
                "benign_avg": float(row["benign_avg"]),
                "malicious_avg": float(row["malicious_avg"]),
                "delta": float(row["delta"]),
                "u_statistic": float(row["u_statistic"]),
                "p_value": float(row["p_value"]),
                "method": row["method"],
            }
        )
    return statistics_rows


def _pending_benign_count(labels_path: Optional[Path]) -> int:
    if labels_path is None or not labels_path.exists():
        return 0
    return sum(
        1
        for row in read_csv(labels_path)
        if row.get("label") in {"negative", "0"} and row.get("status") != "ready"
    )


def category_averages(results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    benign = [row for row in results if row["label"] == 0]
    malicious = [row for row in results if row["label"] == 1]
    categories = sorted(
        {
            category
            for row in results
            for category in row.get("category_counts", {})
        }
    )
    output: List[Dict[str, str]] = []
    for category in categories:
        benign_avg = _mean([int(row["category_counts"].get(category, 0)) for row in benign])
        malicious_avg = _mean([int(row["category_counts"].get(category, 0)) for row in malicious])
        malicious_total = sum(int(row["category_counts"].get(category, 0)) for row in malicious)
        output.append(
            {
                "category": category,
                "benign_avg": f"{benign_avg:.2f}",
                "malicious_avg": f"{malicious_avg:.2f}",
                "delta": f"{malicious_avg - benign_avg:.2f}",
                "malicious_total": str(malicious_total),
            }
        )
    return sorted(output, key=lambda row: (-float(row["delta"]), row["category"]))


def vt_missed_caught(results: List[Dict[str, Any]], threshold: int, path: Path) -> Optional[int]:
    if not path.exists():
        return None
    vt_rows = {
        row.get("sha256", ""): row
        for row in read_csv(path)
        if row.get("vt_status") == "found" and row.get("vt_detections", "").isdigit()
    }
    if not vt_rows:
        return None
    return sum(
        1
        for row in results
        if row["label"] == 1
        and row["score"] >= threshold
        and row.get("sha256") in vt_rows
        and int(vt_rows[row["sha256"]]["vt_detections"]) == 0
    )


def _dynamic_numbers(report_path: Optional[Path], bindings_path: Optional[Path]) -> Dict[str, Any]:
    report = _captured_dynamic_report(report_path)
    if report is None:
        return {
            "dynamic_status": "not_captured",
            "dynamic_events_captured": 0,
            "dynamic_network_calls": 0,
            "capture_mode": "not_captured",
        }
    dynamic = report.get("dynamic", {})
    events = dynamic.get("events", []) if isinstance(dynamic, dict) else []
    network = [event for event in events if isinstance(event, dict) and event.get("layer") == "network"]
    inferred_mode = "companion_build" if "Simulator" in str(dynamic.get("source", "")) else "exact_ipa"
    mode = str(dynamic.get("capture_mode") or inferred_mode)
    values: Dict[str, Any] = {
        "dynamic_status": "captured_companion_build" if mode == "companion_build" else "captured_exact_ipa",
        "dynamic_events_captured": len(events),
        "dynamic_network_calls": len(network),
        "capture_mode": "Xcode Simulator / Frida" if mode == "companion_build" else "Authorized device / Frida",
    }
    if network:
        endpoint = str(network[0].get("value", ""))
        values["dynamic_endpoint_captured"] = endpoint
        values["dynamic_endpoint_correlation"] = str(
            network[0].get("correlation_status") or _endpoint_correlation(endpoint, report)
        )
    if mode == "companion_build":
        values["companion_build_note"] = (
            "Events reflect real app runtime behavior; IPA SHA mismatch from Simulator recompilation"
        )
        simulator_target = _simulator_target(bindings_path)
        if simulator_target:
            values["simulator_target"] = simulator_target
    return values


def _captured_dynamic_report(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None or not path.exists():
        return None
    candidates = [path] if path.is_file() else list(path.glob("*/report.json"))
    captured: List[tuple[float, Dict[str, Any]]] = []
    for candidate in candidates:
        try:
            report = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        events = report.get("dynamic", {}).get("events", [])
        if isinstance(events, list) and events:
            captured.append((candidate.stat().st_mtime, report))
    return max(captured, key=lambda item: item[0])[1] if captured else None


def _endpoint_correlation(endpoint: str, report: Dict[str, Any]) -> str:
    observed = endpoint.rstrip("/")
    urls = report.get("strings", {}).get("urls", [])
    if isinstance(urls, list) and any(str(url).rstrip("/") == observed for url in urls):
        return "CONFIRMED"
    observed_host = (urlparse(endpoint).hostname or "").lower()
    if isinstance(urls, list) and observed_host:
        observed_domain = ".".join(observed_host.split(".")[-2:])
        if any(
            ".".join((urlparse(str(url)).hostname or "").lower().split(".")[-2:]) == observed_domain
            for url in urls
        ):
            return "DOMAIN_MATCH"
    return "DYNAMIC_ONLY"


def _simulator_target(path: Optional[Path]) -> Optional[str]:
    if path is None or not path.exists():
        return None
    try:
        bindings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for binding in bindings.values() if isinstance(bindings, dict) else []:
        if isinstance(binding, dict) and binding.get("environment") == "simulator":
            name = str(binding.get("device_name", "")).strip()
            return f"{name} Simulator" if name else None
    return None


def render_markdown(numbers: Dict[str, Any]) -> str:
    lines = ["# Paper Numbers", "", "Generated from `results.csv` and `metrics.csv`. Do not transcribe statistics from ad hoc runs.", ""]
    for key, value in numbers.items():
        lines.append(f"- `{key}`: `{value}`")
    lines.append("")
    return "\n".join(lines)


def _mean(values: List[int]) -> float:
    return round(statistics.mean(values), 2) if values else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
