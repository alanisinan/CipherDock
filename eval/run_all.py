#!/usr/bin/env python3
"""Orchestrate corpus scoring, held-out metrics, and paper-facing artifacts."""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from .metrics import compute_metrics, main as metrics_main, read_labeled_examples, split_examples
    from .paper_numbers import category_averages, compute_paper_numbers, read_csv, read_results
    from .run_corpus import main as run_corpus_main
    from .vt_compare import main as vt_compare_main
except ImportError:
    from metrics import compute_metrics, main as metrics_main, read_labeled_examples, split_examples
    from paper_numbers import category_averages, compute_paper_numbers, read_csv, read_results
    from run_corpus import main as run_corpus_main
    from vt_compare import main as vt_compare_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the complete iRE-Zero labeled-corpus evaluation pipeline.")
    parser.add_argument("--corpus-dir", type=Path, default=Path("eval/corpus"))
    parser.add_argument("--labels", type=Path, default=Path("eval/corpus/labels.csv"))
    parser.add_argument("--results", type=Path, default=Path("eval/results.csv"))
    parser.add_argument("--metrics", type=Path, default=Path("eval/metrics.csv"))
    parser.add_argument("--threshold-curve", type=Path, default=Path("eval/threshold_curve.csv"))
    parser.add_argument("--category-delta", type=Path, default=Path("eval/category_delta.csv"))
    parser.add_argument("--reports-dir", type=Path, default=Path("eval/reports"))
    parser.add_argument("--vt-results", type=Path, default=Path("eval/vt_results.csv"))
    parser.add_argument("--paper-table", type=Path, default=Path("eval/RESULTS.md"))
    parser.add_argument("--paper-json", type=Path, default=Path("eval/paper_numbers.json"))
    parser.add_argument("--paper-numbers-md", type=Path, default=Path("eval/paper_numbers.md"))
    parser.add_argument("--dynamic-report", type=Path, default=Path("workbench-data/reports"))
    parser.add_argument("--runtime-bindings", type=Path, default=Path("workbench-data/runtime-target-bindings.json"))
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--ghidra-headless", type=Path)
    parser.add_argument("--html", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    parser.add_argument("--vt-delay", type=float, default=15.5)
    parser.add_argument("--reuse-reports", action="store_true", help="Reuse existing SHA-specific static report artifacts")
    parser.add_argument("--split", type=float, default=0.3, help="Held-out proportion for final reported metrics")
    parser.add_argument("--seed", type=int, default=1337, help="Stable held-out split seed")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    corpus_args = [
        str(args.corpus_dir),
        str(args.labels),
        "--output",
        str(args.results),
        "--reports-dir",
        str(args.reports_dir),
    ]
    for flag in ("rules", "ghidra_headless"):
        value = getattr(args, flag)
        if value:
            corpus_args.extend(["--" + flag.replace("_", "-"), str(value)])
    if args.html:
        corpus_args.append("--html")
    if args.sarif:
        corpus_args.append("--sarif")
    if args.reuse_reports:
        corpus_args.append("--reuse-reports")
    corpus_status = run_corpus_main(corpus_args)
    if corpus_status != 0:
        return corpus_status
    metrics_status = metrics_main(
        [
            str(args.results),
            str(args.labels),
            "--output",
            str(args.metrics),
            "--split",
            str(args.split),
            "--seed",
            str(args.seed),
        ]
    )
    if metrics_status != 0:
        return metrics_status
    threshold_curve = write_threshold_curve(
        args.results.resolve(),
        args.labels.resolve(),
        args.threshold_curve.resolve(),
        args.split,
        args.seed,
    )
    if os.environ.get("VT_API_KEY", "").strip():
        vt_status = vt_compare_main([str(args.results), "--output", str(args.vt_results), "--delay", str(args.vt_delay)])
        if vt_status != 0:
            return vt_status
    try:
        results = read_results(args.results.resolve())
        metrics = read_csv(args.metrics.resolve())
        category_stats = write_category_delta(results, args.category_delta.resolve())
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
        write_numbers(numbers, args.paper_json.resolve(), args.paper_numbers_md.resolve())
        args.paper_table.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.paper_table.resolve().write_text(
            render_results_markdown(results, metrics, numbers, args.vt_results.resolve()),
            encoding="utf-8",
        )
    except (OSError, ValueError) as exc:
        print(f"Unable to render paper outputs: {exc}", file=sys.stderr)
        return 2
    print_summary(numbers, results, args.vt_results.resolve())
    print(f"[table] {args.paper_table.resolve()}")
    print(f"[paper] {args.paper_json.resolve()}")
    print(f"[curve] {args.threshold_curve.resolve()} ({len(threshold_curve)} thresholds)")
    print(f"[categories] {args.category_delta.resolve()} ({len(category_stats)} tests)")
    return 0


def write_threshold_curve(
    results_path: Path,
    labels_path: Path,
    output_path: Path,
    held_out_fraction: float,
    seed: int,
) -> List[Dict[str, str]]:
    """Write held-out sensitivity metrics at thresholds from 10 through 95."""
    examples = read_labeled_examples(results_path, labels_path)
    _, held_out = split_examples(examples, held_out_fraction, seed)
    thresholds = range(10, 100, 5)
    rows = [
        {
            "dataset": "held_out" if held_out_fraction else "all",
            **compute_metrics([(item.score, item.label) for item in held_out], threshold),
        }
        for threshold in thresholds
    ]
    fields = [
        "dataset",
        "threshold",
        "evaluated_apps",
        "true_positive",
        "false_positive",
        "true_negative",
        "false_negative",
        "precision",
        "recall",
        "f1",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def write_category_delta(results: List[Dict[str, Any]], output_path: Path) -> List[Dict[str, str]]:
    """Write category-level Mann-Whitney U comparisons for benign and malicious samples."""
    categories = sorted(
        {
            category
            for result in results
            for category in result.get("category_counts", {})
        }
    )
    benign = [result for result in results if result["label"] == 0]
    malicious = [result for result in results if result["label"] == 1]
    rows: List[Dict[str, str]] = []
    for category in categories:
        benign_counts = [int(result["category_counts"].get(category, 0)) for result in benign]
        malicious_counts = [int(result["category_counts"].get(category, 0)) for result in malicious]
        u_statistic, p_value = mann_whitney_u(benign_counts, malicious_counts)
        rows.append(
            {
                "category": category,
                "benign_n": str(len(benign_counts)),
                "malicious_n": str(len(malicious_counts)),
                "benign_avg": f"{sum(benign_counts) / len(benign_counts):.4f}" if benign_counts else "0.0000",
                "malicious_avg": f"{sum(malicious_counts) / len(malicious_counts):.4f}" if malicious_counts else "0.0000",
                "delta": (
                    f"{(sum(malicious_counts) / len(malicious_counts)) - (sum(benign_counts) / len(benign_counts)):.4f}"
                    if benign_counts and malicious_counts
                    else "0.0000"
                ),
                "u_statistic": f"{u_statistic:.4f}",
                "p_value": f"{p_value:.6f}",
                "method": "two-sided asymptotic Mann-Whitney U with tie correction",
            }
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "category",
        "benign_n",
        "malicious_n",
        "benign_avg",
        "malicious_avg",
        "delta",
        "u_statistic",
        "p_value",
        "method",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def mann_whitney_u(first: List[int], second: List[int]) -> tuple[float, float]:
    """Return the minimum U statistic and two-sided tie-corrected asymptotic p-value."""
    if not first or not second:
        return 0.0, 1.0
    combined = sorted([(value, 0) for value in first] + [(value, 1) for value in second])
    first_rank_sum = 0.0
    tie_sizes: List[int] = []
    cursor = 0
    while cursor < len(combined):
        end = cursor + 1
        while end < len(combined) and combined[end][0] == combined[cursor][0]:
            end += 1
        average_rank = ((cursor + 1) + end) / 2.0
        first_rank_sum += average_rank * sum(1 for _, group in combined[cursor:end] if group == 0)
        tie_sizes.append(end - cursor)
        cursor = end
    first_n = len(first)
    second_n = len(second)
    first_u = first_rank_sum - (first_n * (first_n + 1) / 2.0)
    second_u = first_n * second_n - first_u
    statistic = min(first_u, second_u)
    total_n = first_n + second_n
    tie_correction = sum(size ** 3 - size for size in tie_sizes)
    variance = (first_n * second_n / 12.0) * (
        (total_n + 1) - (tie_correction / (total_n * (total_n - 1)))
    )
    if variance <= 0:
        return statistic, 1.0
    mean_u = first_n * second_n / 2.0
    z_value = max(0.0, (abs(first_u - mean_u) - 0.5) / math.sqrt(variance))
    p_value = math.erfc(z_value / math.sqrt(2.0))
    return statistic, min(1.0, p_value)


def write_numbers(numbers: Dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    import json

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(numbers, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Paper Numbers", "", "Generated by `eval/run_all.py` from the labeled evaluation artifacts.", ""]
    lines.extend(f"- `{key}`: `{value}`" for key, value in numbers.items())
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_results_markdown(
    results: List[Dict[str, Any]],
    metrics: List[Dict[str, str]],
    numbers: Dict[str, Any],
    vt_path: Path,
) -> str:
    total = numbers["corpus_total"]
    category_rows = category_averages(results)
    lines = [
        "## Evaluation Results",
        "",
        "Controlled synthetic evaluation. Official open-source builds remain pending. Open-source controls are labeled benign/negative as non-injected benchmark controls; the label does not assert absence of ordinary security findings.",
        "",
        "### Table 1 - Corpus Composition",
        "",
        "| Category | Count | % |",
        "| --- | ---: | ---: |",
        f"| Real benign control analyzed | {numbers['corpus_benign_real']} | {_percent(numbers['corpus_benign_real'], total)} |",
        f"| Controlled malicious variant | {numbers['corpus_malicious']} | {_percent(numbers['corpus_malicious'], total)} |",
        f"| Total | {total} | 100.0% |",
        f"| Pending official benign builds (excluded) | {numbers['corpus_benign_pending']} | - |",
        "",
        "### Table 2 - Held-Out Detection Performance",
        "",
        "| Threshold | TP | FP | TN | FN | Precision | Recall | F1 | 95% CI |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    reported_metrics = [row for row in metrics if row.get("scope", "all") == "all"]
    lines.extend(
        f"| {row['threshold']} | {row['true_positive']} | {row['false_positive']} | {row['true_negative']} | "
        f"{row['false_negative']} | {row['precision']} | {row['recall']} | {row['f1']} | "
        f"[{row.get('f1_ci_low', row['f1'])}, {row.get('f1_ci_high', row['f1'])}] |"
        for row in reported_metrics
    )
    lines.extend(
        [
            "",
            "At the threshold selected on calibration data, obvious and subtle controlled positives are reported separately:",
            "",
            "| Variant Type | Held-Out F1 |",
            "| --- | ---: |",
            f"| Obvious | {numbers.get('obvious_variant_f1')} |",
            f"| Subtle | {numbers.get('subtle_variant_f1')} |",
        ]
    )
    lines.extend(
        [
            "",
            "### Table 3 - CipherDock vs VirusTotal",
            "",
            "| App | CipherDock Score | VT Detections | CipherDock Findings |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    vt = _vt_by_hash(vt_path)
    for row in sorted(results, key=lambda item: (-item["score"], item["ipa_file"])):
        vt_value = vt.get(row.get("sha256", ""), {}).get("vt_detections", "not queried")
        lines.append(f"| {row['ipa_file']} | {row['score']} | {vt_value} | {row['findings_count']} |")
    lines.extend(
        [
            "",
            "### Table 4 - Findings by Category",
            "",
            "| Category | Benign avg | Malicious avg | Delta |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    lines.extend(
        f"| {row['category']} | {row['benign_avg']} | {row['malicious_avg']} | {row['delta']} |"
        for row in category_rows
    )
    lines.append("")
    if numbers.get("dynamic_events_captured"):
        endpoint = numbers.get("dynamic_endpoint_captured", "no network endpoint")
        verdict = numbers.get("dynamic_endpoint_correlation", "OBSERVED")
        lines.extend(
            [
                "### Dynamic Evidence",
                "",
                "CipherDock captured live NSURLSession calls via Frida instrumentation of Mastodon iOS "
                f"running in an {numbers.get('simulator_target', 'iOS Simulator')}. "
                f"The dynamic layer observed {numbers.get('dynamic_network_calls', 0)} network endpoint "
                f"(`{endpoint}`), labeled `{verdict}` against the analyzed IPA static URL list. "
                "This is companion-build evidence and is not asserted as exact IPA execution.",
                "",
            ]
        )
    return "\n".join(lines)


def print_summary(numbers: Dict[str, Any], results: List[Dict[str, Any]], vt_path: Path) -> None:
    print(
        f"Corpus: {numbers['corpus_total']} IPAs "
        f"({numbers['corpus_benign']} benign, {numbers['corpus_malicious']} malicious)"
    )
    print(
        f"Held-out F1: {numbers['best_f1']:.2f} at calibration-selected "
        f"threshold {numbers['best_threshold']} ({numbers['f1_confidence_interval']})"
    )
    vt = _vt_by_hash(vt_path)
    if vt:
        missed = [
            row for row in results
            if row["label"] == 1
            and row.get("sha256") in vt
            and vt[row["sha256"]].get("vt_detections") == "0"
        ]
        caught = sum(row["score"] >= numbers["best_threshold"] for row in missed)
        print(f"CipherDock detected {_percent(caught, len(missed))} of malicious samples VirusTotal missed")
    else:
        print("VirusTotal comparison not run; set VT_API_KEY to perform SHA-256 lookups without uploading IPAs.")


def _vt_by_hash(path: Path) -> Dict[str, Dict[str, str]]:
    if not path.exists():
        return {}
    return {
        row["sha256"]: row
        for row in read_csv(path)
        if row.get("vt_status") == "found"
    }


def _percent(value: int, total: int) -> str:
    return f"{(100.0 * value / total) if total else 0.0:.1f}%"


if __name__ == "__main__":
    raise SystemExit(main())
