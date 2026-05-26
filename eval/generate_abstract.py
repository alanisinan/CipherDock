#!/usr/bin/env python3
"""Generate a factual paper abstract from the current paper-number artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Print a paper-ready abstract using eval/paper_numbers.json.")
    parser.add_argument("--paper-numbers", type=Path, default=Path("eval/paper_numbers.json"))
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        numbers = json.loads(args.paper_numbers.resolve().read_text(encoding="utf-8"))
        abstract = generate_abstract(numbers)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Unable to generate abstract: {exc}", file=sys.stderr)
        return 2
    print(abstract)
    return 0


def generate_abstract(numbers: Dict[str, Any]) -> str:
    """Render a concise abstract with statistics provided by the evaluation pipeline."""
    required = (
        "corpus_total",
        "corpus_benign_real",
        "corpus_malicious",
        "best_threshold",
        "best_f1",
        "precision_at_best",
        "recall_at_best",
        "f1_confidence_interval",
        "avg_score_benign",
        "avg_score_malicious",
        "dynamic_events_captured",
        "dynamic_network_calls",
        "dynamic_endpoint_captured",
        "dynamic_endpoint_correlation",
        "simulator_target",
    )
    missing = [key for key in required if key not in numbers]
    if missing:
        raise KeyError(f"paper_numbers.json missing: {', '.join(missing)}")
    return (
        "Abstract\n\n"
        "Static and dynamic assessment of iOS application packages remains fragmented, particularly when "
        "researchers cannot rely on a jailbroken physical device. CipherDock is a local analysis workbench "
        "that combines typed IPA static analysis, deterministic evidence-weighted scoring, runtime probe "
        "generation, and authorized Frida capture with explicit provenance boundaries. We evaluate CipherDock "
        f"on a controlled corpus of {numbers['corpus_total']} IPAs comprising "
        f"{numbers['corpus_benign_real']} non-injected open-source controls and "
        f"{numbers['corpus_malicious']} synthetic positive variants. At a calibration-selected score threshold "
        f"of {numbers['best_threshold']}, held-out performance reaches precision "
        f"{numbers['precision_at_best']:.4f}, recall {numbers['recall_at_best']:.4f}, and F1 "
        f"{numbers['best_f1']:.4f} ({numbers['f1_confidence_interval']}). Mean risk scores are "
        f"{numbers['avg_score_benign']} for benign controls and {numbers['avg_score_malicious']} for controlled "
        "positives. The dynamic layer records "
        f"{numbers['dynamic_events_captured']} live event(s), including {numbers['dynamic_network_calls']} "
        f"network call to {numbers['dynamic_endpoint_captured']}, from Mastodon iOS in the "
        f"{numbers['simulator_target']}; cross-layer correlation labels this endpoint "
        f"{numbers['dynamic_endpoint_correlation']}. These runtime observations are companion-build evidence, "
        "not byte-identical execution of the uploaded IPA. The results show how a reproducible, provenance-aware "
        "workflow can enrich IPA triage while preserving honest limits on controlled evaluation and Simulator evidence."
    )


if __name__ == "__main__":
    raise SystemExit(main())
