# CipherDock System Overview

## Purpose

CipherDock is a local iOS security-analysis workbench backed by the `iRE-Zero` Python 3 CLI. It accepts authorized IPA artifacts, extracts static evidence from the application bundle and Mach-O executable, assigns a deterministic risk score, prepares runtime probes, ingests authorized Frida traces, and exposes the resulting reports in a browser workbench. The evaluation utilities run the same static CLI against a labeled corpus and produce evaluation CSV and Markdown artifacts.

## Pipeline Stages

1. **IPA intake and bundle discovery.** `ire_zero.unpack.safe_unpack_ipa` uses Python `zipfile` extraction with traversal checks, locates the `.app` bundle, and identifies the main executable named in `CFBundleExecutable`.
2. **Metadata and signing extraction.** Python `plistlib` extracts `Info.plist` fields, while `codesign -d --entitlements :-` and `codesign -dvv` are invoked when available to recover entitlements and signing metadata.
3. **Native binary and string analysis.** The built-in Mach-O parser reads load commands and sections and computes section entropy. Optional local tool invocations are `otool -L`, `otool -tvV`, `nm -m`, and `class-dump`. Printable-string scanning and the JSON rule pack identify URLs, IP addresses, secret-like values, and suspicious vocabulary. Optional Ghidra support runs `analyzeHeadless` when the user supplies its path.
4. **Heuristics, evidence, and reporting.** `ire_zero.heuristics` maps evidence to deterministic findings and score buckets; `ire_zero.runtime` constructs runtime probes; `ire_zero.reporting` writes report artifacts and Frida hooks; `ire_zero.semantics` creates deterministic analyst-note summaries.
5. **Runtime and evaluation layer.** The workbench can execute generated Frida hooks against an authorized Simulator or device target and merge JSONL events into a report. Cross-layer correlation distinguishes `CONFIRMED`, `DOMAIN_MATCH`, and `DYNAMIC_ONLY` events. The `eval` package builds synthetic controls, runs corpus scoring, calculates held-out bootstrap metrics and threshold sensitivity, tests category deltas, verifies corpus hashes, and emits evaluation-number artifacts.

## Inputs And Outputs

CipherDock accepts one IPA file or a directory of IPA files. It can additionally consume a JSON or JSONL runtime trace, an optional rules file, and an optional Ghidra `analyzeHeadless` path.

For each IPA, the CLI can produce `report.json`, `report.md`, `report.html`, `report.sarif`, `frida-hooks.js`, evidence exports, a risk score, a runtime probe plan, and a `cross_layer` dynamic/static comparison section when runtime evidence is present. Batch evaluation produces `results.csv`, `metrics.csv`, `threshold_curve.csv`, `category_delta.csv`, `RESULTS.md`, `evaluation_numbers.json`, and `evaluation_numbers.md`; `generate_summary.py` renders a concise summary from the evaluation numbers.

## Risk Dimensions In The Mastodon Run

The analyzed benign Mastodon corpus artifact scores **18**. CipherDock currently uses deterministic severity-weighted scoring; it does **not** compute SHAP values and does **not** run a learned or voting ensemble. For the five primary requested risk dimensions, the observed score contributions in the Mastodon report are:

| Primary risk dimension | Mastodon score contribution |
| --- | ---: |
| Transport security | 14 |
| Hardcoded secrets | 0 |
| Private API usage | 0 |
| Jailbreak detection | 0 |
| Suspicious network endpoints | 3 |

An auxiliary symbol-intelligence bucket contributes **1** point; entitlement and dynamic-confirmation buckets contribute **0**. These contributions total the reported score of **18**.

## Dynamic Capture

The dynamic evidence record is an authorized Frida `17.9.11` capture from a Mastodon companion build running in the **iPhone 17 Pro Simulator**. CipherDock recorded two runtime events: instrumentation attachment and one `NSURLSession dataTaskWithRequest` call to `https://api.joinmastodon.org/default-servers`. Because the Simulator runs a companion build rather than the exact uploaded IPA binary, the report declares `capture_mode = companion_build` and `dynamic_status = captured (companion build)`. The endpoint is not an exact static URL match but shares a recovered static application domain, so the cross-layer section labels it `DOMAIN_MATCH`.

## Sources

- `eval/evaluation_numbers.json`
- `eval/results.csv`
- `eval/threshold_curve.csv`
- `eval/category_delta.csv`
- `eval/reports/mastodon-ios-f5abc1bed120/mastodon-ios/report.json`
- `workbench-data/reports/org.joinmastodon.app_2026.03_und3fined-26/report.json`
