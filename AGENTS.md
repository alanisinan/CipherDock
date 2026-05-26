# CipherDock — Agent Context

## Purpose
iOS IPA security analysis framework.
Paper target: Computers & Security (Elsevier).

## Documentation
docs/SYSTEM_OVERVIEW.md      — What the system does
docs/TECHNICAL_DETAILS.md    — Implementation details
docs/EVALUATION_SUMMARY.md   — Corpus and metrics
docs/RELATED_GAPS.md         — Research gaps addressed
docs/PAPER_READY_NUMBERS.md  — All paper statistics

## Critical Accuracy Rules
- Scoring is DETERMINISTIC — no SHAP, no ML, no ensemble
- "AI Notes" = deterministic summaries, no LLM
- Dynamic = companion build, not exact IPA execution
- Cross-layer verdict = DOMAIN_MATCH for Mastodon endpoint
- Score delta = 37.67 (benign avg 41.0, malicious avg 78.67)
- Operating threshold = 50 (not 65)
- jtool2 NOT invoked by current code
- Ghidra NOT used in the Mastodon baseline

## Source of Truth
eval/paper_numbers.json
