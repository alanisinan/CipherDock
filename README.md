# CipherDock

A jailbreak-free hybrid static-dynamic iOS IPA
analysis framework.

## What It Does

CipherDock accepts authorized iOS IPA files and
produces a deterministic risk score across seven
evidence-weighted categories: transport security,
hardcoded secrets, private API usage, jailbreak
detection, network endpoints, entitlements, and
symbol intelligence.

It optionally captures live Frida runtime events
from an authorized Simulator or device target and
performs cross-layer correlation between static
and dynamic evidence — classifying each captured
event as CONFIRMED, DOMAIN_MATCH, or DYNAMIC_ONLY
against static URL evidence.

## Workbench Screenshots

Real Mastodon analysis report loaded in the CipherDock Workbench, with
deterministic findings and companion-build Frida capture status.

![CipherDock analysis overview](docs/screenshots/workbench-overview.png)

Static evidence view with recovered Mach-O section data, instruction evidence,
symbol findings, and section visualization.

![CipherDock static evidence workbench](docs/screenshots/workbench-static-evidence.png)

Dynamic evidence view showing the captured `NSURLSession` endpoint and its
`DOMAIN_MATCH` cross-layer correlation against recovered static URL evidence.

![CipherDock dynamic correlation workbench](docs/screenshots/workbench-dynamic-correlation.png)

## Requirements

- Python 3.11+
- macOS (for codesign, otool, nm)
- Xcode Command Line Tools
- Frida 17.9+ (optional, for dynamic capture)
- Ghidra (optional, for symbol enrichment)

## Installation

pip install -r requirements.txt

## Usage

# Analyze a single IPA
python -m ire_zero analyze app.ipa

# Launch browser workbench
python webapp.py

# Run full corpus evaluation
python eval/run_all.py

# Verify corpus integrity (35/35 expected)
python eval/verify_corpus.py

# Generate paper abstract from current numbers
python eval/generate_abstract.py

## Evaluation Results

| Metric | Value |
|--------|-------|
| Corpus | 35 IPAs (5 benign, 30 controlled variants) |
| Held-out F1 | 0.9474 |
| 95% CI | [0.8235, 1.0000] |
| Threshold | 50 (calibration-selected) |
| Significance | p=0.000015 (Mann-Whitney U) |
| Dynamic capture | Frida companion-build, DOMAIN_MATCH |
| Tests passing | 58 |

## Corpus

The evaluation corpus contains 5 real open-source
benign iOS applications built from official source
repositories, and 30 controlled synthetic malicious
variants. SHA-256 hashes and build provenance are
documented in eval/corpus/BUILD.md.

IPA files are not distributed in this repository.
See eval/corpus/BUILD.md for build instructions.

## Paper

Submitted to Computers & Security (Elsevier).
Preprint: [to appear]

## Project Structure

ire_zero/        Core analysis library
eval/            Corpus evaluation scripts and results
docs/            Paper-writing documentation
rules/           JSON detection rule pack
tests/           Test suite (58 tests)
webapp.py        Browser workbench server

## License

MIT
