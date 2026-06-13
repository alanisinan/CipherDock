# CipherDock Usage Guide

CipherDock analyzes authorized iOS IPA files and produces evidence-backed
security reports. The static pipeline is jailbreak-free and can run without a
device. Dynamic capture is optional and uses Frida with an authorized Simulator
or device target.

## Install

```bash
pip install -e .
```

For static-only analysis, the editable install is sufficient. Install optional
dynamic tooling when you want Frida/Objection capture helpers:

```bash
pip install -r requirements.txt
```

## Analyze One IPA

```bash
python -m ire_zero analyze /path/to/app.ipa --output reports/app --sarif --html
```

The report directory contains `report.json`, `report.md`, `report.sarif`,
`report.html`, and `frida-hooks.js`.

## Analyze a Folder of IPAs

```bash
python -m ire_zero analyze /path/to/ipa-folder --output reports/batch
```

CipherDock writes one report per IPA and an index report when multiple targets
are analyzed.

## Launch the Workbench

```bash
python webapp.py
```

Open the displayed local URL in a browser, upload an authorized IPA, and inspect
the static findings, binary evidence, generated reports, runtime readiness, and
dynamic capture results.

## Optional Dynamic Capture

Install Frida tooling, launch the workbench, and use the Runtime tab to attach
to an authorized target. Simulator captures are labeled as companion-build
evidence when the live app binary does not exactly match the uploaded IPA.

## Tool Health Check

```bash
python -m ire_zero doctor
```

The doctor command reports whether `codesign`, `otool`, `nm`, Frida, Objection,
and Ghidra are available.
