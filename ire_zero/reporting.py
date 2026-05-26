"""Writers for JSON, Markdown, HTML, SARIF, and runtime collection artifacts."""

from __future__ import annotations

import html
import json
import os
import base64
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Iterable, List

from .models import AnalysisResult, Finding

SEVERITIES = ("critical", "high", "medium", "low", "info")


def write_reports(result: AnalysisResult, output_dir: Path, sarif: bool = False, html_report: bool = False) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True, default=_json_default),
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(render_markdown(result), encoding="utf-8")
    (output_dir / "runtime-plan.md").write_text(render_runtime_plan(result), encoding="utf-8")
    (output_dir / "frida-hooks.js").write_text(render_frida_script(result), encoding="utf-8")
    if sarif:
        (output_dir / "report.sarif").write_text(
            json.dumps(render_sarif(result), indent=2, sort_keys=True),
            encoding="utf-8",
        )
    if html_report:
        (output_dir / "report.html").write_text(render_html(result), encoding="utf-8")


def write_index_report(results: List[tuple[AnalysisResult, Path]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "index.html").write_text(render_index_html(results, output_dir), encoding="utf-8")


def _json_default(value: object) -> object:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def render_runtime_plan(result: AnalysisResult) -> str:
    bundle_id = result.info_plist.bundle_identifier or "<bundle-id>"
    lines = [
        f"# iRE-Zero Runtime Capture Plan: {result.app_name}",
        "",
        f"- Bundle ID: `{bundle_id}`",
        f"- Static score: `{result.score}/100`",
        f"- Runtime status: `{result.dynamic.status}`",
        f"- Capture mode: `{result.dynamic.capture_mode}`",
        f"- Planned probes: `{len(result.dynamic.probes)}`",
        "",
        "## Collection Boundary",
        "",
        "The probes below are generated from static IPA evidence. They are not observed behavior until a capture is imported into iRE-Zero.",
        "",
        "## Setup Paths",
        "",
        "1. Use an authorized research device with Frida Server, or patch and re-sign the IPA with Frida Gadget for an authorized non-jailbroken device.",
        "2. Install and launch the authorized target, then attach the generated `frida-hooks.js` script.",
        "3. Exercise the workflows associated with the probes below and collect the script output.",
        "4. Import the captured JSONL output into iRE-Zero with `--runtime-trace` or the workbench capture-import button.",
        "",
        "## Capture Command",
        "",
        "```bash",
        f"frida -U -f {bundle_id} -l frida-hooks.js | tee runtime-capture.jsonl",
        "```",
        "",
        "The generated script prints lines beginning with `IRE_ZERO_EVENT`; iRE-Zero accepts these lines directly even when Frida also emits console status output.",
        "",
        "## Assessment Campaigns",
        "",
        "| Campaign | Objective | Workflow |",
        "| --- | --- | --- |",
    ]
    for campaign in result.dynamic.campaigns:
        values = [
            campaign.title,
            campaign.objective,
            " ".join(campaign.workflow),
        ]
        lines.append("| " + " | ".join(value.replace("|", "\\|").replace("\n", " ") for value in values) + " |")
    lines.extend(
        [
        "",
        "## Planned Probes",
        "",
        "| Priority | Layer | Operation | Target | Purpose |",
        "| --- | --- | --- | --- | --- |",
        ]
    )
    for probe in result.dynamic.probes:
        values = [
            probe.priority,
            probe.layer,
            probe.operation,
            probe.target,
            probe.rationale,
        ]
        lines.append("| " + " | ".join(value.replace("|", "\\|").replace("\n", " ") for value in values) + " |")
    if not result.dynamic.probes:
        lines.append("| info | process | baseline launch | application lifecycle | Collect a baseline execution trace. |")
    lines.extend(
        [
            "",
            "## Common Blockers",
            "",
            "- A non-jailbroken device may require a Gadget-patched and re-signed IPA.",
            "- Device enumeration failures may require the matching Developer Disk Image to be mounted through Xcode or device tooling.",
            "- Signing or provisioning changes can prevent installation; preserve required entitlements during an authorized re-signing workflow.",
            "- Treat pinning or anti-instrumentation bypasses as separately authorized testing steps and record exactly what was modified.",
            "",
        ]
    )
    return "\n".join(lines)


def render_frida_script(result: AnalysisResult) -> str:
    layers = {probe.layer for probe in result.dynamic.probes}
    operations = " ".join(probe.operation.lower() for probe in result.dynamic.probes)
    lines = [
        "'use strict';",
        "",
        "// Generated by iRE-Zero. Collects runtime metadata for an authorized target.",
        "// It intentionally avoids logging secret material or modifying app behavior.",
        "function ireZeroEmit(layer, operation, value, severity) {",
        "  const event = {",
        "    timestamp: new Date().toISOString(),",
        "    layer: layer, operation: operation, value: String(value || ''),",
        "    severity: severity || 'info', verdict: 'observed'",
        "  };",
        "  console.log('IRE_ZERO_EVENT ' + JSON.stringify(event));",
        "}",
        "",
    ]
    if "network" in layers:
        lines.extend(
            [
                "if (ObjC.available && ObjC.classes.NSURLSession) {",
                "  const method = ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'];",
                "  if (method) Interceptor.attach(method.implementation, {",
                "    onEnter(args) {",
                "      try { ireZeroEmit('network', 'NSURLSession dataTaskWithRequest', new ObjC.Object(args[2]).URL().absoluteString().toString(), 'info'); } catch (e) {}",
                "    }",
                "  });",
                "}",
                "const trustEvaluate = Module.findGlobalExportByName('SecTrustEvaluateWithError');",
                "if (trustEvaluate) Interceptor.attach(trustEvaluate, {",
                "  onEnter() { ireZeroEmit('network', 'SecTrustEvaluateWithError', 'server trust evaluation (certificates redacted)', 'info'); }",
                "});",
                "",
            ]
        )
    if "keychain" in layers:
        lines.extend(
            [
                "['SecItemAdd', 'SecItemCopyMatching', 'SecItemUpdate'].forEach(function(name) {",
                "  const address = Module.findGlobalExportByName(name);",
                "  if (address) Interceptor.attach(address, { onEnter() { ireZeroEmit('keychain', name, 'Security.framework call (values redacted)', 'info'); } });",
                "});",
                "if (ObjC.available && ObjC.classes.NSUserDefaults) {",
                "  const defaultsWrite = ObjC.classes.NSUserDefaults['- setObject:forKey:'];",
                "  if (defaultsWrite) Interceptor.attach(defaultsWrite.implementation, {",
                "    onEnter(args) { try { ireZeroEmit('file', 'NSUserDefaults setObject:forKey:', 'key=' + new ObjC.Object(args[3]).toString() + ' (value redacted)', 'info'); } catch (e) {} }",
                "  });",
                "}",
                "",
            ]
        )
    if "canopenurl" in operations:
        lines.extend(
            [
                "if (ObjC.available && ObjC.classes.UIApplication) {",
                "  const canOpenURL = ObjC.classes.UIApplication['- canOpenURL:'];",
                "  if (canOpenURL) Interceptor.attach(canOpenURL.implementation, {",
                "    onEnter(args) { try { ireZeroEmit('process', 'UIApplication.canOpenURL', new ObjC.Object(args[2]).toString(), 'info'); } catch (e) {} }",
                "  });",
                "}",
                "",
            ]
        )
    if "uipasteboard" in operations:
        lines.extend(
            [
                "if (ObjC.available && ObjC.classes.UIPasteboard) {",
                "  ['- string', '- setString:'].forEach(function(selector) {",
                "    const method = ObjC.classes.UIPasteboard[selector];",
                "    if (method) Interceptor.attach(method.implementation, { onEnter() { ireZeroEmit('process', 'UIPasteboard ' + selector, 'clipboard access (contents redacted)', 'info'); } });",
                "  });",
                "}",
                "",
            ]
        )
    if "cryptographic" in operations:
        lines.extend(
            [
                "['CCCrypt', 'SecKeyCreateSignature', 'SecKeyVerifySignature'].forEach(function(name) {",
                "  const address = Module.findGlobalExportByName(name);",
                "  if (address) Interceptor.attach(address, { onEnter() { ireZeroEmit('process', name, 'cryptographic operation (material redacted)', 'info'); } });",
                "});",
                "",
            ]
        )
    if any(term in operations for term in ("fileexistsatpath", "dlopen", "sysctl")):
        lines.extend(
            [
                "if (ObjC.available && ObjC.classes.NSFileManager) {",
                "  const fileProbe = ObjC.classes.NSFileManager['- fileExistsAtPath:'];",
                "  if (fileProbe) Interceptor.attach(fileProbe.implementation, {",
                "    onEnter(args) {",
                "      try {",
                "        const path = new ObjC.Object(args[2]).toString();",
                "        if (/cydia|substrate|frida|jailbreak/i.test(path)) ireZeroEmit('process', 'fileExistsAtPath', path, 'medium');",
                "      } catch (e) {}",
                "    }",
                "  });",
                "}",
                "const dlopenAddress = Module.findGlobalExportByName('dlopen');",
                "if (dlopenAddress) Interceptor.attach(dlopenAddress, {",
                "  onEnter(args) { try { const path = args[0].readUtf8String(); if (/substrate|frida/i.test(path)) ireZeroEmit('process', 'dlopen', path, 'medium'); } catch (e) {} }",
                "});",
                "",
            ]
        )
    lines.append("ireZeroEmit('process', 'instrumentation attached', 'iRE-Zero capture started', 'info');")
    return "\n".join(lines) + "\n"


def render_markdown(result: AnalysisResult) -> str:
    lines = [
        f"# iRE-Zero Report: {result.app_name}",
        "",
        f"- IPA: `{result.ipa_path}`",
        f"- Bundle ID: `{result.info_plist.bundle_identifier or 'unknown'}`",
        f"- Executable: `{result.executable_path}`",
        f"- Risk score: **{result.score}/100**",
        "",
        "## Score Breakdown",
        "",
    ]
    for key, value in result.score_breakdown.items():
        lines.append(f"- {key.replace('_', ' ').title()}: {value}")
    lines.extend(["", "## Findings", ""])
    grouped = _group_findings(result.findings)
    for severity in SEVERITIES:
        items = grouped.get(severity, [])
        lines.extend([f"### {severity.title()}", ""])
        if not items:
            lines.extend(["No findings.", ""])
            continue
        for finding in items:
            lines.append(f"#### {finding.title}")
            lines.append("")
            lines.append(f"- ID: `{finding.id}`")
            lines.append(f"- Category: `{finding.category}`")
            lines.append(f"- Confidence: `{finding.confidence}`")
            lines.append(f"- Description: {finding.description}")
            if finding.recommendation:
                lines.append(f"- Recommendation: {finding.recommendation}")
            if finding.evidence:
                lines.append("- Evidence:")
                for value in finding.evidence[:15]:
                    lines.append(f"  - `{value}`")
            lines.append("")
    lines.extend(
        [
            "## App Metadata",
            "",
            f"- Name: `{result.info_plist.bundle_name or 'unknown'}`",
            f"- URL types: `{len(result.info_plist.url_types)}`",
            f"- Query schemes: `{len(result.info_plist.query_schemes)}`",
            f"- Embedded frameworks: `{len(result.binary.embedded_frameworks)}`",
            f"- Embedded dylibs: `{len(result.binary.embedded_dylibs)}`",
            f"- Extracted strings: `{result.strings.total_strings}`",
            f"- Mach-O sections: `{len(result.binary.sections)}`",
            f"- Static evidence items: `{len(result.binary.evidence)}`",
            f"- Dynamic status: `{result.dynamic.status}`",
            f"- Capture mode: `{result.dynamic.capture_mode}`",
            f"- Dynamic evidence source: `{result.dynamic.evidence_source or 'none'}`",
            "",
            "## Dynamic Capture",
            "",
        ]
    )
    coverage = result.dynamic.campaign_coverage
    if coverage:
        lines.extend(
            [
                f"- Campaign coverage: `{coverage.get('observed', 0)}/{coverage.get('total', 0)}` observed",
                "",
                "### Campaign Coverage",
                "",
            ]
        )
        for campaign in coverage.get("campaigns", []):
            lines.append(
                f"- `{campaign.get('status', 'planned')}` **{campaign.get('title', 'Campaign')}**: "
                f"{campaign.get('event_count', 0)} matching event(s) - {campaign.get('objective', '')}"
            )
        lines.append("")
    if result.dynamic.events:
        for event in result.dynamic.events:
            lines.append(
                f"- `{event.timestamp}` `{event.layer}` `{event.operation}`: `{event.value}` "
                f"({event.severity}, `{event.correlation_status}`)"
            )
            lines.append(f"  - Source: `{event.source or result.dynamic.evidence_source or 'authorized runtime capture'}`")
            for correlation in event.static_evidence:
                lines.append(f"  - Static correlation: `{correlation}`")
    else:
        lines.extend(f"- {limitation}" for limitation in result.dynamic.limitations)
        if result.dynamic.probes:
            lines.extend(["", "### Planned Runtime Probes", ""])
            for probe in result.dynamic.probes:
                lines.append(
                    f"- `{probe.priority}` `{probe.layer}` `{probe.operation}` on `{probe.target}`: {probe.rationale}"
                )
    lines.extend(["", "## Evidence Notes", ""])
    for note in result.ai_notes:
        lines.extend(
            [
                f"### {note.title}",
                "",
                f"- Confidence: `{note.confidence}`",
                f"- Source: `{note.source}`",
                f"- Summary: {note.summary}",
                "",
            ]
        )
    lines.extend(
        [
            "## Tool Availability",
            "",
        ]
    )
    for name, tool in result.binary.tools.items():
        status = "available" if tool.available else "missing"
        detail = f" ({tool.error})" if tool.error else ""
        lines.append(f"- {name}: {status}{detail}")
    if result.errors:
        lines.extend(["", "## Analysis Errors", ""])
        for error in result.errors:
            lines.append(f"- {error}")
    lines.append("")
    return "\n".join(lines)


def render_sarif(result: AnalysisResult) -> Dict[str, object]:
    rules = []
    sarif_results = []
    for finding in result.findings:
        rules.append(
            {
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "properties": {"category": finding.category, "severity": finding.severity},
            }
        )
        sarif_results.append(
            {
                "ruleId": finding.id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.ipa_path},
                        }
                    }
                ],
                "properties": {"evidence": finding.evidence},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "iRE-Zero", "rules": rules}},
                "results": sarif_results,
            }
        ],
    }


def render_index_html(results: List[tuple[AnalysisResult, Path]], output_dir: Path) -> str:
    sorted_results = sorted(results, key=lambda item: item[0].score, reverse=True)
    rows = "\n".join(_render_index_row(result, path, output_dir) for result, path in sorted_results)
    total = len(sorted_results)
    max_score = max((result.score for result, _ in sorted_results), default=0)
    avg_score = round(sum(result.score for result, _ in sorted_results) / total, 1) if total else 0
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iRE-Zero Batch Index</title>
<style>
:root {{ color-scheme: dark; --bg:#0e1116; --surface:#171c23; --surface2:#202833; --border:#303a46; --text:#e8edf2; --muted:#9ba8b4; --green:#82c56f; --amber:#e6ad4f; --red:#ec6d6d; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
main {{ max-width:1180px; margin:0 auto; padding:28px; }}
h1 {{ margin:0 0 4px; }}
.subtle {{ color:var(--muted); }}
.metrics {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:18px 0; }}
.metric {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:15px; }}
.metric span {{ display:block; color:var(--muted); text-transform:uppercase; font-size:11px; }}
.metric strong {{ display:block; font-size:28px; margin-top:4px; }}
table {{ width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
th, td {{ padding:11px 12px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }}
th {{ color:var(--muted); text-transform:uppercase; font-size:11px; }}
a {{ color:#7fcfff; text-decoration:none; }}
.score {{ font-weight:700; }}
.high {{ color:var(--red); }} .medium {{ color:var(--amber); }} .low {{ color:var(--green); }}
code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; color:var(--muted); overflow-wrap:anywhere; }}
@media (max-width:800px) {{ main {{ padding:14px; }} .metrics {{ grid-template-columns:1fr; }} table {{ font-size:12px; }} }}
</style>
</head>
<body>
<main>
  <h1>iRE-Zero Batch Index</h1>
  <div class="subtle">Ranked by risk score across analyzed IPA files.</div>
  <section class="metrics">
    <div class="metric"><span>Apps</span><strong>{total}</strong></div>
    <div class="metric"><span>Max Score</span><strong>{max_score}</strong></div>
    <div class="metric"><span>Average Score</span><strong>{avg_score}</strong></div>
  </section>
  <table>
    <tr><th>App</th><th>Bundle</th><th>Score</th><th>Findings</th><th>Reports</th></tr>
    {rows}
  </table>
</main>
</body>
</html>
"""


def render_html(result: AnalysisResult) -> str:
    grouped = _group_findings(result.findings)
    score_color = _score_color(result.score)
    finding_cards = "\n".join(
        _render_html_finding(finding)
        for severity in SEVERITIES
        for finding in grouped.get(severity, [])
    ) or '<div class="empty">No findings.</div>'
    score_rows = "\n".join(
        f"<tr><td>{html.escape(key.replace('_', ' ').title())}</td><td>{value}</td></tr>"
        for key, value in result.score_breakdown.items()
    )
    metadata_rows = _rows(
        {
            "App": result.app_name,
            "Bundle ID": result.info_plist.bundle_identifier or "unknown",
            "Executable": result.executable_path,
            "URL Types": str(len(result.info_plist.url_types)),
            "Query Schemes": str(len(result.info_plist.query_schemes)),
            "Embedded Frameworks": str(len(result.binary.embedded_frameworks)),
            "Embedded Dylibs": str(len(result.binary.embedded_dylibs)),
            "Extracted Strings": str(result.strings.total_strings),
            "Mach-O Sections": str(len(result.binary.sections)),
            "Static Evidence": str(len(result.binary.evidence)),
            "Dynamic Status": result.dynamic.status,
            "Capture Mode": result.dynamic.capture_mode,
            "Dynamic Evidence Source": result.dynamic.evidence_source or "none",
        }
    )
    tool_rows = "\n".join(
        f"<tr><td>{html.escape(name)}</td><td>{'available' if tool.available else 'missing'}</td><td>{html.escape(tool.error or '')}</td></tr>"
        for name, tool in sorted(result.binary.tools.items())
    )
    severity_counts = {severity: len(grouped.get(severity, [])) for severity in SEVERITIES}
    severity_cards = "\n".join(
        f'<div class="metric severity-{severity}"><span>{severity}</span><strong>{count}</strong></div>'
        for severity, count in severity_counts.items()
    )
    urls = _list_items(result.strings.urls[:40])
    ips = _list_items(result.strings.ips[:40])
    secrets = _list_items(result.strings.secrets[:40])
    frameworks = _list_items(result.binary.embedded_frameworks[:60])
    dylibs = _list_items(result.binary.embedded_dylibs[:60])
    symbol_categories = _symbol_category_blocks(result.binary.symbol_categories)
    sections = _section_rows(result)
    dynamic = _dynamic_html(result)
    notes = _notes_html(result)
    errors = _list_items(result.errors)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iRE-Zero Report - {html.escape(result.app_name)}</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #0e1116;
  --surface: #171c23;
  --surface-2: #202833;
  --border: #303a46;
  --text: #e8edf2;
  --muted: #9ba8b4;
  --faint: #687482;
  --green: #82c56f;
  --amber: #e6ad4f;
  --red: #ec6d6d;
  --blue: #6aa7ff;
  --violet: #b891ff;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}
.wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
.hero {{
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);
  gap: 22px;
  align-items: center;
  padding: 22px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
}}
.score {{
  width: 152px; height: 152px; border-radius: 50%;
  display: grid; place-items: center;
  background: conic-gradient({score_color} {result.score * 3.6}deg, #2a333e 0deg);
  position: relative;
}}
.score::after {{ content: ""; position: absolute; inset: 12px; border-radius: 50%; background: var(--surface); }}
.score > div {{ position: relative; z-index: 1; text-align: center; }}
.score strong {{ display: block; font-size: 38px; line-height: 1; }}
.score span {{ color: var(--muted); font-size: 12px; }}
h1 {{ margin: 0 0 8px; font-size: 28px; }}
h2 {{ margin: 0; font-size: 16px; }}
.subtle {{ color: var(--muted); overflow-wrap: anywhere; }}
.grid {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; margin-top: 16px; }}
.panel {{
  grid-column: span 6;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}}
.panel.full {{ grid-column: 1 / -1; }}
.panel.third {{ grid-column: span 4; }}
.head {{ padding: 13px 15px; border-bottom: 1px solid var(--border); }}
.body {{ padding: 15px; }}
.metrics {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }}
.metric {{ padding: 12px; border-radius: 8px; background: var(--surface-2); border: 1px solid var(--border); }}
.metric span {{ display: block; color: var(--muted); text-transform: uppercase; font-size: 11px; }}
.metric strong {{ display: block; font-size: 24px; margin-top: 4px; }}
.severity-critical strong, .severity-high strong {{ color: var(--red); }}
.severity-medium strong {{ color: var(--amber); }}
.severity-low strong {{ color: var(--blue); }}
.severity-info strong {{ color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ padding: 9px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
td:first-child {{ color: var(--muted); width: 190px; }}
code, .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }}
.finding {{ padding: 14px 15px; border-bottom: 1px solid var(--border); }}
.finding:last-child {{ border-bottom: 0; }}
.finding-title {{ display: flex; justify-content: space-between; gap: 12px; }}
.badge {{ border-radius: 999px; padding: 3px 8px; font-size: 11px; text-transform: uppercase; background: var(--surface-2); color: var(--muted); }}
.badge.high, .badge.critical {{ color: #ffd6d6; background: rgba(236,109,109,.18); }}
.badge.medium {{ color: #ffe3b2; background: rgba(230,173,79,.16); }}
.badge.low {{ color: #d9e8ff; background: rgba(106,167,255,.16); }}
.evidence {{ margin: 10px 0 0; padding-left: 18px; color: var(--muted); }}
.evidence li {{ margin: 4px 0; }}
.empty {{ padding: 15px; color: var(--muted); }}
ul.compact {{ margin: 0; padding-left: 18px; color: var(--muted); }}
ul.compact li {{ margin: 4px 0; overflow-wrap: anywhere; }}
@media (max-width: 900px) {{
  .wrap {{ padding: 14px; }}
  .hero, .grid {{ display: block; }}
  .panel {{ margin-top: 14px; }}
  .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
}}
</style>
</head>
<body>
<main class="wrap">
  <section class="hero">
    <div class="score"><div><strong>{result.score}</strong><span>risk / 100</span></div></div>
    <div>
      <h1>{html.escape(result.app_name)}</h1>
      <div class="subtle mono">{html.escape(result.info_plist.bundle_identifier or "unknown")}</div>
      <div class="subtle mono">{html.escape(result.ipa_path)}</div>
    </div>
  </section>
  <section class="grid">
    <div class="panel full">
      <div class="head"><h2>Severity Summary</h2></div>
      <div class="body metrics">{severity_cards}</div>
    </div>
    <div class="panel">
      <div class="head"><h2>App Metadata</h2></div>
      <div class="body"><table>{metadata_rows}</table></div>
    </div>
    <div class="panel">
      <div class="head"><h2>Score Breakdown</h2></div>
      <div class="body"><table>{score_rows}</table></div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Findings</h2></div>
      {finding_cards}
    </div>
    <div class="panel third">
      <div class="head"><h2>URLs</h2></div>
      <div class="body">{urls}</div>
    </div>
    <div class="panel third">
      <div class="head"><h2>IPs</h2></div>
      <div class="body">{ips}</div>
    </div>
    <div class="panel third">
      <div class="head"><h2>Possible Secrets</h2></div>
      <div class="body">{secrets}</div>
    </div>
    <div class="panel">
      <div class="head"><h2>Embedded Frameworks</h2></div>
      <div class="body">{frameworks}</div>
    </div>
    <div class="panel">
      <div class="head"><h2>Embedded Dylibs</h2></div>
      <div class="body">{dylibs}</div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Symbol Intelligence</h2></div>
      <div class="body">{symbol_categories}</div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Mach-O Sections</h2></div>
      <div class="body"><table><tr><th>Section</th><th>Address</th><th>Offset</th><th>Size</th><th>Entropy</th></tr>{sections}</table></div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Dynamic Capture</h2></div>
      <div class="body">{dynamic}</div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Evidence Notes</h2></div>
      <div class="body">{notes}</div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Tool Status</h2></div>
      <div class="body"><table><tr><th>Tool</th><th>Status</th><th>Detail</th></tr>{tool_rows}</table></div>
    </div>
    <div class="panel full">
      <div class="head"><h2>Analysis Errors</h2></div>
      <div class="body">{errors}</div>
    </div>
  </section>
</main>
</body>
</html>
"""


def _group_findings(findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.severity, []).append(finding)
    return grouped


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _rows(values: Dict[str, str]) -> str:
    return "\n".join(
        f"<tr><td>{html.escape(key)}</td><td class=\"mono\">{html.escape(value)}</td></tr>"
        for key, value in values.items()
    )


def _list_items(values: Iterable[str]) -> str:
    items = list(values)
    if not items:
        return '<div class="empty">None observed.</div>'
    return "<ul class=\"compact\">" + "\n".join(f"<li><code>{html.escape(value)}</code></li>" for value in items) + "</ul>"


def _render_html_finding(finding: Finding) -> str:
    evidence = _list_items(finding.evidence)
    recommendation = (
        f"<p><strong>Recommendation:</strong> {html.escape(finding.recommendation)}</p>"
        if finding.recommendation
        else ""
    )
    return f"""
<article class="finding">
  <div class="finding-title">
    <h3>{html.escape(finding.title)}</h3>
    <span class="badge {html.escape(finding.severity)}">{html.escape(finding.severity)}</span>
  </div>
  <p class="subtle">{html.escape(finding.description)}</p>
  <p><strong>ID:</strong> <code>{html.escape(finding.id)}</code> <strong>Category:</strong> <code>{html.escape(finding.category)}</code> <strong>Confidence:</strong> <code>{html.escape(finding.confidence)}</code></p>
  {recommendation}
  {evidence}
</article>
"""


def _score_color(score: int) -> str:
    if score >= 70:
        return "var(--red)"
    if score >= 35:
        return "var(--amber)"
    return "var(--green)"


def _render_index_row(result: AnalysisResult, report_dir: Path, output_dir: Path) -> str:
    finding_summary = ", ".join(
        f"{severity}:{sum(1 for finding in result.findings if finding.severity == severity)}"
        for severity in SEVERITIES
    )
    rel = _relative_report_path(report_dir, output_dir)
    score_class = "high" if result.score >= 70 else "medium" if result.score >= 35 else "low"
    return f"""
<tr>
  <td>{html.escape(result.app_name)}<br><code>{html.escape(Path(result.ipa_path).name)}</code></td>
  <td><code>{html.escape(result.info_plist.bundle_identifier or "unknown")}</code></td>
  <td class="score {score_class}">{result.score}</td>
  <td>{html.escape(finding_summary)}</td>
  <td><a href="{html.escape(rel)}/report.html">HTML</a> · <a href="{html.escape(rel)}/report.md">MD</a> · <a href="{html.escape(rel)}/report.json">JSON</a></td>
</tr>
"""


def _relative_report_path(report_dir: Path, output_dir: Path) -> str:
    return os.path.relpath(report_dir, output_dir)


def _symbol_category_blocks(categories: Dict[str, List[str]]) -> str:
    if not categories:
        return '<div class="empty">No classified symbols observed.</div>'
    blocks = []
    for category, values in sorted(categories.items()):
        blocks.append(
            f"<h3>{html.escape(category.replace('_', ' ').title())}</h3>{_list_items(values[:30])}"
        )
    return "\n".join(blocks)


def _section_rows(result: AnalysisResult) -> str:
    if not result.binary.sections:
        return '<tr><td colspan="5" class="subtle">No Mach-O section table recovered.</td></tr>'
    return "\n".join(
        "<tr>"
        f"<td><code>{html.escape(section.segment)}.{html.escape(section.name)}</code></td>"
        f"<td><code>{html.escape(section.address)}</code></td>"
        f"<td><code>0x{section.offset:x}</code></td>"
        f"<td>{section.size}</td>"
        f"<td>{section.entropy}</td>"
        "</tr>"
        for section in result.binary.sections[:80]
    )


def _dynamic_html(result: AnalysisResult) -> str:
    coverage = _campaign_coverage_html(result)
    if not result.dynamic.events:
        limitations = _list_items(result.dynamic.limitations)
        if not result.dynamic.probes:
            return coverage + limitations
        rows = "\n".join(
            "<tr>"
            f"<td>{html.escape(probe.priority)}</td>"
            f"<td>{html.escape(probe.layer)}</td>"
            f"<td><code>{html.escape(probe.operation)}</code></td>"
            f"<td>{html.escape(probe.target)}</td>"
            f"<td>{html.escape(probe.rationale)}</td>"
            "</tr>"
            for probe in result.dynamic.probes[:100]
        )
        return (
            f"{coverage}{limitations}<h3>Planned Runtime Probes (not observed)</h3>"
            f"<table><tr><th>Priority</th><th>Layer</th><th>Operation</th><th>Target</th><th>Reason</th></tr>{rows}</table>"
        )
    rows = "\n".join(
        "<tr>"
        f"<td><code>{html.escape(event.timestamp)}</code></td>"
        f"<td>{html.escape(event.layer)}</td>"
        f"<td><code>{html.escape(event.operation)}</code></td>"
        f"<td>{html.escape(event.value)}</td>"
        f"<td><code>{html.escape(event.correlation_status)}</code></td>"
        f"<td>{html.escape(event.source or result.dynamic.evidence_source or 'authorized runtime capture')}</td>"
        f"<td>{'<br>'.join(html.escape(value) for value in event.static_evidence) or 'None'}</td>"
        f"<td>{html.escape(event.severity)}</td>"
        "</tr>"
        for event in result.dynamic.events[:100]
    )
    return (
        f"{coverage}<p><strong>Capture mode:</strong> <code>{html.escape(result.dynamic.capture_mode)}</code> "
        f"<strong>Source:</strong> <code>{html.escape(result.dynamic.evidence_source or 'authorized runtime capture')}</code></p>"
        f"<table><tr><th>Time</th><th>Layer</th><th>Operation</th><th>Value</th><th>Verdict</th>"
        f"<th>Source</th><th>Static Correlation</th><th>Severity</th></tr>{rows}</table>"
    )


def _campaign_coverage_html(result: AnalysisResult) -> str:
    coverage = result.dynamic.campaign_coverage
    campaigns = coverage.get("campaigns", []) if isinstance(coverage, dict) else []
    if not campaigns:
        return ""
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(campaign.get('title', 'Campaign')))}</td>"
        f"<td><code>{html.escape(str(campaign.get('status', 'planned')))}</code></td>"
        f"<td>{html.escape(str(campaign.get('event_count', 0)))}</td>"
        f"<td>{html.escape(str(campaign.get('objective', '')))}</td>"
        "</tr>"
        for campaign in campaigns
    )
    return (
        f"<h3>Campaign Coverage ({html.escape(str(coverage.get('observed', 0)))}/"
        f"{html.escape(str(coverage.get('total', 0)))} observed)</h3>"
        f"<table><tr><th>Campaign</th><th>Status</th><th>Events</th><th>Objective</th></tr>{rows}</table>"
    )


def _notes_html(result: AnalysisResult) -> str:
    if not result.ai_notes:
        return '<div class="empty">No notes generated.</div>'
    return "\n".join(
        f"<article class=\"finding\"><h3>{html.escape(note.title)}</h3>"
        f"<p class=\"subtle\">{html.escape(note.summary)}</p>"
        f"<p><strong>Confidence:</strong> <code>{html.escape(note.confidence)}</code> "
        f"<strong>Source:</strong> <code>{html.escape(note.source)}</code></p>"
        f"{_list_items(note.evidence)}</article>"
        for note in result.ai_notes
    )
