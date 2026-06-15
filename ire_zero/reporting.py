"""Writers for JSON, Markdown, HTML, SARIF, and runtime collection artifacts."""

from __future__ import annotations

import html
import json
import os
import base64
import textwrap
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import AnalysisResult, Finding

SEVERITIES = ("critical", "high", "medium", "low", "info")


def write_reports(
    result: AnalysisResult,
    output_dir: Path,
    sarif: bool = False,
    html_report: bool = False,
    pdf_report: bool = False,
) -> None:
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
    if pdf_report:
        (output_dir / "report.pdf").write_bytes(render_pdf(result))


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


def render_pdf(result: AnalysisResult) -> bytes:
    """Render a polished, structured PDF report without external dependencies."""

    document = _StyledPdf(f"CipherDock Report - {result.app_name}")
    _render_pdf_cover(document, result)
    _render_pdf_summary(document, result)
    _render_pdf_findings(document, result)
    _render_pdf_static_evidence(document, result)
    _render_pdf_dynamic(document, result)
    _render_pdf_tools(document, result)
    return document.render()


def render_text_pdf(title: str, text: str) -> bytes:
    """Render arbitrary report text as a PDF document."""

    document = _StyledPdf(title)
    document.add_page()
    document.section(title)
    for line in _markdown_to_pdf_lines(text):
        if line:
            document.paragraph(line)
        else:
            document.space(6)
    return document.render()


def render_report_dict_pdf(payload: Dict[str, Any]) -> bytes:
    """Render a structured PDF from a serialized report.json payload."""

    app_name = str(payload.get("app_name") or "CipherDock Report")
    info = payload.get("info_plist", {}) if isinstance(payload.get("info_plist"), dict) else {}
    binary = payload.get("binary", {}) if isinstance(payload.get("binary"), dict) else {}
    strings = payload.get("strings", {}) if isinstance(payload.get("strings"), dict) else {}
    dynamic = payload.get("dynamic", {}) if isinstance(payload.get("dynamic"), dict) else {}
    findings = payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
    score = int(payload.get("score") or 0)
    document = _StyledPdf(f"CipherDock Report - {app_name}")
    document.add_page(header=False)
    document.rect(0, 0, document.width, document.height, fill=_PDF_COLORS["navy"])
    document.rect(34, 34, document.width - 68, document.height - 68, stroke=_PDF_COLORS["border"])
    document.text(54, 720, "CipherDock", size=28, font="bold", color=_PDF_COLORS["teal"])
    document.text(54, 692, "Hybrid iOS IPA Security Assessment", size=13, color=_PDF_COLORS["muted"])
    document.text(54, 632, app_name, size=24, font="bold", color=_PDF_COLORS["white"], max_width=420)
    document.text(54, 604, str(info.get("bundle_identifier") or "unknown bundle"), size=11, color=_PDF_COLORS["muted"], max_width=430)
    document.text(54, 584, str(payload.get("ipa_path") or ""), size=9, color=_PDF_COLORS["faint"], max_width=430)
    score_color = _pdf_score_color(score)
    document.rect(426, 574, 118, 118, fill=_PDF_COLORS["surface"], stroke=_PDF_COLORS["border"])
    document.rect(426, 574, 118, 7, fill=score_color)
    document.text(452, 642, str(score), size=34, font="bold", color=score_color)
    document.text(452, 622, "risk / 100", size=10, color=_PDF_COLORS["muted"])
    document.add_page()
    document.section("Executive Summary")
    document.paragraph(
        f"CipherDock analyzed {app_name} and produced a deterministic risk score of {score}/100. "
        "This PDF is generated from the stored report.json artifact."
    )
    severity_counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if isinstance(finding, dict):
            severity_counts[str(finding.get("severity", "info"))] = severity_counts.get(str(finding.get("severity", "info")), 0) + 1
    x = document.margin
    y = document.y
    for severity in SEVERITIES:
        document.metric_card(x, y - 56, 92, 46, severity.title(), str(severity_counts.get(severity, 0)), accent=_pdf_severity_color(severity))
        x += 100
    document.y -= 72
    breakdown = payload.get("score_breakdown", {}) if isinstance(payload.get("score_breakdown"), dict) else {}
    document.section("Score Breakdown")
    document.table([(str(key).replace("_", " ").title(), str(value)) for key, value in breakdown.items()], widths=[330, 120])
    document.section("Application Metadata")
    document.table(
        [
            ("Bundle ID", str(info.get("bundle_identifier") or "unknown")),
            ("Executable", str(payload.get("executable_path") or "")),
            ("URL Types", str(len(info.get("url_types", []) if isinstance(info.get("url_types"), list) else []))),
            ("Query Schemes", str(len(info.get("query_schemes", []) if isinstance(info.get("query_schemes"), list) else []))),
            ("Embedded Frameworks", str(len(binary.get("embedded_frameworks", []) if isinstance(binary.get("embedded_frameworks"), list) else []))),
            ("Embedded Dylibs", str(len(binary.get("embedded_dylibs", []) if isinstance(binary.get("embedded_dylibs"), list) else []))),
            ("Dynamic Status", str(dynamic.get("status") or payload.get("dynamic_status") or "not_captured")),
            ("Capture Mode", str(dynamic.get("capture_mode") or payload.get("capture_mode") or "not_captured")),
        ],
        widths=[150, 330],
    )
    document.add_page()
    document.section("Findings")
    for finding in findings[:40]:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence", [])
        evidence_text = "; ".join(str(item) for item in evidence[:4]) if isinstance(evidence, list) else ""
        body = str(finding.get("description") or "")
        if evidence_text:
            body += " Evidence: " + evidence_text
        document.card(
            str(finding.get("title") or finding.get("id") or "Finding"),
            body,
            footer=f"{finding.get('severity', 'info')} | {finding.get('category', 'uncategorized')} | {finding.get('confidence', 'medium')}",
        )
    document.add_page()
    document.section("Static And Dynamic Evidence")
    document.table(
        [
            ("URLs", str(len(strings.get("urls", []) if isinstance(strings.get("urls"), list) else []))),
            ("IP Addresses", str(len(strings.get("ips", []) if isinstance(strings.get("ips"), list) else []))),
            ("Secret Candidates", str(len(strings.get("secrets", []) if isinstance(strings.get("secrets"), list) else []))),
            ("Recovered Symbols", str(len(binary.get("symbols", []) if isinstance(binary.get("symbols"), list) else []))),
            ("Runtime Events", str(len(dynamic.get("events", []) if isinstance(dynamic.get("events"), list) else []))),
        ],
        widths=[220, 120],
    )
    document.list_block("Notable URLs", strings.get("urls", [])[:14] if isinstance(strings.get("urls"), list) else [])
    events = dynamic.get("events", []) if isinstance(dynamic.get("events"), list) else []
    if events:
        document.subsection("Observed Runtime Events")
        for event in events[:16]:
            if isinstance(event, dict):
                document.event_card(
                    str(event.get("layer") or "event"),
                    str(event.get("operation") or "observed"),
                    str(event.get("value") or ""),
                    str(event.get("correlation_status") or event.get("verdict") or "OBSERVED"),
                    str(event.get("source") or dynamic.get("evidence_source") or "authorized runtime capture"),
                )
    else:
        limitations = dynamic.get("limitations", []) if isinstance(dynamic.get("limitations"), list) else []
        document.list_block("Limitations", limitations)
    return document.render()


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
  <td><a href="{html.escape(rel)}/report.html">HTML</a> · <a href="{html.escape(rel)}/report.pdf">PDF</a> · <a href="{html.escape(rel)}/report.md">MD</a> · <a href="{html.escape(rel)}/report.json">JSON</a></td>
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


def _render_pdf_cover(document: "_StyledPdf", result: AnalysisResult) -> None:
    document.add_page(header=False)
    document.rect(0, 0, document.width, document.height, fill=_PDF_COLORS["navy"])
    document.rect(34, 34, document.width - 68, document.height - 68, stroke=_PDF_COLORS["border"])
    document.text(54, 720, "CipherDock", size=28, font="bold", color=_PDF_COLORS["teal"])
    document.text(54, 692, "Hybrid iOS IPA Security Assessment", size=13, color=_PDF_COLORS["muted"])
    document.text(54, 632, result.app_name, size=24, font="bold", color=_PDF_COLORS["white"], max_width=420)
    document.text(54, 604, result.info_plist.bundle_identifier or "unknown bundle", size=11, color=_PDF_COLORS["muted"], max_width=430)
    document.text(54, 584, result.ipa_path, size=9, color=_PDF_COLORS["faint"], max_width=430)
    score_color = _pdf_score_color(result.score)
    document.rect(426, 574, 118, 118, fill=_PDF_COLORS["surface"], stroke=_PDF_COLORS["border"])
    document.rect(426, 574, 118, 7, fill=score_color)
    document.text(452, 642, str(result.score), size=34, font="bold", color=score_color)
    document.text(452, 622, "risk / 100", size=10, color=_PDF_COLORS["muted"])
    document.text(54, 512, "Assessment Snapshot", size=15, font="bold", color=_PDF_COLORS["white"])
    grouped = _group_findings(result.findings)
    snapshot = [
        ("Findings", str(len(result.findings))),
        ("Critical/High", str(len(grouped.get("critical", [])) + len(grouped.get("high", [])))),
        ("Dynamic", result.dynamic.status.replace("_", " ")),
        ("Strings", str(result.strings.total_strings)),
    ]
    x = 54
    for label, value in snapshot:
        document.metric_card(x, 454, 112, 50, label, value)
        x += 122
    document.text(54, 404, "Generated artifacts include JSON, Markdown, HTML, SARIF, Frida hooks, runtime plan, and this PDF report.", size=10, color=_PDF_COLORS["muted"], max_width=490)


def _render_pdf_summary(document: "_StyledPdf", result: AnalysisResult) -> None:
    document.add_page()
    document.section("Executive Summary")
    document.paragraph(
        f"CipherDock analyzed {result.app_name} and produced a deterministic risk score of {result.score}/100. "
        f"The report combines plist metadata, entitlement and signing information, Mach-O structure, extracted strings, "
        f"symbol intelligence, heuristic findings, and optional runtime evidence."
    )
    grouped = _group_findings(result.findings)
    x = document.margin
    y = document.y
    for severity in SEVERITIES:
        document.metric_card(x, y - 56, 92, 46, severity.title(), str(len(grouped.get(severity, []))), accent=_pdf_severity_color(severity))
        x += 100
    document.y -= 72
    document.section("Score Breakdown")
    rows = [(key.replace("_", " ").title(), str(value)) for key, value in result.score_breakdown.items()]
    document.table(rows, widths=[330, 120])
    document.section("Application Metadata")
    document.table(
        [
            ("Bundle ID", result.info_plist.bundle_identifier or "unknown"),
            ("Executable", result.executable_path),
            ("URL Types", str(len(result.info_plist.url_types))),
            ("Query Schemes", str(len(result.info_plist.query_schemes))),
            ("Embedded Frameworks", str(len(result.binary.embedded_frameworks))),
            ("Embedded Dylibs", str(len(result.binary.embedded_dylibs))),
            ("Mach-O Sections", str(len(result.binary.sections))),
            ("Dynamic Status", result.dynamic.status),
            ("Capture Mode", result.dynamic.capture_mode),
        ],
        widths=[150, 330],
    )


def _render_pdf_findings(document: "_StyledPdf", result: AnalysisResult) -> None:
    document.add_page()
    document.section("Findings")
    grouped = _group_findings(result.findings)
    if not result.findings:
        document.empty("No findings were produced.")
        return
    for severity in SEVERITIES:
        findings = grouped.get(severity, [])
        if not findings:
            continue
        document.subsection(f"{severity.title()} Findings ({len(findings)})", color=_pdf_severity_color(severity))
        for finding in findings:
            document.finding_card(finding)


def _render_pdf_static_evidence(document: "_StyledPdf", result: AnalysisResult) -> None:
    document.add_page()
    document.section("Static Evidence")
    document.subsection("Network And Secret Strings")
    document.table(
        [
            ("URLs", str(len(result.strings.urls))),
            ("IP Addresses", str(len(result.strings.ips))),
            ("Secret Candidates", str(len(result.strings.secrets))),
            ("Suspicious Keyword Groups", str(len(result.strings.suspicious_keywords))),
        ],
        widths=[210, 120],
    )
    document.list_block("Notable URLs", result.strings.urls[:12])
    document.list_block("Secret Candidates", result.strings.secrets[:8])
    document.subsection("Bundle And Mach-O Inventory")
    document.table(
        [
            ("Linked Libraries", str(len(result.binary.linked_libraries))),
            ("Embedded Frameworks", str(len(result.binary.embedded_frameworks))),
            ("Embedded Dylibs", str(len(result.binary.embedded_dylibs))),
            ("Recovered Symbols", str(len(result.binary.symbols))),
            ("Static Evidence Items", str(len(result.binary.evidence))),
        ],
        widths=[210, 120],
    )
    document.list_block("Embedded Frameworks", result.binary.embedded_frameworks[:12])
    if result.binary.symbol_categories:
        document.subsection("Symbol Categories")
        rows = [(key.replace("_", " ").title(), str(len(values))) for key, values in sorted(result.binary.symbol_categories.items())]
        document.table(rows, widths=[260, 80])


def _render_pdf_dynamic(document: "_StyledPdf", result: AnalysisResult) -> None:
    document.add_page()
    document.section("Dynamic Capture")
    document.table(
        [
            ("Status", result.dynamic.status),
            ("Capture Mode", result.dynamic.capture_mode),
            ("Evidence Source", result.dynamic.evidence_source or "none"),
            ("Session", result.dynamic.session or "none"),
            ("Events", str(len(result.dynamic.events))),
            ("Planned Probes", str(len(result.dynamic.probes))),
        ],
        widths=[150, 330],
    )
    coverage = result.dynamic.campaign_coverage
    if coverage:
        document.subsection("Campaign Coverage")
        document.table(
            [
                (
                    str(campaign.get("title", "Campaign")),
                    str(campaign.get("status", "planned")),
                    str(campaign.get("event_count", 0)),
                )
                for campaign in coverage.get("campaigns", [])[:14]
            ],
            widths=[260, 120, 70],
        )
    if result.dynamic.events:
        document.subsection("Observed Events")
        for event in result.dynamic.events[:18]:
            document.event_card(
                event.layer,
                event.operation,
                event.value,
                event.correlation_status,
                event.source or result.dynamic.evidence_source or "authorized runtime capture",
            )
    else:
        document.list_block("Limitations", result.dynamic.limitations)
        document.list_block("Planned Probes", [f"{probe.priority} {probe.layer} {probe.operation}: {probe.target}" for probe in result.dynamic.probes[:12]])


def _render_pdf_tools(document: "_StyledPdf", result: AnalysisResult) -> None:
    document.add_page()
    document.section("Tool Status And Notes")
    if result.ai_notes:
        document.subsection("Analyst Notes")
        for note in result.ai_notes[:8]:
            document.card(note.title, note.summary, footer=f"Confidence: {note.confidence} | Source: {note.source}")
    if result.binary.tools:
        document.subsection("Tool Availability")
        rows = [
            (name, "available" if tool.available else "missing", tool.error or "")
            for name, tool in sorted(result.binary.tools.items())
        ]
        document.table(rows, widths=[150, 90, 250])
    if result.errors:
        document.list_block("Analysis Errors", result.errors)


def _markdown_to_pdf_lines(markdown: str) -> List[str]:
    lines: List[str] = []
    for raw_line in markdown.splitlines():
        cleaned = raw_line.replace("`", "").replace("**", "").strip()
        if cleaned.startswith("#### "):
            cleaned = cleaned[5:].upper()
        elif cleaned.startswith("### "):
            cleaned = cleaned[4:].upper()
        elif cleaned.startswith("## "):
            cleaned = cleaned[3:].upper()
        elif cleaned.startswith("# "):
            cleaned = cleaned[2:].upper()
        if not cleaned:
            lines.append("")
            continue
        indent = "  " if cleaned.startswith("- ") else ""
        text = cleaned[2:] if cleaned.startswith("- ") else cleaned
        wrapped = textwrap.wrap(text, width=92, subsequent_indent=indent + "  ") or [""]
        lines.extend(indent + line if index == 0 else line for index, line in enumerate(wrapped))
    return lines


def _paginate_pdf_lines(lines: List[str], lines_per_page: int = 52) -> List[List[str]]:
    pages: List[List[str]] = []
    current: List[str] = []
    for line in lines:
        if len(current) >= lines_per_page:
            pages.append(current)
            current = []
        current.append(line)
    if current:
        pages.append(current)
    return pages or [["No report content."]]


_PDF_COLORS = {
    "white": (0.91, 0.94, 0.97),
    "muted": (0.58, 0.65, 0.72),
    "faint": (0.40, 0.46, 0.52),
    "navy": (0.05, 0.07, 0.10),
    "surface": (0.09, 0.12, 0.16),
    "surface2": (0.13, 0.16, 0.20),
    "border": (0.22, 0.27, 0.33),
    "teal": (0.31, 0.79, 0.75),
    "green": (0.51, 0.77, 0.44),
    "amber": (0.90, 0.68, 0.31),
    "red": (0.93, 0.43, 0.43),
    "blue": (0.42, 0.65, 1.00),
    "violet": (0.72, 0.57, 1.00),
}


class _StyledPdf:
    width = 612
    height = 792
    margin = 42

    def __init__(self, title: str) -> None:
        self.title = title
        self.pages: List[List[str]] = []
        self.commands: List[str] = []
        self.y = 742

    def add_page(self, header: bool = True) -> None:
        if self.commands:
            self.pages.append(self.commands)
        self.commands = []
        self.y = 742
        self.rect(0, 0, self.width, self.height, fill=(0.98, 0.99, 1.0))
        if header:
            self.rect(0, 748, self.width, 44, fill=_PDF_COLORS["navy"])
            self.text(self.margin, 770, "CipherDock", size=12, font="bold", color=_PDF_COLORS["teal"])
            self.text(128, 770, self.title[:78], size=9, color=_PDF_COLORS["muted"])
            self.y = 724

    def render(self) -> bytes:
        if self.commands:
            self.pages.append(self.commands)
            self.commands = []
        if not self.pages:
            self.add_page()
            self.pages.append(self.commands)
        streams = ["\n".join(page).encode("latin-1", errors="replace") for page in self.pages]
        return _build_pdf_streams(streams)

    def ensure(self, height: float) -> None:
        if self.y - height < 48:
            self.add_page()

    def section(self, title: str) -> None:
        self.ensure(38)
        self.space(6)
        self.text(self.margin, self.y, title, size=16, font="bold", color=_PDF_COLORS["navy"])
        self.line(self.margin, self.y - 8, self.width - self.margin, self.y - 8, color=_PDF_COLORS["teal"], width=1.2)
        self.y -= 28

    def subsection(self, title: str, color: tuple[float, float, float] = _PDF_COLORS["navy"]) -> None:
        self.ensure(28)
        self.text(self.margin, self.y, title, size=12, font="bold", color=color)
        self.y -= 20

    def paragraph(self, text: str, size: int = 9, color: tuple[float, float, float] = _PDF_COLORS["surface"]) -> None:
        lines = _wrap_pdf_text(text, 100)
        self.ensure(len(lines) * 12 + 4)
        for line in lines:
            self.text(self.margin, self.y, line, size=size, color=color)
            self.y -= 12
        self.y -= 4

    def empty(self, text: str) -> None:
        self.card("No Evidence", text)

    def metric_card(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        label: str,
        value: str,
        accent: tuple[float, float, float] = _PDF_COLORS["teal"],
    ) -> None:
        self.rect(x, y, width, height, fill=(0.96, 0.98, 0.99), stroke=(0.80, 0.84, 0.88))
        self.rect(x, y + height - 5, width, 5, fill=accent)
        self.text(x + 9, y + height - 18, label.upper(), size=7, color=_PDF_COLORS["faint"])
        self.text(x + 9, y + 14, value[:28], size=15, font="bold", color=accent)

    def table(self, rows: List[tuple[str, ...]], widths: List[int]) -> None:
        if not rows:
            self.empty("No table rows available.")
            return
        row_height = 20
        total_width = sum(widths)
        for row_index, row in enumerate(rows):
            cell_lines = [
                _wrap_pdf_text(str(value), max(10, int(widths[index] / 5.3)))
                for index, value in enumerate(row)
            ]
            height = max(row_height, max(len(lines) for lines in cell_lines) * 10 + 8)
            self.ensure(height + 2)
            y = self.y - height
            self.rect(self.margin, y, total_width, height, fill=(0.97, 0.98, 0.99) if row_index % 2 else (0.93, 0.95, 0.97), stroke=(0.82, 0.86, 0.90))
            x = self.margin
            for index, lines in enumerate(cell_lines):
                if index:
                    self.line(x, y, x, y + height, color=(0.82, 0.86, 0.90), width=0.4)
                font = "bold" if index == 0 else "regular"
                for line_index, line in enumerate(lines[:4]):
                    self.text(x + 6, y + height - 13 - line_index * 10, line, size=8, font=font, color=_PDF_COLORS["surface"])
                x += widths[index]
            self.y -= height
        self.y -= 10

    def card(self, title: str, body: str, footer: str = "") -> None:
        body_lines = _wrap_pdf_text(body, 92)
        footer_lines = _wrap_pdf_text(footer, 92) if footer else []
        height = 34 + len(body_lines) * 11 + len(footer_lines) * 10
        self.ensure(height + 8)
        y = self.y - height
        self.rect(self.margin, y, self.width - self.margin * 2, height, fill=(0.97, 0.98, 0.99), stroke=(0.82, 0.86, 0.90))
        self.text(self.margin + 12, y + height - 18, title[:92], size=10, font="bold", color=_PDF_COLORS["navy"])
        line_y = y + height - 33
        for line in body_lines:
            self.text(self.margin + 12, line_y, line, size=8, color=_PDF_COLORS["surface"])
            line_y -= 11
        for line in footer_lines:
            self.text(self.margin + 12, line_y - 2, line, size=7, color=_PDF_COLORS["faint"])
            line_y -= 10
        self.y -= height + 8

    def finding_card(self, finding: Finding) -> None:
        accent = _pdf_severity_color(finding.severity)
        evidence = "; ".join(finding.evidence[:4])
        body_parts = [finding.description]
        if finding.recommendation:
            body_parts.append("Recommendation: " + finding.recommendation)
        if evidence:
            body_parts.append("Evidence: " + evidence)
        footer = f"{finding.id} | {finding.category} | confidence: {finding.confidence}"
        height_hint = 76 + len(_wrap_pdf_text(" ".join(body_parts), 92)) * 6
        self.ensure(min(150, height_hint))
        y_start = self.y
        self.card(finding.title, " ".join(body_parts), footer=footer)
        self.rect(self.margin, self.y + 8, 5, y_start - self.y - 8, fill=accent)

    def event_card(self, layer: str, operation: str, value: str, verdict: str, source: str) -> None:
        self.card(f"{layer.upper()} | {operation}", value, footer=f"{verdict} | {source}")

    def list_block(self, title: str, values: Iterable[str]) -> None:
        items = [str(value) for value in values if str(value)]
        self.subsection(title)
        if not items:
            self.empty("None observed.")
            return
        for item in items[:18]:
            self.paragraph("- " + item, size=8)

    def space(self, height: float) -> None:
        self.y -= height

    def rect(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
    ) -> None:
        if fill:
            self.commands.append(_pdf_color(fill, fill_op=True))
        if stroke:
            self.commands.append(_pdf_color(stroke, fill_op=False))
        op = "B" if fill and stroke else "f" if fill else "S"
        self.commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re {op}")

    def line(self, x1: float, y1: float, x2: float, y2: float, color: tuple[float, float, float], width: float = 1.0) -> None:
        self.commands.append(_pdf_color(color, fill_op=False))
        self.commands.append(f"{width:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def text(
        self,
        x: float,
        y: float,
        text: str,
        size: int = 9,
        font: str = "regular",
        color: tuple[float, float, float] = _PDF_COLORS["surface"],
        max_width: int | None = None,
    ) -> None:
        lines = _wrap_pdf_text(text, max_width // max(4, int(size * 0.52)) if max_width else 999)
        font_name = "/F2" if font == "bold" else "/F1"
        for index, line in enumerate(lines[:3]):
            self.commands.append(_pdf_color(color, fill_op=True))
            self.commands.append(f"BT {font_name} {size} Tf {x:.2f} {y - index * (size + 3):.2f} Td ({_pdf_escape(line)}) Tj ET")


def _wrap_pdf_text(value: str, width: int) -> List[str]:
    cleaned = " ".join(str(value).replace("\n", " ").split())
    if not cleaned:
        return [""]
    return textwrap.wrap(cleaned, width=width, break_long_words=True, replace_whitespace=True) or [cleaned]


def _pdf_score_color(score: int) -> tuple[float, float, float]:
    if score >= 70:
        return _PDF_COLORS["red"]
    if score >= 35:
        return _PDF_COLORS["amber"]
    return _PDF_COLORS["green"]


def _pdf_severity_color(severity: str) -> tuple[float, float, float]:
    if severity in {"critical", "high"}:
        return _PDF_COLORS["red"]
    if severity == "medium":
        return _PDF_COLORS["amber"]
    if severity == "low":
        return _PDF_COLORS["blue"]
    return _PDF_COLORS["muted"]


def _pdf_color(color: tuple[float, float, float], fill_op: bool) -> str:
    op = "rg" if fill_op else "RG"
    return f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} {op}"


def _build_pdf_streams(page_streams: List[bytes]) -> bytes:
    objects: List[bytes] = []
    page_object_ids: List[int] = []
    regular_font_id = 3
    bold_font_id = 4
    pages_id = 2

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    add_object(_pdf_dict({"Type": "/Catalog", "Pages": f"{pages_id} 0 R"}))
    add_object(b"")
    add_object(_pdf_dict({"Type": "/Font", "Subtype": "/Type1", "BaseFont": "/Helvetica"}))
    add_object(_pdf_dict({"Type": "/Font", "Subtype": "/Type1", "BaseFont": "/Helvetica-Bold"}))

    for content in page_streams:
        content_id = add_object(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")
        page_id = add_object(
            _pdf_dict(
                {
                    "Type": "/Page",
                    "Parent": f"{pages_id} 0 R",
                    "MediaBox": "[0 0 612 792]",
                    "Resources": f"<< /Font << /F1 {regular_font_id} 0 R /F2 {bold_font_id} 0 R >> >>",
                    "Contents": f"{content_id} 0 R",
                }
            )
        )
        page_object_ids.append(page_id)

    objects[pages_id - 1] = _pdf_dict(
        {
            "Type": "/Pages",
            "Kids": "[" + " ".join(f"{page_id} 0 R" for page_id in page_object_ids) + "]",
            "Count": str(len(page_object_ids)),
        }
    )
    return _serialize_pdf(objects)


def _pdf_dict(values: Dict[str, str]) -> bytes:
    body = " ".join(f"/{key} {value}" for key, value in values.items())
    return f"<< {body} >>".encode("ascii")


def _serialize_pdf(objects: List[bytes]) -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            "trailer\n"
            f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            "startxref\n"
            f"{xref_offset}\n"
            "%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
