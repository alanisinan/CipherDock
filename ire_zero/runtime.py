"""Runtime trace normalization, static correlation, probes, and dynamic findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .models import BinaryArtifacts, CaptureMode, CorrelationStatus, DynamicCapture, Finding, PlistInfo, RuntimeCampaign, RuntimeEvent, RuntimeProbe, StringIndicators


def load_runtime_capture(
    path: Optional[Path],
    capture_mode: CaptureMode = "exact_ipa",
    source: Optional[str] = None,
    session: Optional[str] = None,
) -> DynamicCapture:
    if path is None:
        return DynamicCapture()
    payload = _read_payload(path)
    raw_events: Iterable[object]
    payload_session: Optional[str] = None
    if isinstance(payload, dict):
        if isinstance(payload.get("events"), list):
            raw_events = payload["events"]
            session_value = payload.get("session")
            payload_session = str(session_value) if session_value else None
        elif payload.get("type") == "send" and isinstance(payload.get("payload"), dict):
            raw_events = [payload["payload"]]
        elif any(key in payload for key in ("timestamp", "layer", "operation", "value", "url")):
            raw_events = [payload]
        else:
            raw_events = []
    elif isinstance(payload, list):
        raw_events = payload
    else:
        raise ValueError("Runtime trace must be a JSON array, JSON object with events, or JSONL records")
    events = [
        event
        for index, item in enumerate(raw_events)
        if (event := _normalize_event(item, index)) is not None
    ]
    observed_mode: CaptureMode = capture_mode if events else "not_captured"
    evidence_source = _capture_source(observed_mode)
    return DynamicCapture(
        status=_capture_status(observed_mode) if events else "empty_capture",
        capture_mode=observed_mode,
        source=source or str(path),
        evidence_source=evidence_source,
        session=session or payload_session or path.stem,
        events=events,
        limitations=[] if events else ["A trace file was supplied, but it contained no normalized runtime events."],
    )


def runtime_findings(capture: DynamicCapture) -> List[Finding]:
    if not capture.events:
        return []
    findings: List[Finding] = []
    keychain = [event for event in capture.events if event.layer == "keychain" and "accessiblealways" in event.value.lower()]
    if keychain:
        findings.append(
            Finding(
                id="dynamic.keychain_accessibility",
                title="Runtime keychain operation uses broad accessibility",
                severity="high",
                category="dynamic-keychain",
                description="Captured execution observed a keychain operation using kSecAttrAccessibleAlways.",
                evidence=[f"{event.timestamp} {event.operation} {event.value}" for event in keychain[:10]],
                recommendation="Use a narrower accessibility class and verify that tokens cannot be retrieved unnecessarily.",
                confidence="high",
            )
        )
    cleartext = [event for event in capture.events if event.layer == "network" and "http://" in event.value.lower()]
    if cleartext:
        findings.append(
            Finding(
                id="dynamic.cleartext_network",
                title="Runtime cleartext network request observed",
                severity="high",
                category="dynamic-network",
                description="Captured execution contacted an HTTP endpoint without TLS.",
                evidence=[f"{event.timestamp} {event.value}" for event in cleartext[:10]],
                recommendation="Require HTTPS for all observed runtime requests.",
                confidence="high",
            )
        )
    private_calls = [
        event for event in capture.events
        if "cpdistributedmessagingcenter" in (event.operation + " " + event.value).lower()
    ]
    if private_calls:
        findings.append(
            Finding(
                id="dynamic.private_api_call",
                title="Private API invocation captured",
                severity="high",
                category="dynamic-private-api",
                description="Runtime evidence confirms execution of a private iOS messaging API.",
                evidence=[f"{event.timestamp} {event.operation} {event.value}" for event in private_calls[:10]],
                recommendation="Remove private API calls or justify them for the authorized research target.",
                confidence="high",
            )
        )
    pasteboard_reads = [
        event for event in capture.events
        if "uipasteboard" in event.operation.lower() and "set" not in event.operation.lower()
    ]
    if pasteboard_reads:
        findings.append(
            Finding(
                id="dynamic.pasteboard_read",
                title="Pasteboard read observed during tested workflow",
                severity="medium",
                category="dynamic-privacy",
                description="Captured execution accessed pasteboard content; confirm that the access followed clear user intent.",
                evidence=[f"{event.timestamp} {event.operation} {event.value}" for event in pasteboard_reads[:10]],
                recommendation="Limit clipboard reads to user-initiated actions and avoid background polling.",
                confidence="high",
            )
        )
    scheme_probes = [event for event in capture.events if "canopenurl" in event.operation.lower()]
    if scheme_probes:
        findings.append(
            Finding(
                id="dynamic.url_scheme_probe",
                title="Installed-app discovery check observed",
                severity="low",
                category="dynamic-privacy",
                description="Captured execution used canOpenURL to query an application URL scheme.",
                evidence=[f"{event.timestamp} {event.operation} {event.value}" for event in scheme_probes[:10]],
                recommendation="Only query URL schemes required for a user-facing integration.",
                confidence="high",
            )
        )
    tamper_probes = [
        event for event in capture.events
        if any(marker in (event.operation + " " + event.value).lower() for marker in ("cydia", "substrate", "frida", "jailbreak"))
    ]
    if tamper_probes:
        findings.append(
            Finding(
                id="dynamic.anti_analysis_probe",
                title="Anti-analysis or jailbreak probe executed",
                severity="medium",
                category="dynamic-tamper",
                description="Captured execution inspected a known jailbreak or instrumentation indicator.",
                evidence=[f"{event.timestamp} {event.operation} {event.value}" for event in tamper_probes[:10]],
                recommendation="Document tamper-response behavior and verify it does not conceal unrelated privacy or security risks.",
                confidence="high",
            )
        )
    return findings


def runtime_observation_findings(capture: DynamicCapture) -> List[Finding]:
    """Expose captured runtime events as informational, non-scored findings."""
    if not capture.events:
        return []
    findings: List[Finding] = []
    for event in capture.events:
        evidence = [
            f"Source: {event.source or capture.evidence_source or 'authorized runtime capture'}",
            f"{event.timestamp} {event.operation}: {event.value}",
        ]
        if event.correlation_status:
            evidence.append(f"Static correlation: {event.correlation_status}")
        findings.append(
            Finding(
                id=f"dynamic.observation.{event.id}",
                title=f"Runtime event observed: {event.operation}",
                severity="info",
                category="dynamic-network" if event.layer == "network" else "dynamic-observation",
                description="An authorized runtime capture recorded this behavior; it is evidence rather than an automatic risk condition.",
                evidence=evidence,
                confidence="high",
            )
        )
    return findings


def correlate_runtime_events(
    capture: DynamicCapture,
    plist: PlistInfo,
    binary: BinaryArtifacts,
    indicators: StringIndicators,
) -> None:
    if not capture.events:
        return
    for event in capture.events:
        correlations = list(event.static_evidence)
        text = f"{event.layer} {event.operation} {event.value}".lower()
        event.source = capture.evidence_source or _capture_source(capture.capture_mode)
        if "instrumentation attached" in text:
            correlations.append(f"Analyzed executable: {binary.executable_path}")
            if binary.platform:
                correlations.append(f"Mach-O platform: {binary.platform}")
        if event.layer == "network" or "urlsession" in text or "trust" in text:
            runtime_url = event.value.rstrip("/")
            runtime_host = (urlparse(event.value).hostname or "").lower()
            for url in indicators.urls:
                if runtime_url and runtime_url == url.rstrip("/"):
                    correlations.append(f"Recovered URL string: {url}")
                    continue
                static_host = (urlparse(url).hostname or "").lower()
                if not runtime_host or not static_host:
                    continue
                if _domain_family(runtime_host) == _domain_family(static_host):
                    correlations.append(f"Related recovered domain string: {url}")
            exception_domains = plist.app_transport_security.get("NSExceptionDomains", {})
            if isinstance(exception_domains, dict):
                for domain in exception_domains:
                    normalized = str(domain).lower()
                    if runtime_host == normalized or runtime_host.endswith("." + normalized):
                        correlations.append(f"ATS exception domain: {domain}")
            correlations.extend(
                f"Recovered networking artifact: {value}"
                for value in binary.symbol_categories.get("networking", [])[:2]
            )
        if "canopenurl" in text:
            scheme = event.value.split(":", 1)[0].lower()
            for declared in plist.query_schemes:
                if scheme == declared.lower():
                    correlations.append(f"Declared LSApplicationQueriesSchemes value: {declared}")
        category_triggers = (
            ("pasteboard", "pasteboard"),
            ("secitem", "storage_keychain"),
            ("keychain", "storage_keychain"),
            ("crypt", "crypto"),
        )
        for marker, category in category_triggers:
            if marker in text:
                correlations.extend(
                    f"Recovered {category.replace('_', ' ')} artifact: {value}"
                    for value in binary.symbol_categories.get(category, [])[:2]
                )
        if any(marker in text for marker in ("cydia", "substrate", "frida", "jailbreak", "fileexistsatpath", "dlopen")):
            correlations.extend(
                f"Recovered anti-analysis artifact: {value}"
                for value in binary.symbol_categories.get("jailbreak_instrumentation", [])[:3]
            )
        event.static_evidence = _dedupe_strings(correlations)[:8]
    capture.cross_layer = cross_layer_correlation(capture, indicators)


def cross_layer_correlation(capture: DynamicCapture, indicators: StringIndicators) -> Dict[str, Any]:
    """Classify dynamic events against exact, domain-related, or absent static evidence."""
    output: List[Dict[str, Any]] = []
    summary = {"CONFIRMED": 0, "DOMAIN_MATCH": 0, "DYNAMIC_ONLY": 0}
    for event in capture.events:
        text = f"{event.layer} {event.operation} {event.value}".lower()
        evidence = [
            item
            for item in event.static_evidence
            if not item.startswith("Correlation verdict:")
        ]
        label: CorrelationStatus = "DYNAMIC_ONLY"
        matched_static: List[str] = []
        if event.layer == "network" or "urlsession" in text or "trust" in text:
            observed_url = event.value.rstrip("/")
            observed_host = (urlparse(event.value).hostname or "").lower()
            exact_urls = [url for url in indicators.urls if observed_url and observed_url == url.rstrip("/")]
            domain_urls = [
                url
                for url in indicators.urls
                if observed_host
                and (urlparse(url).hostname or "")
                and _domain_family(observed_host) == _domain_family((urlparse(url).hostname or "").lower())
            ]
            if exact_urls:
                label = "CONFIRMED"
                matched_static = exact_urls
            elif domain_urls:
                label = "DOMAIN_MATCH"
                matched_static = domain_urls
        elif "instrumentation attached" not in text and evidence:
            label = "CONFIRMED"
            matched_static = evidence[:3]
        event.correlation_status = label
        event.verdict = label
        event.static_evidence = _dedupe_strings([f"Correlation verdict: {label}", *evidence])[:8]
        summary[label] += 1
        output.append(
            {
                "event_id": event.id,
                "operation": event.operation,
                "value": event.value,
                "label": label,
                "static_matches": matched_static[:8],
            }
        )
    return {"events": output, "summary": summary}


def generate_runtime_probes(
    plist: PlistInfo,
    entitlements: Dict[str, object],
    binary: BinaryArtifacts,
    indicators: StringIndicators,
    findings: Iterable[Finding],
) -> List[RuntimeProbe]:
    probes: List[RuntimeProbe] = []
    static_findings = list(findings)
    exception_domains = plist.app_transport_security.get("NSExceptionDomains", {})
    if isinstance(exception_domains, dict):
        for domain, configuration in list(exception_domains.items())[:8]:
            if isinstance(configuration, dict) and configuration.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                probes.append(
                    RuntimeProbe(
                        id=f"probe-ats-{_safe_id(str(domain))}",
                        layer="network",
                        operation="URLSessionTask.resume",
                        target=str(domain),
                        rationale="Verify whether an ATS exception domain is contacted over cleartext HTTP.",
                        priority="high",
                        evidence=[f"NSExceptionAllowsInsecureHTTPLoads = true for {domain}"],
                        capture_method="Capture Network.framework or URLSession requests and TLS metadata.",
                    )
                )
    endpoint_urls = [url for url in indicators.urls if not _is_platform_url(url)]
    for index, url in enumerate(endpoint_urls[:4]):
        probes.append(
            RuntimeProbe(
                id=f"probe-url-{index}",
                layer="network",
                operation="URLSessionTask.resume",
                target=url,
                rationale="Determine whether a recovered endpoint is reachable during tested workflows and what data is sent.",
                priority="medium" if url.lower().startswith("http://") else "low",
                evidence=[url],
                capture_method="Record URLSession/Network.framework requests with endpoint and response metadata.",
            )
        )
    categories = binary.symbol_categories
    if categories.get("networking") and not endpoint_urls:
        probes.append(
            RuntimeProbe(
                id="probe-network-stack",
                layer="network",
                operation="URLSessionTask.resume",
                target="recovered networking call sites",
                rationale="Identify hosts and payload classes used by the app at runtime.",
                priority="low",
                evidence=categories["networking"][:3],
                capture_method="Trace URLSessionTask resume calls and correlate stack symbols.",
            )
        )
    if categories.get("storage_keychain"):
        probes.append(
            RuntimeProbe(
                id="probe-keychain",
                layer="keychain",
                operation="SecItemAdd / SecItemCopyMatching / SecItemUpdate",
                target="keychain access groups and accessibility classes",
                rationale="Verify secret storage accessibility and whether credentials leave intended scope.",
                priority="high",
                evidence=categories["storage_keychain"][:5],
                capture_method="Hook Security.framework SecItem APIs and capture attributes without secret values.",
            )
        )
    pasteboard_evidence = categories.get("pasteboard", []) or indicators.suspicious_keywords.get("pasteboard", [])
    if pasteboard_evidence:
        probes.append(
            RuntimeProbe(
                id="probe-pasteboard",
                layer="process",
                operation="UIPasteboard reads and writes",
                target="pasteboard contents and triggering workflow",
                rationale="Confirm whether clipboard access occurs only after explicit user action.",
                priority="medium",
                evidence=pasteboard_evidence[:5],
                capture_method="Trace UIPasteboard selectors and record data type only.",
            )
        )
    if categories.get("private_api"):
        probes.append(
            RuntimeProbe(
                id="probe-private-api",
                layer="process",
                operation="private API entry points",
                target="reachable private framework calls",
                rationale="Determine whether recovered private API references are executed.",
                priority="high",
                evidence=categories["private_api"][:5],
                capture_method="Hook recovered private API symbols and record call stacks.",
            )
        )
    if categories.get("jailbreak_instrumentation") or any(
        indicators.suspicious_keywords.get(marker) for marker in ("jailbreak", "cydia", "frida", "substrate")
    ):
        probes.append(
            RuntimeProbe(
                id="probe-anti-analysis",
                layer="process",
                operation="fileExistsAtPath / dlopen / sysctl",
                target="jailbreak and instrumentation checks",
                rationale="Observe whether anti-analysis checks execute and change application behavior.",
                priority="medium",
                evidence=_anti_analysis_evidence(categories, indicators),
                capture_method="Instrument filesystem, dynamic-loader, and process-inspection calls.",
            )
        )
    if categories.get("crypto"):
        probes.append(
            RuntimeProbe(
                id="probe-crypto",
                layer="process",
                operation="CryptoKit / Security cryptographic operations",
                target="key creation, signing, and protected payload flows",
                rationale="Correlate cryptographic operations with authentication and network workflows.",
                priority="low",
                evidence=categories["crypto"][:5],
                capture_method="Record cryptographic API names and call stacks; do not extract keys.",
            )
        )
    analytics_finding = next((finding for finding in static_findings if finding.id == "symbols.analytics_tracking"), None)
    if analytics_finding:
        probes.append(
            RuntimeProbe(
                id="probe-telemetry",
                layer="network",
                operation="telemetry request dispatch",
                target="analytics or attribution traffic",
                rationale="Validate whether recovered SDK indicators produce runtime data transfers.",
                priority="medium",
                evidence=analytics_finding.evidence[:5],
                capture_method="Capture outgoing requests and correlate them with the triggering UI action.",
            )
        )
    if plist.query_schemes:
        probes.append(
            RuntimeProbe(
                id="probe-url-schemes",
                layer="process",
                operation="UIApplication.canOpenURL",
                target=", ".join(plist.query_schemes[:8]),
                rationale="Determine which installed-app discovery checks occur during normal flows.",
                priority="medium",
                evidence=[f"LSApplicationQueriesSchemes: {scheme}" for scheme in plist.query_schemes[:8]],
                capture_method="Trace canOpenURL calls and user workflow that triggered them.",
            )
        )
    entitlement_keys = set(entitlements)
    if "com.apple.developer.associated-domains" in entitlement_keys:
        values = entitlements.get("com.apple.developer.associated-domains")
        probes.append(
            RuntimeProbe(
                id="probe-associated-domains",
                layer="network",
                operation="associated domain resolution",
                target=str(values) if values else "declared associated domains",
                rationale="Verify universal-link and web-credential domain contacts.",
                priority="low",
                evidence=["com.apple.developer.associated-domains entitlement"],
                capture_method="Capture associated-domain requests and matched application links.",
            )
        )
    return _dedupe_probes(probes)[:20]


def generate_runtime_campaigns(probes: List[RuntimeProbe]) -> List[RuntimeCampaign]:
    campaigns = [
        RuntimeCampaign(
            id="campaign-startup",
            title="Launch Baseline",
            objective="Confirm the app launches under observation and capture startup behavior.",
            layers=["process"],
            workflow=["Start capture with Spawn.", "Wait for the initial screen to load.", "Record launch and first-use events."],
        )
    ]
    specs = [
        (
            "campaign-network",
            "Network & TLS",
            "Observe outbound destinations and trust-evaluation surfaces during network activity.",
            lambda probe: probe.layer == "network",
            ["network"],
            ["Launch the app.", "Refresh a network-backed view.", "Review endpoints and TLS calls."],
        ),
        (
            "campaign-storage",
            "Secrets & Storage",
            "Observe keychain and local-storage APIs without collecting secret values.",
            lambda probe: probe.layer in {"keychain", "file"} or "userdefaults" in probe.operation.lower(),
            ["keychain", "file"],
            ["Sign in or change an account setting.", "Trigger persistence.", "Review redacted storage operations."],
        ),
        (
            "campaign-privacy",
            "Privacy Access",
            "Measure clipboard and installed-application discovery behavior.",
            lambda probe: any(term in probe.operation.lower() for term in ("pasteboard", "canopenurl")),
            ["process"],
            ["Open sharing or compose surfaces.", "Exercise external-app integrations.", "Review access timing."],
        ),
        (
            "campaign-tamper",
            "Tamper Response",
            "Detect executed jailbreak and instrumentation checks during launch or sensitive flows.",
            lambda probe: any(term in probe.operation.lower() for term in ("fileexists", "dlopen", "sysctl", "private api")),
            ["process"],
            ["Launch under observation.", "Exercise protected screens.", "Review executed integrity checks."],
        ),
        (
            "campaign-crypto",
            "Cryptographic Use",
            "Observe cryptographic entry points without exposing keys or payload material.",
            lambda probe: "cryptographic" in probe.operation.lower(),
            ["process"],
            ["Trigger authentication or signing flows.", "Review cryptographic API events."],
        ),
    ]
    for campaign_id, title, objective, selector, layers, workflow in specs:
        matching = [probe.id for probe in probes if selector(probe)]
        if matching:
            campaigns.append(
                RuntimeCampaign(
                    id=campaign_id,
                    title=title,
                    objective=objective,
                    layers=layers,
                    probe_ids=matching,
                    workflow=workflow,
                )
            )
    return campaigns


def measure_campaign_coverage(campaigns: List[RuntimeCampaign], events: List[RuntimeEvent]) -> Dict[str, Any]:
    measured: List[Dict[str, Any]] = []
    for campaign in campaigns:
        matched = [event for event in events if _campaign_matches(campaign.id, event)]
        record = campaign.to_dict()
        record.update(
            {
                "status": "observed" if matched else ("not_observed" if events else "planned"),
                "event_count": len(matched),
                "event_ids": [event.id for event in matched],
            }
        )
        measured.append(record)
    return {
        "total": len(measured),
        "observed": sum(1 for item in measured if item["status"] == "observed"),
        "campaigns": measured,
    }


def _read_payload(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        records: List[object] = []
        for source_line in text.splitlines():
            line = source_line.strip()
            if "IRE_ZERO_EVENT " in line:
                line = line.split("IRE_ZERO_EVENT ", 1)[1]
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and record.get("type") == "send" and isinstance(record.get("payload"), dict):
                record = record["payload"]
            records.append(record)
        if records:
            return records
        raise ValueError("Runtime trace contains no JSON events or IRE_ZERO_EVENT records")


def _normalize_event(item: object, index: int) -> Optional[RuntimeEvent]:
    if not isinstance(item, dict):
        return None
    timestamp = _field(item, "timestamp", "time", default=f"event-{index + 1}")
    layer = _field(item, "layer", "category", "type", default="process").lower()
    operation = _field(item, "operation", "op", "name", default="observed event")
    value = _field(item, "value", "target", "detail", "url", default="")
    severity = _severity(_field(item, "severity", default="info"))
    verdict = _field(item, "verdict", "finding", default="")
    stack_value = item.get("stack", [])
    static_value = item.get("static_evidence", item.get("correlation", []))
    return RuntimeEvent(
        id=_field(item, "id", default=f"event-{index + 1}"),
        timestamp=timestamp,
        layer=layer,
        operation=operation,
        value=value,
        severity=severity,
        verdict=verdict,
        source=_field(item, "source", default=""),
        correlation_status=_correlation_status(_field(item, "correlation_status", default="OBSERVED")),
        stack=_list_strings(stack_value),
        static_evidence=_list_strings(static_value),
    )


def _field(item: Dict[str, Any], *keys: str, default: str) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None:
            return str(value)
    return default


def _list_strings(value: object) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value][:40]
    return []


def _severity(value: str) -> str:
    normalized = value.lower()
    return normalized if normalized in {"critical", "high", "medium", "low", "info"} else "info"


def _correlation_status(value: str) -> str:
    normalized = value.upper()
    return normalized if normalized in {"CONFIRMED", "DYNAMIC_ONLY", "OBSERVED"} else "OBSERVED"


def _capture_status(capture_mode: CaptureMode) -> str:
    return "captured (companion build)" if capture_mode == "companion_build" else "captured"


def _capture_source(capture_mode: CaptureMode) -> str:
    if capture_mode == "companion_build":
        return "Frida Simulator live capture"
    if capture_mode == "exact_ipa":
        return "Frida authorized target live capture"
    return ""


def _safe_id(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.lower()).strip("-")


def _is_platform_url(url: str) -> bool:
    lowered = url.lower()
    return "apple.com/" in lowered and any(part in lowered for part in ("/dtds/", "ocsp.", "crl.", "/appleca/"))


def _domain_family(host: str) -> str:
    labels = host.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _anti_analysis_evidence(categories: Dict[str, List[str]], indicators: StringIndicators) -> List[str]:
    evidence = list(categories.get("jailbreak_instrumentation", [])[:4])
    for marker in ("jailbreak", "cydia", "frida", "substrate"):
        evidence.extend(indicators.suspicious_keywords.get(marker, [])[:2])
    return evidence[:8]


def _dedupe_probes(probes: Iterable[RuntimeProbe]) -> List[RuntimeProbe]:
    seen = set()
    output: List[RuntimeProbe] = []
    for probe in probes:
        key = (probe.layer, probe.operation, probe.target)
        if key not in seen:
            seen.add(key)
            output.append(probe)
    return output


def _dedupe_strings(values: Iterable[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _campaign_matches(campaign_id: str, event: RuntimeEvent) -> bool:
    text = f"{event.layer} {event.operation} {event.value}".lower()
    if campaign_id == "campaign-startup":
        return "instrumentation attached" in text or "launch" in text
    if campaign_id == "campaign-network":
        return event.layer == "network" or "sectrustevaluate" in text
    if campaign_id == "campaign-storage":
        return event.layer in {"keychain", "file"} or "userdefaults" in text
    if campaign_id == "campaign-privacy":
        return "pasteboard" in text or "canopenurl" in text
    if campaign_id == "campaign-tamper":
        return any(marker in text for marker in ("fileexistsatpath", "dlopen", "sysctl", "cydia", "substrate", "frida"))
    if campaign_id == "campaign-crypto":
        return any(marker in text for marker in ("cccrypt", "seckey", "cryptokit", "cryptographic"))
    return False
