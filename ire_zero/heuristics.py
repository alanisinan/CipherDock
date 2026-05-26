"""Apply deterministic security findings and weighted risk scoring rules."""

from __future__ import annotations

from typing import Dict, Iterable, List
from urllib.parse import urlparse

from .models import BinaryArtifacts, Finding, PlistInfo, StringIndicators

PRIVATE_API_MARKERS = (
    "LSApplicationWorkspace",
    "MobileInstallation",
    "CPDistributedMessagingCenter",
    "SBApplicationController",
    "SpringBoardServices",
    "BackBoardServices",
    "AppSupport.framework",
    "GraphicsServices.framework",
)

JAILBREAK_MARKERS = ("jailbreak", "cydia", "frida", "substrate")


def evaluate_heuristics(
    plist: PlistInfo,
    entitlements: Dict[str, object],
    binary: BinaryArtifacts,
    indicators: StringIndicators,
) -> tuple[List[Finding], int, Dict[str, int]]:
    findings: List[Finding] = []
    breakdown = {
        "transport_security": 0,
        "hardcoded_secrets": 0,
        "private_api": 0,
        "jailbreak_detection": 0,
        "network_endpoints": 0,
        "entitlements": 0,
        "symbol_intelligence": 0,
    }

    ats_findings = detect_transport_security(plist)
    findings.extend(ats_findings)
    breakdown["transport_security"] = _points_for(ats_findings)

    secret_findings = detect_hardcoded_secrets(indicators)
    findings.extend(secret_findings)
    breakdown["hardcoded_secrets"] = _points_for(secret_findings)

    private_api_findings = detect_private_api_usage(binary, indicators)
    findings.extend(private_api_findings)
    breakdown["private_api"] = _points_for(private_api_findings)

    jailbreak_findings = detect_jailbreak_logic(indicators)
    findings.extend(jailbreak_findings)
    breakdown["jailbreak_detection"] = _points_for(jailbreak_findings)

    endpoint_findings = detect_suspicious_endpoints(indicators)
    findings.extend(endpoint_findings)
    breakdown["network_endpoints"] = _points_for(endpoint_findings)

    entitlement_findings = detect_sensitive_entitlements(entitlements)
    findings.extend(entitlement_findings)
    breakdown["entitlements"] = _points_for(entitlement_findings)

    symbol_findings = detect_symbol_categories(binary)
    findings.extend(symbol_findings)
    breakdown["symbol_intelligence"] = _points_for(symbol_findings)

    score = min(100, sum(breakdown.values()))
    return _dedupe_findings(findings), score, breakdown


def detect_transport_security(plist: PlistInfo) -> List[Finding]:
    ats = plist.app_transport_security
    findings: List[Finding] = []
    if ats.get("NSAllowsArbitraryLoads") is True:
        findings.append(
            Finding(
                id="ats.arbitrary_loads",
                title="App Transport Security allows arbitrary loads",
                severity="high",
                category="transport-security",
                description="NSAllowsArbitraryLoads disables ATS protections broadly.",
                evidence=["NSAppTransportSecurity.NSAllowsArbitraryLoads = true"],
                recommendation="Scope ATS exceptions to specific domains and require TLS.",
                confidence="high",
            )
        )
    exception_domains = ats.get("NSExceptionDomains")
    if isinstance(exception_domains, dict):
        weak_domains = []
        for domain, config in exception_domains.items():
            if not isinstance(config, dict):
                continue
            if config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                weak_domains.append(str(domain))
        if weak_domains:
            findings.append(
                Finding(
                    id="ats.insecure_domain_exceptions",
                    title="ATS domain exceptions allow insecure HTTP",
                    severity="medium",
                    category="transport-security",
                    description="One or more ATS exception domains permit insecure HTTP loads.",
                    evidence=weak_domains[:20],
                    recommendation="Remove insecure HTTP exceptions or justify them in review.",
                    confidence="high",
                )
            )
    return findings


def detect_hardcoded_secrets(indicators: StringIndicators) -> List[Finding]:
    if not indicators.secrets and not any(key.startswith("rule.secret") for key in indicators.rule_matches):
        return []
    evidence = list(indicators.secrets)
    for key, matches in indicators.rule_matches.items():
        if key.startswith("rule.secret"):
            evidence.extend(matches)
    return [
        Finding(
            id="strings.hardcoded_secret",
            title="Possible hardcoded secret or token",
            severity="high",
            category="secrets",
            description="The binary contains strings that resemble API keys, tokens, or client secrets.",
            evidence=evidence[:25],
            recommendation="Move secrets server-side or into a revocable runtime delivery path.",
            confidence="high",
        )
    ]


def detect_private_api_usage(binary: BinaryArtifacts, indicators: StringIndicators) -> List[Finding]:
    haystack = [*binary.symbols, *binary.class_dump, *binary.linked_libraries, *binary.symbol_categories.get("private_api", [])]
    for matches in indicators.rule_matches.values():
        haystack.extend(matches)
    hits = _marker_hits(PRIVATE_API_MARKERS, haystack)
    if not hits:
        return []
    return [
        Finding(
            id="binary.private_api_usage",
            title="Possible private API usage",
            severity="medium",
            category="private-api",
            description="The app references iOS private APIs or private frameworks.",
            evidence=hits[:30],
            recommendation="Review whether these APIs are reachable and remove private framework dependencies.",
            confidence="high" if binary.symbol_categories.get("private_api") else "medium",
        )
    ]


def detect_jailbreak_logic(indicators: StringIndicators) -> List[Finding]:
    evidence: List[str] = []
    for marker in JAILBREAK_MARKERS:
        evidence.extend(indicators.suspicious_keywords.get(marker, []))
    if not evidence:
        return []
    return [
        Finding(
            id="strings.jailbreak_detection",
            title="Jailbreak or instrumentation detection strings",
            severity="medium",
            category="anti-analysis",
            description="The app contains strings associated with jailbreak, Frida, or Substrate detection.",
            evidence=evidence[:30],
            recommendation="Confirm whether checks are used for defensive hardening or anti-analysis behavior.",
            confidence="medium",
        )
    ]


def detect_suspicious_endpoints(indicators: StringIndicators) -> List[Finding]:
    findings: List[Finding] = []
    http_urls = [
        url
        for url in indicators.urls
        if url.lower().startswith("http://") and not _is_low_signal_http_url(url)
    ]
    if http_urls:
        findings.append(
            Finding(
                id="network.cleartext_urls",
                title="Cleartext HTTP endpoints found",
                severity="medium",
                category="network",
                description="The binary contains cleartext HTTP URLs.",
                evidence=http_urls[:25],
                recommendation="Use HTTPS endpoints and remove obsolete cleartext URLs.",
                confidence="medium",
            )
        )
    if indicators.ips:
        findings.append(
            Finding(
                id="network.hardcoded_ips",
                title="Hardcoded IP addresses found",
                severity="low",
                category="network",
                description="Hardcoded IP addresses can indicate brittle routing, tracking, or command infrastructure.",
                evidence=indicators.ips[:25],
                recommendation="Review IP ownership and ensure endpoints are expected.",
                confidence="low",
            )
        )
    return findings


def _is_low_signal_http_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if host == "www.apple.com" and path.endswith("/dtds/propertylist-1.0.dtd"):
        return True
    if host.endswith(".apple.com") and (host.startswith("ocsp.") or host.startswith("crl.")):
        return True
    if host == "ocsp.apple.com" or host == "crl.apple.com":
        return True
    return False


def detect_sensitive_entitlements(entitlements: Dict[str, object]) -> List[Finding]:
    sensitive_keys = [
        key
        for key in entitlements
        if key.startswith("com.apple.developer.") or key.startswith("com.apple.security.")
    ]
    private_keys = [key for key in entitlements if key.startswith("com.apple.private.")]
    findings: List[Finding] = []
    if private_keys:
        findings.append(
            Finding(
                id="entitlements.private",
                title="Private entitlement present",
                severity="high",
                category="entitlements",
                description="The app declares private Apple entitlements.",
                evidence=private_keys[:25],
                recommendation="Validate signing provenance and determine whether private entitlements are expected.",
                confidence="high",
            )
        )
    elif len(sensitive_keys) >= 8:
        findings.append(
            Finding(
                id="entitlements.broad",
                title="Broad entitlement surface",
                severity="low",
                category="entitlements",
                description="The app declares many Apple developer or security entitlements.",
                evidence=sensitive_keys[:25],
                recommendation="Review entitlement necessity and least-privilege posture.",
                confidence="medium",
            )
        )
    return findings


def detect_symbol_categories(binary: BinaryArtifacts) -> List[Finding]:
    findings: List[Finding] = []
    categories = binary.symbol_categories
    if categories.get("analytics_tracking"):
        findings.append(
            Finding(
                id="symbols.analytics_tracking",
                title="Analytics or attribution SDK markers",
                severity="info",
                category="third-party-sdk",
                description="Symbols or linked libraries indicate analytics, attribution, or tracking SDKs.",
                evidence=categories["analytics_tracking"][:25],
                recommendation="Review SDK purpose, privacy disclosures, and data-flow coverage.",
                confidence="high",
            )
        )
    if categories.get("storage_keychain"):
        findings.append(
            Finding(
                id="symbols.keychain_usage",
                title="Keychain API usage observed",
                severity="info",
                category="sensitive-storage",
                description="Symbols indicate use of Keychain APIs or keychain accessibility constants.",
                evidence=categories["storage_keychain"][:25],
                recommendation="Check accessibility classes and whether secrets are scoped least-privilege.",
                confidence="high",
            )
        )
    if categories.get("pasteboard"):
        findings.append(
            Finding(
                id="symbols.pasteboard_usage",
                title="Pasteboard access markers observed",
                severity="info",
                category="sensitive-storage",
                description="Symbols or strings indicate pasteboard access.",
                evidence=categories["pasteboard"][:25],
                recommendation="Confirm pasteboard access is user-visible and privacy-preserving.",
                confidence="medium",
            )
        )
    if categories.get("crypto"):
        findings.append(
            Finding(
                id="symbols.crypto_usage",
                title="Cryptographic API usage observed",
                severity="info",
                category="crypto",
                description="Symbols indicate cryptographic APIs or libraries.",
                evidence=categories["crypto"][:25],
                recommendation="Review algorithm choices, key handling, and platform API usage.",
                confidence="medium",
            )
        )
    return findings


def _marker_hits(markers: Iterable[str], values: Iterable[str]) -> List[str]:
    hits: List[str] = []
    for value in values:
        lower = value.lower()
        if any(marker.lower() in lower for marker in markers):
            hits.append(value)
    seen = set()
    out: List[str] = []
    for hit in hits:
        if hit in seen:
            continue
        seen.add(hit)
        out.append(hit)
    return out


def _points_for(findings: Iterable[Finding]) -> int:
    weights = {"critical": 35, "high": 24, "medium": 14, "low": 6, "info": 1}
    confidence_factor = {"high": 1.0, "medium": 0.75, "low": 0.5}
    return min(35, round(sum(weights[finding.severity] * confidence_factor.get(finding.confidence, 0.75) for finding in findings)))


def _dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return sorted(out, key=lambda finding: (order[finding.severity], finding.id))
