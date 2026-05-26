"""Typed report schema for static analysis, dynamic evidence, and analyst notes."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

Severity = Literal["critical", "high", "medium", "low", "info"]
CaptureMode = Literal["exact_ipa", "companion_build", "not_captured"]
CorrelationStatus = Literal["CONFIRMED", "DOMAIN_MATCH", "DYNAMIC_ONLY", "OBSERVED"]


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    name: str
    available: bool
    command: List[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlistInfo:
    bundle_identifier: Optional[str] = None
    bundle_name: Optional[str] = None
    bundle_executable: Optional[str] = None
    url_types: List[Dict[str, Any]] = field(default_factory=list)
    app_transport_security: Dict[str, Any] = field(default_factory=dict)
    query_schemes: List[str] = field(default_factory=list)
    raw_subset: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BinarySection:
    segment: str
    name: str
    address: str
    offset: int
    size: int
    entropy: float
    flags: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceItem:
    id: str
    kind: str
    title: str
    source: str
    severity: Severity = "info"
    address: Optional[str] = None
    section: Optional[str] = None
    summary: str = ""
    evidence: List[str] = field(default_factory=list)
    instructions: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BinaryArtifacts:
    executable_path: str
    platform: Optional[str] = None
    embedded_frameworks: List[str] = field(default_factory=list)
    embedded_dylibs: List[str] = field(default_factory=list)
    linked_libraries: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    class_dump: List[str] = field(default_factory=list)
    symbol_categories: Dict[str, List[str]] = field(default_factory=dict)
    ghidra: Dict[str, Any] = field(default_factory=dict)
    tools: Dict[str, ToolResult] = field(default_factory=dict)
    sections: List[BinarySection] = field(default_factory=list)
    disassembly: List[Dict[str, str]] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executable_path": self.executable_path,
            "platform": self.platform,
            "embedded_frameworks": self.embedded_frameworks,
            "embedded_dylibs": self.embedded_dylibs,
            "linked_libraries": self.linked_libraries,
            "symbols": self.symbols,
            "class_dump": self.class_dump,
            "symbol_categories": self.symbol_categories,
            "ghidra": self.ghidra,
            "tools": {name: result.to_dict() for name, result in self.tools.items()},
            "sections": [section.to_dict() for section in self.sections],
            "disassembly": self.disassembly,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class StringIndicators:
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    suspicious_keywords: Dict[str, List[str]] = field(default_factory=dict)
    rule_matches: Dict[str, List[str]] = field(default_factory=dict)
    total_strings: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeEvent:
    id: str
    timestamp: str
    layer: str
    operation: str
    value: str
    severity: Severity = "info"
    verdict: str = ""
    source: str = ""
    correlation_status: CorrelationStatus = "OBSERVED"
    stack: List[str] = field(default_factory=list)
    static_evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeProbe:
    id: str
    layer: str
    operation: str
    target: str
    rationale: str
    priority: Severity = "info"
    evidence: List[str] = field(default_factory=list)
    capture_method: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeCampaign:
    id: str
    title: str
    objective: str
    layers: List[str] = field(default_factory=list)
    probe_ids: List[str] = field(default_factory=list)
    workflow: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicCapture:
    status: str = "not_captured"
    capture_mode: CaptureMode = "not_captured"
    source: Optional[str] = None
    evidence_source: Optional[str] = None
    session: Optional[str] = None
    events: List[RuntimeEvent] = field(default_factory=list)
    probes: List[RuntimeProbe] = field(default_factory=list)
    campaigns: List[RuntimeCampaign] = field(default_factory=list)
    campaign_coverage: Dict[str, Any] = field(default_factory=dict)
    cross_layer: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=lambda: [
        "No runtime trace supplied. Dynamic findings require an authorized iOS execution target or imported capture."
    ])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "capture_mode": self.capture_mode,
            "source": self.source,
            "evidence_source": self.evidence_source,
            "session": self.session,
            "events": [event.to_dict() for event in self.events],
            "probes": [probe.to_dict() for probe in self.probes],
            "campaigns": [campaign.to_dict() for campaign in self.campaigns],
            "campaign_coverage": self.campaign_coverage,
            "cross_layer": self.cross_layer,
            "limitations": self.limitations,
        }


@dataclass
class AINote:
    id: str
    title: str
    summary: str
    confidence: str
    evidence: List[str] = field(default_factory=list)
    source: str = "deterministic evidence synthesis"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    ipa_path: str
    app_name: str
    app_bundle_path: str
    executable_path: str
    info_plist: PlistInfo
    entitlements: Dict[str, Any]
    signing: Dict[str, Any]
    binary: BinaryArtifacts
    strings: StringIndicators
    findings: List[Finding]
    score: int
    score_breakdown: Dict[str, int]
    dynamic: DynamicCapture = field(default_factory=DynamicCapture)
    ai_notes: List[AINote] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ipa_path": self.ipa_path,
            "app_name": self.app_name,
            "app_bundle_path": self.app_bundle_path,
            "executable_path": self.executable_path,
            "info_plist": self.info_plist.to_dict(),
            "entitlements": self.entitlements,
            "signing": self.signing,
            "binary": self.binary.to_dict(),
            "strings": self.strings.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "score": self.score,
            "score_breakdown": self.score_breakdown,
            "dynamic_status": self.dynamic.status,
            "capture_mode": self.dynamic.capture_mode,
            "cross_layer": self.dynamic.cross_layer,
            "dynamic": self.dynamic.to_dict(),
            "ai_notes": [note.to_dict() for note in self.ai_notes],
            "errors": self.errors,
        }


def result_dir_name(ipa_path: Path, fallback_name: str) -> str:
    stem = ipa_path.stem or fallback_name
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in stem)
    return safe or "app"
