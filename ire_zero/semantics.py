"""Generate deterministic analyst-note summaries from collected evidence."""

from __future__ import annotations

from typing import List

from .models import AINote, BinaryArtifacts, DynamicCapture, Finding, PlistInfo


def synthesize_notes(
    plist: PlistInfo,
    binary: BinaryArtifacts,
    findings: List[Finding],
    dynamic: DynamicCapture,
) -> List[AINote]:
    notes: List[AINote] = []
    for finding in findings[:8]:
        notes.append(
            AINote(
                id=f"note-{finding.id}",
                title=finding.title,
                summary=_finding_summary(finding, dynamic),
                confidence=finding.confidence,
                evidence=finding.evidence[:8],
            )
        )
    notes.append(
        AINote(
            id="note-coverage",
            title="Analysis coverage",
            summary=_coverage_summary(plist, binary, dynamic),
            confidence="high",
            evidence=[
                f"sections={len(binary.sections)}",
                f"symbols={len(binary.symbols)}",
                f"linked_libraries={len(binary.linked_libraries)}",
                f"dynamic_status={dynamic.status}",
            ],
        )
    )
    return notes


def _finding_summary(finding: Finding, dynamic: DynamicCapture) -> str:
    confirmation = " Dynamic capture is available for correlation." if dynamic.events else (
        " This is static evidence only until an authorized runtime capture is imported."
    )
    return finding.description + confirmation


def _coverage_summary(plist: PlistInfo, binary: BinaryArtifacts, dynamic: DynamicCapture) -> str:
    identity = plist.bundle_identifier or "the application"
    static = (
        f"Static analysis of {identity} recovered {len(binary.sections)} Mach-O sections, "
        f"{len(binary.symbols)} symbols, and {len(binary.linked_libraries)} linked libraries."
    )
    if dynamic.events:
        return static + f" Imported runtime evidence contains {len(dynamic.events)} observed events."
    return static + " No runtime event source is attached; dynamic conclusions remain unavailable."
