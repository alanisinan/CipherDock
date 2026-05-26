"""Convert recovered static artifacts into navigable evidence records."""

from __future__ import annotations

import re
from typing import Iterable, List
from urllib.parse import urlparse

from .models import BinaryArtifacts, EvidenceItem, Finding, StringIndicators


def build_static_evidence(
    binary: BinaryArtifacts,
    indicators: StringIndicators,
    findings: Iterable[Finding],
) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    instructions = binary.disassembly[:80]
    for index, section in enumerate(binary.sections[:80]):
        items.append(
            EvidenceItem(
                id=f"section-{index}",
                kind="Mach-O section",
                title=f"{section.segment}.{section.name}",
                source="Mach-O load command",
                address=section.address,
                section=section.name,
                summary=f"{section.size} bytes at file offset 0x{section.offset:x}; entropy {section.entropy}.",
                evidence=[f"flags={section.flags}", f"entropy={section.entropy}", f"offset=0x{section.offset:x}"],
                instructions=instructions if section.name == "__text" else [],
            )
        )
    for index, library in enumerate(binary.linked_libraries[:80]):
        items.append(
            EvidenceItem(
                id=f"import-{index}",
                kind="Import",
                title=library,
                source="otool -L",
                section="imports",
                summary="Mach-O linked library reference recovered from load commands.",
                evidence=[library],
            )
        )
    for category, symbols in binary.symbol_categories.items():
        for index, symbol in enumerate(symbols[:30]):
            severity = "medium" if category in {"private_api", "jailbreak_instrumentation"} else "info"
            items.append(
                EvidenceItem(
                    id=f"symbol-{_safe_id(category)}-{index}",
                    kind=category.replace("_", " ").title(),
                    title=symbol,
                    source="nm / Ghidra / library classification",
                    severity=severity,
                    section="symbols",
                    summary=f"Recovered {category.replace('_', ' ')} indicator.",
                    evidence=[symbol],
                )
            )
    for index, url in enumerate(indicators.urls[:60]):
        items.append(
            EvidenceItem(
                id=f"url-{index}",
                kind="URL string",
                title=url,
                source="strings",
                severity="medium" if url.lower().startswith("http://") and not _is_platform_url(url) else "info",
                section="__cstring",
                summary="URL-like string extracted from the application executable.",
                evidence=[url],
            )
        )
    for index, secret in enumerate(indicators.secrets[:30]):
        items.append(
            EvidenceItem(
                id=f"secret-{index}",
                kind="Secret candidate",
                title=secret,
                source="strings rule engine",
                severity="high",
                section="__cstring",
                summary="Token or secret-shaped value extracted from executable strings.",
                evidence=[secret],
            )
        )
    for finding in findings:
        items.append(
            EvidenceItem(
                id=f"finding-{_safe_id(finding.id)}",
                kind="Finding",
                title=finding.title,
                source=finding.category,
                severity=finding.severity,
                summary=finding.description,
                evidence=finding.evidence[:25],
            )
        )
    if instructions:
        items.insert(
            0,
            EvidenceItem(
                id="disassembly-text",
                kind="Disassembly",
                title="__TEXT.__text instruction sample",
                source="otool -tvV",
                section="__text",
                summary="Instruction sample recovered from the executable text section.",
                evidence=[f"{len(instructions)} instructions displayed"],
                instructions=instructions,
            ),
        )
    binary.evidence = items
    return items


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _is_platform_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "www.apple.com" or host.endswith(".apple.com")
