"""Extract printable strings and detect endpoints, secrets, and keywords."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from .models import StringIndicators
from .rules import StringRule, scan_rules
from .utils import dedupe

URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{8,}"
)
BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")
SUSPICIOUS_KEYWORDS = ("jailbreak", "cydia", "frida", "substrate", "keychain", "pasteboard")


def extract_strings_from_file(path: Path, min_length: int = 4) -> List[str]:
    data = path.read_bytes()
    ascii_strings = _extract_ascii(data, min_length)
    utf16_strings = _extract_utf16le(data, min_length)
    return dedupe([*ascii_strings, *utf16_strings])


def analyze_strings(strings: Iterable[str], rules: Iterable[StringRule]) -> StringIndicators:
    values = list(strings)
    urls = dedupe((match.group(0).rstrip(".,;") for value in values for match in URL_RE.finditer(value)), 100)
    ips = dedupe((match.group(0) for value in values for match in IP_RE.finditer(value)), 100)
    assignment_secrets = (match.group(0) for value in values for match in SECRET_ASSIGNMENT_RE.finditer(value))
    bearer_secrets = (match.group(0) for value in values for match in BEARER_TOKEN_RE.finditer(value))
    secrets = dedupe((*assignment_secrets, *bearer_secrets), 100)
    suspicious = {
        keyword: dedupe((value for value in values if keyword.lower() in value.lower()), 40)
        for keyword in SUSPICIOUS_KEYWORDS
    }
    suspicious = {keyword: matches for keyword, matches in suspicious.items() if matches}
    return StringIndicators(
        urls=urls,
        ips=ips,
        secrets=secrets,
        suspicious_keywords=suspicious,
        rule_matches=scan_rules(values, rules),
        total_strings=len(values),
    )


def _extract_ascii(data: bytes, min_length: int) -> List[str]:
    out: List[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                out.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_length:
        out.append(current.decode("ascii", errors="ignore"))
    return out


def _extract_utf16le(data: bytes, min_length: int) -> List[str]:
    out: List[str] = []
    for start in (0, 1):
        current = bytearray()
        for index in range(start, len(data) - 1, 2):
            lo = data[index]
            hi = data[index + 1]
            if hi == 0 and 32 <= lo <= 126:
                if not current and index > 0 and 32 <= data[index - 1] <= 126:
                    continue
                current.append(lo)
            else:
                if len(current) >= min_length:
                    out.append(current.decode("ascii", errors="ignore"))
                current.clear()
        if len(current) >= min_length:
            out.append(current.decode("ascii", errors="ignore"))
    return out
