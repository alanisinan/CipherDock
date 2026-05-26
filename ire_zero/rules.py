"""Define and evaluate built-in and user-provided string pattern rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern

from .models import Severity
from .utils import dedupe


@dataclass(frozen=True)
class StringRule:
    id: str
    pattern: str
    severity: Severity
    category: str
    description: str
    regex: bool = False

    def compiled(self) -> Pattern[str]:
        source = self.pattern if self.regex else re.escape(self.pattern)
        return re.compile(source, re.IGNORECASE)


BUILTIN_RULES = [
    StringRule("rule.secret.aws", r"AKIA[0-9A-Z]{16}", "high", "secrets", "Possible AWS access key", regex=True),
    StringRule("rule.secret.jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "high", "secrets", "Possible JWT token", regex=True),
    StringRule("rule.private.mobileinstallation", "MobileInstallation", "medium", "private-api", "Private MobileInstallation API reference"),
    StringRule("rule.private.lsworkspace", "LSApplicationWorkspace", "medium", "private-api", "Private LaunchServices workspace API reference"),
    StringRule("rule.jailbreak.frida", "frida", "medium", "jailbreak-detection", "Frida-related string"),
    StringRule("rule.jailbreak.cydia", "cydia", "medium", "jailbreak-detection", "Cydia-related string"),
]


def load_rules(path: Optional[Path]) -> List[StringRule]:
    rules = list(BUILTIN_RULES)
    rules.extend(_load_packaged_rules())
    if path is None:
        return _dedupe_rules(rules)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Rule file must contain a JSON list")
    for item in raw:
        if not isinstance(item, dict):
            continue
        rules.append(_rule_from_dict(item))
    return _dedupe_rules(rules)


def validate_rules_file(path: Path) -> List[str]:
    errors: List[str] = []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"Could not read rule file: {exc}"]
    if not isinstance(raw, list):
        return ["Rule file must contain a JSON list"]
    seen = set()
    for index, item in enumerate(raw):
        prefix = f"rule[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        for key in ("id", "pattern"):
            if not isinstance(item.get(key), str) or not item.get(key):
                errors.append(f"{prefix}: missing string field {key}")
        rule_id = item.get("id")
        if isinstance(rule_id, str):
            if rule_id in seen:
                errors.append(f"{prefix}: duplicate id {rule_id}")
            seen.add(rule_id)
        severity = str(item.get("severity", "medium")).lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            errors.append(f"{prefix}: invalid severity {severity}")
        if item.get("regex") is True and isinstance(item.get("pattern"), str):
            try:
                re.compile(item["pattern"])
            except re.error as exc:
                errors.append(f"{prefix}: invalid regex: {exc}")
    return errors


def scan_rules(strings: Iterable[str], rules: Iterable[StringRule], evidence_limit: int = 25) -> Dict[str, List[str]]:
    compiled = [(rule, rule.compiled()) for rule in rules]
    matches: Dict[str, List[str]] = {}
    for value in strings:
        for rule, pattern in compiled:
            if pattern.search(value):
                matches.setdefault(rule.id, []).append(value)
    return {rule_id: dedupe(values, evidence_limit) for rule_id, values in matches.items()}


def _rule_from_dict(item: Dict[str, Any]) -> StringRule:
    severity = str(item.get("severity", "medium")).lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "medium"
    return StringRule(
        id=str(item["id"]),
        pattern=str(item["pattern"]),
        severity=severity,  # type: ignore[arg-type]
        category=str(item.get("category", "custom")),
        description=str(item.get("description", item["id"])),
        regex=bool(item.get("regex", False)),
    )


def _load_packaged_rules() -> List[StringRule]:
    try:
        payload = resources.files("ire_zero.data").joinpath("ios-security-rules.json").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        fallback = Path(__file__).with_name("data") / "ios-security-rules.json"
        if not fallback.exists():
            return []
        payload = fallback.read_text(encoding="utf-8")
    raw = json.loads(payload)
    if not isinstance(raw, list):
        return []
    return [_rule_from_dict(item) for item in raw if isinstance(item, dict)]


def _dedupe_rules(rules: Iterable[StringRule]) -> List[StringRule]:
    seen = set()
    output: List[StringRule] = []
    for rule in rules:
        if rule.id in seen:
            continue
        seen.add(rule.id)
        output.append(rule)
    return output
