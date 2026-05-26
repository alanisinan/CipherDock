"""Extract code-signing metadata and entitlements from application bundles."""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any, Dict, Tuple

from .models import ToolResult
from .utils import run_tool


def extract_entitlements(app_bundle: Path) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, ToolResult]]:
    tools: Dict[str, ToolResult] = {}
    entitlements: Dict[str, Any] = {}
    signing: Dict[str, Any] = {}

    entitlement_result = run_tool("codesign", ["-d", "--entitlements", ":-", str(app_bundle)], timeout=45)
    tools["codesign_entitlements"] = entitlement_result
    entitlements = _parse_codesign_entitlements(entitlement_result.stdout)

    signing_result = run_tool("codesign", ["-dvv", str(app_bundle)], timeout=45)
    tools["codesign_metadata"] = signing_result
    signing = _parse_codesign_metadata(signing_result.stderr or signing_result.stdout)

    mobileprovision = app_bundle / "embedded.mobileprovision"
    if mobileprovision.exists():
        profile_data = _parse_mobileprovision(mobileprovision)
        signing["embedded_mobileprovision"] = profile_data
        if not entitlements:
            profile_entitlements = profile_data.get("Entitlements")
            if isinstance(profile_entitlements, dict):
                entitlements = profile_entitlements

    return entitlements, signing, tools


def _parse_codesign_entitlements(text: str) -> Dict[str, Any]:
    if not text.strip():
        return {}
    start = text.find("<?xml")
    if start == -1:
        start = text.find("<plist")
    if start == -1:
        return {}
    payload = text[start:].encode("utf-8", errors="ignore")
    try:
        parsed = plistlib.loads(payload)
    except Exception:
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def _parse_codesign_metadata(text: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def _parse_mobileprovision(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    start = data.find(b"<?xml")
    end = data.find(b"</plist>")
    if start == -1 or end == -1:
        return {"path": str(path), "parse_error": "plist payload not found"}
    payload = data[start : end + len(b"</plist>")]
    try:
        parsed = plistlib.loads(payload)
    except Exception as exc:
        return {"path": str(path), "parse_error": str(exc)}
    return dict(parsed) if isinstance(parsed, dict) else {"path": str(path)}
