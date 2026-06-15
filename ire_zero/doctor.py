"""Check availability of optional static and dynamic analysis tools."""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Iterable, List, Optional

from .playcover import amfi_status, playcover_status, sip_status


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str
    required: bool = False


def run_doctor(ghidra_headless: Optional[Path] = None) -> List[DoctorCheck]:
    checks = [
        DoctorCheck("python", "ok", platform.python_version(), required=True),
        _tool_check("zip", ["zip", "-h"], required=False),
        _tool_check("codesign", ["codesign", "--help"], required=False),
        _tool_check("otool", ["otool", "-h"], required=False),
        _tool_check("nm", ["nm", "-h"], required=False),
        _tool_check("class-dump", ["class-dump"], required=False),
        _ghidra_check(ghidra_headless),
        _tool_check("frida", ["frida", "--version"], required=False),
        _tool_check("objection", ["objection", "--version"], required=False),
        _tool_check("ideviceinstaller", ["ideviceinstaller", "--version"], required=False),
        _tool_check("ideviceimagemounter", ["ideviceimagemounter", "--help"], required=False),
        _playcover_check(),
        _playcover_cli_check(),
        _security_check("sip", sip_status()),
        _security_check("amfi", amfi_status()),
    ]
    return checks


def render_doctor(checks: Iterable[DoctorCheck]) -> str:
    rows = list(checks)
    width = max(len(check.name) for check in rows) if rows else 4
    lines = ["iRE-Zero environment doctor", ""]
    for check in rows:
        marker = "OK" if check.status == "ok" else "WARN" if check.status == "warn" else "MISS"
        required = " required" if check.required else ""
        lines.append(f"[{marker:4}] {check.name.ljust(width)}  {check.detail}{required}")
    lines.extend(
        [
            "",
            "Required: Python 3.9+.",
            "Static tools improve fidelity: codesign, otool, nm, class-dump, and Ghidra analyzeHeadless.",
            "Dynamic tools enable capture workflows: frida, objection, ideviceinstaller, ideviceimagemounter, and PlayCover.",
        ]
    )
    return "\n".join(lines)


def doctor_exit_code(checks: Iterable[DoctorCheck]) -> int:
    return 1 if any(check.required and check.status != "ok" for check in checks) else 0


def _tool_check(name: str, command: List[str], required: bool) -> DoctorCheck:
    executable = which(name)
    if executable is None:
        return DoctorCheck(name, "missing", "not found on PATH", required=required)
    detail = executable
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DoctorCheck(name, "warn", f"{executable} ({exc})", required=required)
    version_hint = (completed.stdout or completed.stderr).splitlines()[0:1]
    if version_hint:
        detail = f"{executable} - {version_hint[0][:80]}"
    return DoctorCheck(name, "ok", detail, required=required)


def _ghidra_check(ghidra_headless: Optional[Path]) -> DoctorCheck:
    candidates: List[Path] = []
    if ghidra_headless is not None:
        candidates.append(ghidra_headless)
    found = which("analyzeHeadless")
    if found is not None:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return DoctorCheck("ghidra", "ok", str(candidate), required=False)
    if ghidra_headless is not None:
        return DoctorCheck("ghidra", "missing", f"not found: {ghidra_headless}", required=False)
    return DoctorCheck("ghidra", "missing", "analyzeHeadless not found; pass --ghidra-headless when needed", required=False)


def _playcover_check() -> DoctorCheck:
    status = playcover_status()
    if status.installed:
        return DoctorCheck("playcover", "ok", status.detail, required=False)
    return DoctorCheck("playcover", "missing", status.detail, required=False)


def _playcover_cli_check() -> DoctorCheck:
    status = playcover_status()
    if status.cli_path is not None:
        return DoctorCheck("playcover-cli", "ok", str(status.cli_path), required=False)
    if status.installed:
        return DoctorCheck("playcover-cli", "warn", "CLI not found; IPA import will fall back to opening PlayCover.app", required=False)
    return DoctorCheck("playcover-cli", "missing", "PlayCover CLI not found", required=False)


def _security_check(name: str, status: dict[str, str]) -> DoctorCheck:
    return DoctorCheck(name, status.get("status", "warn"), status.get("detail", "status unavailable"), required=False)
