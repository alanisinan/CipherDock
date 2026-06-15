"""PlayCover-backed runtime capture for authorized iOS app assessments."""

from __future__ import annotations

import json
import os
import plistlib
import select
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class PlayCoverStatus:
    """Detected PlayCover installation state."""

    installed: bool
    app_path: Optional[Path] = None
    cli_path: Optional[Path] = None
    detail: str = ""


@dataclass(frozen=True)
class XcodeBuildOptions:
    """Options used to produce a PlayCover installable IPA from Xcode."""

    workspace: Optional[Path] = None
    project: Optional[Path] = None
    scheme: Optional[str] = None
    configuration: str = "Release"
    export_method: str = "development"
    build_root: Optional[Path] = None


@dataclass(frozen=True)
class PlayCoverCaptureResult:
    """Summary of a PlayCover Frida capture session."""

    trace_path: Path
    pid: int
    events: int
    command: List[str]
    session_id: str


def playcover_status() -> PlayCoverStatus:
    """Return the local PlayCover installation and CLI status."""

    env_cli = os.environ.get("IRE_ZERO_PLAYCOVER_CLI")
    cli_candidates = [Path(env_cli).expanduser()] if env_cli else []
    discovered = shutil.which("playcover")
    if discovered:
        cli_candidates.append(Path(discovered))
    app_path = _playcover_app_path()
    cli_path = next((candidate for candidate in cli_candidates if candidate.is_file() and os.access(candidate, os.X_OK)), None)
    installed = app_path is not None or cli_path is not None
    detail = str(cli_path or app_path or "PlayCover.app not found")
    return PlayCoverStatus(installed=installed, app_path=app_path, cli_path=cli_path, detail=detail)


def sip_status() -> Dict[str, str]:
    """Check System Integrity Protection because it can affect process attachment."""

    try:
        completed = subprocess.run(["csrutil", "status"], check=False, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "warn", "detail": f"unable to query SIP: {exc}"}
    detail = (completed.stdout or completed.stderr).strip() or "no SIP status output"
    if completed.returncode != 0:
        return {"status": "warn", "detail": detail}
    return {"status": "ok", "detail": detail}


def amfi_status() -> Dict[str, str]:
    """Check AMFI-related boot arguments that may influence Frida attach behavior."""

    try:
        completed = subprocess.run(["nvram", "boot-args"], check=False, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "warn", "detail": f"unable to query boot-args: {exc}"}
    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0:
        return {"status": "ok", "detail": "no custom AMFI boot arguments reported"}
    if "amfi" in output.lower():
        return {"status": "warn", "detail": output}
    return {"status": "ok", "detail": output or "boot-args empty"}


def build_ipa_from_xcode(options: XcodeBuildOptions, output_dir: Path) -> Path:
    """Run xcodebuild archive and exportArchive, returning the produced IPA path."""

    if not options.scheme:
        raise ValueError("PlayCover Xcode build requires --playcover-scheme")
    output_dir.mkdir(parents=True, exist_ok=True)
    build_root = (options.build_root or Path.cwd()).resolve()
    archive_path = output_dir / f"{_safe_name(options.scheme)}.xcarchive"
    export_dir = output_dir / "export"
    export_dir.mkdir(parents=True, exist_ok=True)

    archive_command = [
        "xcodebuild",
        "archive",
        "-scheme",
        options.scheme,
        "-configuration",
        options.configuration,
        "-archivePath",
        str(archive_path),
        "SKIP_INSTALL=NO",
    ]
    if options.workspace is not None:
        archive_command.extend(["-workspace", str(options.workspace)])
    elif options.project is not None:
        archive_command.extend(["-project", str(options.project)])
    subprocess.run(archive_command, cwd=build_root, check=True)

    export_options = output_dir / "ExportOptions.plist"
    with export_options.open("wb") as handle:
        plistlib.dump({"method": options.export_method, "compileBitcode": False}, handle)
    subprocess.run(
        [
            "xcodebuild",
            "-exportArchive",
            "-archivePath",
            str(archive_path),
            "-exportPath",
            str(export_dir),
            "-exportOptionsPlist",
            str(export_options),
        ],
        cwd=build_root,
        check=True,
    )
    ipas = sorted(export_dir.glob("*.ipa"))
    if not ipas:
        raise RuntimeError(f"xcodebuild exportArchive did not produce an IPA in {export_dir}")
    return ipas[0]


def install_ipa_in_playcover(ipa_path: Path, status: Optional[PlayCoverStatus] = None) -> None:
    """Install or import an IPA into PlayCover using the available local integration."""

    current = status or playcover_status()
    if not current.installed:
        raise RuntimeError("PlayCover is not installed or is not discoverable")
    if current.cli_path is not None:
        errors: List[str] = []
        for verb in ("install", "import"):
            completed = subprocess.run([str(current.cli_path), verb, str(ipa_path)], check=False, capture_output=True, text=True, timeout=180)
            if completed.returncode == 0:
                return
            errors.append((completed.stderr or completed.stdout).strip())
        if current.app_path is None:
            raise RuntimeError("PlayCover CLI could not install IPA: " + " | ".join(error for error in errors if error))
    subprocess.run(["open", "-a", "PlayCover", str(ipa_path)], check=True)


def launch_playcover_app(bundle_identifier: str, status: Optional[PlayCoverStatus] = None) -> None:
    """Launch a PlayCover app by bundle identifier when a CLI or LaunchServices path is available."""

    current = status or playcover_status()
    if current.cli_path is not None:
        completed = subprocess.run([str(current.cli_path), "launch", bundle_identifier], check=False, capture_output=True, text=True, timeout=60)
        if completed.returncode == 0:
            return
    subprocess.run(["open", "-b", bundle_identifier], check=False, capture_output=True, text=True, timeout=60)


def discover_playcover_pid(bundle_identifier: str, retries: int = 20, delay: float = 0.5) -> int:
    """Find a running PlayCover-hosted app process by bundle identifier."""

    for _ in range(retries):
        for command in (["pgrep", "-f", bundle_identifier], ["pgrep", "-fl", bundle_identifier]):
            try:
                completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                continue
            pid = _first_pid(completed.stdout)
            if pid is not None:
                return pid
        time.sleep(delay)
    raise RuntimeError(f"PlayCover process for {bundle_identifier} was not found")


def capture_playcover_runtime(
    bundle_identifier: str,
    script_path: Path,
    trace_path: Path,
    ipa_path: Optional[Path] = None,
    duration: int = 20,
    frida_path: Optional[Path] = None,
    install: bool = True,
    launch: bool = True,
) -> PlayCoverCaptureResult:
    """Attach Frida to a PlayCover macOS process and write normalized JSONL events."""

    status = playcover_status()
    if ipa_path is not None and install:
        install_ipa_in_playcover(ipa_path, status)
    if launch:
        launch_playcover_app(bundle_identifier, status)
    pid = discover_playcover_pid(bundle_identifier)
    frida = frida_path or _find_frida()
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    command = [str(frida), "-p", str(pid), "-q", "-t", "inf", "-l", str(script_path)]
    session_id = f"playcover-{uuid.uuid4().hex[:12]}"
    event_count = 0
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    deadline = time.monotonic() + max(1, duration)
    try:
        with trace_path.open("w", encoding="utf-8") as trace:
            while process.poll() is None and time.monotonic() < deadline:
                line = _read_process_line(process)
                if line is None:
                    continue
                event = event_from_frida_line(line)
                if event is None:
                    continue
                event_count += 1
                trace.write(json.dumps(event) + "\n")
                trace.flush()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
    return PlayCoverCaptureResult(trace_path=trace_path, pid=pid, events=event_count, command=command, session_id=session_id)


def event_from_frida_line(line: str) -> Optional[Dict[str, object]]:
    """Extract a JSON runtime event from one Frida stdout line."""

    if "IRE_ZERO_EVENT " not in line:
        return None
    payload = line.split("IRE_ZERO_EVENT ", 1)[1].strip()
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return event if isinstance(event, dict) else None


def _find_frida() -> Path:
    configured = os.environ.get("IRE_ZERO_FRIDA_PATH")
    candidates = [Path(configured).expanduser()] if configured else []
    discovered = shutil.which("frida")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("Frida is not installed or not executable")


def _playcover_app_path() -> Optional[Path]:
    configured = os.environ.get("IRE_ZERO_PLAYCOVER_APP")
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.extend([Path("/Applications/PlayCover.app"), Path.home() / "Applications" / "PlayCover.app"])
    return next((candidate for candidate in candidates if candidate.exists()), None)


def _read_process_line(process: subprocess.Popen[str]) -> Optional[str]:
    if process.stdout is None:
        time.sleep(0.1)
        return None
    ready, _, _ = select.select([process.stdout], [], [], 0.2)
    if not ready:
        return None
    line = process.stdout.readline()
    return line.rstrip() if line else None


def _first_pid(output: str) -> Optional[int]:
    for line in output.splitlines():
        fields = line.strip().split()
        if not fields:
            continue
        try:
            return int(fields[0])
        except ValueError:
            continue
    return None


def _safe_name(value: str) -> str:
    cleaned = "".join(character if character.isalnum() or character in {"-", "_"} else "-" for character in value)
    return cleaned.strip("-") or "PlayCover"
