"""Local HTTP workbench for IPA analysis, reports, and authorized runtime capture."""

from __future__ import annotations

import argparse
import cgi
import json
import mimetypes
import os
import plistlib
import shutil
import subprocess
import threading
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .analyzer import analyze_ipa
from .macho import extract_platform, extract_platform_data
from .models import result_dir_name
from .reporting import write_index_report, write_reports
from .rules import load_rules


@dataclass
class Job:
    id: str
    files: List[Path]
    trace_path: Optional[Path] = None
    state: str = "queued"
    phase: str = "Queued"
    progress: int = 0
    current_file: Optional[str] = None
    reports: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    batch_index_url: Optional[str] = None

    def payload(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "phase": self.phase,
            "progress": self.progress,
            "current_file": self.current_file,
            "report_count": len(self.reports),
            "reports": self.reports if self.state == "completed" else [],
            "error": self.error,
            "batch": len(self.files) > 1,
            "file_count": len(self.files),
            "batch_index_url": self.batch_index_url,
        }


@dataclass
class RuntimeSession:
    id: str
    report_id: str
    ipa_path: Path
    bundle_identifier: str
    capture_mode: str
    runtime_environment: str
    script_path: Path
    trace_path: Path
    device_id: Optional[str] = None
    state: str = "queued"
    phase: str = "Preparing capture"
    events: List[Dict[str, Any]] = field(default_factory=list)
    log_tail: List[str] = field(default_factory=list)
    result_report_id: Optional[str] = None
    error: Optional[str] = None
    stop_requested: bool = False
    process: Optional[subprocess.Popen[str]] = field(default=None, repr=False)

    def payload(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "report_id": self.report_id,
            "bundle_identifier": self.bundle_identifier,
            "capture_mode": self.capture_mode,
            "runtime_environment": self.runtime_environment,
            "state": self.state,
            "phase": self.phase,
            "events": self.events[-200:],
            "event_count": len(self.events),
            "result_report_id": self.result_report_id,
            "error": self.error,
            "log_tail": self.log_tail[-20:],
        }


class WorkbenchState:
    def __init__(self, workspace: Path, html_path: Path) -> None:
        self.workspace = workspace
        self.html_path = html_path
        self.uploads = workspace / "uploads"
        self.reports = workspace / "reports"
        self.runtime_sessions_dir = workspace / "runtime-sessions"
        self.runtime_companions_dir = workspace / "runtime-companions"
        self.runtime_bindings_path = workspace / "runtime-target-bindings.json"
        self.uploads.mkdir(parents=True, exist_ok=True)
        self.reports.mkdir(parents=True, exist_ok=True)
        self.runtime_sessions_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_companions_dir.mkdir(parents=True, exist_ok=True)
        self.jobs: Dict[str, Job] = {}
        self.runtime_sessions: Dict[str, RuntimeSession] = {}
        self.lock = threading.Lock()

    def create_job(self, files: List[Path], trace_path: Optional[Path] = None) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], files=files, trace_path=trace_path)
        with self.lock:
            self.jobs[job.id] = job
        thread = threading.Thread(target=self._run_job, args=(job,), daemon=True)
        thread.start()
        return job

    def _run_job(self, job: Job) -> None:
        try:
            rules = load_rules(None)
            complete = []
            total = len(job.files)
            for index, ipa_path in enumerate(job.files):
                job.state = "running"
                job.phase = "Static analysis"
                job.current_file = ipa_path.name
                job.progress = 8 + round(index / max(total, 1) * 80)
                result = analyze_ipa(
                    ipa_path,
                    rules,
                    runtime_trace=job.trace_path if total == 1 else None,
                )
                job.phase = "Writing reports"
                job.progress = 84 + round((index + 1) / max(total, 1) * 12)
                report_dir = _unique_report_dir(self.reports, result_dir_name(ipa_path, result.app_name))
                write_reports(result, report_dir, sarif=True, html_report=True)
                complete.append((result, report_dir))
                job.reports.append(
                    {
                        "id": report_dir.name,
                        "directory": str(report_dir),
                        "report": result.to_dict(),
                    }
                )
            write_index_report(complete, self.reports)
            if total > 1:
                batch_dir = self.reports / "_batches" / job.id
                write_index_report(complete, batch_dir)
                job.batch_index_url = f"/reports/_batches/{job.id}/index.html"
                (batch_dir / "batch.json").write_text(
                    json.dumps(
                        {
                            "id": job.id,
                            "created_at": _timestamp(),
                            "file_count": total,
                            "index_url": job.batch_index_url,
                            "reports": [
                                {
                                    "id": report_dir.name,
                                    "app_name": result.app_name,
                                    "bundle_identifier": result.info_plist.bundle_identifier,
                                    "score": result.score,
                                    "findings": len(result.findings),
                                    "dynamic_status": result.dynamic.status,
                                }
                                for result, report_dir in complete
                            ],
                        },
                        indent=2,
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
            job.state = "completed"
            job.phase = "Completed"
            job.progress = 100
        except Exception as exc:
            job.state = "failed"
            job.phase = "Failed"
            job.error = str(exc)

    def report_catalog(self) -> List[Dict[str, Any]]:
        catalog: List[Dict[str, Any]] = []
        for report_path in sorted(self.reports.glob("*/report.json"), key=lambda path: path.stat().st_mtime, reverse=True):
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            catalog.append(
                {
                    "id": report_path.parent.name,
                    "app_name": payload.get("app_name"),
                    "bundle_identifier": payload.get("info_plist", {}).get("bundle_identifier"),
                    "score": payload.get("score", 0),
                    "findings": len(payload.get("findings", [])),
                    "dynamic_status": payload.get("dynamic", {}).get("status", "not_captured"),
                    "analyst_notes": len(self._read_report_notes(report_path.parent)),
                }
            )
        return catalog

    def batch_catalog(self) -> List[Dict[str, Any]]:
        batches: List[Dict[str, Any]] = []
        for path in sorted(
            (self.reports / "_batches").glob("*/batch.json"),
            key=lambda candidate: candidate.stat().st_mtime,
            reverse=True,
        ):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                batches.append(payload)
        return batches

    def report_notes(self, report_id: str) -> List[Dict[str, Any]]:
        report_dir = self._report_dir(report_id)
        return self._read_report_notes(report_dir)

    def save_report_note(self, report_id: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        report_dir = self._report_dir(report_id)
        title = str(payload.get("title", "")).strip()
        body = str(payload.get("body", "")).strip()
        if not title or not body:
            raise ValueError("Note title and body are required")
        severity = str(payload.get("severity", "info")).strip().lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError("Invalid note severity")
        status = str(payload.get("status", "open")).strip().lower()
        if status not in {"open", "confirmed", "mitigated", "accepted", "dismissed"}:
            raise ValueError("Invalid note status")
        raw_evidence = payload.get("evidence", [])
        evidence = [
            str(item).strip()
            for item in raw_evidence
            if isinstance(item, str) and str(item).strip()
        ][:12] if isinstance(raw_evidence, list) else []
        note = {
            "id": uuid.uuid4().hex[:12],
            "title": title[:180],
            "body": body[:6000],
            "severity": severity,
            "status": status,
            "evidence": evidence,
            "created_at": _timestamp(),
            "source": "analyst annotation",
        }
        with self.lock:
            notes = self._read_report_notes(report_dir)
            notes.insert(0, note)
            self._write_report_notes(report_dir, notes)
        return notes

    def delete_report_note(self, report_id: str, note_id: str) -> List[Dict[str, Any]]:
        report_dir = self._report_dir(report_id)
        with self.lock:
            notes = self._read_report_notes(report_dir)
            notes = [note for note in notes if str(note.get("id")) != note_id]
            self._write_report_notes(report_dir, notes)
        return notes

    def runtime_status(self) -> Dict[str, Any]:
        tools = {}
        for name in ("frida", "frida-ls-devices", "objection", "ideviceinstaller", "ideviceimagemounter"):
            executable = self._find_runtime_tool(name)
            tools[name] = {"available": executable is not None, "path": executable}
        device_status = self._frida_device_status(tools["frida"]["path"])
        simulator_status = self._simulator_status()
        active = [
            session.payload()
            for session in self.runtime_sessions.values()
            if session.state in {"queued", "starting", "running", "stopping", "finalizing"}
        ]
        installed = bool(tools["frida"]["available"])
        return {
            "installed": installed,
            "ready": installed and bool(device_status["usb_connected"]),
            "tools": tools,
            "device_status": device_status,
            "simulator_status": simulator_status,
            "environments": {
                "usb": {
                    "ready": installed and bool(device_status["usb_connected"]),
                    "devices": device_status["devices"],
                },
                "simulator": {
                    "ready": installed and bool(simulator_status["booted_devices"]),
                    "devices": simulator_status["booted_devices"],
                },
            },
            "active_sessions": active,
        }

    def runtime_preflight(
        self,
        report_id: str,
        capture_mode: str = "spawn",
        runtime_environment: str = "usb",
    ) -> Dict[str, Any]:
        if capture_mode not in {"spawn", "attach", "gadget"}:
            raise ValueError("Unsupported capture mode")
        if runtime_environment not in {"usb", "simulator"}:
            raise ValueError("Unsupported runtime environment")
        report = self._load_report(report_id)
        bundle_identifier = str(report.get("info_plist", {}).get("bundle_identifier") or "")
        if not bundle_identifier:
            raise ValueError("Selected report does not contain a bundle identifier")
        script_path = (self.reports / report_id / "frida-hooks.js").resolve()
        frida_path = self._find_runtime_tool("frida")
        status = self.runtime_status()
        checks = [
            {
                "id": "frida-client",
                "label": "Frida client",
                "state": "pass" if frida_path else "fail",
                "detail": frida_path or "Install the managed Frida client.",
            },
        ]
        if runtime_environment == "simulator":
            return self._simulator_preflight(
                report_id,
                report,
                bundle_identifier,
                capture_mode,
                script_path,
                frida_path,
                status,
                checks,
            )
        checks.extend(
            [
                {
                    "id": "usb-device",
                    "label": "USB device",
                    "state": "pass" if status["device_status"]["usb_connected"] else "fail",
                    "detail": ", ".join(status["device_status"]["devices"]) or "No USB iOS device detected.",
                },
                {
                    "id": "hook-script",
                    "label": "Capture hooks",
                    "state": "pass" if script_path.exists() else "fail",
                    "detail": script_path.name if script_path.exists() else "Generated Frida hook script is unavailable.",
                },
            ]
        )
        device_probe = self._frida_target_probe(frida_path, bundle_identifier)
        bridge_ok = bool(device_probe.get("reachable"))
        bridge_detail = str(device_probe.get("detail") or "Device channel is unavailable.")
        target_installed = bool(device_probe.get("installed"))
        target_running = bool(device_probe.get("running"))
        checks.extend(
            [
                {
                    "id": "frida-channel",
                    "label": "Frida channel",
                    "state": "pass" if bridge_ok else "fail",
                    "detail": bridge_detail,
                },
                {
                    "id": "target-app",
                    "label": "Target app",
                    "state": "pass" if target_installed else ("blocked" if not bridge_ok else "fail"),
                    "detail": (
                        f"{bundle_identifier} is installed"
                        if target_installed
                        else (
                            "Awaiting a working Frida channel before verifying the installed bundle."
                            if not bridge_ok
                            else f"{bundle_identifier} was not found on the device"
                        )
                    ),
                },
            ]
        )
        if capture_mode == "attach":
            checks.append(
                {
                    "id": "running-process",
                    "label": "Running process",
                    "state": "pass" if target_running else "fail",
                    "detail": "App process is running and attachable." if target_running else "Launch the app first, then refresh preflight.",
                }
            )
        live_ready = bridge_ok and target_installed and script_path.exists() and (
            capture_mode == "spawn" or (capture_mode == "attach" and target_running)
        )
        if capture_mode == "gadget":
            live_ready = False
            checks.append(
                {
                    "id": "gadget-package",
                    "label": "Gadget package",
                    "state": "guide",
                    "detail": "Patch and re-sign the authorized IPA with Frida Gadget, then install it before capture.",
                }
            )
            deployment_tool = status["tools"]["ideviceinstaller"]["available"]
            checks.append(
                {
                    "id": "deployment-tool",
                    "label": "Deployment tool",
                    "state": "pass" if deployment_tool else "guide",
                    "detail": (
                        "ideviceinstaller is available for an authorized signed IPA."
                        if deployment_tool
                        else "Install libimobiledevice/ideviceinstaller, or install the signed IPA through Xcode."
                    ),
                }
            )
        next_steps = []
        if capture_mode == "gadget":
            next_steps = [
                "Prepare a Frida Gadget configuration that loads the generated hook script.",
                "Patch and re-sign the authorized IPA while preserving required entitlements.",
                "Install the patched app, launch it, capture output, and import the JSONL trace.",
            ]
        elif not bridge_ok and "Developer Disk Image" in bridge_detail:
            next_steps = [
                "Mount the matching iOS Developer Disk Image by opening Xcode with this iPhone connected, or use ideviceimagemounter.",
                "Refresh preflight after the developer services image is mounted.",
            ]
        elif not bridge_ok:
            next_steps = [
                "Start a matching Frida Server on an authorized research device, or select the Gadget path.",
                "Refresh preflight after the device channel is reachable.",
            ]
        elif not target_installed:
            next_steps = [
                f"Install the authorized app with bundle identifier {bundle_identifier} on the connected device.",
                "Refresh preflight after installation.",
            ]
        elif capture_mode == "attach" and not target_running:
            next_steps = ["Open the target app on the device, then refresh preflight before attaching."]
        else:
            next_steps = ["Preflight passed. Starting capture will execute the selected instrumentation mode."]
        return {
            "report_id": report_id,
            "bundle_identifier": bundle_identifier,
            "capture_mode": capture_mode,
            "runtime_environment": runtime_environment,
            "capture_ready": live_ready,
            "checks": checks,
            "device_probe": device_probe,
            "next_steps": next_steps,
        }

    def runtime_targets(self, report_id: str) -> Dict[str, Any]:
        report = self._load_report(report_id)
        bundle_identifier = str(report.get("info_plist", {}).get("bundle_identifier") or "")
        if not bundle_identifier:
            raise ValueError("Selected report does not contain a bundle identifier")
        status = self.runtime_status()
        frida_path = self._find_runtime_tool("frida")
        simulator = status["simulator_status"]
        booted = simulator.get("booted_devices", [])
        device_id = str(booted[0].get("id", "")) if booted else ""
        simulator_probe = (
            self._frida_simulator_target_probe(frida_path, bundle_identifier, device_id)
            if frida_path and device_id
            else {
                "device_id": device_id,
                "reachable": False,
                "installed": False,
                "running": False,
                "detail": "Boot a Simulator to discover installed companion builds.",
            }
        )
        usb_connected = bool(status.get("device_status", {}).get("usb_connected"))
        usb_probe = (
            self._frida_target_probe(frida_path, bundle_identifier)
            if frida_path and usb_connected
            else {
                "reachable": False,
                "installed": False,
                "running": False,
                "detail": "No authorized Frida USB target is connected.",
            }
        )
        binding = self._target_binding(bundle_identifier)
        if simulator_probe.get("installed") and (
            not binding or binding.get("environment") != "simulator"
        ):
            binding = self._remember_target_binding(
                bundle_identifier,
                {
                    "environment": "simulator",
                    "artifact_kind": "simulator_companion",
                    "source": "discovered installed bundle",
                    "device_id": device_id,
                    "device_name": str(booted[0].get("name", "iPhone Simulator")) if booted else "",
                    "report_id": report_id,
                },
            )
        artifact_platform = self._report_platform(report)
        simulator_exact = artifact_platform == "IOSSIMULATOR"
        companion_candidates = self._simulator_companion_candidates(bundle_identifier)
        return {
            "report_id": report_id,
            "bundle_identifier": bundle_identifier,
            "artifact_platform": artifact_platform,
            "binding": binding,
            "companion_candidates": companion_candidates,
            "targets": [
                {
                    "environment": "simulator",
                    "label": "Xcode Simulator",
                    "device": str(booted[0].get("name", "")) if booted else "",
                    "available": bool(booted),
                    "installed": bool(simulator_probe.get("installed")),
                    "running": bool(simulator_probe.get("running")),
                    "state": "ready" if simulator_probe.get("installed") else "needs_companion",
                    "boundary": "exact Simulator artifact" if simulator_exact else "companion-build evidence",
                    "detail": str(simulator_probe.get("detail", "")),
                    "candidate": companion_candidates[0] if companion_candidates else None,
                },
                {
                    "environment": "usb",
                    "label": "Physical Device",
                    "device": ", ".join(status.get("device_status", {}).get("devices", [])),
                    "available": usb_connected,
                    "installed": bool(usb_probe.get("installed")),
                    "running": bool(usb_probe.get("running")),
                    "state": "bundle_match" if usb_probe.get("installed") else "unavailable",
                    "boundary": "bundle match; exact IPA requires provenance verification",
                    "detail": str(usb_probe.get("detail", "")),
                },
            ],
        }

    def install_simulator_companion(self, report_id: str, app_bundle: Path) -> Dict[str, Any]:
        report = self._load_report(report_id)
        expected_identifier = str(report.get("info_plist", {}).get("bundle_identifier") or "")
        if not expected_identifier:
            raise ValueError("Selected report does not contain a bundle identifier")
        plist_path = app_bundle / "Info.plist"
        if not plist_path.is_file():
            raise ValueError("Selected Simulator application bundle does not contain Info.plist")
        with plist_path.open("rb") as handle:
            plist = plistlib.load(handle)
        if not isinstance(plist, dict):
            raise ValueError("Selected Simulator application Info.plist is invalid")
        bundle_identifier = str(plist.get("CFBundleIdentifier") or "")
        if bundle_identifier != expected_identifier:
            raise ValueError(
                f"Companion bundle identifier {bundle_identifier or 'unknown'} does not match {expected_identifier}"
            )
        executable_name = str(plist.get("CFBundleExecutable") or "")
        executable = app_bundle / executable_name
        if not executable_name or not executable.is_file():
            raise ValueError("Selected Simulator application does not contain its main executable")
        platform = extract_platform(executable) or "UNKNOWN"
        if platform != "IOSSIMULATOR":
            raise ValueError(f"Companion application platform is {platform}; an IOSSIMULATOR build is required")
        boot = self.boot_simulator()
        device = boot["device"]
        xcrun = shutil.which("xcrun")
        if not xcrun:
            raise RuntimeError("Xcode command-line Simulator support is unavailable.")
        try:
            install = subprocess.run(
                [xcrun, "simctl", "install", str(device["id"]), str(app_bundle)],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Simulator companion installation failed: {exc}") from exc
        if install.returncode != 0:
            raise RuntimeError(install.stderr.strip() or "Simulator companion installation failed.")
        return self._remember_target_binding(
            expected_identifier,
            {
                "environment": "simulator",
                "artifact_kind": "simulator_companion",
                "source": "installed from workbench",
                "app_bundle": str(app_bundle),
                "platform": platform,
                "device_id": str(device["id"]),
                "device_name": str(device["name"]),
                "report_id": report_id,
            },
        )

    def install_companion_candidate(self, report_id: str, candidate_path: Path) -> Dict[str, Any]:
        report = self._load_report(report_id)
        bundle_identifier = str(report.get("info_plist", {}).get("bundle_identifier") or "")
        candidates = self._simulator_companion_candidates(bundle_identifier)
        allowed = {Path(str(candidate["path"])).resolve() for candidate in candidates}
        resolved = candidate_path.expanduser().resolve()
        if resolved not in allowed:
            raise ValueError("Selected build product is not a matching Simulator companion candidate")
        return self.install_simulator_companion(report_id, resolved)

    def launch_runtime_target(self, report_id: str, runtime_environment: str) -> Dict[str, Any]:
        if runtime_environment != "simulator":
            raise ValueError("Direct launch is currently available for Xcode Simulator companion builds")
        targets = self.runtime_targets(report_id)
        target = next(item for item in targets["targets"] if item["environment"] == "simulator")
        if not target["installed"]:
            raise RuntimeError("Install a matching Simulator companion build before launching this target")
        boot = self.boot_simulator()
        device = boot["device"]
        xcrun = shutil.which("xcrun")
        if not xcrun:
            raise RuntimeError("Xcode command-line Simulator support is unavailable.")
        try:
            launch = subprocess.run(
                [xcrun, "simctl", "launch", str(device["id"]), targets["bundle_identifier"]],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Simulator launch failed: {exc}") from exc
        if launch.returncode != 0:
            raise RuntimeError(launch.stderr.strip() or "Simulator launch failed.")
        return {
            "launched": True,
            "bundle_identifier": targets["bundle_identifier"],
            "device": device,
            "detail": launch.stdout.strip() or "Simulator target launched.",
        }

    def _simulator_preflight(
        self,
        report_id: str,
        report: Dict[str, Any],
        bundle_identifier: str,
        capture_mode: str,
        script_path: Path,
        frida_path: Optional[str],
        status: Dict[str, Any],
        checks: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        simulator_status = status["simulator_status"]
        booted = simulator_status["booted_devices"]
        device_id = str(booted[0]["id"]) if booted else ""
        artifact_platform = self._report_platform(report)
        checks.extend(
            [
                {
                    "id": "simulator-runtime",
                    "label": "Simulator runtime",
                    "state": "pass" if simulator_status["available_devices"] else "fail",
                    "detail": (
                        f"{len(simulator_status['available_devices'])} Xcode Simulator target(s) available."
                        if simulator_status["available_devices"]
                        else simulator_status["detail"]
                    ),
                },
                {
                    "id": "booted-simulator",
                    "label": "Booted simulator",
                    "state": "pass" if booted else "fail",
                    "detail": booted[0]["name"] if booted else "Boot an iOS Simulator target before capture.",
                },
                {
                    "id": "hook-script",
                    "label": "Capture hooks",
                    "state": "pass" if script_path.exists() else "fail",
                    "detail": script_path.name if script_path.exists() else "Generated Frida hook script is unavailable.",
                },
                {
                    "id": "artifact-platform",
                    "label": "Artifact fidelity",
                    "state": "pass" if artifact_platform == "IOSSIMULATOR" else "guide",
                    "detail": (
                        "Analyzed artifact is built for iOS Simulator."
                        if artifact_platform == "IOSSIMULATOR"
                        else f"Static artifact platform is {artifact_platform}; captured events are companion-build evidence, not exact IPA execution."
                    ),
                },
            ]
        )
        if capture_mode == "gadget":
            checks.append(
                {
                    "id": "simulator-gadget",
                    "label": "Capture path",
                    "state": "guide",
                    "detail": "Use Spawn or Attach for Simulator targets; Gadget is intended for packaged device-app workflows.",
                }
            )
            return {
                "report_id": report_id,
                "bundle_identifier": bundle_identifier,
                "capture_mode": capture_mode,
                "runtime_environment": "simulator",
                "capture_ready": False,
                "checks": checks,
                "device_probe": {"device_id": device_id, "reachable": False, "installed": False, "running": False},
                "artifact_platform": artifact_platform,
                "next_steps": ["Select Spawn or Attach to run through Frida's Xcode Simulator backend."],
            }
        device_probe = (
            self._frida_simulator_target_probe(frida_path, bundle_identifier, device_id)
            if frida_path and device_id
            else {
                "device_id": device_id,
                "reachable": False,
                "installed": False,
                "running": False,
                "detail": "A booted Xcode Simulator is required before querying the installed app.",
            }
        )
        bridge_ok = bool(device_probe.get("reachable"))
        target_installed = bool(device_probe.get("installed"))
        target_running = bool(device_probe.get("running"))
        checks.extend(
            [
                {
                    "id": "frida-channel",
                    "label": "Frida channel",
                    "state": "pass" if bridge_ok else ("blocked" if not booted else "fail"),
                    "detail": str(device_probe.get("detail") or "Simulator channel is unavailable."),
                },
                {
                    "id": "target-app",
                    "label": "Target app",
                    "state": "pass" if target_installed else ("blocked" if not bridge_ok else "fail"),
                    "detail": (
                        f"{bundle_identifier} is installed in the Simulator"
                        if target_installed
                        else (
                            "Awaiting a working Simulator channel before verifying the installed bundle."
                            if not bridge_ok
                            else f"{bundle_identifier} was not found in the booted Simulator."
                        )
                    ),
                },
            ]
        )
        if capture_mode == "attach":
            checks.append(
                {
                    "id": "running-process",
                    "label": "Running process",
                    "state": "pass" if target_running else "fail",
                    "detail": "Simulator app process is running and attachable." if target_running else "Launch the Simulator app first, then refresh preflight.",
                }
            )
        live_ready = bridge_ok and target_installed and script_path.exists() and (
            capture_mode == "spawn" or (capture_mode == "attach" and target_running)
        )
        if not simulator_status["available_devices"]:
            next_steps = ["Install an iOS Simulator runtime in Xcode Components, create a simulator device, and refresh preflight."]
        elif not booted:
            next_steps = ["Boot an available iPhone Simulator, install or run an authorized Simulator build of this target, and refresh preflight."]
        elif not bridge_ok:
            next_steps = ["Refresh after the booted Simulator is available to Frida."]
        elif not target_installed:
            next_steps = [
                f"Build and run an authorized Simulator version with bundle identifier {bundle_identifier} from Xcode.",
                "Refresh preflight; results will be labeled as Simulator companion-build evidence.",
            ]
        elif capture_mode == "attach" and not target_running:
            next_steps = ["Open the target app in Simulator, then refresh preflight before attaching."]
        else:
            next_steps = ["Preflight passed. Starting capture will instrument the authorized Simulator target."]
        return {
            "report_id": report_id,
            "bundle_identifier": bundle_identifier,
            "capture_mode": capture_mode,
            "runtime_environment": "simulator",
            "capture_ready": live_ready,
            "checks": checks,
            "device_probe": device_probe,
            "artifact_platform": artifact_platform,
            "next_steps": next_steps,
        }

    def create_runtime_session(
        self,
        report_id: str,
        capture_mode: str = "spawn",
        runtime_environment: str = "usb",
    ) -> RuntimeSession:
        frida_path = self._find_runtime_tool("frida")
        if frida_path is None:
            raise RuntimeError("Frida is not installed. Install Frida before starting a live capture.")
        preflight = self.runtime_preflight(report_id, capture_mode, runtime_environment)
        if not preflight["capture_ready"]:
            raise RuntimeError("Runtime preflight has not passed for the selected capture mode.")
        report = self._load_report(report_id)
        bundle_identifier = report.get("info_plist", {}).get("bundle_identifier")
        ipa_path = Path(str(report.get("ipa_path", "")))
        script_path = (self.reports / report_id / "frida-hooks.js").resolve()
        if not bundle_identifier:
            raise ValueError("Selected report does not contain a bundle identifier")
        if not ipa_path.exists():
            raise ValueError("Original IPA is unavailable for post-capture report generation")
        if self.reports.resolve() not in script_path.parents or not script_path.exists():
            raise ValueError("Generated Frida hook script is unavailable for this report")
        session_id = uuid.uuid4().hex[:12]
        session_dir = self.runtime_sessions_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        session = RuntimeSession(
            id=session_id,
            report_id=report_id,
            ipa_path=ipa_path,
            bundle_identifier=str(bundle_identifier),
            capture_mode=capture_mode,
            runtime_environment=runtime_environment,
            script_path=script_path,
            trace_path=session_dir / "runtime-capture.jsonl",
            device_id=str(preflight.get("device_probe", {}).get("device_id") or "") or None,
        )
        with self.lock:
            self.runtime_sessions[session.id] = session
        thread = threading.Thread(target=self._run_runtime_session, args=(session, frida_path), daemon=True)
        thread.start()
        return session

    def _find_runtime_tool(self, name: str) -> Optional[str]:
        env_name = "IRE_ZERO_" + name.upper().replace("-", "_") + "_PATH"
        candidates = []
        configured = os.environ.get(env_name)
        if configured:
            candidates.append(Path(configured).expanduser())
        discovered = shutil.which(name)
        if discovered:
            candidates.append(Path(discovered))
        candidates.append(self.html_path.parent / ".ire-zero-tools" / "bin" / name)
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def _frida_device_status(self, frida_path: Optional[str]) -> Dict[str, Any]:
        if not frida_path:
            return {"checked": False, "usb_connected": False, "devices": [], "error": None}
        python_path = Path(frida_path).parent / "python"
        if not python_path.is_file() or not os.access(python_path, os.X_OK):
            return {
                "checked": False,
                "usb_connected": False,
                "devices": [],
                "error": "Frida is installed, but automated device discovery is unavailable.",
            }
        probe = (
            "import frida,json;"
            "print(json.dumps([{'id': d.id, 'name': d.name, 'type': d.type} "
            "for d in frida.get_device_manager().enumerate_devices()]))"
        )
        try:
            result = subprocess.run(
                [str(python_path), "-c", probe],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"checked": True, "usb_connected": False, "devices": [], "error": str(exc)}
        if result.returncode != 0:
            return {
                "checked": True,
                "usb_connected": False,
                "devices": [],
                "error": result.stderr.strip() or "Device discovery failed",
            }
        try:
            devices = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return {"checked": True, "usb_connected": False, "devices": [], "error": "Invalid device discovery output"}
        usb_devices = [
            str(device.get("name") or device.get("id") or "USB device")
            for device in devices
            if isinstance(device, dict) and device.get("type") == "usb"
        ]
        return {
            "checked": True,
            "usb_connected": bool(usb_devices),
            "devices": usb_devices[:8],
            "error": None,
        }

    def _simulator_status(self) -> Dict[str, Any]:
        xcrun = shutil.which("xcrun")
        if not xcrun:
            return {
                "checked": False,
                "available_devices": [],
                "booted_devices": [],
                "detail": "Xcode command-line Simulator support is unavailable.",
            }
        try:
            result = subprocess.run(
                [xcrun, "simctl", "list", "devices", "available", "--json"],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"checked": True, "available_devices": [], "booted_devices": [], "detail": str(exc)}
        if result.returncode != 0:
            return {
                "checked": True,
                "available_devices": [],
                "booted_devices": [],
                "detail": result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "Simulator discovery failed.",
            }
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"checked": True, "available_devices": [], "booted_devices": [], "detail": "Invalid Simulator discovery output."}
        raw_devices = payload.get("devices", {}) if isinstance(payload, dict) else {}
        available = [
            {"id": str(device.get("udid", "")), "name": str(device.get("name", "iPhone Simulator")), "state": str(device.get("state", ""))}
            for devices in raw_devices.values()
            if isinstance(devices, list)
            for device in devices
            if isinstance(device, dict) and device.get("isAvailable", True)
        ]
        booted = [device for device in available if device["state"] == "Booted"]
        return {
            "checked": True,
            "available_devices": available,
            "booted_devices": booted,
            "detail": "No iOS Simulator runtime/device is installed in Xcode." if not available else "No Simulator is currently booted.",
        }

    def boot_simulator(self, preferred_device_id: Optional[str] = None) -> Dict[str, Any]:
        status = self._simulator_status()
        booted = status["booted_devices"]
        if booted:
            return {"booted": True, "already_booted": True, "device": booted[0], "simulator_status": status}
        available = status["available_devices"]
        if not available:
            raise RuntimeError(status["detail"])
        device = next(
            (item for item in available if preferred_device_id and item["id"] == preferred_device_id),
            None,
        )
        if device is None:
            device = next((item for item in available if item["name"] == "iPhone 17 Pro"), None)
        if device is None:
            device = next((item for item in available if item["name"].startswith("iPhone")), available[0])
        xcrun = shutil.which("xcrun")
        if not xcrun:
            raise RuntimeError("Xcode command-line Simulator support is unavailable.")
        try:
            boot = subprocess.run(
                [xcrun, "simctl", "boot", device["id"]],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            already_booted = "current state: Booted" in (boot.stderr + boot.stdout)
            if boot.returncode != 0 and not already_booted:
                raise RuntimeError(boot.stderr.strip() or "Simulator boot failed.")
            ready = subprocess.run(
                [xcrun, "simctl", "bootstatus", device["id"], "-b"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if ready.returncode != 0:
                raise RuntimeError(ready.stderr.strip() or "Simulator did not finish booting.")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Simulator boot failed: {exc}") from exc
        refreshed = self._simulator_status()
        selected = next(
            (item for item in refreshed["booted_devices"] if item["id"] == device["id"]),
            device,
        )
        return {"booted": True, "already_booted": False, "device": selected, "simulator_status": refreshed}

    def _target_binding(self, bundle_identifier: str) -> Optional[Dict[str, Any]]:
        if not self.runtime_bindings_path.exists():
            return None
        try:
            payload = json.loads(self.runtime_bindings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        value = payload.get(bundle_identifier) if isinstance(payload, dict) else None
        return dict(value) if isinstance(value, dict) else None

    def _simulator_companion_candidates(self, bundle_identifier: str) -> List[Dict[str, Any]]:
        roots = [
            self.html_path.parent / "simulator-targets",
            Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData",
        ]
        paths: List[Path] = []
        for root in roots:
            if not root.exists():
                continue
            paths.extend(root.glob("**/Build/Products/*-iphonesimulator/*.app"))
        candidates: List[Dict[str, Any]] = []
        for app_bundle in sorted(set(paths), key=lambda path: path.stat().st_mtime, reverse=True):
            plist_path = app_bundle / "Info.plist"
            if not plist_path.exists():
                continue
            try:
                with plist_path.open("rb") as handle:
                    plist = plistlib.load(handle)
                if not isinstance(plist, dict) or str(plist.get("CFBundleIdentifier") or "") != bundle_identifier:
                    continue
                executable = app_bundle / str(plist.get("CFBundleExecutable") or "")
                platform = extract_platform(executable) if executable.is_file() else None
            except (OSError, plistlib.InvalidFileException):
                continue
            if platform != "IOSSIMULATOR":
                continue
            candidates.append(
                {
                    "path": str(app_bundle),
                    "name": app_bundle.name,
                    "platform": platform,
                    "source": "Xcode build product",
                }
            )
        return candidates[:8]

    def _remember_target_binding(self, bundle_identifier: str, binding: Dict[str, Any]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if self.runtime_bindings_path.exists():
            try:
                stored = json.loads(self.runtime_bindings_path.read_text(encoding="utf-8"))
                if isinstance(stored, dict):
                    payload = stored
            except (OSError, json.JSONDecodeError):
                payload = {}
        saved = {**binding, "bundle_identifier": bundle_identifier, "updated_at": _timestamp()}
        payload[bundle_identifier] = saved
        self.runtime_bindings_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return saved

    def _frida_target_probe(self, frida_path: Optional[str], bundle_identifier: str) -> Dict[str, Any]:
        if not frida_path:
            return {"reachable": False, "installed": False, "running": False, "detail": "Frida client unavailable."}
        python_path = Path(frida_path).parent / "python"
        if not python_path.exists():
            return {"reachable": False, "installed": False, "running": False, "detail": "Managed Frida Python is unavailable."}
        probe = (
            "import frida,json,sys;"
            "bundle=sys.argv[1];"
            "device=frida.get_usb_device(timeout=5);"
            "apps=device.enumerate_applications();"
            "matches=[{'identifier':a.identifier,'name':a.name,'pid':a.pid} for a in apps if a.identifier == bundle];"
            "print(json.dumps({'device':device.name,'matches':matches}))"
        )
        try:
            result = subprocess.run(
                [str(python_path), "-c", probe, bundle_identifier],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"reachable": False, "installed": False, "running": False, "detail": str(exc)}
        if result.returncode != 0:
            detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "Frida device query failed."
            return {"reachable": False, "installed": False, "running": False, "detail": detail}
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return {"reachable": False, "installed": False, "running": False, "detail": "Invalid Frida query output."}
        matches = payload.get("matches", []) if isinstance(payload, dict) else []
        installed = bool(matches)
        running = bool(installed and int(matches[0].get("pid") or 0) > 0)
        name = str(payload.get("device", "iPhone")) if isinstance(payload, dict) else "iPhone"
        return {
            "reachable": True,
            "installed": installed,
            "running": running,
            "detail": f"{name} responded to application enumeration.",
            "matches": matches,
        }

    def _frida_simulator_target_probe(
        self,
        frida_path: Optional[str],
        bundle_identifier: str,
        device_id: str,
    ) -> Dict[str, Any]:
        if not frida_path or not device_id:
            return {"device_id": device_id, "reachable": False, "installed": False, "running": False, "detail": "Simulator target unavailable."}
        python_path = Path(frida_path).parent / "python"
        if not python_path.exists():
            return {"device_id": device_id, "reachable": False, "installed": False, "running": False, "detail": "Managed Frida Python is unavailable."}
        probe = (
            "import frida,json,sys;"
            "bundle=sys.argv[1];device_id=sys.argv[2];"
            "device=frida.get_device(device_id,timeout=5);"
            "apps=device.enumerate_applications();"
            "matches=[{'identifier':a.identifier,'name':a.name,'pid':a.pid} for a in apps if a.identifier == bundle];"
            "print(json.dumps({'device':device.name,'matches':matches}))"
        )
        try:
            result = subprocess.run(
                [str(python_path), "-c", probe, bundle_identifier, device_id],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"device_id": device_id, "reachable": False, "installed": False, "running": False, "detail": str(exc)}
        if result.returncode != 0:
            detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "Frida Simulator query failed."
            return {"device_id": device_id, "reachable": False, "installed": False, "running": False, "detail": detail}
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return {"device_id": device_id, "reachable": False, "installed": False, "running": False, "detail": "Invalid Frida Simulator query output."}
        matches = payload.get("matches", []) if isinstance(payload, dict) else []
        installed = bool(matches)
        running = bool(installed and int(matches[0].get("pid") or 0) > 0)
        name = str(payload.get("device", "iPhone Simulator")) if isinstance(payload, dict) else "iPhone Simulator"
        return {
            "device_id": device_id,
            "reachable": True,
            "installed": installed,
            "running": running,
            "detail": f"{name} responded through Frida Simmy.",
            "matches": matches,
        }

    def _report_platform(self, report: Dict[str, Any]) -> str:
        stored = report.get("binary", {}).get("platform")
        if isinstance(stored, str) and stored:
            return stored
        ipa_path = Path(str(report.get("ipa_path", "")))
        executable_path = str(report.get("executable_path", ""))
        if not ipa_path.exists() or not executable_path:
            return "UNKNOWN"
        try:
            with zipfile.ZipFile(ipa_path) as archive:
                with archive.open(executable_path) as executable:
                    platform = extract_platform_data(executable.read(4 * 1024 * 1024))
            return platform or "UNKNOWN"
        except (OSError, KeyError, zipfile.BadZipFile):
            return "UNKNOWN"

    def stop_runtime_session(self, session_id: str) -> RuntimeSession:
        with self.lock:
            session = self.runtime_sessions.get(session_id)
        if session is None:
            raise KeyError(session_id)
        session.stop_requested = True
        if session.state in {"queued", "starting", "running"}:
            session.state = "stopping"
            session.phase = "Stopping capture"
        process = session.process
        if process is not None and process.poll() is None:
            process.terminate()
        return session

    def _run_runtime_session(self, session: RuntimeSession, frida_path: str) -> None:
        target_options = ["-f", session.bundle_identifier] if session.capture_mode == "spawn" else ["-N", session.bundle_identifier]
        connection_options = ["-D", session.device_id] if session.runtime_environment == "simulator" and session.device_id else ["-U"]
        command = [frida_path, *connection_options, "-q", "-t", "inf", *target_options, "-l", str(session.script_path)]
        try:
            session.state = "starting"
            session.phase = "Attaching Frida to authorized target"
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            session.process = process
            session.state = "running"
            session.phase = "Capturing observed runtime events"
            with session.trace_path.open("w", encoding="utf-8") as trace:
                if process.stdout is not None:
                    for line in process.stdout:
                        cleaned = line.rstrip()
                        session.log_tail.append(cleaned)
                        if len(session.log_tail) > 100:
                            del session.log_tail[:-100]
                        event = _runtime_event_from_line(cleaned)
                        if event is not None:
                            session.events.append(event)
                            trace.write(json.dumps(event) + "\n")
                            trace.flush()
            process.wait()
            if session.events:
                self._finalize_runtime_session(session)
            elif session.stop_requested:
                session.state = "stopped"
                session.phase = "Stopped without captured events"
            else:
                session.state = "completed"
                session.phase = "Capture ended without observed events"
        except Exception as exc:
            session.state = "failed"
            session.phase = "Live capture failed"
            session.error = str(exc)
        finally:
            session.process = None

    def _finalize_runtime_session(self, session: RuntimeSession) -> None:
        session.state = "finalizing"
        session.phase = "Merging captured evidence into report"
        is_simulator = session.runtime_environment == "simulator"
        result = analyze_ipa(
            session.ipa_path,
            load_rules(None),
            runtime_trace=session.trace_path,
            runtime_capture_mode="companion_build" if is_simulator else "exact_ipa",
            runtime_source="Frida Simulator live capture" if is_simulator else "Frida USB device live capture",
            runtime_session=session.id,
        )
        if is_simulator:
            result.dynamic.limitations.append(
                "Runtime evidence was captured from an installed Simulator companion build and is not proof that the analyzed device IPA executed identically."
            )
        report_dir = _unique_report_dir(self.reports, result_dir_name(session.ipa_path, result.app_name))
        write_reports(result, report_dir, sarif=True, html_report=True)
        session.result_report_id = report_dir.name
        session.state = "completed"
        session.phase = f"Captured evidence saved in {report_dir.name}"

    def _load_report(self, report_id: str) -> Dict[str, Any]:
        report_path = self._report_dir(report_id) / "report.json"
        return json.loads(report_path.read_text(encoding="utf-8"))

    def _report_dir(self, report_id: str) -> Path:
        report_dir = (self.reports / report_id).resolve()
        report_path = report_dir / "report.json"
        if self.reports.resolve() not in report_dir.parents or not report_path.exists():
            raise ValueError("Report not found")
        return report_dir

    def _read_report_notes(self, report_dir: Path) -> List[Dict[str, Any]]:
        notes_path = report_dir / "analyst-notes.json"
        if not notes_path.exists():
            return []
        try:
            payload = json.loads(notes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return [note for note in payload if isinstance(note, dict)] if isinstance(payload, list) else []

    def _write_report_notes(self, report_dir: Path, notes: List[Dict[str, Any]]) -> None:
        (report_dir / "analyst-notes.json").write_text(
            json.dumps(notes, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        lines = ["# Analyst Notes", ""]
        if not notes:
            lines.append("No analyst annotations saved.")
        for note in notes:
            lines.extend(
                [
                    f"## {note['title']}",
                    "",
                    f"- Severity: `{note['severity']}`",
                    f"- Status: `{note['status']}`",
                    f"- Created: `{note['created_at']}`",
                    "",
                    str(note["body"]),
                    "",
                ]
            )
            if note.get("evidence"):
                lines.append("Evidence:")
                lines.extend(f"- `{item}`" for item in note["evidence"])
                lines.append("")
        (report_dir / "analyst-notes.md").write_text("\n".join(lines), encoding="utf-8")


class WorkbenchHandler(BaseHTTPRequestHandler):
    server_version = "iRE-Zero/0.2"

    @property
    def state(self) -> WorkbenchState:
        return self.server.state  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route in {"/", "/cipherdock-workbench.html"}:
            return self._serve_file(self.state.html_path)
        if route == "/api/health":
            return self._json({"ok": True, "service": "iRE-Zero workbench", "reports": len(self.state.report_catalog())})
        if route == "/api/reports":
            return self._json({"reports": self.state.report_catalog()})
        if route == "/api/batches":
            return self._json({"batches": self.state.batch_catalog()})
        if route == "/api/runtime/status":
            return self._json(self.state.runtime_status())
        if route == "/api/runtime/targets":
            report_id = str(parse_qs(urlparse(self.path).query).get("report_id", [""])[0]).strip()
            if not report_id:
                return self._json({"error": "report_id is required"}, HTTPStatus.BAD_REQUEST)
            try:
                return self._json(self.state.runtime_targets(report_id))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if route.startswith("/api/runtime/sessions/"):
            session_id = unquote(route.removeprefix("/api/runtime/sessions/"))
            with self.state.lock:
                session = self.state.runtime_sessions.get(session_id)
            if session is None:
                return self._json({"error": "runtime session not found"}, HTTPStatus.NOT_FOUND)
            return self._json(session.payload())
        if route.startswith("/api/reports/") and route.endswith("/notes"):
            report_id = unquote(route.removeprefix("/api/reports/").removesuffix("/notes").rstrip("/"))
            try:
                return self._json({"notes": self.state.report_notes(report_id)})
            except ValueError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        if route.startswith("/api/reports/"):
            report_id = unquote(route.removeprefix("/api/reports/"))
            return self._serve_report(report_id)
        if route.startswith("/api/jobs/"):
            job_id = unquote(route.removeprefix("/api/jobs/"))
            with self.state.lock:
                job = self.state.jobs.get(job_id)
            if job is None:
                return self._json({"error": "job not found"}, HTTPStatus.NOT_FOUND)
            return self._json(job.payload())
        if route.startswith("/reports/"):
            requested = (self.state.reports / unquote(route.removeprefix("/reports/"))).resolve()
            if self.state.reports.resolve() not in requested.parents:
                return self._json({"error": "invalid report path"}, HTTPStatus.BAD_REQUEST)
            return self._serve_file(requested)
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        if route == "/api/jobs":
            return self._create_upload_job()
        if route == "/api/sample":
            fixture = self.state.html_path.parent / "fixtures" / "SyntheticRisk" / "SyntheticRisk.ipa"
            if not fixture.exists():
                return self._json({"error": "sample fixture missing"}, HTTPStatus.NOT_FOUND)
            return self._json(self.state.create_job([fixture]).payload(), HTTPStatus.ACCEPTED)
        if route == "/api/runtime/sessions":
            return self._create_runtime_session()
        if route == "/api/runtime/preflight":
            return self._create_runtime_preflight()
        if route == "/api/runtime/simulator/boot":
            return self._boot_simulator()
        if route == "/api/runtime/targets/launch":
            return self._launch_runtime_target()
        if route == "/api/runtime/targets/install":
            return self._install_simulator_companion()
        if route == "/api/runtime/targets/install-candidate":
            return self._install_companion_candidate()
        if route == "/api/runtime/import":
            return self._create_runtime_import()
        if route.startswith("/api/reports/") and route.endswith("/notes"):
            return self._save_report_note(route)
        if route.startswith("/api/reports/") and route.endswith("/notes/delete"):
            return self._delete_report_note(route)
        if route.startswith("/api/runtime/sessions/") and route.endswith("/stop"):
            session_id = unquote(route.removeprefix("/api/runtime/sessions/").removesuffix("/stop").rstrip("/"))
            try:
                session = self.state.stop_runtime_session(session_id)
            except KeyError:
                return self._json({"error": "runtime session not found"}, HTTPStatus.NOT_FOUND)
            return self._json(session.payload(), HTTPStatus.ACCEPTED)
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _save_report_note(self, route: str) -> None:
        report_id = unquote(route.removeprefix("/api/reports/").removesuffix("/notes").rstrip("/"))
        try:
            notes = self.state.save_report_note(report_id, self._read_json_body())
        except ValueError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json({"notes": notes}, HTTPStatus.CREATED)

    def _delete_report_note(self, route: str) -> None:
        report_id = unquote(route.removeprefix("/api/reports/").removesuffix("/notes/delete").rstrip("/"))
        try:
            note_id = str(self._read_json_body().get("note_id", "")).strip()
            if not note_id:
                raise ValueError("note_id is required")
            notes = self.state.delete_report_note(report_id, note_id)
        except ValueError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json({"notes": notes})

    def _create_runtime_session(self) -> None:
        try:
            payload = self._read_json_body()
            report_id = str(payload.get("report_id", "")).strip()
            capture_mode = str(payload.get("capture_mode", "spawn")).strip()
            runtime_environment = str(payload.get("runtime_environment", "usb")).strip()
            if not report_id:
                return self._json({"error": "report_id is required"}, HTTPStatus.BAD_REQUEST)
            session = self.state.create_runtime_session(report_id, capture_mode, runtime_environment)
        except RuntimeError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json(session.payload(), HTTPStatus.ACCEPTED)

    def _create_runtime_preflight(self) -> None:
        try:
            payload = self._read_json_body()
            report_id = str(payload.get("report_id", "")).strip()
            capture_mode = str(payload.get("capture_mode", "spawn")).strip()
            runtime_environment = str(payload.get("runtime_environment", "usb")).strip()
            if not report_id:
                return self._json({"error": "report_id is required"}, HTTPStatus.BAD_REQUEST)
            preflight = self.state.runtime_preflight(report_id, capture_mode, runtime_environment)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json(preflight)

    def _boot_simulator(self) -> None:
        try:
            payload = self._read_json_body()
            device_id = str(payload.get("device_id", "")).strip() or None
            result = self.state.boot_simulator(device_id)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
        self._json(result)

    def _launch_runtime_target(self) -> None:
        try:
            payload = self._read_json_body()
            report_id = str(payload.get("report_id", "")).strip()
            runtime_environment = str(payload.get("runtime_environment", "")).strip()
            if not report_id:
                raise ValueError("report_id is required")
            result = self.state.launch_runtime_target(report_id, runtime_environment)
        except RuntimeError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json(result)

    def _install_simulator_companion(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return self._json({"error": "expected multipart upload"}, HTTPStatus.BAD_REQUEST)
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type},
        )
        report_id = str(form.getfirst("report_id", "")).strip()
        entries = form["bundle"] if "bundle" in form else []
        if not isinstance(entries, list):
            entries = [entries]
        relative_paths = form.getlist("relative_path")
        if not report_id or not entries or len(entries) != len(relative_paths):
            return self._json({"error": "report_id and an application bundle directory are required"}, HTTPStatus.BAD_REQUEST)
        upload_root = self.state.runtime_companions_dir / uuid.uuid4().hex[:12]
        try:
            app_name: Optional[str] = None
            for entry, raw_path in zip(entries, relative_paths):
                relative = PurePosixPath(str(raw_path))
                if relative.is_absolute() or ".." in relative.parts or len(relative.parts) < 2:
                    raise ValueError("Invalid companion bundle file path")
                if not relative.parts[0].lower().endswith(".app"):
                    raise ValueError("Select an iOS Simulator .app bundle directory")
                if app_name is None:
                    app_name = relative.parts[0]
                if relative.parts[0] != app_name:
                    raise ValueError("Select one application bundle at a time")
                destination = upload_root.joinpath(*relative.parts).resolve()
                if upload_root.resolve() not in destination.parents:
                    raise ValueError("Invalid companion bundle file path")
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("wb") as target:
                    shutil.copyfileobj(entry.file, target)
            if app_name is None:
                raise ValueError("Application bundle selection is empty")
            binding = self.state.install_simulator_companion(report_id, upload_root / app_name)
        except RuntimeError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except (OSError, ValueError, plistlib.InvalidFileException, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json({"installed": True, "binding": binding}, HTTPStatus.CREATED)

    def _install_companion_candidate(self) -> None:
        try:
            payload = self._read_json_body()
            report_id = str(payload.get("report_id", "")).strip()
            candidate_path = str(payload.get("candidate_path", "")).strip()
            if not report_id or not candidate_path:
                raise ValueError("report_id and candidate_path are required")
            binding = self.state.install_companion_candidate(report_id, Path(candidate_path))
        except RuntimeError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        self._json({"installed": True, "binding": binding}, HTTPStatus.CREATED)

    def _create_runtime_import(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return self._json({"error": "expected multipart upload"}, HTTPStatus.BAD_REQUEST)
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type},
        )
        report_id = str(form.getfirst("report_id", "")).strip()
        trace = form["trace"] if "trace" in form else None
        filename = Path(getattr(trace, "filename", "") or "").name
        if not report_id or trace is None or not filename:
            return self._json({"error": "report_id and trace are required"}, HTTPStatus.BAD_REQUEST)
        try:
            report = self.state._load_report(report_id)
            ipa_path = Path(str(report.get("ipa_path", "")))
            if not ipa_path.exists():
                raise ValueError("Original IPA is unavailable for trace correlation")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        upload_dir = self.state.uploads / uuid.uuid4().hex[:12]
        upload_dir.mkdir(parents=True, exist_ok=True)
        trace_path = upload_dir / filename
        with trace_path.open("wb") as target:
            shutil.copyfileobj(trace.file, target)
        return self._json(self.state.create_job([ipa_path], trace_path).payload(), HTTPStatus.ACCEPTED)

    def _create_upload_job(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return self._json({"error": "expected multipart upload"}, HTTPStatus.BAD_REQUEST)
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type},
        )
        upload_dir = self.state.uploads / uuid.uuid4().hex[:12]
        upload_dir.mkdir(parents=True, exist_ok=True)
        files: List[Path] = []
        entries = form["ipa"] if "ipa" in form else []
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            filename = Path(getattr(entry, "filename", "") or "").name
            if not filename.lower().endswith(".ipa"):
                continue
            destination = upload_dir / filename
            with destination.open("wb") as target:
                shutil.copyfileobj(entry.file, target)
            files.append(destination)
        trace_path: Optional[Path] = None
        if "trace" in form and getattr(form["trace"], "filename", ""):
            trace_path = upload_dir / Path(form["trace"].filename).name
            with trace_path.open("wb") as target:
                shutil.copyfileobj(form["trace"].file, target)
        if not files:
            return self._json({"error": "no IPA files supplied"}, HTTPStatus.BAD_REQUEST)
        if trace_path is not None and len(files) != 1:
            return self._json({"error": "a runtime trace may only accompany one IPA"}, HTTPStatus.BAD_REQUEST)
        self._json(self.state.create_job(files, trace_path).payload(), HTTPStatus.ACCEPTED)

    def _serve_report(self, report_id: str) -> None:
        report_path = (self.state.reports / report_id / "report.json").resolve()
        if self.state.reports.resolve() not in report_path.parents or not report_path.exists():
            return self._json({"error": "report not found"}, HTTPStatus.NOT_FOUND)
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        self._json({"id": report_id, "report": payload, "analyst_notes": self.state.report_notes(report_id)})

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        return payload if isinstance(payload, dict) else {}

    def _serve_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            return self._json({"error": "file not found"}, HTTPStatus.NOT_FOUND)
        data = path.read_bytes()
        mime_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def serve(host: str, port: int, workspace: Path, html_path: Path) -> None:
    state = WorkbenchState(workspace, html_path)
    server = ThreadingHTTPServer((host, port), WorkbenchHandler)
    server.state = state  # type: ignore[attr-defined]
    print(f"iRE-Zero workbench listening at http://{host}:{port}/cipherdock-workbench.html", flush=True)
    print(f"Reports: {state.reports}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="ire-zero-workbench")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--workspace", type=Path, default=Path("workbench-data"))
    parser.add_argument("--html", type=Path, default=Path("cipherdock-workbench.html"))
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.workspace, args.html.resolve())
    return 0


def _unique_report_dir(output: Path, name: str) -> Path:
    candidate = output / name
    if not candidate.exists():
        return candidate
    index = 2
    while (output / f"{name}-{index}").exists():
        index += 1
    return output / f"{name}-{index}"


def _runtime_event_from_line(line: str) -> Optional[Dict[str, Any]]:
    if "IRE_ZERO_EVENT " not in line:
        return None
    payload = line.split("IRE_ZERO_EVENT ", 1)[1].strip()
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict):
        return None
    return event


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
