"""Tests for PlayCover runtime capture integration."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ire_zero.doctor import render_doctor, run_doctor
from ire_zero.playcover import (
    PlayCoverStatus,
    XcodeBuildOptions,
    build_ipa_from_xcode,
    capture_playcover_runtime,
    discover_playcover_pid,
    event_from_frida_line,
)


class PlayCoverTests(unittest.TestCase):
    def test_event_from_frida_line_extracts_runtime_json(self) -> None:
        event = event_from_frida_line('noise IRE_ZERO_EVENT {"layer":"network","value":"https://api.example.test"}')

        self.assertIsNotNone(event)
        self.assertEqual(event["layer"], "network")
        self.assertEqual(event["value"], "https://api.example.test")

    def test_discover_playcover_pid_uses_pgrep_bundle_match(self) -> None:
        completed = subprocess.CompletedProcess(["pgrep"], 0, stdout="4321 /Applications/App.app/App\n", stderr="")
        with patch("ire_zero.playcover.subprocess.run", return_value=completed):
            pid = discover_playcover_pid("com.example.app", retries=1, delay=0)

        self.assertEqual(pid, 4321)

    def test_capture_playcover_runtime_attaches_to_pid_and_writes_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "frida-hooks.js"
            script.write_text("// hooks", encoding="utf-8")
            trace = root / "capture.jsonl"
            process = Mock()
            process.poll.side_effect = [None, None, 0, 0]
            process.terminate.return_value = None
            process.wait.return_value = 0

            with patch("ire_zero.playcover.playcover_status", return_value=PlayCoverStatus(installed=True)):
                with patch("ire_zero.playcover.install_ipa_in_playcover") as install:
                    with patch("ire_zero.playcover.launch_playcover_app") as launch:
                        with patch("ire_zero.playcover.discover_playcover_pid", return_value=4321):
                            with patch("ire_zero.playcover._find_frida", return_value=Path("/usr/local/bin/frida")):
                                with patch("ire_zero.playcover._read_process_line", side_effect=[
                                    'IRE_ZERO_EVENT {"layer":"network","operation":"NSURLSession","value":"https://api.example.test"}',
                                    None,
                                ]):
                                    with patch("ire_zero.playcover.subprocess.Popen", return_value=process) as popen:
                                        result = capture_playcover_runtime(
                                            bundle_identifier="com.example.app",
                                            script_path=script,
                                            trace_path=trace,
                                            ipa_path=root / "App.ipa",
                                            duration=1,
                                        )

            install.assert_called_once()
            launch.assert_called_once()
            self.assertEqual(result.pid, 4321)
            self.assertEqual(result.events, 1)
            self.assertIn("-p", result.command)
            self.assertIn("4321", result.command)
            popen.assert_called_once()
            self.assertIn("https://api.example.test", trace.read_text(encoding="utf-8"))

    def test_build_ipa_from_xcode_archives_and_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "out"

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                if "-exportArchive" in command:
                    export_index = command.index("-exportPath") + 1
                    export_dir = Path(command[export_index])
                    export_dir.mkdir(parents=True, exist_ok=True)
                    (export_dir / "App.ipa").write_bytes(b"ipa")
                return subprocess.CompletedProcess(command, 0)

            with patch("ire_zero.playcover.subprocess.run", side_effect=fake_run) as run:
                ipa = build_ipa_from_xcode(
                    XcodeBuildOptions(project=Path("App.xcodeproj"), scheme="App", build_root=root),
                    output,
                )

        self.assertEqual(ipa.name, "App.ipa")
        self.assertEqual(run.call_count, 2)
        first_command = run.call_args_list[0].args[0]
        second_command = run.call_args_list[1].args[0]
        self.assertIn("archive", first_command)
        self.assertIn("-exportArchive", second_command)

    def test_doctor_surfaces_playcover_checks(self) -> None:
        with patch("ire_zero.doctor.playcover_status", return_value=PlayCoverStatus(installed=True, cli_path=Path("/usr/local/bin/playcover"), detail="/Applications/PlayCover.app")):
            with patch("ire_zero.doctor.sip_status", return_value={"status": "ok", "detail": "System Integrity Protection status: enabled."}):
                with patch("ire_zero.doctor.amfi_status", return_value={"status": "ok", "detail": "boot-args empty"}):
                    rendered = render_doctor(run_doctor())

        self.assertIn("playcover", rendered)
        self.assertIn("playcover-cli", rendered)
        self.assertIn("sip", rendered)
        self.assertIn("amfi", rendered)


if __name__ == "__main__":
    unittest.main()
