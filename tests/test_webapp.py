"""Tests for local workbench state, Simulator preflight, and live capture."""

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ire_zero.webapp import RuntimeSession, WorkbenchState, _runtime_event_from_line


class _FakeProcess:
    def __init__(self) -> None:
        self.stdout = iter(
            [
                "Frida attached\n",
                'IRE_ZERO_EVENT {"timestamp":"now","layer":"network","operation":"URLSession","value":"https://example.test"}\n',
            ]
        )

    def wait(self) -> int:
        return 0

    def poll(self) -> int:
        return 0


class LiveCaptureTests(unittest.TestCase):
    def test_extracts_event_from_frida_output_line(self) -> None:
        event = _runtime_event_from_line(
            'console IRE_ZERO_EVENT {"layer":"process","operation":"attached","value":"ready"}'
        )

        self.assertIsNotNone(event)
        self.assertEqual(event["operation"], "attached")

    def test_runtime_status_reports_missing_frida(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = WorkbenchState(Path(tmp) / "data", Path(tmp) / "workbench.html")
            with mock.patch("ire_zero.webapp.shutil.which", return_value=None):
                status = state.runtime_status()

        self.assertFalse(status["ready"])
        self.assertFalse(status["installed"])
        self.assertFalse(status["tools"]["frida"]["available"])

    def test_runtime_status_discovers_managed_frida_without_claiming_device_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / ".ire-zero-tools" / "bin"
            tools.mkdir(parents=True)
            for tool in ("frida", "frida-ls-devices"):
                path = tools / tool
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o755)
            state = WorkbenchState(root / "data", root / "workbench.html")
            discovery = mock.Mock(returncode=0, stdout='[{"id": "local", "type": "local", "name": "Local System"}]\n', stderr="")
            with mock.patch("ire_zero.webapp.shutil.which", return_value=None):
                with mock.patch("ire_zero.webapp.subprocess.run", return_value=discovery):
                    status = state.runtime_status()

        self.assertTrue(status["installed"])
        self.assertFalse(status["ready"])
        self.assertTrue(status["tools"]["frida"]["available"])
        self.assertFalse(status["device_status"]["usb_connected"])

    def test_runner_writes_events_and_finalizes_only_after_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            session_dir = root / "data" / "runtime-sessions" / "abc"
            session_dir.mkdir(parents=True)
            session = RuntimeSession(
                id="abc",
                report_id="report",
                ipa_path=root / "app.ipa",
                bundle_identifier="com.example.app",
                capture_mode="spawn",
                runtime_environment="usb",
                script_path=root / "hooks.js",
                trace_path=session_dir / "runtime-capture.jsonl",
            )

            def finalize(current: RuntimeSession) -> None:
                current.state = "completed"
                current.result_report_id = "merged-report"

            with mock.patch("ire_zero.webapp.subprocess.Popen", return_value=_FakeProcess()):
                with mock.patch.object(state, "_finalize_runtime_session", side_effect=finalize):
                    state._run_runtime_session(session, "/fake/frida")

            trace = session.trace_path.read_text(encoding="utf-8")

        self.assertEqual(session.state, "completed")
        self.assertEqual(session.result_report_id, "merged-report")
        self.assertEqual(len(session.events), 1)
        self.assertIn("https://example.test", trace)

    def test_simulator_runner_uses_selected_frida_device_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            session_dir = root / "data" / "runtime-sessions" / "sim"
            session_dir.mkdir(parents=True)
            session = RuntimeSession(
                id="sim",
                report_id="report",
                ipa_path=root / "app.ipa",
                bundle_identifier="com.example.app",
                capture_mode="spawn",
                runtime_environment="simulator",
                script_path=root / "hooks.js",
                trace_path=session_dir / "runtime-capture.jsonl",
                device_id="sim-device-id",
            )

            with mock.patch("ire_zero.webapp.subprocess.Popen", return_value=_FakeProcess()) as popen:
                with mock.patch.object(state, "_finalize_runtime_session"):
                    state._run_runtime_session(session, "/fake/frida")

        command = popen.call_args.args[0]
        self.assertEqual(command[:3], ["/fake/frida", "-D", "sim-device-id"])
        self.assertNotIn("-U", command)
        self.assertIn("-q", command)
        self.assertIn("-t", command)
        self.assertEqual(command[command.index("-t") + 1], "inf")

    def test_preflight_requires_running_app_for_attach_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}}),
                encoding="utf-8",
            )
            (report_dir / "frida-hooks.js").write_text("// hooks", encoding="utf-8")
            status = {"device_status": {"usb_connected": True, "devices": ["iPhone"]}}
            probe = {"reachable": True, "installed": True, "running": False, "detail": "iPhone responded."}
            with mock.patch.object(state, "_find_runtime_tool", return_value="/tool/frida"):
                with mock.patch.object(state, "runtime_status", return_value=status):
                    with mock.patch.object(state, "_frida_target_probe", return_value=probe):
                        preflight = state.runtime_preflight("sample", "attach")

        self.assertFalse(preflight["capture_ready"])
        self.assertEqual(preflight["checks"][-1]["id"], "running-process")
        self.assertEqual(preflight["checks"][-1]["state"], "fail")

    def test_preflight_passes_spawn_for_installed_target_and_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}}),
                encoding="utf-8",
            )
            (report_dir / "frida-hooks.js").write_text("// hooks", encoding="utf-8")
            status = {"device_status": {"usb_connected": True, "devices": ["iPhone"]}}
            probe = {"reachable": True, "installed": True, "running": False, "detail": "iPhone responded."}
            with mock.patch.object(state, "_find_runtime_tool", return_value="/tool/frida"):
                with mock.patch.object(state, "runtime_status", return_value=status):
                    with mock.patch.object(state, "_frida_target_probe", return_value=probe):
                        preflight = state.runtime_preflight("sample", "spawn")

        self.assertTrue(preflight["capture_ready"])

    def test_preflight_surfaces_developer_disk_image_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}}),
                encoding="utf-8",
            )
            (report_dir / "frida-hooks.js").write_text("// hooks", encoding="utf-8")
            status = {"device_status": {"usb_connected": True, "devices": ["iPhone"]}}
            probe = {
                "reachable": False,
                "installed": False,
                "running": False,
                "detail": "this feature requires an iOS Developer Disk Image to be mounted",
            }
            with mock.patch.object(state, "_find_runtime_tool", return_value="/tool/frida"):
                with mock.patch.object(state, "runtime_status", return_value=status):
                    with mock.patch.object(state, "_frida_target_probe", return_value=probe):
                        preflight = state.runtime_preflight("sample", "spawn")

        self.assertEqual(preflight["checks"][-1]["state"], "blocked")
        self.assertIn("Developer Disk Image", preflight["next_steps"][0])

    def test_simulator_preflight_labels_device_ipa_as_companion_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}, "binary": {"platform": "IOS"}}),
                encoding="utf-8",
            )
            (report_dir / "frida-hooks.js").write_text("// hooks", encoding="utf-8")
            status = {
                "simulator_status": {
                    "available_devices": [{"id": "sim-1", "name": "iPhone 17", "state": "Booted"}],
                    "booted_devices": [{"id": "sim-1", "name": "iPhone 17", "state": "Booted"}],
                    "detail": "",
                }
            }
            probe = {"device_id": "sim-1", "reachable": True, "installed": True, "running": False, "detail": "Simulator responded."}
            with mock.patch.object(state, "_find_runtime_tool", return_value="/tool/frida"):
                with mock.patch.object(state, "runtime_status", return_value=status):
                    with mock.patch.object(state, "_frida_simulator_target_probe", return_value=probe):
                        preflight = state.runtime_preflight("sample", "spawn", "simulator")

        self.assertTrue(preflight["capture_ready"])
        fidelity = next(check for check in preflight["checks"] if check["id"] == "artifact-platform")
        self.assertEqual(fidelity["state"], "guide")
        self.assertIn("companion-build evidence", fidelity["detail"])

    def test_simulator_preflight_blocks_without_installed_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}, "binary": {"platform": "IOSSIMULATOR"}}),
                encoding="utf-8",
            )
            (report_dir / "frida-hooks.js").write_text("// hooks", encoding="utf-8")
            status = {
                "simulator_status": {
                    "available_devices": [],
                    "booted_devices": [],
                    "detail": "No iOS Simulator runtime/device is installed in Xcode.",
                }
            }
            with mock.patch.object(state, "_find_runtime_tool", return_value="/tool/frida"):
                with mock.patch.object(state, "runtime_status", return_value=status):
                    preflight = state.runtime_preflight("sample", "spawn", "simulator")

        self.assertFalse(preflight["capture_ready"])
        self.assertIn("Install an iOS Simulator runtime", preflight["next_steps"][0])

    def test_boot_simulator_prefers_previous_device_and_waits_until_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            available = {
                "available_devices": [
                    {"id": "other", "name": "iPhone 17", "state": "Shutdown"},
                    {"id": "previous", "name": "iPhone 17 Pro", "state": "Shutdown"},
                ],
                "booted_devices": [],
                "detail": "No Simulator is currently booted.",
            }
            booted = {
                "available_devices": [{"id": "previous", "name": "iPhone 17 Pro", "state": "Booted"}],
                "booted_devices": [{"id": "previous", "name": "iPhone 17 Pro", "state": "Booted"}],
                "detail": "",
            }
            result = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch.object(state, "_simulator_status", side_effect=[available, booted]):
                with mock.patch("ire_zero.webapp.shutil.which", return_value="/usr/bin/xcrun"):
                    with mock.patch("ire_zero.webapp.subprocess.run", return_value=result) as run:
                        payload = state.boot_simulator("previous")

        self.assertTrue(payload["booted"])
        self.assertEqual(payload["device"]["id"], "previous")
        self.assertEqual(run.call_args_list[0].args[0], ["/usr/bin/xcrun", "simctl", "boot", "previous"])
        self.assertEqual(run.call_args_list[1].args[0], ["/usr/bin/xcrun", "simctl", "bootstatus", "previous", "-b"])

    def test_runtime_targets_records_simulator_companion_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}, "binary": {"platform": "IOS"}}),
                encoding="utf-8",
            )
            status = {
                "device_status": {"usb_connected": False, "devices": []},
                "simulator_status": {
                    "booted_devices": [{"id": "sim-1", "name": "iPhone 17 Pro", "state": "Booted"}],
                },
            }
            probe = {"device_id": "sim-1", "reachable": True, "installed": True, "running": False, "detail": "Simulator responded."}
            with mock.patch.object(state, "runtime_status", return_value=status):
                with mock.patch.object(state, "_find_runtime_tool", return_value="/tool/frida"):
                    with mock.patch.object(state, "_frida_simulator_target_probe", return_value=probe):
                        targets = state.runtime_targets("sample")

        simulator = next(item for item in targets["targets"] if item["environment"] == "simulator")
        self.assertEqual(simulator["boundary"], "companion-build evidence")
        self.assertEqual(simulator["state"], "ready")
        self.assertEqual(targets["binding"]["artifact_kind"], "simulator_companion")

    def test_install_simulator_companion_validates_and_persists_pairing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.app"}}),
                encoding="utf-8",
            )
            app = root / "Example.app"
            app.mkdir()
            with (app / "Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleIdentifier": "com.example.app", "CFBundleExecutable": "Example"}, handle)
            (app / "Example").write_bytes(b"macho")
            boot = {"device": {"id": "sim-1", "name": "iPhone 17 Pro"}}
            install = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch("ire_zero.webapp.extract_platform", return_value="IOSSIMULATOR"):
                with mock.patch.object(state, "boot_simulator", return_value=boot):
                    with mock.patch("ire_zero.webapp.shutil.which", return_value="/usr/bin/xcrun"):
                        with mock.patch("ire_zero.webapp.subprocess.run", return_value=install) as run:
                            binding = state.install_simulator_companion("sample", app)

        self.assertEqual(binding["artifact_kind"], "simulator_companion")
        self.assertEqual(binding["source"], "installed from workbench")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/xcrun", "simctl", "install", "sim-1", str(app)])

    def test_install_simulator_companion_rejects_bundle_identifier_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text(
                json.dumps({"info_plist": {"bundle_identifier": "com.example.expected"}}),
                encoding="utf-8",
            )
            app = root / "Wrong.app"
            app.mkdir()
            with (app / "Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleIdentifier": "com.example.wrong", "CFBundleExecutable": "Wrong"}, handle)

            with self.assertRaisesRegex(ValueError, "does not match"):
                state.install_simulator_companion("sample", app)

    def test_discovers_matching_xcode_simulator_build_product(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            app = root / "simulator-targets" / "DerivedData" / "Build" / "Products" / "Debug-iphonesimulator" / "Example.app"
            app.mkdir(parents=True)
            with (app / "Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleIdentifier": "com.example.app", "CFBundleExecutable": "Example"}, handle)
            (app / "Example").write_bytes(b"macho")

            with mock.patch("ire_zero.webapp.extract_platform", return_value="IOSSIMULATOR"):
                candidates = state._simulator_companion_candidates("com.example.app")

        self.assertEqual(candidates[0]["path"], str(app))
        self.assertEqual(candidates[0]["source"], "Xcode build product")


class WorkbenchReviewTests(unittest.TestCase):
    def test_analyst_notes_are_persisted_and_exported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            report_dir = state.reports / "sample"
            report_dir.mkdir()
            (report_dir / "report.json").write_text("{}", encoding="utf-8")

            notes = state.save_report_note(
                "sample",
                {
                    "title": "Observed authorization check",
                    "body": "Review endpoint behavior on authenticated launch.",
                    "severity": "medium",
                    "status": "open",
                    "evidence": ["Import: AuthenticationServices"],
                },
            )

            self.assertEqual(len(notes), 1)
            self.assertEqual(state.report_notes("sample")[0]["source"], "analyst annotation")
            self.assertIn("Observed authorization check", (report_dir / "analyst-notes.md").read_text(encoding="utf-8"))
            self.assertEqual(state.delete_report_note("sample", notes[0]["id"]), [])

    def test_batch_catalog_returns_saved_batch_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WorkbenchState(root / "data", root / "workbench.html")
            batch_dir = state.reports / "_batches" / "batch-one"
            batch_dir.mkdir(parents=True)
            (batch_dir / "batch.json").write_text(
                json.dumps({"id": "batch-one", "file_count": 2, "reports": [{"id": "app"}]}),
                encoding="utf-8",
            )

            batches = state.batch_catalog()

        self.assertEqual(batches[0]["id"], "batch-one")
        self.assertEqual(batches[0]["file_count"], 2)


if __name__ == "__main__":
    unittest.main()
