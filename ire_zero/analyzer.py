"""Coordinate IPA extraction, static analysis, runtime merging, and reporting data."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Optional

from .binary import analyze_binary
from .entitlements import extract_entitlements
from .evidence import build_static_evidence
from .ghidra import run_ghidra
from .heuristics import evaluate_heuristics
from .models import AnalysisResult, CaptureMode
from .plist_parser import load_info_plist
from .rules import StringRule
from .runtime import correlate_runtime_events, generate_runtime_campaigns, generate_runtime_probes, load_runtime_capture, measure_campaign_coverage, runtime_findings, runtime_observation_findings
from .semantics import synthesize_notes
from .symbols import classify_symbols
from .string_scan import analyze_strings, extract_strings_from_file
from .unpack import locate_app_bundle, locate_main_executable, safe_unpack_ipa
from .utils import dedupe, path_for_report


def analyze_ipa(
    ipa_path: Path,
    rules: List[StringRule],
    ghidra_headless: Optional[Path] = None,
    ghidra_script: Optional[Path] = None,
    runtime_trace: Optional[Path] = None,
    runtime_capture_mode: CaptureMode = "exact_ipa",
    runtime_source: Optional[str] = None,
    runtime_session: Optional[str] = None,
) -> AnalysisResult:
    errors: List[str] = []
    with tempfile.TemporaryDirectory(prefix="ire_zero_") as tmp:
        unpacked = safe_unpack_ipa(ipa_path, Path(tmp))
        app_bundle = locate_app_bundle(unpacked)
        info_plist = load_info_plist(app_bundle / "Info.plist")
        executable = locate_main_executable(app_bundle)
        app_bundle_report_path = _relative_path(app_bundle, unpacked)
        executable_report_path = _relative_path(executable, unpacked)

        entitlements, signing, signing_tools = extract_entitlements(app_bundle)
        binary = analyze_binary(app_bundle, executable)
        binary.executable_path = executable_report_path
        binary.tools.update(signing_tools)

        extracted_strings = _extract_bundle_strings(app_bundle, executable, errors)
        indicators = analyze_strings(extracted_strings, rules)

        ghidra_payload = run_ghidra(executable, ghidra_headless, ghidra_script)
        binary.ghidra = ghidra_payload
        ghidra_export = ghidra_payload.get("export")
        if isinstance(ghidra_export, dict):
            binary.symbols = _merge_symbol_lists(binary.symbols, ghidra_export.get("symbols"))
            binary.symbols = _merge_symbol_lists(binary.symbols, ghidra_export.get("imports"))
        binary.symbol_categories = classify_symbols(
            [
                *binary.symbols,
                *binary.class_dump,
                *binary.linked_libraries,
                *binary.embedded_frameworks,
                *binary.embedded_dylibs,
            ]
        )

        findings, score, breakdown = evaluate_heuristics(info_plist, entitlements, binary, indicators)
        dynamic = load_runtime_capture(
            runtime_trace,
            capture_mode=runtime_capture_mode,
            source=runtime_source,
            session=runtime_session,
        )
        dynamic.probes = generate_runtime_probes(info_plist, entitlements, binary, indicators, findings)
        dynamic.campaigns = generate_runtime_campaigns(dynamic.probes)
        correlate_runtime_events(dynamic, info_plist, binary, indicators)
        dynamic.campaign_coverage = measure_campaign_coverage(dynamic.campaigns, dynamic.events)
        confirmed_findings = runtime_findings(dynamic)
        observations = runtime_observation_findings(dynamic)
        if confirmed_findings:
            findings = [*confirmed_findings, *observations, *findings]
            breakdown["dynamic_confirmation"] = min(35, len(confirmed_findings) * 18)
            score = min(100, score + breakdown["dynamic_confirmation"])
        else:
            findings = [*observations, *findings]
            breakdown["dynamic_confirmation"] = 0
        build_static_evidence(binary, indicators, findings)
        notes = synthesize_notes(info_plist, binary, findings, dynamic)
        return AnalysisResult(
            ipa_path=path_for_report(ipa_path),
            app_name=info_plist.bundle_name or ipa_path.stem,
            app_bundle_path=app_bundle_report_path,
            executable_path=executable_report_path,
            info_plist=info_plist,
            entitlements=entitlements,
            signing=signing,
            binary=binary,
            strings=indicators,
            findings=findings,
            score=score,
            score_breakdown=breakdown,
            dynamic=dynamic,
            ai_notes=notes,
            errors=errors,
        )


def _merge_symbol_lists(existing: List[str], extra: object) -> List[str]:
    merged = list(existing)
    if isinstance(extra, list):
        for item in extra:
            if isinstance(item, str) and item not in merged:
                merged.append(item)
    return merged[:5000]


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _extract_bundle_strings(app_bundle: Path, executable: Path, errors: List[str]) -> List[str]:
    targets = [executable, app_bundle / "Info.plist"]
    frameworks_dir = app_bundle / "Frameworks"
    if frameworks_dir.exists():
        for path in sorted(frameworks_dir.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix == ".dylib" or (path.parent.suffix == ".framework" and path.name == path.parent.stem):
                targets.append(path)
    strings: List[str] = []
    for target in targets:
        try:
            strings.extend(extract_strings_from_file(target))
        except OSError as exc:
            errors.append(f"String extraction failed for {target.name}: {exc}")
    return dedupe(strings, 100000)
