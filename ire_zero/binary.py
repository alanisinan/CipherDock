"""Extract linked libraries, symbols, disassembly, and Mach-O metadata."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from .macho import extract_platform, extract_sections
from .models import BinaryArtifacts, ToolResult
from .symbols import classify_symbols
from .utils import dedupe, run_tool


def analyze_binary(app_bundle: Path, executable: Path) -> BinaryArtifacts:
    frameworks, dylibs = enumerate_embedded_libraries(app_bundle)
    tools: Dict[str, ToolResult] = {}

    otool_result = run_tool("otool", ["-L", str(executable)], timeout=60)
    tools["otool"] = otool_result
    linked_libraries = _parse_otool_libraries(otool_result.stdout)
    _truncate_tool_output(otool_result)

    nm_result = run_tool("nm", ["-m", str(executable)], timeout=90)
    tools["nm"] = nm_result
    symbols = _parse_nm_symbols(nm_result.stdout)
    _truncate_tool_output(nm_result)

    class_dump_result = run_tool("class-dump", [str(executable)], timeout=90)
    tools["class_dump"] = class_dump_result
    class_dump = _parse_class_dump(class_dump_result.stdout)
    _truncate_tool_output(class_dump_result)
    disassembly_result = run_tool("otool", ["-tvV", str(executable)], timeout=90)
    disassembly = _parse_otool_disassembly(disassembly_result.stdout)
    _truncate_tool_output(disassembly_result, 25000)
    tools["otool_disassembly"] = disassembly_result
    symbol_categories = classify_symbols([*symbols, *class_dump, *linked_libraries, *frameworks, *dylibs])

    return BinaryArtifacts(
        executable_path=str(executable),
        platform=extract_platform(executable),
        embedded_frameworks=frameworks,
        embedded_dylibs=dylibs,
        linked_libraries=linked_libraries,
        symbols=symbols,
        class_dump=class_dump,
        symbol_categories=symbol_categories,
        tools=tools,
        sections=extract_sections(executable),
        disassembly=disassembly,
    )


def enumerate_embedded_libraries(app_bundle: Path) -> tuple[List[str], List[str]]:
    framework_paths: List[str] = []
    dylib_paths: List[str] = []
    search_roots = [app_bundle / "Frameworks", app_bundle / "PlugIns", app_bundle]
    for root in search_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix == ".framework" and path.is_dir():
                framework_paths.append(_relative(path, app_bundle))
            elif path.suffix == ".dylib" and path.is_file():
                dylib_paths.append(_relative(path, app_bundle))
    return dedupe(framework_paths), dedupe(dylib_paths)


def _parse_otool_libraries(output: str) -> List[str]:
    libraries: List[str] = []
    for line in output.splitlines()[1:]:
        value = line.strip().split(" ", 1)[0]
        if value:
            libraries.append(value)
    return dedupe(libraries, 500)


def _parse_nm_symbols(output: str) -> List[str]:
    symbols: List[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        external = re.search(r"\b(?:weak\s+)?external\s+(\S+)", stripped)
        if external:
            symbols.append(external.group(1))
            continue
        parts = stripped.split()
        if parts:
            symbols.append(parts[-1])
    return dedupe(symbols, 2000)


def _parse_class_dump(output: str) -> List[str]:
    interesting: List[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("@interface", "@protocol", "@property", "- (", "+ (")):
            interesting.append(stripped)
    return dedupe(interesting, 2000)


def _parse_otool_disassembly(output: str, limit: int = 500) -> List[Dict[str, str]]:
    instructions: List[Dict[str, str]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":") or "\t" not in line:
            continue
        fields = [field.strip() for field in line.split("\t") if field.strip()]
        if len(fields) < 2 or not all(ch in "0123456789abcdefABCDEF" for ch in fields[0]):
            continue
        operation = fields[1]
        operand = fields[2] if len(fields) > 2 else ""
        comment = ""
        if ";" in operand:
            operand, comment = (part.strip() for part in operand.split(";", 1))
        instructions.append(
            {
                "address": "0x" + fields[0].lower(),
                "operation": operation,
                "operand": operand,
                "comment": comment,
            }
        )
        if len(instructions) >= limit:
            break
    return instructions


def _truncate_tool_output(result: ToolResult, limit: int = 12000) -> None:
    if len(result.stdout) > limit:
        result.stdout = result.stdout[:limit] + "\n... output truncated; parsed artifacts retained ..."
    if len(result.stderr) > limit:
        result.stderr = result.stderr[:limit] + "\n... output truncated ..."


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
