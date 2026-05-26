"""Run optional Ghidra headless analysis and export symbols and imports."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional


GHIDRA_EXPORT_SCRIPT = r'''
from ghidra.program.model.symbol import SourceType
import json
import sys

program = getCurrentProgram()
out_path = getScriptArgs()[0]
symbols = []
imports = []
exports = []

symbol_table = program.getSymbolTable()
for symbol in symbol_table.getAllSymbols(True):
    name = symbol.getName(True)
    if symbol.isExternal():
        imports.append(name)
    else:
        symbols.append(name)
        if symbol.isGlobal():
            exports.append(name)

payload = {
    "program": program.getName(),
    "language": str(program.getLanguageID()),
    "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
    "symbols": symbols[:5000],
    "imports": imports[:5000],
    "exports": exports[:5000],
}

with open(out_path, "w") as handle:
    json.dump(payload, handle, indent=2)
'''


def run_ghidra(
    executable: Path,
    analyze_headless: Optional[Path],
    script_path: Optional[Path] = None,
    timeout: int = 600,
) -> Dict[str, Any]:
    if analyze_headless is None:
        return {"enabled": False, "reason": "Ghidra headless path not provided"}
    if not analyze_headless.exists():
        return {"enabled": False, "reason": f"Ghidra headless not found: {analyze_headless}"}

    with tempfile.TemporaryDirectory(prefix="ire_zero_ghidra_") as tmp:
        tmp_path = Path(tmp)
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        export_path = tmp_path / "ghidra_export.json"
        script_dir = tmp_path / "scripts"
        script_dir.mkdir()
        export_script = script_dir / "IREZeroExport.py"
        export_script.write_text(GHIDRA_EXPORT_SCRIPT, encoding="utf-8")

        args = [
            str(analyze_headless),
            str(project_dir),
            "IREZeroProject",
            "-import",
            str(executable),
            "-scriptPath",
            str(script_dir),
            "-postScript",
            export_script.name,
            str(export_path),
            "-deleteProject",
        ]
        if script_path is not None:
            args.extend(["-scriptPath", str(script_path.parent), "-postScript", script_path.name])

        try:
            completed = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"enabled": True, "available": False, "error": str(exc)}

        payload: Dict[str, Any] = {
            "enabled": True,
            "available": True,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
        }
        if export_path.exists():
            try:
                payload["export"] = json.loads(export_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                payload["export_error"] = str(exc)
        if completed.returncode != 0:
            payload["error"] = f"Ghidra exited with {completed.returncode}"
        return payload
