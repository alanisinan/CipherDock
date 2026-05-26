"""Small utilities for tool execution, de-duplication, and report paths."""

from __future__ import annotations

import subprocess
from pathlib import Path
from shutil import which
from typing import Iterable, List, Optional

from .models import ToolResult


def run_tool(name: str, args: Iterable[str], timeout: int = 60) -> ToolResult:
    executable = which(name)
    command = [name, *list(args)]
    if executable is None:
        return ToolResult(name=name, available=False, command=command, error=f"{name} not found")
    try:
        completed = subprocess.run(
            [executable, *list(args)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolResult(name=name, available=True, command=command, error=str(exc))
    return ToolResult(
        name=name,
        available=True,
        command=command,
        stdout=completed.stdout,
        stderr=completed.stderr,
        error=None if completed.returncode == 0 else f"exit code {completed.returncode}",
    )


def dedupe(items: Iterable[str], limit: Optional[int] = None) -> List[str]:
    seen = set()
    output: List[str] = []
    for item in items:
        value = item.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
        if limit is not None and len(output) >= limit:
            break
    return output


def path_for_report(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)
