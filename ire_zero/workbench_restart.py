"""Stop a locally running CipherDock workbench instance."""

from __future__ import annotations

import argparse
import subprocess
from typing import List, Optional


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for the restart helper."""
    parser = argparse.ArgumentParser(description="Stop a CipherDock workbench process bound to a local TCP port.")
    parser.add_argument("--port", type=int, default=8765, help="Workbench port to free")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Kill processes listening on the configured workbench port."""
    args = build_parser().parse_args(argv)
    probe = subprocess.run(["/usr/sbin/lsof", "-ti", f"tcp:{args.port}"], capture_output=True, text=True, check=False)
    pids = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    if not pids:
        print(f"No CipherDock workbench found on port {args.port}.")
        return 0
    kill = subprocess.run(["/bin/kill", *pids], capture_output=True, text=True, check=False)
    if kill.returncode:
        message = kill.stderr.strip() or "kill failed"
        print(f"Could not stop workbench on port {args.port}: {message}")
        return kill.returncode
    print(f"Stopped CipherDock workbench on port {args.port}: {', '.join(pids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
