"""Safely unpack IPA archives and locate the primary app executable."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Optional

from .plist_parser import load_info_plist


class IPAError(RuntimeError):
    pass


def safe_unpack_ipa(ipa_path: Path, destination: Path, max_member_size: int = 600 * 1024 * 1024) -> Path:
    if not ipa_path.is_file():
        raise IPAError(f"IPA does not exist: {ipa_path}")
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    try:
        with zipfile.ZipFile(ipa_path) as archive:
            for member in archive.infolist():
                if member.file_size > max_member_size:
                    raise IPAError(f"Archive member too large: {member.filename}")
                target = (destination / member.filename).resolve()
                if root not in target.parents and target != root:
                    raise IPAError(f"Unsafe archive path: {member.filename}")
                archive.extract(member, destination)
    except zipfile.BadZipFile as exc:
        raise IPAError(f"Invalid IPA zip: {ipa_path}") from exc
    return destination


def locate_app_bundle(unpacked_root: Path) -> Path:
    payload = unpacked_root / "Payload"
    candidates = sorted(payload.glob("*.app")) if payload.exists() else []
    if not candidates:
        candidates = sorted(unpacked_root.rglob("*.app"))
    if not candidates:
        raise IPAError("No .app bundle found in IPA")
    return candidates[0]


def locate_main_executable(app_bundle: Path) -> Path:
    plist = load_info_plist(app_bundle / "Info.plist")
    executable_name: Optional[str] = plist.bundle_executable or plist.bundle_name
    if executable_name:
        executable = app_bundle / executable_name
        if executable.exists() and executable.is_file():
            return executable
    candidates = [
        path
        for path in app_bundle.iterdir()
        if path.is_file() and not path.suffix and path.name not in {"PkgInfo"}
    ]
    if not candidates:
        raise IPAError("Could not locate main Mach-O executable")
    return candidates[0]
