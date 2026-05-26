"""Load and normalize security-relevant Info.plist properties."""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .models import PlistInfo


PLIST_KEYS = (
    "CFBundleIdentifier",
    "CFBundleName",
    "CFBundleExecutable",
    "CFBundleURLTypes",
    "NSAppTransportSecurity",
    "LSApplicationQueriesSchemes",
)


def read_plist(path: Path) -> Dict[str, Any]:
    with path.open("rb") as handle:
        data = plistlib.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Expected plist dictionary: {path}")
    return dict(data)


def parse_info_plist(data: Mapping[str, Any]) -> PlistInfo:
    url_types = _as_list_of_dicts(data.get("CFBundleURLTypes"))
    ats = data.get("NSAppTransportSecurity")
    schemes = data.get("LSApplicationQueriesSchemes")
    raw_subset = {key: data[key] for key in PLIST_KEYS if key in data}
    return PlistInfo(
        bundle_identifier=_as_optional_str(data.get("CFBundleIdentifier")),
        bundle_name=_as_optional_str(data.get("CFBundleName")),
        bundle_executable=_as_optional_str(data.get("CFBundleExecutable")),
        url_types=url_types,
        app_transport_security=dict(ats) if isinstance(ats, dict) else {},
        query_schemes=[str(item) for item in schemes] if isinstance(schemes, list) else [],
        raw_subset=raw_subset,
    )


def load_info_plist(path: Path) -> PlistInfo:
    return parse_info_plist(read_plist(path))


def _as_optional_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _as_list_of_dicts(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]
