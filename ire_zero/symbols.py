"""Classify native and Swift symbol identifiers into evidence categories."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

from .utils import dedupe


SYMBOL_PATTERNS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("private_api", ("LSApplicationWorkspace", "MobileInstallation", "CPDistributedMessagingCenter", "SpringBoard", "BackBoardServices")),
    ("networking", ("NSURLSession", "CFNetwork", "NWConnection", "URLSession", "Alamofire", "WebSocket", "Network.framework")),
    ("crypto", ("CCCrypt", "SecKey", "CryptoKit", "kCCAlgorithmAES", "kSecAttrKeyTypeRSA", "SHA256", "HMAC", "CommonCrypto")),
    ("storage_keychain", ("SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "Keychain", "kSecAttrAccessible")),
    ("pasteboard", ("UIPasteboard", "pasteboard", "generalPasteboard")),
    ("jailbreak_instrumentation", ("jailbreak", "Cydia", "frida", "substrate", "MobileSubstrate", "ptrace", "sysctl")),
    ("analytics_tracking", ("FirebaseAnalytics", "GoogleAnalytics", "AppsFlyer", "AdjustSDK", "ADJEvent", "Amplitude", "Mixpanel", "SEGAnalytics", "BranchSDK", "BranchUniversalObject")),
    ("objc_runtime", ("objc_msgSend", "_OBJC_CLASS_", "_OBJC_METACLASS_", "selRef", "@interface", "@protocol")),
    ("swift", ("_$s", "__swift", "Swift.", "swift_getTypeByMangledName", "swift_once")),
)


def classify_symbols(values: Iterable[str], limit_per_category: int = 80) -> Dict[str, List[str]]:
    categories: Dict[str, List[str]] = {category: [] for category, _ in SYMBOL_PATTERNS}
    for value in values:
        lower = value.lower()
        for category, markers in SYMBOL_PATTERNS:
            if any(marker.lower() in lower for marker in markers):
                categories[category].append(value)
    demangled = [_simple_swift_hint(value) for value in values if value.startswith("_$s")]
    if demangled:
        categories.setdefault("swift_hints", []).extend(demangled)
    return {
        category: dedupe(matches, limit_per_category)
        for category, matches in categories.items()
        if matches
    }


def _simple_swift_hint(symbol: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.$]+", " ", symbol)
    return cleaned[:180]
