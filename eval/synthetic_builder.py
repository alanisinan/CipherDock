#!/usr/bin/env python3
"""Produce controlled positive IPA variants for evaluation experiments."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import plistlib
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence

try:
    from .common import upsert_label_rows
except ImportError:
    from common import upsert_label_rows

BEHAVIOR_FLAGS = (
    "ats_disabled",
    "hardcoded_secret",
    "cydia_scheme",
    "jailbreak_strings",
    "http_endpoint",
    "pasteboard",
    "frida_detection",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate controlled static-analysis positive IPA variants from an authorized base IPA."
    )
    parser.add_argument("base_ipa", type=Path, help="Authorized IPA used as the non-executed benchmark base")
    parser.add_argument("--output-dir", type=Path, default=Path("eval/corpus/synthetic"))
    parser.add_argument("--update-labels", type=Path, default=Path("eval/corpus/labels.csv"))
    parser.add_argument("--count", type=int, default=1, help="Number of deterministic variants to produce")
    parser.add_argument("--all", action="store_true", help="Enable every injection behavior")
    parser.add_argument("--ats-disabled", action="store_true", help="Inject NSAllowsArbitraryLoads=true")
    parser.add_argument("--hardcoded-secret", action="store_true", help="Inject a fake API key metadata string")
    parser.add_argument("--cydia-scheme", action="store_true", help="Inject a cydia URL scheme query")
    parser.add_argument("--jailbreak-strings", action="store_true", help="Inject jailbreak marker strings in a stub dylib")
    parser.add_argument("--http-endpoint", action="store_true", help="Inject a cleartext test endpoint")
    parser.add_argument("--pasteboard", action="store_true", help="Inject a UIPasteboard marker in a stub dylib")
    parser.add_argument("--frida-detection", action="store_true", help="Inject Frida marker strings in a stub dylib")
    parser.add_argument(
        "--subtle",
        action="store_true",
        help="Generate low-signal variants with one obfuscated or plausible-looking injected behavior each",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    base_ipa = args.base_ipa.expanduser().resolve()
    if args.count < 1:
        print("--count must be at least 1", file=sys.stderr)
        return 2
    behaviors = selected_behaviors(args)
    if not behaviors:
        print("Select at least one injection behavior or pass --all", file=sys.stderr)
        return 2
    try:
        app_root, original_plist = load_base_plist(base_ipa)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Unable to read base IPA: {exc}", file=sys.stderr)
        return 2
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    label_rows: List[Dict[str, str]] = []
    variants: List[Dict[str, Any]] = []
    base_digest = sha256_file(base_ipa)
    for index in range(1, args.count + 1):
        variant_behaviors = subtle_behaviors(index) if args.subtle else behaviors
        suffix = f"irez.subtle{index:03d}" if args.subtle else f"irez.eval{index:03d}"
        output_path = output_dir / f"{base_ipa.stem}__{suffix}.ipa"
        bundle_id = write_variant(
            base_ipa=base_ipa,
            output_path=output_path,
            app_root=app_root,
            original_plist=original_plist,
            index=index,
            behaviors=variant_behaviors,
            subtle=args.subtle,
        )
        digest = sha256_file(output_path)
        relative_path = _relative_to_labels(output_path, args.update_labels.resolve().parent)
        variants.append(
            {
                "file": output_path.name,
                "relative_path": relative_path,
                "sha256": digest,
                "bundle_identifier": bundle_id,
                "variant_type": "subtle" if args.subtle else "obvious",
                "behaviors": variant_behaviors,
            }
        )
        label_rows.append(
            {
                "app_id": f"synthetic-{index:03d}",
                "relative_path": relative_path,
                "ipa_file": output_path.name,
                "sha256": digest,
                "label": "positive",
                "benchmark_role": "controlled injected positive",
                "variant_type": "subtle" if args.subtle else "obvious",
                "base_sha256": base_digest,
                "behaviors": ",".join(variant_behaviors),
                "source": str(base_ipa),
                "status": "ready",
            }
        )
    upsert_label_rows(args.update_labels.resolve(), label_rows)
    manifest = {
        "schema": "ire-zero-synthetic-corpus-v1",
        "purpose": "Controlled static-analysis positive fixtures; not deployable app releases.",
        "base_ipa": str(base_ipa),
        "base_sha256": base_digest,
        "code_signature_note": "Variant modification invalidates any original code signature; use only for static evaluation.",
        "variant_type": "subtle" if args.subtle else "obvious",
        "variants": variants,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[synthetic] {len(variants)} variant(s) -> {output_dir}")
    print(f"[manifest] {manifest_path}")
    print(f"[labels] {args.update_labels.resolve()}")
    return 0


def selected_behaviors(args: argparse.Namespace) -> List[str]:
    if args.subtle:
        return ["encoded_secret", "misspelled_jailbreak", "plausible_endpoint"]
    return [
        behavior
        for behavior in BEHAVIOR_FLAGS
        if args.all or bool(getattr(args, behavior))
    ]


def subtle_behaviors(index: int) -> List[str]:
    sequence = ("encoded_secret", "misspelled_jailbreak", "plausible_endpoint")
    return [sequence[(index - 1) % len(sequence)]]


def load_base_plist(ipa_path: Path) -> tuple[str, Dict[str, Any]]:
    if not ipa_path.is_file():
        raise ValueError(f"IPA does not exist: {ipa_path}")
    with zipfile.ZipFile(ipa_path) as archive:
        candidates = [
            name for name in archive.namelist()
            if len(PurePosixPath(name).parts) == 3
            and name.startswith("Payload/")
            and name.endswith(".app/Info.plist")
        ]
        if not candidates:
            raise ValueError("No top-level Payload/*.app/Info.plist found")
        plist_path = sorted(candidates)[0]
        payload = plistlib.loads(archive.read(plist_path))
        if not isinstance(payload, dict):
            raise ValueError("Info.plist does not contain a dictionary")
    return str(PurePosixPath(plist_path).parent), dict(payload)


def write_variant(
    *,
    base_ipa: Path,
    output_path: Path,
    app_root: str,
    original_plist: Dict[str, Any],
    index: int,
    behaviors: List[str],
    subtle: bool = False,
) -> str:
    plist = dict(original_plist)
    base_bundle_id = str(plist.get("CFBundleIdentifier") or "org.irezero.base")
    marker = "subtle" if subtle else "eval"
    bundle_id = f"{base_bundle_id}.irez.{marker}{index:03d}"
    plist["CFBundleIdentifier"] = bundle_id
    inject_plist_values(plist, index, behaviors)
    plist_name = f"{app_root}/Info.plist"
    stub_name = f"{app_root}/Frameworks/libIREZeroBenchmark_{index:03d}.dylib"
    with zipfile.ZipFile(base_ipa) as source, zipfile.ZipFile(output_path, "w") as destination:
        for member in source.infolist():
            if member.filename == plist_name or member.filename.startswith(f"{app_root}/Frameworks/libIREZeroBenchmark_"):
                continue
            destination.writestr(member, source.read(member.filename))
        destination.writestr(_new_member(plist_name), plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True))
        if needs_stub(behaviors):
            destination.writestr(_new_member(stub_name), render_stub(index, behaviors))
    return bundle_id


def inject_plist_values(plist: Dict[str, Any], index: int, behaviors: List[str]) -> None:
    if "ats_disabled" in behaviors:
        ats = dict(plist.get("NSAppTransportSecurity") or {})
        ats["NSAllowsArbitraryLoads"] = True
        plist["NSAppTransportSecurity"] = ats
    if "hardcoded_secret" in behaviors:
        plist["IREZeroInjectedStringsFile"] = f"api_key=IREZERO_FAKE_KEY_{index:03d}_ABCD1234"
    if "cydia_scheme" in behaviors:
        schemes = [str(value) for value in plist.get("LSApplicationQueriesSchemes", [])]
        if "cydia" not in schemes:
            schemes.append("cydia")
        plist["LSApplicationQueriesSchemes"] = schemes
        plist["IREZeroInjectedCydiaURL"] = "cydia://package/org.irezero.benchmark"
    if "http_endpoint" in behaviors:
        plist["IREZeroEvaluationEndpoint"] = f"http://benchmark.invalid/variant/{index:03d}"
    if "encoded_secret" in behaviors:
        encoded = base64.b64encode(f"api_key=IREZERO_FAKE_KEY_{index:03d}_ABCD1234".encode("ascii")).decode("ascii")
        plist["IREZeroCacheSeed"] = encoded
    if "plausible_endpoint" in behaviors:
        plist["IREZeroTelemetryEndpoint"] = f"https://telemetry.account-sync.example.invalid/v1/session/{index:03d}"


def needs_stub(behaviors: List[str]) -> bool:
    return any(
        behavior in behaviors
        for behavior in ("jailbreak_strings", "pasteboard", "frida_detection", "misspelled_jailbreak")
    )


def render_stub(index: int, behaviors: List[str]) -> bytes:
    strings = [f"IREZero static benchmark marker {index:03d}"]
    if "jailbreak_strings" in behaviors:
        strings.extend(("sysctl", "dlopen", "/Library/MobileSubstrate/MobileSubstrate.dylib", "jailbreak"))
    if "pasteboard" in behaviors:
        strings.extend(("UIPasteboard", "generalPasteboard", "pasteboard"))
    if "frida_detection" in behaviors:
        strings.extend(("frida-server", "FridaGadget.dylib", "frida gadget detection"))
    if "misspelled_jailbreak" in behaviors:
        strings.extend(("cydi4", "fr1da-server", "sub5trate", "sysct1"))
    return ("\n".join(strings) + "\n").encode("ascii")


def _new_member(name: str) -> zipfile.ZipInfo:
    member = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    member.compress_type = zipfile.ZIP_DEFLATED
    member.external_attr = 0o100644 << 16
    return member


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_to_labels(path: Path, labels_parent: Path) -> str:
    try:
        return path.relative_to(labels_parent).as_posix()
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
