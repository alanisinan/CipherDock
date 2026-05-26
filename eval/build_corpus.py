#!/usr/bin/env python3
"""Prepare documented open-source IPA control artifacts and their labels."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

try:
    from .common import upsert_label_rows
except ImportError:
    from common import upsert_label_rows


@dataclass(frozen=True)
class OpenSourceApp:
    app_id: str
    name: str
    repo_url: str
    project: str
    scheme: str
    notes: str
    official_ipa_url: Optional[str] = None


APPS = (
    OpenSourceApp(
        "mastodon-ios",
        "Mastodon iOS",
        "https://github.com/mastodon/mastodon-ios.git",
        "Mastodon.xcworkspace",
        "Mastodon",
        "A locally authorized IPA has already been supplied for this evaluation.",
    ),
    OpenSourceApp(
        "wikipedia-ios",
        "Wikipedia iOS",
        "https://github.com/wikimedia/wikipedia-ios.git",
        "Wikipedia.xcodeproj",
        "Wikipedia",
        "Official Wikimedia client; run ./scripts/setup, then archive the Wikipedia scheme from Wikipedia.xcodeproj.",
    ),
    OpenSourceApp(
        "firefox-ios",
        "Firefox for iOS",
        "https://github.com/mozilla-mobile/firefox-ios.git",
        "firefox-ios/Client.xcodeproj",
        "Fennec",
        "Official Mozilla source; bootstrap with fxios where available, then archive Fennec from firefox-ios/Client.xcodeproj.",
    ),
    OpenSourceApp(
        "vlc-ios",
        "VLC for iOS",
        "https://code.videolan.org/videolan/vlc-ios.git",
        "VLC.xcworkspace",
        "VLC-iOS",
        "VideoLAN publishes an official IPA binary; prefer it for reproducible static evaluation.",
        "https://get.videolan.org/vlc-iOS/3.5.0/VLC-iOS.ipa",
    ),
    OpenSourceApp(
        "bitwarden-ios",
        "Bitwarden iOS",
        "https://github.com/bitwarden/ios.git",
        "Bitwarden.xcworkspace",
        "Bitwarden",
        "Official GPL iOS repository; follow its contribution setup for generated projects/dependencies.",
    ),
    OpenSourceApp(
        "signal-ios",
        "Signal iOS",
        "https://github.com/signalapp/Signal-iOS.git",
        "Signal.xcworkspace",
        "Signal",
        "Official repository; consult BUILDING.md for environment setup before producing an archive.",
    ),
    OpenSourceApp(
        "nextcloud-ios",
        "Nextcloud iOS",
        "https://github.com/nextcloud/ios.git",
        "Nextcloud.xcodeproj",
        "Nextcloud",
        "Official repository; add the documented mock GoogleService-Info.plist before archiving from Nextcloud.xcodeproj.",
    ),
    OpenSourceApp(
        "protonmail-ios",
        "Proton Mail iOS",
        "https://github.com/ProtonMail/ios-mail.git",
        "",
        "ProtonMail",
        "Upstream README states this public repository cannot currently be built externally because its Mail SDK distribution is not public.",
    ),
)
APP_BY_ID = {app.app_id: app for app in APPS}
SETUP_COMMANDS = {
    "wikipedia-ios": ["./scripts/setup"],
    "firefox-ios": ["sh ./bootstrap.sh firefox"],
    "bitwarden-ios": ["./Scripts/bootstrap.sh"],
    "signal-ios": ["git submodule update --init --recursive", "make dependencies"],
    "nextcloud-ios": [
        "curl -L --fail --output GoogleService-Info.plist https://raw.githubusercontent.com/firebase/quickstart-ios/master/mock-GoogleService-Info.plist"
    ],
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare reproducible open-source iOS negative-control artifacts for iRE-Zero evaluation."
    )
    parser.add_argument("--corpus-dir", type=Path, default=Path("eval/corpus"), help="Corpus output directory")
    parser.add_argument("--labels", type=Path, help="Labels CSV path; defaults to <corpus-dir>/labels.csv")
    parser.add_argument(
        "--import-ipa",
        action="append",
        default=[],
        metavar="APP_ID=PATH",
        help="Import a locally built or authorized IPA for one app; may be repeated",
    )
    parser.add_argument(
        "--discover-mastodon",
        action="store_true",
        help="Import the known local Mastodon IPA from Downloads when available",
    )
    parser.add_argument(
        "--download-official",
        choices=("vlc-ios", "all"),
        help="Download official upstream IPA assets where one is published (currently VLC for iOS)",
    )
    parser.add_argument("--clone-sources", action="store_true", help="Clone missing official source repositories")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    corpus_dir = args.corpus_dir.resolve()
    labels_path = (args.labels or corpus_dir / "labels.csv").resolve()
    benign_dir = corpus_dir / "benign"
    sources_dir = corpus_dir / "sources"
    benign_dir.mkdir(parents=True, exist_ok=True)
    imports = parse_imports(args.import_ipa)
    if args.discover_mastodon:
        candidate = Path.home() / "Downloads" / "org.joinmastodon.app_2026.03_und3fined.ipa"
        if candidate.exists():
            imports.setdefault("mastodon-ios", candidate)
    rows: List[Dict[str, str]] = []
    for app in APPS:
        destination = benign_dir / f"{app.app_id}.ipa"
        source = ""
        status = "pending_build"
        if app.app_id in imports:
            copy_ipa(imports[app.app_id], destination)
            source = f"local import: {imports[app.app_id]}"
            status = "ready"
        elif args.download_official in {"all", app.app_id} and app.official_ipa_url:
            download_ipa(app.official_ipa_url, destination)
            source = app.official_ipa_url
            status = "ready"
        elif destination.exists():
            source = "existing corpus artifact"
            status = "ready"
        if args.clone_sources:
            clone_source(app, sources_dir / app.app_id)
        rows.append(label_row(app, corpus_dir, destination, source, status))
    upsert_label_rows(labels_path, rows)
    (corpus_dir / "BUILD.md").write_text(render_build_document(corpus_dir, labels_path), encoding="utf-8")
    ready = sum(row["status"] == "ready" for row in rows)
    print(f"[corpus] {corpus_dir} ({ready}/{len(APPS)} benign IPA artifact(s) ready)")
    print(f"[labels] {labels_path}")
    print(f"[build] {corpus_dir / 'BUILD.md'}")
    return 0


def parse_imports(values: Sequence[str]) -> Dict[str, Path]:
    imports: Dict[str, Path] = {}
    for value in values:
        app_id, separator, path = value.partition("=")
        if not separator or app_id not in APP_BY_ID:
            valid = ", ".join(APP_BY_ID)
            raise ValueError(f"--import-ipa requires APP_ID=PATH; APP_ID must be one of: {valid}")
        imports[app_id] = Path(path).expanduser().resolve()
    return imports


def copy_ipa(source: Path, destination: Path) -> None:
    validate_ipa(source)
    if source.resolve() != destination.resolve():
        shutil.copy2(source, destination)


def download_ipa(url: str, destination: Path) -> None:
    with tempfile.NamedTemporaryFile(suffix=".ipa", dir=destination.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        print(f"[download] {url}")
        urllib.request.urlretrieve(url, temporary)
        validate_ipa(temporary)
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def validate_ipa(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"IPA does not exist: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            if not any(name.startswith("Payload/") and ".app/" in name for name in archive.namelist()):
                raise ValueError(f"Not an IPA app archive: {path}")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Not a zip-based IPA: {path}") from exc


def clone_source(app: OpenSourceApp, destination: Path) -> None:
    if destination.exists():
        print(f"[source] present: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["git", "clone", "--depth", "1", app.repo_url, str(destination)],
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git clone failed for {app.name}")


def label_row(
    app: OpenSourceApp,
    corpus_dir: Path,
    destination: Path,
    source: str,
    status: str,
) -> Dict[str, str]:
    ready = status == "ready" and destination.exists()
    return {
        "app_id": app.app_id,
        "relative_path": destination.relative_to(corpus_dir).as_posix(),
        "ipa_file": destination.name,
        "sha256": sha256_file(destination) if ready else "",
        "label": "negative",
        "benchmark_role": "non-injected open-source control",
        "variant_type": "real_benign",
        "base_sha256": "",
        "behaviors": "",
        "source": source or app.repo_url,
        "status": status,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_build_document(corpus_dir: Path, labels_path: Path) -> str:
    lines = [
        "# Open-Source iOS Evaluation Corpus",
        "",
        "## Label Boundary",
        "",
        "`negative` means a non-injected open-source control sample in this benchmark. It is not a claim that the app is free of security findings. All SHAs identify the exact IPA artifact analyzed.",
        "",
        "## Prepare Artifacts",
        "",
        "```bash",
        "python3 eval/build_corpus.py --discover-mastodon --download-official vlc-ios",
        "# For locally archived apps:",
        "python3 eval/build_corpus.py --import-ipa wikipedia-ios=/path/to/Wikipedia.ipa --import-ipa firefox-ios=/path/to/Firefox.ipa",
        "# Optional source acquisition:",
        "python3 eval/build_corpus.py --clone-sources",
        "```",
        "",
        f"- Corpus directory: `{corpus_dir}`",
        f"- Labels and SHA-256 provenance: `{labels_path}`",
        "",
        "A source build archive must be packaged as `Payload/<App>.app` inside an `.ipa` zip before import. Code signing is not required for static evaluation; a signed artifact is needed for real device execution.",
        "",
        "## Application Sources And Build Commands",
        "",
    ]
    for app in APPS:
        download = (
            f"- Official IPA: [{app.official_ipa_url}]({app.official_ipa_url})"
            if app.official_ipa_url
            else "- Official IPA: no upstream IPA asset documented here; build from official source."
        )
        lines.extend(
            [
                f"### {app.name} (`{app.app_id}`)",
                "",
                f"- Official source: [{app.repo_url}]({app.repo_url})",
                download,
                f"- Note: {app.notes}",
                "",
            ]
        )
        if app.project:
            project_flag = "-workspace" if app.project.endswith(".xcworkspace") else "-project"
            lines.extend(
                [
                    "```bash",
                    f"git clone --depth 1 {app.repo_url} eval/corpus/sources/{app.app_id}",
                    f"cd eval/corpus/sources/{app.app_id}",
                    *SETUP_COMMANDS.get(app.app_id, []),
                    f"xcodebuild -list {project_flag} {app.project}",
                    f"xcodebuild {project_flag} {app.project} -scheme {app.scheme} -configuration Release -sdk iphoneos -archivePath \"$PWD/build/{app.scheme}.xcarchive\" archive CODE_SIGNING_ALLOWED=NO",
                    "mkdir -p \"$PWD/build/package/Payload\"",
                    f"cp -R \"$PWD/build/{app.scheme}.xcarchive/Products/Applications/\"*.app \"$PWD/build/package/Payload/\"",
                    f"(cd \"$PWD/build/package\" && ditto -c -k --sequesterRsrc --keepParent Payload \"../{app.app_id}.ipa\")",
                    "```",
                    "",
                    "If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "No public build command is available from upstream at this time; retain this entry as `pending_build` rather than counting it as an analyzed benign artifact.",
                    "",
                ]
            )
    lines.extend(
        [
            "## Reproducible Evaluation Run",
            "",
            "```bash",
            "python3 eval/synthetic_builder.py eval/corpus/benign/mastodon-ios.ipa --all --count 20 --output-dir eval/corpus/synthetic --update-labels eval/corpus/labels.csv",
            "python3 eval/synthetic_builder.py eval/corpus/benign/vlc-ios.ipa --subtle --count 10 --output-dir eval/corpus/subtle --update-labels eval/corpus/labels.csv",
            "python3 eval/run_all.py --corpus-dir eval/corpus --labels eval/corpus/labels.csv --reuse-reports --split 0.3",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Unable to build corpus: {exc}", file=sys.stderr)
        raise SystemExit(2)
