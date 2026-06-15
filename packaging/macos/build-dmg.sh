#!/bin/zsh
# Build a CipherDock DMG with an installer wizard.
#
# Usage:
#   packaging/macos/build-dmg.sh
#   INCLUDE_PLAYCOVER=1 packaging/macos/build-dmg.sh
#
# When INCLUDE_PLAYCOVER=1 and /Applications/PlayCover.app exists, the app is
# copied into the DMG under Optional/PlayCover.app. Otherwise the installer
# offers Homebrew install or opens the PlayCover download page.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${VERSION:-1.0.0}"
DIST_DIR="${ROOT}/dist"
STAGE_DIR="${DIST_DIR}/dmg-stage"
DMG_PATH="${DIST_DIR}/CipherDock-${VERSION}.dmg"
VOLUME_NAME="CipherDock ${VERSION}"

echo "==> Preparing DMG stage"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/CipherDock" "$STAGE_DIR/Optional"

rsync -a --delete \
  --exclude ".git" \
  --exclude ".venv" \
  --exclude ".DS_Store" \
  --exclude ".ire-zero-tools" \
  --exclude "__pycache__" \
  --exclude "*.pyc" \
  --exclude "*.ipa" \
  --exclude "AGENTS.md" \
  --exclude "eval" \
  --exclude "dist" \
  --exclude "simulator-targets" \
  --exclude "sample-reports" \
  --exclude "real-sample-reports" \
  --exclude "verification-reports" \
  --exclude "batch-verification-reports" \
  --exclude "mastodon-symbol-reports" \
  --exclude "workbench-data/uploads" \
  --exclude "workbench-data/reports" \
  --exclude "workbench-data/runtime-sessions" \
  --exclude "workbench-data/runtime-companions" \
  "$ROOT/" "$STAGE_DIR/CipherDock/"

cp "$ROOT/packaging/macos/install-cipherdock.command" "$STAGE_DIR/Install CipherDock.command"
chmod +x "$STAGE_DIR/Install CipherDock.command"

cat > "$STAGE_DIR/README-FIRST.txt" <<'EOF'
CipherDock macOS installer

1. Double-click "Install CipherDock.command".
2. Approve Terminal and sudo prompts when asked.
3. The installer prepares /Applications/CipherDock, installs Frida, and offers PlayCover setup.
4. After install, run:

   cipherdock --help
   cipherdock-workbench

PlayCover note:
If PlayCover.app is bundled in Optional/, the installer can copy it into /Applications.
If it is not bundled, the installer tries Homebrew or opens https://playcover.io/.
EOF

if [[ "${INCLUDE_PLAYCOVER:-0}" == "1" ]]; then
  PLAYCOVER_APP="${PLAYCOVER_APP:-/Applications/PlayCover.app}"
  if [[ -d "$PLAYCOVER_APP" ]]; then
    echo "==> Including PlayCover.app from $PLAYCOVER_APP"
    rsync -a --delete "$PLAYCOVER_APP/" "$STAGE_DIR/Optional/PlayCover.app/"
  else
    echo "warning: INCLUDE_PLAYCOVER=1 but $PLAYCOVER_APP was not found" >&2
  fi
fi

echo "==> Building ${DMG_PATH}"
rm -f "$DMG_PATH"
hdiutil create \
  -volname "$VOLUME_NAME" \
  -srcfolder "$STAGE_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

echo "==> DMG created: $DMG_PATH"
