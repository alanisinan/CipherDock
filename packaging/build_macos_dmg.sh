#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-1.0.0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/macos-installer"
PAYLOAD_DIR="$BUILD_DIR/payload"
APP_DIR="$PAYLOAD_DIR/Applications/CipherDock"
SCRIPTS_DIR="$BUILD_DIR/scripts"
RESOURCES_DIR="$BUILD_DIR/resources"
DMG_ROOT="$BUILD_DIR/dmg-root"
DIST_XML="$BUILD_DIR/distribution.xml"
COMPONENT_PKG="$BUILD_DIR/CipherDock-${VERSION}-component.pkg"
PRODUCT_PKG="$BUILD_DIR/CipherDock-${VERSION}.pkg"
DMG_PATH="$ROOT_DIR/dist/CipherDock-${VERSION}.dmg"

command -v pkgbuild >/dev/null || { echo "pkgbuild is required on macOS" >&2; exit 1; }
command -v productbuild >/dev/null || { echo "productbuild is required on macOS" >&2; exit 1; }
command -v hdiutil >/dev/null || { echo "hdiutil is required on macOS" >&2; exit 1; }
command -v rsync >/dev/null || { echo "rsync is required" >&2; exit 1; }

rm -rf "$BUILD_DIR"
mkdir -p "$APP_DIR" "$SCRIPTS_DIR" "$RESOURCES_DIR" "$DMG_ROOT" "$ROOT_DIR/dist"

rsync -a "$ROOT_DIR"/ "$APP_DIR"/ \
  --exclude ".git/" \
  --exclude ".gitignore" \
  --exclude ".gitattributes" \
  --exclude ".DS_Store" \
  --exclude "__pycache__/" \
  --exclude "*.pyc" \
  --exclude "*.pyo" \
  --exclude "*.ipa" \
  --exclude "build/" \
  --exclude "dist/" \
  --exclude "fixtures/" \
  --exclude "venv/" \
  --exclude ".venv/" \
  --exclude ".ire-zero-tools/" \
  --exclude "workbench-data/uploads/" \
  --exclude "workbench-data/reports/" \
  --exclude "workbench-data/runtime-sessions/" \
  --exclude "workbench-data/runtime-companions/" \
  --exclude "workbench-data/verification/" \
  --exclude "eval/corpus/sources/" \
  --exclude "eval/corpus/**/*.ipa" \
  --exclude "AGENTS.md"

cp "$ROOT_DIR/packaging/macos/postinstall" "$SCRIPTS_DIR/postinstall"
chmod 0755 "$SCRIPTS_DIR/postinstall"

sed "s/@VERSION@/${VERSION}/g" "$ROOT_DIR/packaging/macos/welcome.txt" > "$RESOURCES_DIR/welcome.txt"
sed "s/@VERSION@/${VERSION}/g" "$ROOT_DIR/packaging/macos/readme.txt" > "$RESOURCES_DIR/readme.txt"
cp "$ROOT_DIR/LICENSE" "$RESOURCES_DIR/license.txt"

pkgbuild \
  --root "$PAYLOAD_DIR" \
  --scripts "$SCRIPTS_DIR" \
  --identifier "org.cipherdock.pkg" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT_PKG"

cat > "$DIST_XML" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
  <title>CipherDock ${VERSION}</title>
  <welcome file="welcome.txt"/>
  <readme file="readme.txt"/>
  <license file="license.txt"/>
  <options customize="never" require-scripts="true"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <choices-outline>
    <line choice="cipherdock"/>
  </choices-outline>
  <choice id="cipherdock" title="CipherDock ${VERSION}">
    <pkg-ref id="org.cipherdock.pkg"/>
  </choice>
  <pkg-ref id="org.cipherdock.pkg" version="${VERSION}" onConclusion="none">CipherDock-${VERSION}-component.pkg</pkg-ref>
</installer-gui-script>
EOF

productbuild \
  --distribution "$DIST_XML" \
  --package-path "$BUILD_DIR" \
  --resources "$RESOURCES_DIR" \
  "$PRODUCT_PKG"

cp "$PRODUCT_PKG" "$DMG_ROOT/CipherDock-${VERSION}.pkg"
cp "$ROOT_DIR/packaging/macos/README_INSTALLER.md" "$DMG_ROOT/README.txt"

hdiutil create \
  -volname "CipherDock ${VERSION}" \
  -srcfolder "$DMG_ROOT" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

echo "$DMG_PATH"
