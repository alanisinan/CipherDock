#!/bin/zsh
# CipherDock macOS installer wizard.
#
# Run this from the mounted CipherDock DMG. It installs CipherDock into
# /Applications/CipherDock, prepares a private Python virtual environment,
# installs Frida for dynamic capture, and optionally installs PlayCover.

set -euo pipefail

APP_NAME="CipherDock"
INSTALL_DIR="/Applications/${APP_NAME}"
DMG_ROOT="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="${DMG_ROOT}/CipherDock"
VENDORED_PLAYCOVER="${DMG_ROOT}/Optional/PlayCover.app"
LOG_FILE="${TMPDIR:-/tmp}/cipherdock-install.log"

say_step() {
  printf "\n==> %s\n" "$1"
}

fail() {
  printf "\nInstaller error: %s\nSee %s for details.\n" "$1" "$LOG_FILE" >&2
  exit 1
}

dialog() {
  /usr/bin/osascript -e "display dialog \"$1\" buttons {\"$2\"} default button \"$2\" with title \"CipherDock Installer\"" >/dev/null 2>&1 || true
}

choose_optional_playcover() {
  /usr/bin/osascript <<'APPLESCRIPT'
set answer to button returned of (display dialog "CipherDock dynamic capture can use PlayCover to run compatible iOS apps as macOS processes on Apple Silicon.

Install or configure PlayCover now?" buttons {"Skip", "Install PlayCover"} default button "Install PlayCover" with title "CipherDock Installer")
return answer
APPLESCRIPT
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required but was not found"
}

find_python() {
  if command -v python3.11 >/dev/null 2>&1; then
    command -v python3.11
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    fail "Python 3.11+ is required. Install Python from python.org or Homebrew, then rerun this installer."
  fi
}

copy_cipherdock() {
  say_step "Installing CipherDock application files"
  if [[ ! -d "$SOURCE_DIR" ]]; then
    fail "CipherDock source folder was not found inside the DMG at ${SOURCE_DIR}"
  fi
  /usr/bin/sudo /bin/mkdir -p "$INSTALL_DIR"
  /usr/bin/sudo /usr/bin/rsync -a --delete \
    --exclude ".git" \
    --exclude ".venv" \
    --exclude ".DS_Store" \
    --exclude ".ire-zero-tools" \
    --exclude "__pycache__" \
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
    --exclude "*.ipa" \
    "${SOURCE_DIR}/" "${INSTALL_DIR}/" >>"$LOG_FILE" 2>&1
  /usr/bin/sudo /usr/sbin/chown -R "$USER":admin "$INSTALL_DIR" >>"$LOG_FILE" 2>&1 || true
}

install_python_env() {
  say_step "Preparing Python runtime"
  local python_bin
  python_bin="$(find_python)"
  "$python_bin" - <<'PY' || fail "Python 3.9+ is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
PY
  "$python_bin" -m venv "${INSTALL_DIR}/.venv" >>"$LOG_FILE" 2>&1
  "${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel >>"$LOG_FILE" 2>&1
  "${INSTALL_DIR}/.venv/bin/python" -m pip install -e "$INSTALL_DIR" >>"$LOG_FILE" 2>&1
}

install_frida() {
  say_step "Installing Frida client"
  "${INSTALL_DIR}/.venv/bin/python" -m pip install "frida-tools>=14.0" >>"$LOG_FILE" 2>&1 || {
    printf "Frida installation failed. CipherDock will still run, but live dynamic capture needs Frida.\n" >&2
    return 0
  }
}

install_launchers() {
  say_step "Installing command-line launchers"
  /usr/bin/sudo /bin/mkdir -p /usr/local/bin
  /usr/bin/sudo /bin/sh -c "cat > /usr/local/bin/cipherdock" <<EOF
#!/bin/zsh
exec "${INSTALL_DIR}/.venv/bin/python" -m ire_zero.cli "\$@"
EOF
  /usr/bin/sudo /bin/chmod +x /usr/local/bin/cipherdock

  /usr/bin/sudo /bin/sh -c "cat > /usr/local/bin/cipherdock-workbench" <<EOF
#!/bin/zsh
cd "${INSTALL_DIR}"
exec "${INSTALL_DIR}/.venv/bin/python" -m ire_zero.webapp "\$@"
EOF
  /usr/bin/sudo /bin/chmod +x /usr/local/bin/cipherdock-workbench

  /usr/bin/sudo /bin/sh -c "cat > /usr/local/bin/cipherdock-workbench-restart" <<'EOF'
#!/bin/zsh
PORT="${CIPHERDOCK_PORT:-8765}"
PIDS="$(/usr/sbin/lsof -ti tcp:${PORT} 2>/dev/null || true)"
if [[ -z "$PIDS" ]]; then
  echo "No CipherDock workbench found on port ${PORT}."
  exit 0
fi
echo "$PIDS" | xargs kill
echo "Stopped CipherDock workbench on port ${PORT}."
EOF
  /usr/bin/sudo /bin/chmod +x /usr/local/bin/cipherdock-workbench-restart
}

install_playcover_from_bundle() {
  if [[ -d "$VENDORED_PLAYCOVER" ]]; then
    say_step "Installing bundled PlayCover"
    /usr/bin/sudo /usr/bin/rsync -a --delete "$VENDORED_PLAYCOVER/" "/Applications/PlayCover.app/" >>"$LOG_FILE" 2>&1
    return 0
  fi
  return 1
}

install_playcover_with_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    return 1
  fi
  say_step "Installing PlayCover with Homebrew"
  brew install --cask playcover >>"$LOG_FILE" 2>&1
}

install_or_prompt_playcover() {
  say_step "Checking PlayCover"
  if [[ -d "/Applications/PlayCover.app" || -d "${HOME}/Applications/PlayCover.app" ]]; then
    printf "PlayCover is already installed.\n"
    return 0
  fi

  local answer
  answer="$(choose_optional_playcover || true)"
  if [[ "$answer" != "Install PlayCover" ]]; then
    printf "Skipping PlayCover. Static analysis and imported traces will still work.\n"
    return 0
  fi

  if install_playcover_from_bundle; then
    return 0
  fi
  if install_playcover_with_brew; then
    return 0
  fi

  printf "PlayCover was not bundled and Homebrew is not available.\n"
  printf "Opening the PlayCover download page. Install it, then run: cipherdock doctor\n"
  /usr/bin/open "https://playcover.io/" >/dev/null 2>&1 || true
}

main() {
  : >"$LOG_FILE"
  dialog "This wizard installs CipherDock, Frida, launch commands, and optional PlayCover support." "Continue"
  require_command rsync
  copy_cipherdock
  install_python_env
  install_frida
  install_launchers
  install_or_prompt_playcover
  say_step "Verifying installation"
  /usr/local/bin/cipherdock doctor || true
  dialog "CipherDock installation is complete.

Run:
cipherdock --help
cipherdock-workbench" "Done"
  printf "\nCipherDock installation complete.\n"
  printf "Run: cipherdock --help\n"
  printf "Run: cipherdock-workbench\n"
}

main "$@"
