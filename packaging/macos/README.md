# CipherDock macOS DMG Packaging

This folder contains the macOS DMG installer assets.

## Build The DMG

```sh
packaging/macos/build-dmg.sh
```

The output is:

```text
dist/CipherDock-1.0.0.dmg
```

## Include PlayCover In The DMG

PlayCover is a third-party application. The safer default is to make the
CipherDock installer detect PlayCover, install it through Homebrew when
available, or open the official download page.

If you have confirmed redistribution is acceptable for your release, you can
bundle a local PlayCover.app:

```sh
INCLUDE_PLAYCOVER=1 packaging/macos/build-dmg.sh
```

By default this copies:

```text
/Applications/PlayCover.app
```

To use another path:

```sh
INCLUDE_PLAYCOVER=1 PLAYCOVER_APP="$HOME/Applications/PlayCover.app" packaging/macos/build-dmg.sh
```

The installer looks for bundled PlayCover at:

```text
Optional/PlayCover.app
```

## What The Installer Does

The `Install CipherDock.command` wizard:

1. Copies CipherDock into `/Applications/CipherDock`.
2. Creates `/Applications/CipherDock/.venv`.
3. Installs the local package into that virtual environment.
4. Installs `frida-tools>=14.0` into the virtual environment.
5. Creates launchers:
   - `/usr/local/bin/cipherdock`
   - `/usr/local/bin/cipherdock-workbench`
   - `/usr/local/bin/cipherdock-workbench-restart`
6. Detects PlayCover:
   - uses existing `/Applications/PlayCover.app` or `~/Applications/PlayCover.app`
   - copies bundled `Optional/PlayCover.app` when present
   - otherwise tries `brew install --cask playcover`
   - otherwise opens `https://playcover.io/`

## Why PlayCover Is Optional

CipherDock can always perform static analysis and report generation without
PlayCover. PlayCover is only needed for the Apple Silicon companion-process
dynamic capture backend. The installer labels this as companion execution
evidence, not exact physical-device IPA execution.
