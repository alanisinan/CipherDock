CipherDock 1.0.0 macOS Installer

Open CipherDock-1.0.0.pkg to start the macOS Installer wizard.

The installer copies CipherDock to /Applications/CipherDock and creates:

- /usr/local/bin/cipherdock
- /usr/local/bin/cipherdock-workbench
- /usr/local/bin/cipherdock-workbench-stop
- /usr/local/bin/cipherdock-workbench-restart

Quick test after installation:

```bash
cipherdock --help
cipherdock-workbench
```

Restart the workbench cleanly:

```bash
cipherdock-workbench-restart
```

Or stop and start it manually:

```bash
cipherdock-workbench-stop
cipherdock-workbench
```

For full IPA analysis, install Xcode Command Line Tools. For dynamic capture,
install Frida and Objection separately.
