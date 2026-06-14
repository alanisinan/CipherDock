CipherDock @VERSION@

After installation:

  cipherdock --help
  cipherdock analyze /path/to/app.ipa --sarif --html
  cipherdock-workbench
  cipherdock-workbench-stop
  cipherdock-workbench-restart

Requirements:

  - macOS with Python 3.11+ recommended
  - Xcode Command Line Tools for complete IPA analysis
  - Optional Frida and Objection tooling for dynamic capture
  - Optional Ghidra analyzeHeadless for symbol enrichment

The installer does not download external dependencies. Optional runtime tools
can be installed separately after installation.
