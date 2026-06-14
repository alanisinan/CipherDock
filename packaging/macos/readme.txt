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
  - Local Frida and Objection clients are installed by this package
  - Optional Ghidra analyzeHeadless for symbol enrichment

Physical iOS device capture still requires an authorized device-side
Frida/Gadget setup. Simulator capture of device IPAs requires a matching
Simulator .app build of the same authorized app.
