# Related Research Gaps

1. **Jailbreak dependency.** CipherDock makes static IPA triage and Simulator companion-build Frida capture usable without requiring a jailbroken physical device, while explicitly preserving the provenance distinction from exact-IPA runtime evidence.
2. **Private framework opacity.** It combines linked-library, symbol, class-dump when available, string-rule, and optional Ghidra evidence to flag references to known private APIs and frameworks.
3. **Multi-language binaries.** It analyzes Mach-O evidence independently of source language and classifies Objective-C runtime and Swift mangled-symbol indicators, although it does not reconstruct high-level source semantics.
4. **LLM decompilation on ARM64.** The current implementation does not claim LLM decompilation; it exports bounded disassembly, symbol, section, and dynamic evidence that can ground later human or model-assisted interpretation.
5. **Sideloaded app risk scoring.** It accepts arbitrary authorized IPA files and applies a repeatable, explainable score over transport, secrets, APIs, tamper indicators, endpoints, entitlements, and symbol signals.
6. **No unified iOS assessment workflow.** CipherDock joins IPA intake, static evidence, cross-layer runtime correlation, reporting, corpus-hash verification, sensitivity analysis, and category statistics in one local workbench, addressing workflow fragmentation without claiming complete feature parity with broader mobile suites.
