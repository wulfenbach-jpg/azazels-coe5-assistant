# Azazel's CoE5 Assistant

Windows companion for **Conquest of Elysium 5**. The Assistant combines a tray-resident external process with a version-gated injected module.

## Capabilities

- detects or launches CoE5 and verifies the executable fingerprint;
- injects a Rust DLL through the Windows loader and confirms a versioned IPC handshake;
- reads typed game state through validated symbol manifests;
- observes mapped internal functions through capability-gated detours;
- preserves named profiles for roles, participants, map settings, mods, and controls;
- provides double-tap quick restart with external relaunch fallback;
- rebinds Assistant actions and CoE5 keyboard/mouse controls;
- exposes memory, symbols, hooks, threads, registers, breakpoints, stepping, disassembly, and an external Lua console;
- keeps compiled extensions outside both the Assistant and CoE5 processes behind a versioned protocol;
- retains logs and dumps locally until explicit export.

## Safety model

Observation is the default capability tier. Every state mutation or internal function call names its supported executable fingerprints, required signatures, validation invariants, and failure behavior. Unknown builds and failed invariants leave CoE5 unmodified and place the Assistant in persistent degraded mode.

Internal restart is disabled until teardown ordering, RNG balance, participant restoration, and repeated-cycle stability are dynamically proven. External restart remains available when injection fails.

## Repositories

This product repository contains only sanitized interfaces, version manifests, and original source. Exhaustive reverse-engineering dossiers remain in the private `azazels-coe5-research` repository. Neither repository stores game binaries, saves, assets, or bulk decompiler output.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
