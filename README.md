# Azazel's CoE5 Assistant

Windows companion for **Conquest of Elysium 5**. The Assistant combines a tray-resident external process with a version-gated injected module.

**[User guide](docs/user-guide.md)** — how to run the Assistant, restart your game with the double-tap hotkey, manage profiles, and read the diagnostics tabs.

## Downloads

Windows prebuilt releases attach to tagged GitHub releases. Each release ships a portable zip containing the Assistant executable, the injected module (`azazel_coe5_injected.dll`, required alongside the exe), and the user guide:

- **Latest release** — [releases/latest](https://github.com/wulfenbach-jpg/azazels-coe5-assistant/releases/latest)
- Unzip anywhere, run `azazel-coe5-assistant.exe`. The in-app **Updates** tab checks the release channel when an update signing key is configured.

## Building from source

```bash
# Rust 1.97 stable (x86_64-pc-windows-msvc), pinned by rust-toolchain.toml
cargo build --release -p azazel-coe5-assistant -p azazel-coe5-injected
```

Copy both `target/release/azazel-coe5-assistant.exe` and
`target/release/azazel_coe5_injected.dll` to the same folder — the Assistant
locates the injected module next to its own executable.

### Publishing a release

Push a `v*` tag; the [release workflow](.github/workflows/release.yml) runs
clippy, the test suite, builds the release binaries, packages the portable
zip, and attaches it to the GitHub release.

The **Updates** channel is signed with Ed25519. To enable in-app updates:

1. Generate a key pair once and store the seed as a GitHub Actions secret
   named `UPDATE_SIGNING_KEY` (base64 of the 32-byte seed):
   ```bash
   cargo run --release -p azazel-coe5-update-signer -- --help
   ```
   (generate a seed with any Ed25519 tool; the signer prints the matching
   public key with `--print-public-key`).
2. Put the public key (base64) into the Assistant's config:
   `%APPDATA%\Azazel\AzazelsCoe5Assistant\config\config.toml` →
   `update.public_key_base64 = "<key>"`.
3. The workflow signs `update.json` automatically whenever the secret is
   set. Without the secret, releases ship without an update manifest and
   the Updates tab reports no channel.

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
