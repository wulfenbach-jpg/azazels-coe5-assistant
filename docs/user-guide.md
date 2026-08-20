# Azazel's CoE5 Assistant — user guide

A Windows companion for **Conquest of Elysium 5**. The Assistant runs as a
tray-resident process, injects a small version-gated module into the game,
and gives you a control panel for quick restarts, named setup profiles, and
deep diagnostics.

## Starting up

1. Build (or download) the release: `cargo build --release`, run
   `azazel-coe5-assistant.exe`. The app lives in the system tray as
   *Azazel's CoE5 Assistant*.
2. Launch CoE5 any way you like — Steam, the executable, a shortcut. The
   Assistant detects the running game, verifies its fingerprint (only the
   supported build is touched), and injects its module.
3. Open the panel (tray → *Open*). The **Status** tab shows the connection
   spine: **PROC** (game process found) → **HASH** (fingerprint verified) →
   **PIPE** (IPC connected) → **HOOK** (observation hooks armed). Icons are
   lit as each stage completes.

If the game is not running, press **Retry injection** after launching it, or
let the Assistant launch it itself from a configured profile.

## The quick restart (the heart of the tool)

**Double-tap the restart hotkey (default `Ctrl+Alt+R`)** — first tap arms,
second tap within the double-tap window (default 1.2 s) executes. The
Assistant:

1. closes the running game;
2. relaunches CoE5 with the chosen settings;
3. waits for the Setup Participants screen, writes the roster (players,
   your class, AI on random, teams none), and forces the screen to repaint;
4. waits for the world to be created.

The one step that remains manual is the final **Enter/Ok** on the setup
screen — the game's own input path still resists external automation. The
roster is already written; just press Enter.

### Where the restart settings come from

The **Status** tab's *Restart settings source* toggle chooses:

- **Copy last played game settings** — the relaunch mirrors the running
  game: map/rule arguments taken from its own command line, and its
  participant roster (your class preserved, AI classes reset to random)
  read live from the game.
- **Use set profile settings** — the relaunch uses the active profile's
  configured map, participants, class, and rules.

### Launching through Steam

The *Launch restarts through Steam* checkbox routes relaunches through the
Steam client (`steam://run/1606340`), so overlay, achievements, and playtime
engage. Steam must be running.

## Profiles

The **Profiles** tab manages named setups:

- select a profile by its name; **+** creates a copy of the active one;
  the **×** trash button deletes a profile (never the last one);
  **Lock** pins the selection so live snapshots cannot switch it.
- **Class** is a dropdown of the game's real roles (Necromancer, Pale One,
  Warlock, …). **Players**, **AI difficulty**, **Map** dimensions,
  **Society**, **North/South** percentages, **Wilder**, **Common cause**,
  and **Unique classes** configure the rest.
- **Save changes** writes the profile to the config file.

## Hotkeys & remaps

The **Hotkeys** tab rebinds the restart hotkey and edits control remaps:

- **Restart** + **Bind** — click and type the new chord.
- Remap rows map a trigger key (or mouse button, with Ctrl/Alt/Shift
  modifiers) to an output virtual key. **Add key** / **Add mouse** create
  rows; the trash icon removes one; **Save** applies them live.

## Diagnostics tabs

- **Memory** — live typed snapshot: turn, plane, world extent, society,
  and the participant table with named classes.
- **Symbols** — the validated symbol manifest for the running build.
- **Hooks** — capability-gated detours and their observed events.
- **Debugger** — attach a debug session: threads, registers, memory,
  breakpoints, stepping, disassembly (prefer this over raw tooling).
- **Lua** — an external Lua console for scripting against the snapshot.
- **Plugins** — load out-of-process extension modules.
- **Logs** — the Assistant's diagnostic ledger.
- **Updates** — fetch and apply signed release updates.

## Configuration file

`%APPDATA%\Azazel\AzazelsCoe5Assistant\config\config.toml` holds the
executable path, hotkey, profiles, remaps, settings source, and Steam
launch flag. The Assistant rewrites it on save; the first run creates it.

## Troubleshooting

- **"Unsupported CoE5 hash"** — the running build is not the pinned one the
  Assistant was built against. No modifications are made; update the
  Assistant or use the supported build.
- **Restart lands on Setup with nothing written** — the restart thread may
  have hit the game while it was still initializing; press **Retry
  injection**, then restart again. Transient read failures are retried
  automatically now, but a dead game process cannot be recovered.
- **The roster does not appear** — a one-pixel window nudge is sent after
  the write to force the game's event-driven redraw; if the game still
  holds a stale frame, maximize/restore once.
- **The tray icon is missing** — check the notification overflow area.

## Safety model

Observation is the default. Every mutation names its supported executable
fingerprint, required signatures, invariants, and failure behavior. Unknown
builds leave CoE5 untouched and place the Assistant in persistent degraded
mode. Internal same-process restart stays disabled until dynamic stability
is proven; external restart remains available.
