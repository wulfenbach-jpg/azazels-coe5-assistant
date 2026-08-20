use std::{
    ffi::c_void,
    mem::size_of,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use azazel_coe5_protocol::GameSnapshot;
use windows::Win32::{
    Foundation::{POINT, RECT},
    Graphics::Gdi::{ClientToScreen, InvalidateRect},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
            PROCESS_VM_WRITE,
        },
    },
    UI::{
        Input::KeyboardAndMouse::{
            INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
            MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEINPUT, SendInput, VIRTUAL_KEY,
            VK_RETURN,
        },
        WindowsAndMessaging::{
            FindWindowW, GetClientRect, GetWindowThreadProcessId, SetForegroundWindow,
        },
    },
};
use windows::core::{PCWSTR, w};

use crate::{
    config::{Profile, StartPolicy},
    process::{OwnedHandle, ProcessInfo, command_line, launch_coe5, stop_coe5, wait_for_coe5},
};

const SUPPORTED_SHA256: &str = "0b422183ca978551f104db865d1869eddfd4301ab160cd28c18a6783ec4ddf03";
const PARTICIPANT_CLASSES: usize = 0x0e40_8640;
const PARTICIPANT_CONTROLLERS: usize = 0x0e40_8680;
const PARTICIPANT_START_X: usize = 0x0e40_8700;
const PLAYER_TEAM: usize = 0x1092_0110;
const PLAYER_DIFFICULTY: usize = 0x1092_0112;
const PLAYER_STRIDE: usize = 0x7884;
const UNIQUE_RANDOM_CLASSES: usize = 0x0521_3d88;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPress {
    Armed,
    Execute,
}

pub struct RestartGuard {
    first_press: Option<Instant>,
    interval: Duration,
}

impl RestartGuard {
    pub fn new(interval: Duration) -> Self {
        Self {
            first_press: None,
            interval,
        }
    }

    pub fn press(&mut self) -> RestartPress {
        let now = Instant::now();
        if self
            .first_press
            .is_some_and(|first| now.duration_since(first) <= self.interval)
        {
            self.first_press = None;
            RestartPress::Execute
        } else {
            self.first_press = Some(now);
            RestartPress::Armed
        }
    }

    pub fn armed(&self) -> bool {
        self.first_press
            .is_some_and(|first| first.elapsed() <= self.interval)
    }
}

#[derive(Debug)]
pub struct ExternalRestartResult {
    pub pid: u32,
    pub forced_termination: bool,
    pub participant_setup_applied: bool,
    pub live_map_settings: bool,
    pub live_roster: bool,
}

/// The full relaunch plan: the command-line arguments plus the participant
/// roster to write into the fresh instance. `capture` prefers the running
/// game's own settings — command line for the map/rule arguments, the live
/// injected snapshot for the participant roster — and falls back to the
/// static profile when either source is unavailable.
#[derive(Debug, Clone)]
pub struct RestartPlan {
    pub arguments: Vec<String>,
    pub controllers: [i16; 32],
    pub classes: [i16; 32],
    pub teams: [i16; 24],
    pub difficulties: [i16; 24],
    pub unique_random: i32,
    pub participant_count: usize,
    pub map_from_live: bool,
    pub roster_from_live: bool,
}

impl RestartPlan {
    pub fn capture(
        current: &ProcessInfo,
        snapshot: Option<&GameSnapshot>,
        profile: &Profile,
    ) -> Self {
        let (arguments, map_from_live) = match command_line(current.pid).ok().and_then(|line| {
            preserved_arguments(&line).map(|arguments| (arguments, true))
        }) {
            Some((arguments, live)) => (arguments, live),
            None => (launch_arguments(profile), false),
        };
        let mut plan = Self::from_profile(profile);
        plan.arguments = arguments;
        plan.map_from_live = map_from_live;
        if let Some(roster) = roster_from_snapshot(snapshot) {
            plan.controllers = roster.controllers;
            plan.classes = roster.classes;
            plan.teams = roster.teams;
            plan.difficulties = roster.difficulties;
            plan.unique_random = roster.unique_random;
            plan.participant_count = roster.participant_count;
            plan.roster_from_live = true;
        }
        plan
    }

    pub fn from_profile(profile: &Profile) -> Self {
        let mut controllers = [-1i16; 32];
        let mut classes = [-1i16; 32];
        let mut teams = [0i16; 24];
        let mut difficulties = [2i16; 24];
        let count = profile.participant_count as usize;
        for slot in 0..32usize {
            let active = slot < count;
            controllers[slot] = match slot {
                0 => 0,
                _ if active => 1,
                _ => -1,
            };
            classes[slot] = match slot {
                0 => profile.human_class_id,
                _ if active => 0,
                _ => -1,
            };
            if slot < 24 {
                teams[slot] = if active { 100 + slot as i16 } else { 0 };
                difficulties[slot] = profile.ai_difficulty;
            }
        }
        Self {
            arguments: launch_arguments(profile),
            controllers,
            classes,
            teams,
            difficulties,
            unique_random: i32::from(profile.rules.unique_random_classes),
            participant_count: count,
            map_from_live: false,
            roster_from_live: false,
        }
    }
}

struct Roster {
    controllers: [i16; 32],
    classes: [i16; 32],
    teams: [i16; 24],
    difficulties: [i16; 24],
    unique_random: i32,
    participant_count: usize,
}

/// Translates a live [`GameSnapshot`] into the roster arrays the setup screen
/// expects. The participant table is dense: the active slots form a leading
/// run, and everything past it is written inactive. The human's class is
/// preserved; AI (controller 1) slots are reset to `-1` so the game rolls
/// their classes fresh on world creation instead of carrying the resolved
/// classes of the restarted game.
fn roster_from_snapshot(snapshot: Option<&GameSnapshot>) -> Option<Roster> {
    let snapshot = snapshot?;
    let count = snapshot
        .participants
        .iter()
        .take_while(|participant| participant.active)
        .count();
    if count == 0 {
        return None;
    }
    let count = count.min(24);
    let mut controllers = [-1i16; 32];
    let mut classes = [-1i16; 32];
    let mut teams = [0i16; 24];
    let mut difficulties = [2i16; 24];
    for participant in snapshot.participants.iter().take(count) {
        let slot = participant.slot as usize;
        controllers[slot] = participant.controller;
        classes[slot] = if participant.controller == 0 {
            participant.class_id
        } else {
            -1
        };
        if let Some(team) = participant.team {
            teams[slot] = team;
        }
        if let Some(difficulty) = participant.difficulty {
            difficulties[slot] = difficulty;
        }
    }
    Some(Roster {
        controllers,
        classes,
        teams,
        difficulties,
        unique_random: snapshot.options.unique_random_classes,
        participant_count: count,
    })
}

/// Splits a CoE5 command line into the tokens after the executable path,
/// honouring quoted arguments.
fn tokenize_command_line(command_line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for character in command_line.chars() {
        match character {
            '"' => in_quotes = !in_quotes,
            character if character.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Extracts the game-setting arguments from a CoE5 command line. Returns
/// `None` when the process was not launched with an explicit map source
/// (`--randommap`/`--loadmap`); the assistant's own rendering, logging, and
/// relaunch flags are excluded because the relaunch re-adds them.
fn preserved_arguments(command_line: &str) -> Option<Vec<String>> {
    const MAP_FLAGS: &[&str] = &[
        "--mapw=",
        "--maph=",
        "--society=",
        "--northpart=",
        "--southpart=",
    ];
    const RULE_FLAGS: &[&str] = &[
        "--wilder",
        "--commoncause",
        "--graphs",
        "--battlereports",
        "--unique",
        "--nocitynames",
        "--clusterstart",
        "--noclusterstart",
        "--westeaststart",
        "--nomods",
        "--loadmod=",
        "--subsoc",
    ];

    let mut random_map = false;
    let mut load_map = None;
    let mut map_arguments = Vec::new();
    let mut rule_arguments = Vec::new();

    for token in tokenize_command_line(command_line).into_iter().skip(1) {
        if token == "--randommap" {
            random_map = true;
            continue;
        }
        if let Some(path) = token.strip_prefix("--loadmap=") {
            load_map = Some(path.to_string());
            continue;
        }
        if MAP_FLAGS.iter().any(|flag| token.starts_with(flag)) {
            map_arguments.push(token);
            continue;
        }
        if RULE_FLAGS.iter().any(|flag| token.starts_with(flag)) {
            rule_arguments.push(token);
        }
    }

    if let Some(path) = load_map {
        let mut arguments = vec!["--newgame".into(), format!("--loadmap={path}")];
        arguments.extend(rule_arguments);
        return Some(arguments);
    }
    if random_map {
        let mut arguments = vec!["--newgame".into(), "--randommap".into()];
        arguments.extend(map_arguments);
        arguments.extend(rule_arguments);
        arguments.extend([
            "--autosave".into(),
            "--window".into(),
            "--winres=1024*768".into(),
            "--nosound".into(),
        ]);
        return Some(arguments);
    }
    None
}

pub fn execute_external(
    current: &ProcessInfo,
    executable: &Path,
    plan: &RestartPlan,
) -> Result<ExternalRestartResult> {
    let forced_termination = stop_coe5(current.pid, Duration::from_secs(4))?;
    let child = launch_coe5(executable, &plan.arguments)?;
    let process = wait_for_coe5(child.id(), Duration::from_secs(20))?;
    if !process.sha256.eq_ignore_ascii_case(SUPPORTED_SHA256) {
        bail!(
            "external setup refuses unsupported CoE5 hash {}",
            process.sha256
        );
    }
    apply_participant_setup(&process, plan)?;
    activate_setup_ok(&process)?;
    wait_for_world_creation(&process, Duration::from_secs(90))?;
    Ok(ExternalRestartResult {
        pid: process.pid,
        forced_termination,
        participant_setup_applied: true,
        live_map_settings: plan.map_from_live,
        live_roster: plan.roster_from_live,
    })
}

pub fn launch_arguments(profile: &Profile) -> Vec<String> {
    let mut arguments = vec![
        "--newgame".into(),
        "--randommap".into(),
        format!("--mapw={}", profile.map.width),
        format!("--maph={}", profile.map.height),
        format!("--society={}", profile.map.society),
        format!("--northpart={}", profile.map.north_percent),
        format!("--southpart={}", profile.map.south_percent),
        "--autosave".into(),
        // Windowed rendering with a known resolution and sound disabled: a
        // bare relaunch renders a black fullscreen surface on this build and
        // the external setup automation needs a visible, deterministically
        // sized window to complete the participant screen.
        "--window".into(),
        "--winres=1024*768".into(),
        "--nosound".into(),
    ];
    if profile.rules.independent_strength > 1 {
        arguments.push("--wilder".into());
    }
    if profile.rules.common_cause {
        arguments.push("--commoncause".into());
    }
    if profile.rules.score_graphs {
        arguments.push("--graphs".into());
    }
    if profile.rules.battle_reports {
        arguments.push("--battlereports".into());
    }
    if profile.rules.unique_random_classes {
        arguments.push("--unique".into());
    }
    if !profile.rules.city_names {
        arguments.push("--nocitynames".into());
    }
    match profile.rules.start_policy {
        StartPolicy::Random => arguments.push("--noclusterstart".into()),
        StartPolicy::Clustered => arguments.push("--clusterstart".into()),
        StartPolicy::WestEast => arguments.push("--westeaststart".into()),
    }
    arguments.extend(profile.mods.iter().map(|name| format!("--loadmod={name}")));
    arguments
}

fn apply_participant_setup(process: &ProcessInfo, plan: &RestartPlan) -> Result<()> {
    let handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            false,
            process.pid,
        )
    }?);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let controller: i16 = read_remote(&handle, process.module_base + PARTICIPANT_CONTROLLERS)?;
        if controller == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    for slot in 0..32usize {
        let active = slot < plan.participant_count;
        let controller = if active {
            plan.controllers[slot]
        } else {
            -1
        };
        let class_id = if active { plan.classes[slot] } else { -1 };
        write_remote(
            &handle,
            process.module_base + PARTICIPANT_CONTROLLERS + slot * 2,
            &controller,
        )?;
        write_remote(
            &handle,
            process.module_base + PARTICIPANT_CLASSES + slot * 2,
            &class_id,
        )?;
        if slot < 24 {
            let team = if active { plan.teams[slot] } else { 0 };
            let difficulty = if active { plan.difficulties[slot] } else { 2 };
            write_remote(
                &handle,
                process.module_base + PLAYER_TEAM + slot * PLAYER_STRIDE,
                &team,
            )?;
            write_remote(
                &handle,
                process.module_base + PLAYER_DIFFICULTY + slot * PLAYER_STRIDE,
                &difficulty,
            )?;
        }
    }
    write_remote(
        &handle,
        process.module_base + UNIQUE_RANDOM_CLASSES,
        &plan.unique_random,
    )?;
    invalidate_game_window(process)?;
    Ok(())
}

/// Forces the game window to repaint after the participant table was written
/// into memory. The setup screen is event-driven and draws only when the
/// game decides to; the roster would otherwise stay invisible until some
/// window event (like a maximize/restore) happens to trigger a redraw.
fn invalidate_game_window(process: &ProcessInfo) -> Result<()> {
    let window = unsafe { FindWindowW(PCWSTR::null(), w!("CoE 5")) }?;
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    if pid != process.pid {
        return Ok(());
    }
    unsafe { InvalidateRect(Some(window), None, true) }.ok()?;
    Ok(())
}

fn activate_setup_ok(process: &ProcessInfo) -> Result<()> {
    let window = unsafe { FindWindowW(PCWSTR::null(), w!("CoE 5")) }?;
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    if pid != process.pid {
        bail!(
            "CoE 5 window belongs to process {pid}, expected {}",
            process.pid
        );
    }
    let _ = unsafe { SetForegroundWindow(window) };

    // The game needs a few seconds to initialize SDL, load assets, and reach
    // the Setup Participants screen; interacting earlier misses the dialog.
    std::thread::sleep(Duration::from_secs(4));
    let handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process.pid,
        )
    }?);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let controller: i16 = read_remote(&handle, process.module_base + PARTICIPANT_CONTROLLERS)?;
        if controller == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Dismiss any initial prompt and confirm the participant table.
    let enter = [key_input(VK_RETURN, false), key_input(VK_RETURN, true)];
    unsafe { SendInput(&enter, size_of::<INPUT>() as i32) };
    std::thread::sleep(Duration::from_millis(750));

    let start_x: i16 = read_remote(&handle, process.module_base + PARTICIPANT_START_X)?;
    if start_x >= 0 {
        return Ok(());
    }

    // The participant table sits in the upper portion of the 1024x768 render;
    // the confirm button row sits beneath it near the bottom of the render.
    let mut client = RECT::default();
    unsafe { GetClientRect(window, &mut client) }?;
    let client_height = client.bottom - client.top;
    let mut point = POINT {
        x: (client.right - client.left) / 2,
        y: (client_height as f32 * 0.86) as i32,
    };
    unsafe { ClientToScreen(window, &mut point) }.ok()?;
    unsafe { windows::Win32::UI::WindowsAndMessaging::SetCursorPos(point.x, point.y) }?;
    let click = [
        mouse_input(MOUSEEVENTF_LEFTDOWN),
        mouse_input(MOUSEEVENTF_LEFTUP),
    ];
    unsafe { SendInput(&click, size_of::<INPUT>() as i32) };
    Ok(())
}

fn wait_for_world_creation(process: &ProcessInfo, timeout: Duration) -> Result<()> {
    let handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process.pid,
        )
    }?);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let start_x: i16 = read_remote(&handle, process.module_base + PARTICIPANT_START_X)?;
        if start_x >= 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("world creation did not produce a human start coordinate")
}

fn read_remote<T: Copy>(process: &OwnedHandle, address: usize) -> Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut bytes_read = 0usize;
    unsafe {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process.raw(),
            address as *const c_void,
            value.as_mut_ptr().cast(),
            size_of::<T>(),
            Some(&mut bytes_read),
        )
    }?;
    if bytes_read != size_of::<T>() {
        bail!("short remote read at 0x{address:x}");
    }
    Ok(unsafe { value.assume_init() })
}

fn write_remote<T: Copy>(process: &OwnedHandle, address: usize, value: &T) -> Result<()> {
    let mut bytes_written = 0usize;
    unsafe {
        WriteProcessMemory(
            process.raw(),
            address as *const c_void,
            (value as *const T).cast(),
            size_of::<T>(),
            Some(&mut bytes_written),
        )
    }?;
    if bytes_written != size_of::<T>() {
        bail!("short remote write at 0x{address:x}");
    }
    Ok(())
}

fn key_input(key: VIRTUAL_KEY, key_up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key,
                wScan: 0,
                dwFlags: if key_up {
                    KEYEVENTF_KEYUP
                } else {
                    Default::default()
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn mouse_input(flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use azazel_coe5_protocol::{
        LifecycleSnapshot, MapSnapshot, OptionsSnapshot, ParticipantSnapshot,
    };

    use super::*;

    #[test]
    fn double_tap_arms_then_executes() {
        let mut guard = RestartGuard::new(Duration::from_secs(1));
        assert_eq!(guard.press(), RestartPress::Armed);
        assert_eq!(guard.press(), RestartPress::Execute);
    }

    #[test]
    fn launch_arguments_preserve_profile_map_and_rules() {
        let mut profile = Profile::default();
        profile.map.width = 60;
        profile.map.height = 44;
        profile.map.society = 3;
        profile.rules.independent_strength = 2;
        profile.rules.unique_random_classes = true;
        let arguments = launch_arguments(&profile);
        assert!(arguments.contains(&"--mapw=60".into()));
        assert!(arguments.contains(&"--maph=44".into()));
        assert!(arguments.contains(&"--society=3".into()));
        assert!(arguments.contains(&"--wilder".into()));
        assert!(arguments.contains(&"--unique".into()));
    }

    #[test]
    fn preserved_arguments_keep_live_map_and_drop_diagnostics() {
        let line = "\"D:/SteamLibrary/steamapps/common/ConquestOfElysium5/CoE5.exe\" \
            --newgame --randommap --mapw=60 --maph=44 --society=3 \
            --northpart=25 --southpart=35 --autosave --window --winres=1024*768 \
            --nosound --gamelog=currentconfig";
        let arguments = preserved_arguments(line).expect("map source");
        for expected in [
            "--newgame",
            "--randommap",
            "--mapw=60",
            "--maph=44",
            "--society=3",
            "--northpart=25",
            "--southpart=35",
            "--autosave",
            "--window",
            "--winres=1024*768",
            "--nosound",
        ] {
            assert!(arguments.iter().any(|arg| arg == expected), "missing {expected}");
        }
        assert!(
            arguments.iter().all(|arg| arg != "--gamelog=currentconfig"),
            "diagnostic flag must not be preserved"
        );
    }

    #[test]
    fn preserved_arguments_keep_rules_and_mods() {
        let line = "\"C:/Games/CoE5.exe\" --newgame --randommap --loadmod=my_mod --wilder \
            --nocitynames --clusterstart";
        let arguments = preserved_arguments(line).expect("map source");
        assert!(arguments.iter().any(|arg| arg == "--loadmod=my_mod"));
        assert!(arguments.iter().any(|arg| arg == "--wilder"));
        assert!(arguments.iter().any(|arg| arg == "--nocitynames"));
        assert!(arguments.iter().any(|arg| arg == "--clusterstart"));
    }

    #[test]
    fn preserved_arguments_preserve_loaded_map() {
        let line = "\"C:/Games/CoE5.exe\" --newgame --loadmap=C:/maps/arena.map --battlereports";
        let arguments = preserved_arguments(line).expect("map source");
        assert!(arguments.iter().any(|arg| arg == "--loadmap=C:/maps/arena.map"));
        assert!(arguments.iter().any(|arg| arg == "--battlereports"));
        assert!(arguments.iter().all(|arg| arg != "--randommap"));
    }

    #[test]
    fn preserved_arguments_none_without_map_source() {
        let bare = "\"D:/Games/CoE5.exe\"";
        assert!(preserved_arguments(bare).is_none());
        let unrelated = "\"D:/Games/CoE5.exe\" --window --nosound";
        assert!(preserved_arguments(unrelated).is_none());
    }

    fn live_snapshot() -> GameSnapshot {
        GameSnapshot {
            lifecycle: LifecycleSnapshot {
                world_state_unknown_abc: 0,
                turn: 0,
                plane: 0,
            },
            map: MapSnapshot {
                width: 60,
                height: 44,
                real_width: 60,
                random_map_launch_mode: 0,
            },
            options: OptionsSnapshot {
                flags_a: 0,
                flags_b: 0,
                society: 3,
                short_0c: 0,
                short_0e: 0,
                short_10: 0,
                int_14: 0,
                common_cause: 0,
                score_graphs: 0,
                int_20: 0,
                int_24: 0,
                int_28: 0,
                int_2c: 0,
                independent_strength: 1,
                int_34: 0,
                battle_reports: 0,
                north_percent_ui: 25,
                south_percent_ui: 35,
                start_policy_ui: 1,
                unique_random_classes: 0,
            },
            participants: (0..32)
                .map(|slot| ParticipantSnapshot {
                    slot,
                    active: slot < 4,
                    controller: match slot {
                        0 => 0,
                        1..=3 => 1,
                        _ => -1,
                    },
                    class_id: match slot {
                        0 => 2,
                        1..=3 => 0,
                        _ => -1,
                    },
                    start_x: -1,
                    start_y: -1,
                    team: (slot < 4).then(|| 100 + slot as i16),
                    difficulty: (slot < 4).then_some(2),
                })
                .collect(),
        }
    }

    #[test]
    fn roster_from_snapshot_keeps_live_participants() {
        let roster = roster_from_snapshot(Some(&live_snapshot())).expect("live roster");
        assert_eq!(roster.participant_count, 4);
        assert_eq!(roster.controllers[0], 0);
        assert_eq!(roster.controllers[1], 1);
        assert_eq!(roster.controllers[3], 1);
        assert_eq!(roster.controllers[4], -1);
        assert_eq!(roster.classes[0], 2, "human class is preserved");
        assert_eq!(roster.classes[1], -1, "AI classes reset to random");
        assert_eq!(roster.classes[3], -1, "AI classes reset to random");
        assert_eq!(roster.teams[2], 102);
        assert_eq!(roster.difficulties[1], 2);
    }

    #[test]
    fn roster_from_snapshot_none_without_active_participants() {
        let mut snapshot = live_snapshot();
        for participant in &mut snapshot.participants {
            participant.active = false;
        }
        assert!(roster_from_snapshot(Some(&snapshot)).is_none());
        assert!(roster_from_snapshot(None).is_none());
    }

    #[test]
    fn profile_plan_matches_static_behavior() {
        let profile = Profile {
            human_class_id: 7,
            participant_count: 3,
            ai_difficulty: 4,
            ..Profile::default()
        };
        let plan = RestartPlan::from_profile(&profile);
        assert_eq!(plan.participant_count, 3);
        assert_eq!(plan.controllers[0], 0);
        assert_eq!(plan.controllers[1], 1);
        assert_eq!(plan.controllers[3], -1);
        assert_eq!(plan.classes[0], 7);
        assert_eq!(plan.teams[2], 102);
        assert_eq!(plan.difficulties[1], 4);
        assert!(!plan.roster_from_live);
        assert!(!plan.map_from_live);
    }
}
