use std::{
    ffi::c_void,
    mem::size_of,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use windows::Win32::{
    Foundation::{POINT, RECT},
    Graphics::Gdi::ClientToScreen,
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
    process::{OwnedHandle, ProcessInfo, launch_coe5, stop_coe5, wait_for_coe5},
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
}

pub fn execute_external(
    current: &ProcessInfo,
    executable: &Path,
    profile: &Profile,
) -> Result<ExternalRestartResult> {
    let forced_termination = stop_coe5(current.pid, Duration::from_secs(4))?;
    let arguments = launch_arguments(profile);
    let child = launch_coe5(executable, &arguments)?;
    let process = wait_for_coe5(child.id(), Duration::from_secs(20))?;
    if !process.sha256.eq_ignore_ascii_case(SUPPORTED_SHA256) {
        bail!(
            "external setup refuses unsupported CoE5 hash {}",
            process.sha256
        );
    }
    apply_participant_setup(&process, profile)?;
    activate_setup_ok(&process)?;
    wait_for_world_creation(&process, Duration::from_secs(90))?;
    Ok(ExternalRestartResult {
        pid: process.pid,
        forced_termination,
        participant_setup_applied: true,
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

fn apply_participant_setup(process: &ProcessInfo, profile: &Profile) -> Result<()> {
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
        let active = slot < profile.participant_count as usize;
        let controller: i16 = if slot == 0 {
            0
        } else if active {
            1
        } else {
            -1
        };
        let class_id: i16 = if slot == 0 {
            profile.human_class_id
        } else if active {
            0
        } else {
            -1
        };
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
            let team = if active { 100i16 + slot as i16 } else { 0 };
            write_remote(
                &handle,
                process.module_base + PLAYER_TEAM + slot * PLAYER_STRIDE,
                &team,
            )?;
            write_remote(
                &handle,
                process.module_base + PLAYER_DIFFICULTY + slot * PLAYER_STRIDE,
                &profile.ai_difficulty,
            )?;
        }
    }
    let unique = i32::from(profile.rules.unique_random_classes);
    write_remote(
        &handle,
        process.module_base + UNIQUE_RANDOM_CLASSES,
        &unique,
    )?;
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
}
