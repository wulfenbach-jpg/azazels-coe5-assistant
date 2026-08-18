use std::{
    mem::size_of,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU32, Ordering},
    },
    thread,
};

use anyhow::{Context, Result, bail};
use parking_lot::RwLock;
use windows::Win32::{
    Foundation::{LPARAM, LRESULT, WPARAM},
    System::Threading::GetCurrentThreadId,
    UI::{
        Input::KeyboardAndMouse::{
            GetAsyncKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
            SendInput, VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_SHIFT,
        },
        WindowsAndMessaging::{
            CallNextHookEx, GetForegroundWindow, GetMessageW, GetWindowThreadProcessId,
            KBDLLHOOKSTRUCT, LLKHF_INJECTED, MSG, MSLLHOOKSTRUCT, PostThreadMessageW,
            SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN,
            WM_LBUTTONDOWN, WM_MBUTTONDOWN, WM_MOUSEWHEEL, WM_QUIT, WM_RBUTTONDOWN, WM_SYSKEYDOWN,
            WM_XBUTTONDOWN,
        },
    },
};

use crate::config::{InputAction, InputTrigger, MouseButton, RemapRule};

static HOOK_STATE: OnceLock<Arc<HookState>> = OnceLock::new();

struct HookState {
    target_pid: AtomicU32,
    rules: RwLock<Vec<RemapRule>>,
}

pub struct InputRemapper {
    state: Arc<HookState>,
    thread_id: u32,
    thread: Option<thread::JoinHandle<()>>,
}

impl InputRemapper {
    pub fn start(target_pid: u32, rules: Vec<RemapRule>) -> Result<Self> {
        let state = Arc::new(HookState {
            target_pid: AtomicU32::new(target_pid),
            rules: RwLock::new(rules),
        });
        HOOK_STATE
            .set(Arc::clone(&state))
            .map_err(|_| anyhow::anyhow!("input remapper already initialized"))?;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("azazel-coe5-input-remapper".into())
            .spawn(move || hook_thread(ready_tx))
            .context("spawn input-remapper thread")?;
        let thread_id = ready_rx
            .recv()
            .context("input-remapper thread exited before ready")??;
        Ok(Self {
            state,
            thread_id,
            thread: Some(thread),
        })
    }

    pub fn set_target_pid(&self, pid: u32) {
        self.state.target_pid.store(pid, Ordering::Release);
    }

    pub fn update_rules(&self, rules: Vec<RemapRule>) {
        *self.state.rules.write() = rules;
    }

    pub fn stop(&mut self) {
        if self.thread_id != 0 {
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
            self.thread_id = 0;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for InputRemapper {
    fn drop(&mut self) {
        self.stop();
    }
}

fn hook_thread(ready: std::sync::mpsc::SyncSender<Result<u32>>) {
    let keyboard = match unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), None, 0) }
    {
        Ok(hook) => hook,
        Err(error) => {
            let _ = ready.send(Err(error).context("install keyboard hook"));
            return;
        }
    };
    let mouse = match unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), None, 0) } {
        Ok(hook) => hook,
        Err(error) => {
            unsafe {
                let _ = UnhookWindowsHookEx(keyboard);
            }
            let _ = ready.send(Err(error).context("install mouse hook"));
            return;
        }
    };
    let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));

    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.0 > 0 {}
    unsafe {
        let _ = UnhookWindowsHookEx(mouse);
        let _ = UnhookWindowsHookEx(keyboard);
    }
}

unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code < 0 || !target_is_foreground() {
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    if wparam.0 != WM_KEYDOWN as usize && wparam.0 != WM_SYSKEYDOWN as usize {
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let event = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
    if event.flags.contains(LLKHF_INJECTED) {
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let modifiers = current_modifiers();
    let action = HOOK_STATE.get().and_then(|state| {
        state
            .rules
            .read()
            .iter()
            .find(|rule| {
                rule.enabled
                    && matches!(
                        rule.trigger,
                        InputTrigger::Keyboard {
                            virtual_key,
                            control,
                            alt,
                            shift,
                        } if virtual_key as u32 == event.vkCode
                            && (control, alt, shift) == modifiers
                    )
            })
            .map(|rule| rule.action.clone())
    });
    if let Some(action) = action {
        let _ = send_action(&action);
        return LRESULT(1);
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

unsafe extern "system" fn mouse_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code < 0 || !target_is_foreground() {
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let event = unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
    if event.flags & 1 != 0 {
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let button = match wparam.0 as u32 {
        WM_LBUTTONDOWN => Some(MouseButton::Left),
        WM_RBUTTONDOWN => Some(MouseButton::Right),
        WM_MBUTTONDOWN => Some(MouseButton::Middle),
        WM_XBUTTONDOWN => match (event.mouseData >> 16) as u16 {
            1 => Some(MouseButton::X1),
            2 => Some(MouseButton::X2),
            _ => None,
        },
        WM_MOUSEWHEEL => None,
        _ => None,
    };
    let action = button.and_then(|button| {
        HOOK_STATE.get().and_then(|state| {
            state
                .rules
                .read()
                .iter()
                .find(|rule| {
                    rule.enabled
                        && matches!(rule.trigger, InputTrigger::MouseButton { button: expected } if expected == button)
                })
                .map(|rule| rule.action.clone())
        })
    });
    if let Some(action) = action {
        let _ = send_action(&action);
        return LRESULT(1);
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

fn target_is_foreground() -> bool {
    let Some(state) = HOOK_STATE.get() else {
        return false;
    };
    let target = state.target_pid.load(Ordering::Acquire);
    if target == 0 {
        return false;
    }
    let window = unsafe { GetForegroundWindow() };
    if window.is_invalid() {
        return false;
    }
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    pid == target
}

fn current_modifiers() -> (bool, bool, bool) {
    unsafe {
        (
            GetAsyncKeyState(VK_CONTROL.0 as i32) < 0,
            GetAsyncKeyState(VK_MENU.0 as i32) < 0,
            GetAsyncKeyState(VK_SHIFT.0 as i32) < 0,
        )
    }
}

fn send_action(action: &InputAction) -> Result<()> {
    let mut inputs = Vec::with_capacity(8);
    if action.control {
        inputs.push(key_input(VK_CONTROL.0, false));
    }
    if action.alt {
        inputs.push(key_input(VK_MENU.0, false));
    }
    if action.shift {
        inputs.push(key_input(VK_SHIFT.0, false));
    }
    inputs.push(key_input(action.virtual_key, false));
    inputs.push(key_input(action.virtual_key, true));
    if action.shift {
        inputs.push(key_input(VK_SHIFT.0, true));
    }
    if action.alt {
        inputs.push(key_input(VK_MENU.0, true));
    }
    if action.control {
        inputs.push(key_input(VK_CONTROL.0, true));
    }
    let sent = unsafe { SendInput(&inputs, size_of::<INPUT>() as i32) };
    if sent != inputs.len() as u32 {
        bail!("SendInput sent {sent} of {} events", inputs.len());
    }
    Ok(())
}

fn key_input(virtual_key: u16, key_up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(virtual_key),
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
