use std::{
    collections::BTreeMap,
    ffi::c_void,
    sync::{
        OnceLock,
        atomic::{AtomicPtr, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{Envelope, HookEvent, Message};
use azazel_coe5_symbols::Rva;
use crossbeam_channel::Sender;
use minhook::MinHook;
use windows::Win32::System::Threading::GetCurrentThreadId;

use crate::state::RuntimeState;

static EVENT_SENDER: OnceLock<Sender<Envelope>> = OnceLock::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

static ORIGINAL_GAME_LOOP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WORLD_RESET: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_PARTICIPANT_DEFAULTS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_GAME_OVER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RNG_PUSH: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RNG_POP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[derive(Debug, Clone)]
struct InstalledHook {
    target: usize,
}

#[derive(Default)]
pub struct HookManager {
    installed: BTreeMap<String, InstalledHook>,
}

impl HookManager {
    pub fn set_event_sender(sender: Sender<Envelope>) -> Result<()> {
        EVENT_SENDER
            .set(sender)
            .map_err(|_| anyhow::anyhow!("hook event sender already initialized"))
    }

    pub fn set_enabled(&mut self, state: &RuntimeState, symbol: &str, enabled: bool) -> Result<()> {
        if enabled {
            self.enable(state, symbol)
        } else {
            self.disable(symbol)
        }
    }

    pub fn is_installed(&self, symbol: &str) -> bool {
        self.installed.contains_key(symbol)
    }

    pub fn disable_all(&mut self) {
        let symbols = self.installed.keys().cloned().collect::<Vec<_>>();
        for symbol in symbols {
            let _ = self.disable(&symbol);
        }
    }

    fn enable(&mut self, state: &RuntimeState, symbol: &str) -> Result<()> {
        if self.installed.contains_key(symbol) {
            return Ok(());
        }
        let (detour, original) = hook_definition(symbol)
            .with_context(|| format!("symbol '{symbol}' is not an observable hook"))?;
        let target = state.address_of_function(symbol)?;
        let trampoline = unsafe { MinHook::create_hook(target, detour) }
            .map_err(|status| anyhow::anyhow!("MinHook create {symbol}: {status}"))?;
        original.store(trampoline, Ordering::Release);
        if let Err(status) = unsafe { MinHook::enable_hook(target) } {
            let _ = unsafe { MinHook::remove_hook(target) };
            original.store(std::ptr::null_mut(), Ordering::Release);
            bail!("MinHook enable {symbol}: {status}");
        }
        self.installed.insert(
            symbol.to_owned(),
            InstalledHook {
                target: target as usize,
            },
        );
        Ok(())
    }

    fn disable(&mut self, symbol: &str) -> Result<()> {
        let Some(installed) = self.installed.remove(symbol) else {
            return Ok(());
        };
        let target = installed.target as *mut c_void;
        unsafe { MinHook::disable_hook(target) }
            .map_err(|status| anyhow::anyhow!("MinHook disable {symbol}: {status}"))?;
        unsafe { MinHook::remove_hook(target) }
            .map_err(|status| anyhow::anyhow!("MinHook remove {symbol}: {status}"))?;
        if let Some((_, original)) = hook_definition(symbol) {
            original.store(std::ptr::null_mut(), Ordering::Release);
        }
        Ok(())
    }
}

impl Drop for HookManager {
    fn drop(&mut self) {
        self.disable_all();
    }
}

fn hook_definition(symbol: &str) -> Option<(*mut c_void, &'static AtomicPtr<c_void>)> {
    match symbol {
        "game_main_loop_run_turns" => Some((
            detour_game_loop as *const () as *mut c_void,
            &ORIGINAL_GAME_LOOP,
        )),
        "world_reset_static_state" => Some((
            detour_world_reset as *const () as *mut c_void,
            &ORIGINAL_WORLD_RESET,
        )),
        "newgame_apply_participant_defaults" => Some((
            detour_participant_defaults as *const () as *mut c_void,
            &ORIGINAL_PARTICIPANT_DEFAULTS,
        )),
        "game_over_detect_and_announce" => Some((
            detour_game_over as *const () as *mut c_void,
            &ORIGINAL_GAME_OVER,
        )),
        "rng_state_stack_push" => Some((
            detour_rng_push as *const () as *mut c_void,
            &ORIGINAL_RNG_PUSH,
        )),
        "rng_state_stack_pop" => Some((
            detour_rng_pop as *const () as *mut c_void,
            &ORIGINAL_RNG_POP,
        )),
        _ => None,
    }
}

fn emit(symbol: &'static str, rva: u64) {
    let Some(sender) = EVENT_SENDER.get() else {
        return;
    };
    let timestamp_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as u64)
        .unwrap_or_default();
    let event = HookEvent {
        symbol: symbol.into(),
        rva: Rva(rva),
        thread_id: unsafe { GetCurrentThreadId() },
        sequence: SEQUENCE.fetch_add(1, Ordering::Relaxed),
        timestamp_micros,
    };
    let _ = sender.try_send(Envelope::event(Message::HookEvent(event)));
}

unsafe extern "C" fn detour_game_loop(mode: i32) -> u64 {
    emit("game_main_loop_run_turns", 0x83290);
    let original = ORIGINAL_GAME_LOOP.load(Ordering::Acquire);
    if original.is_null() {
        return 0;
    }
    let function: unsafe extern "C" fn(i32) -> u64 = unsafe { std::mem::transmute(original) };
    unsafe { function(mode) }
}

unsafe extern "C" fn detour_world_reset() {
    emit("world_reset_static_state", 0x1c6d10);
    call_void0(&ORIGINAL_WORLD_RESET);
}

unsafe extern "C" fn detour_participant_defaults(mode: i32) {
    emit("newgame_apply_participant_defaults", 0x1caf10);
    let original = ORIGINAL_PARTICIPANT_DEFAULTS.load(Ordering::Acquire);
    if original.is_null() {
        return;
    }
    let function: unsafe extern "C" fn(i32) = unsafe { std::mem::transmute(original) };
    unsafe { function(mode) };
}

unsafe extern "C" fn detour_game_over() {
    emit("game_over_detect_and_announce", 0xecea0);
    call_void0(&ORIGINAL_GAME_OVER);
}

unsafe extern "C" fn detour_rng_push() {
    emit("rng_state_stack_push", 0x50e40);
    call_void0(&ORIGINAL_RNG_PUSH);
}

unsafe extern "C" fn detour_rng_pop() {
    emit("rng_state_stack_pop", 0x50ea0);
    call_void0(&ORIGINAL_RNG_POP);
}

fn call_void0(slot: &AtomicPtr<c_void>) {
    let original = slot.load(Ordering::Acquire);
    if original.is_null() {
        return;
    }
    let function: unsafe extern "C" fn() = unsafe { std::mem::transmute(original) };
    unsafe { function() };
}
