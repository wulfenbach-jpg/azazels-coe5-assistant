use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use parking_lot::Mutex;
use windows::Win32::{
    Foundation::{
        CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT,
        EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, GetLastError, HANDLE, NTSTATUS,
    },
    Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW},
    System::{
        Diagnostics::Debug::{
            CONTEXT, CONTEXT_ALL_AMD64, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
            ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess, DebugActiveProcessStop,
            DebugBreakProcess, DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT,
            EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, FlushInstructionCache,
            GetThreadContext, LOAD_DLL_DEBUG_EVENT, ReadProcessMemory, SetThreadContext,
            UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEvent, WriteProcessMemory,
        },
        Threading::{
            OpenProcess, OpenThread, PROCESS_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        },
    },
};

const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DEBUG_EVENT_TIMEOUT_MS: u32 = 50;
const MAX_MEMORY_READ: usize = 1024 * 1024;
const TRAP_FLAG: u32 = 0x100;

pub struct DebuggerSession {
    commands: Sender<DebuggerCommand>,
    events: Receiver<DebuggerEvent>,
    process: Arc<OwnedHandle>,
    debug_thread: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone, Debug)]
pub enum DebuggerCommand {
    AddBreakpoint { address: u64 },
    RemoveBreakpoint { address: u64 },
    Continue,
    Step { thread_id: u32 },
    Pause,
    Detach,
}

#[derive(Clone, Debug)]
pub enum DebuggerEvent {
    Attached {
        pid: u32,
    },
    ProcessCreated {
        process_id: u32,
        thread_id: u32,
    },
    ProcessExited {
        exit_code: u32,
    },
    ThreadCreated {
        thread_id: u32,
    },
    ThreadExited {
        thread_id: u32,
        exit_code: u32,
    },
    ModuleLoaded {
        base: u64,
        path: Option<String>,
    },
    ModuleUnloaded {
        base: u64,
    },
    BreakpointHit {
        thread_id: u32,
        address: u64,
        registers: Registers,
    },
    SingleStep {
        thread_id: u32,
        address: u64,
        registers: Registers,
    },
    Exception {
        thread_id: u32,
        code: u32,
        address: u64,
        first_chance: bool,
    },
    Detached,
    Error(String),
}

impl DebuggerEvent {
    pub fn thread_id(&self) -> Option<u32> {
        match self {
            Self::ProcessCreated { thread_id, .. }
            | Self::ThreadCreated { thread_id }
            | Self::ThreadExited { thread_id, .. }
            | Self::BreakpointHit { thread_id, .. }
            | Self::SingleStep { thread_id, .. }
            | Self::Exception { thread_id, .. } => Some(*thread_id),
            _ => None,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Attached { pid } => format!("attached pid={pid}"),
            Self::ProcessCreated {
                process_id,
                thread_id,
            } => format!("process pid={process_id} thread={thread_id}"),
            Self::ProcessExited { exit_code } => format!("process exit=0x{exit_code:x}"),
            Self::ThreadCreated { thread_id } => format!("thread +{thread_id}"),
            Self::ThreadExited {
                thread_id,
                exit_code,
            } => format!("thread -{thread_id} exit=0x{exit_code:x}"),
            Self::ModuleLoaded { base, path } => format!(
                "module +0x{base:x} {}",
                path.as_deref().unwrap_or("<unknown>")
            ),
            Self::ModuleUnloaded { base } => format!("module -0x{base:x}"),
            Self::BreakpointHit {
                thread_id,
                address,
                registers,
            } => format!("break t{thread_id} 0x{address:x} {}", registers.summary()),
            Self::SingleStep {
                thread_id,
                address,
                registers,
            } => format!("step t{thread_id} 0x{address:x} {}", registers.summary()),
            Self::Exception {
                thread_id,
                code,
                address,
                first_chance,
            } => format!(
                "exception t{thread_id} code=0x{code:x} at 0x{address:x} first={first_chance}"
            ),
            Self::Detached => "detached".into(),
            Self::Error(error) => format!("error {error}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Registers {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u32,
}

impl Registers {
    pub fn summary(&self) -> String {
        format!(
            "rip={:016x} rsp={:016x} rbp={:016x} rax={:016x} rbx={:016x} rcx={:016x} rdx={:016x} rsi={:016x} rdi={:016x} r8={:016x} r9={:016x} r10={:016x} r11={:016x} r12={:016x} r13={:016x} r14={:016x} r15={:016x} flags={:08x}",
            self.rip,
            self.rsp,
            self.rbp,
            self.rax,
            self.rbx,
            self.rcx,
            self.rdx,
            self.rsi,
            self.rdi,
            self.r8,
            self.r9,
            self.r10,
            self.r11,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.eflags
        )
    }
}

#[derive(Clone, Debug)]
pub struct DisassemblyLine {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

impl DebuggerSession {
    pub fn attach(pid: u32) -> Result<Self> {
        // OpenProcess returns a real kernel handle with the access required by memory operations
        // and DebugBreakProcess. The owned wrapper closes it after both session and worker release it.
        let process = Arc::new(OwnedHandle::new(unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, false, pid)
        }?)?);
        let (command_tx, command_rx) = crossbeam_channel::unbounded();
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let (startup_tx, startup_rx) = crossbeam_channel::bounded(1);
        let worker_process = Arc::clone(&process);

        let debug_thread = thread::Builder::new()
            .name(format!("coe5-debugger-{pid}"))
            .spawn(move || {
                debug_thread_entry(pid, worker_process, command_rx, event_tx, startup_tx);
            })
            .context("spawn debugger thread")?;

        match startup_rx
            .recv()
            .context("debugger thread exited during attach")?
        {
            Ok(()) => Ok(Self {
                commands: command_tx,
                events: event_rx,
                process,
                debug_thread: Mutex::new(Some(debug_thread)),
            }),
            Err(message) => {
                let _ = debug_thread.join();
                bail!(message)
            }
        }
    }

    pub fn send(&self, command: DebuggerCommand) -> Result<()> {
        self.commands
            .send(command)
            .map_err(|_| anyhow!("debugger thread is no longer running"))
    }

    pub fn events(&self) -> &Receiver<DebuggerEvent> {
        &self.events
    }

    pub fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        read_process_memory(self.process.raw(), address, length)
    }

    pub fn disassemble(&self, address: u64, length: usize) -> Result<Vec<DisassemblyLine>> {
        let bytes = self.read_memory(address, length)?;
        let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let mut lines = Vec::new();

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }

            let Some(offset) = instruction.ip().checked_sub(address) else {
                break;
            };
            let Ok(offset) = usize::try_from(offset) else {
                break;
            };
            let end = offset.saturating_add(instruction.len());
            if end > bytes.len() {
                break;
            }

            let mut text = String::new();
            formatter.format(&instruction, &mut text);
            lines.push(DisassemblyLine {
                address: instruction.ip(),
                bytes: bytes[offset..end].to_vec(),
                text,
            });
        }

        Ok(lines)
    }
}

impl Drop for DebuggerSession {
    fn drop(&mut self) {
        let _ = self.commands.send(DebuggerCommand::Detach);
        if let Some(worker) = self.debug_thread.get_mut().take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!("received an invalid Windows handle");
        }
        Ok(Self(handle))
    }

    fn from_event(handle: HANDLE) -> Option<Self> {
        if handle.is_invalid() {
            None
        } else {
            Some(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

// Windows kernel handles may be used and closed from a thread other than the one that opened them.
unsafe impl Send for OwnedHandle {}
// The wrapper only exposes the copyable handle value; Windows synchronizes operations on the object.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // This wrapper uniquely owns the real, non-null kernel handle.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Clone, Copy)]
struct SoftwareBreakpoint {
    original_byte: u8,
    inserted: bool,
}

#[derive(Clone, Copy)]
struct PendingReinsert {
    address: u64,
    stop_after_step: bool,
}

#[derive(Clone, Copy)]
enum HeldKind {
    Breakpoint { address: u64 },
    SingleStep,
    Exception,
}

#[derive(Clone, Copy)]
struct HeldEvent {
    process_id: u32,
    thread_id: u32,
    continue_status: NTSTATUS,
    kind: HeldKind,
}

enum ExceptionOutcome {
    Continue(NTSTATUS),
    Hold(HeldEvent),
}

struct DebuggerCore {
    pid: u32,
    process: Arc<OwnedHandle>,
    commands: Receiver<DebuggerCommand>,
    events: Sender<DebuggerEvent>,
    breakpoints: HashMap<u64, SoftwareBreakpoint>,
    threads: HashMap<u32, OwnedHandle>,
    modules: HashMap<u64, Option<String>>,
    pending_reinsert: HashMap<u32, PendingReinsert>,
    explicit_steps: HashSet<u32>,
    trap_threads: HashSet<u32>,
    held: Option<HeldEvent>,
    pause_pending: bool,
    initial_breakpoint_pending: bool,
    detach_pending: bool,
    attached: bool,
}

fn debug_thread_entry(
    pid: u32,
    process: Arc<OwnedHandle>,
    commands: Receiver<DebuggerCommand>,
    events: Sender<DebuggerEvent>,
    startup: Sender<std::result::Result<(), String>>,
) {
    // DebugActiveProcess makes this dedicated thread the debugger event owner.
    if let Err(error) = unsafe { DebugActiveProcess(pid) } {
        let _ = startup.send(Err(format!("DebugActiveProcess({pid}) failed: {error}")));
        return;
    }

    // This is set only after an explicit attach and prevents debugger teardown from killing CoE5.
    if let Err(error) = unsafe { DebugSetProcessKillOnExit(false) } {
        // The attach succeeded, so stop it before reporting startup failure.
        unsafe {
            let _ = DebugActiveProcessStop(pid);
        }
        let _ = startup.send(Err(format!(
            "DebugSetProcessKillOnExit(false) failed: {error}"
        )));
        return;
    }

    let mut core = DebuggerCore {
        pid,
        process,
        commands,
        events,
        breakpoints: HashMap::new(),
        threads: HashMap::new(),
        modules: HashMap::new(),
        pending_reinsert: HashMap::new(),
        explicit_steps: HashSet::new(),
        trap_threads: HashSet::new(),
        held: None,
        pause_pending: false,
        initial_breakpoint_pending: true,
        detach_pending: false,
        attached: true,
    };

    core.emit(DebuggerEvent::Attached { pid });
    if startup.send(Ok(())).is_err() {
        core.detach();
        return;
    }
    core.run();
}

impl DebuggerCore {
    fn run(&mut self) {
        loop {
            if self.detach_pending && (self.held.is_some() || self.trap_threads.is_empty()) {
                self.detach();
                return;
            }
            if self.held.is_some() {
                match self.commands.recv_timeout(COMMAND_POLL_INTERVAL) {
                    Ok(command) => {
                        if !self.handle_command(command) {
                            return;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        self.detach();
                        return;
                    }
                }
                continue;
            }

            loop {
                match self.commands.try_recv() {
                    Ok(command) => {
                        if !self.handle_command(command) {
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.detach();
                        return;
                    }
                }
            }

            let mut event = DEBUG_EVENT::default();
            // The finite timeout lets this event-owning thread service commands while the target runs.
            match unsafe { WaitForDebugEvent(&mut event, DEBUG_EVENT_TIMEOUT_MS) } {
                Ok(()) => {
                    if !self.handle_debug_event(event) {
                        return;
                    }
                }
                Err(error) => {
                    // WaitForDebugEvent reports an ordinary poll timeout through GetLastError.
                    let timed_out = unsafe { GetLastError() } == ERROR_SEM_TIMEOUT;
                    if !timed_out {
                        self.emit(DebuggerEvent::Error(format!(
                            "WaitForDebugEvent failed: {error}"
                        )));
                        self.detach();
                        return;
                    }
                }
            }
        }
    }

    fn handle_command(&mut self, command: DebuggerCommand) -> bool {
        let result = match command {
            DebuggerCommand::AddBreakpoint { address } => self.add_breakpoint(address),
            DebuggerCommand::RemoveBreakpoint { address } => self.remove_breakpoint(address),
            DebuggerCommand::Continue => self.continue_held(false, None),
            DebuggerCommand::Step { thread_id } => self.continue_held(true, Some(thread_id)),
            DebuggerCommand::Pause => {
                // The process handle was opened with the access required by DebugBreakProcess.
                let result =
                    unsafe { DebugBreakProcess(self.process.raw()) }.context("DebugBreakProcess");
                if result.is_ok() {
                    self.pause_pending = true;
                }
                result
            }
            DebuggerCommand::Detach => {
                if self.held.is_none() && !self.trap_threads.is_empty() {
                    self.detach_pending = true;
                    return true;
                }
                self.detach();
                return false;
            }
        };

        if let Err(error) = result {
            self.emit(DebuggerEvent::Error(error.to_string()));
        }
        true
    }

    fn handle_debug_event(&mut self, event: DEBUG_EVENT) -> bool {
        let process_id = event.dwProcessId;
        let thread_id = event.dwThreadId;
        let code = event.dwDebugEventCode;
        let mut continue_status = DBG_CONTINUE;
        let mut exit_after_continue = false;

        if code == CREATE_PROCESS_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.CreateProcessInfo };
            let file = OwnedHandle::from_event(info.hFile);
            let event_process = OwnedHandle::from_event(info.hProcess);
            if let Some(thread) = OwnedHandle::from_event(info.hThread) {
                self.threads.insert(thread_id, thread);
            }
            let base = info.lpBaseOfImage as usize as u64;
            let path = file.as_ref().and_then(|handle| module_path(handle.raw()));
            self.modules.insert(base, path.clone());
            self.emit(DebuggerEvent::ProcessCreated {
                process_id,
                thread_id,
            });
            self.emit(DebuggerEvent::ModuleLoaded { base, path });
            drop(event_process);
            drop(file);
        } else if code == CREATE_THREAD_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.CreateThread };
            if let Some(thread) = OwnedHandle::from_event(info.hThread) {
                self.threads.insert(thread_id, thread);
            }
            self.emit(DebuggerEvent::ThreadCreated { thread_id });
        } else if code == EXIT_THREAD_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.ExitThread };
            if let Some(pending) = self.pending_reinsert.remove(&thread_id)
                && let Err(error) = self.reinsert_breakpoint(pending.address) {
                    self.emit(DebuggerEvent::Error(format!(
                        "reinsert breakpoint {:#x} while thread {thread_id} exits: {error}",
                        pending.address
                    )));
                }
            self.threads.remove(&thread_id);
            self.explicit_steps.remove(&thread_id);
            self.trap_threads.remove(&thread_id);
            self.emit(DebuggerEvent::ThreadExited {
                thread_id,
                exit_code: info.dwExitCode,
            });
        } else if code == EXIT_PROCESS_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.ExitProcess };
            self.emit(DebuggerEvent::ProcessExited {
                exit_code: info.dwExitCode,
            });
            exit_after_continue = true;
        } else if code == LOAD_DLL_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.LoadDll };
            let file = OwnedHandle::from_event(info.hFile);
            let base = info.lpBaseOfDll as usize as u64;
            let path = file.as_ref().and_then(|handle| module_path(handle.raw()));
            self.modules.insert(base, path.clone());
            self.emit(DebuggerEvent::ModuleLoaded { base, path });
            drop(file);
        } else if code == UNLOAD_DLL_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.UnloadDll };
            let base = info.lpBaseOfDll as usize as u64;
            self.modules.remove(&base);
            self.emit(DebuggerEvent::ModuleUnloaded { base });
        } else if code == EXCEPTION_DEBUG_EVENT {
            // The active union member is selected by dwDebugEventCode.
            let info = unsafe { event.u.Exception };
            match self.handle_exception(process_id, thread_id, info) {
                Ok(ExceptionOutcome::Continue(status)) => continue_status = status,
                Ok(ExceptionOutcome::Hold(held)) => {
                    self.held = Some(held);
                    return true;
                }
                Err(error) => {
                    let record = info.ExceptionRecord;
                    let first_chance = info.dwFirstChance != 0;
                    self.emit(DebuggerEvent::Error(error.to_string()));
                    self.emit(DebuggerEvent::Exception {
                        thread_id,
                        code: record.ExceptionCode.0 as u32,
                        address: record.ExceptionAddress as usize as u64,
                        first_chance,
                    });
                    self.held = Some(HeldEvent {
                        process_id,
                        thread_id,
                        continue_status: DBG_EXCEPTION_NOT_HANDLED,
                        kind: HeldKind::Exception,
                    });
                    return true;
                }
            }
        }

        if let Err(error) = continue_debug_event(process_id, thread_id, continue_status) {
            self.emit(DebuggerEvent::Error(error.to_string()));
            self.held = Some(HeldEvent {
                process_id,
                thread_id,
                continue_status,
                kind: HeldKind::Exception,
            });
            return true;
        }

        if exit_after_continue {
            self.attached = false;
            self.breakpoints.clear();
            self.pending_reinsert.clear();
            self.explicit_steps.clear();
            self.trap_threads.clear();
            self.modules.clear();
            self.threads.clear();
            if self.detach_pending {
                self.emit(DebuggerEvent::Detached);
            }
            return false;
        }
        true
    }

    fn handle_exception(
        &mut self,
        process_id: u32,
        thread_id: u32,
        info: windows::Win32::System::Diagnostics::Debug::EXCEPTION_DEBUG_INFO,
    ) -> Result<ExceptionOutcome> {
        let record = info.ExceptionRecord;
        let code = record.ExceptionCode;
        let address = record.ExceptionAddress as usize as u64;
        let first_chance = info.dwFirstChance != 0;

        if code == EXCEPTION_BREAKPOINT {
            if self.breakpoints.contains_key(&address) {
                let mut context = self.thread_context(thread_id)?;
                self.restore_breakpoint(address)?;
                context.Rip = address;
                let registers = Registers::from_context(&context);
                context.EFlags |= TRAP_FLAG;
                self.set_thread_context(thread_id, &context)?;
                self.trap_threads.insert(thread_id);
                self.emit(DebuggerEvent::BreakpointHit {
                    thread_id,
                    address,
                    registers,
                });
                return Ok(ExceptionOutcome::Hold(HeldEvent {
                    process_id,
                    thread_id,
                    continue_status: DBG_CONTINUE,
                    kind: HeldKind::Breakpoint { address },
                }));
            }

            if self.initial_breakpoint_pending {
                self.initial_breakpoint_pending = false;
                return Ok(ExceptionOutcome::Continue(DBG_CONTINUE));
            }

            if self.pause_pending {
                self.pause_pending = false;
                self.emit(DebuggerEvent::Exception {
                    thread_id,
                    code: code.0 as u32,
                    address,
                    first_chance,
                });
                return Ok(ExceptionOutcome::Hold(HeldEvent {
                    process_id,
                    thread_id,
                    continue_status: DBG_CONTINUE,
                    kind: HeldKind::Exception,
                }));
            }
        }

        if code == EXCEPTION_SINGLE_STEP {
            if let Some(pending) = self.pending_reinsert.get(&thread_id).copied() {
                self.reinsert_breakpoint(pending.address)?;
                let mut context = self.thread_context(thread_id)?;
                context.EFlags &= !TRAP_FLAG;
                self.set_thread_context(thread_id, &context)?;
                self.pending_reinsert.remove(&thread_id);
                self.trap_threads.remove(&thread_id);

                if pending.stop_after_step {
                    let step_address = context.Rip;
                    let registers = Registers::from_context(&context);
                    self.emit(DebuggerEvent::SingleStep {
                        thread_id,
                        address: step_address,
                        registers,
                    });
                    return Ok(ExceptionOutcome::Hold(HeldEvent {
                        process_id,
                        thread_id,
                        continue_status: DBG_CONTINUE,
                        kind: HeldKind::SingleStep,
                    }));
                }
                return Ok(ExceptionOutcome::Continue(DBG_CONTINUE));
            }

            if self.explicit_steps.contains(&thread_id) {
                let mut context = self.thread_context(thread_id)?;
                context.EFlags &= !TRAP_FLAG;
                self.set_thread_context(thread_id, &context)?;
                self.explicit_steps.remove(&thread_id);
                self.trap_threads.remove(&thread_id);
                let step_address = context.Rip;
                let registers = Registers::from_context(&context);
                self.emit(DebuggerEvent::SingleStep {
                    thread_id,
                    address: step_address,
                    registers,
                });
                return Ok(ExceptionOutcome::Hold(HeldEvent {
                    process_id,
                    thread_id,
                    continue_status: DBG_CONTINUE,
                    kind: HeldKind::SingleStep,
                }));
            }
        }

        self.emit(DebuggerEvent::Exception {
            thread_id,
            code: code.0 as u32,
            address,
            first_chance,
        });
        if first_chance {
            Ok(ExceptionOutcome::Continue(DBG_EXCEPTION_NOT_HANDLED))
        } else {
            Ok(ExceptionOutcome::Hold(HeldEvent {
                process_id,
                thread_id,
                continue_status: DBG_EXCEPTION_NOT_HANDLED,
                kind: HeldKind::Exception,
            }))
        }
    }

    fn continue_held(&mut self, step: bool, requested_thread: Option<u32>) -> Result<()> {
        let Some(held) = self.held else {
            return Ok(());
        };

        if let Some(thread_id) = requested_thread
            && thread_id != held.thread_id {
                bail!(
                    "cannot step thread {thread_id} while debug event for thread {} is held",
                    held.thread_id
                );
            }

        if step && !matches!(held.kind, HeldKind::Breakpoint { .. }) {
            self.set_trap_flag(held.thread_id, true)?;
            self.trap_threads.insert(held.thread_id);
        }

        let status = if step {
            DBG_CONTINUE
        } else {
            held.continue_status
        };
        continue_debug_event(held.process_id, held.thread_id, status)?;
        self.held = None;

        match held.kind {
            HeldKind::Breakpoint { address } => {
                self.pending_reinsert.insert(
                    held.thread_id,
                    PendingReinsert {
                        address,
                        stop_after_step: step,
                    },
                );
            }
            HeldKind::SingleStep | HeldKind::Exception if step => {
                self.explicit_steps.insert(held.thread_id);
            }
            HeldKind::SingleStep | HeldKind::Exception => {}
        }
        Ok(())
    }

    fn add_breakpoint(&mut self, address: u64) -> Result<()> {
        if self.breakpoints.contains_key(&address) {
            return Ok(());
        }

        let original = read_process_memory(self.process.raw(), address, 1)?;
        let Some(&original_byte) = original.first() else {
            bail!("could not read breakpoint byte at {address:#x}");
        };
        if let Err(error) = write_process_byte(self.process.raw(), address, 0xcc) {
            let _ = write_process_byte(self.process.raw(), address, original_byte);
            return Err(error);
        }
        self.breakpoints.insert(
            address,
            SoftwareBreakpoint {
                original_byte,
                inserted: true,
            },
        );
        Ok(())
    }

    fn remove_breakpoint(&mut self, address: u64) -> Result<()> {
        let Some(breakpoint) = self.breakpoints.get(&address).copied() else {
            return Ok(());
        };
        if breakpoint.inserted {
            write_process_byte(self.process.raw(), address, breakpoint.original_byte)?;
        }
        self.breakpoints.remove(&address);
        Ok(())
    }

    fn restore_breakpoint(&mut self, address: u64) -> Result<()> {
        let Some(breakpoint) = self.breakpoints.get(&address).copied() else {
            bail!("breakpoint at {address:#x} disappeared while handling its exception");
        };
        if breakpoint.inserted {
            write_process_byte(self.process.raw(), address, breakpoint.original_byte)?;
            if let Some(entry) = self.breakpoints.get_mut(&address) {
                entry.inserted = false;
            }
        }
        Ok(())
    }

    fn reinsert_breakpoint(&mut self, address: u64) -> Result<()> {
        let Some(breakpoint) = self.breakpoints.get(&address).copied() else {
            return Ok(());
        };
        if !breakpoint.inserted {
            if let Err(error) = write_process_byte(self.process.raw(), address, 0xcc) {
                let _ = write_process_byte(self.process.raw(), address, breakpoint.original_byte);
                return Err(error);
            }
            if let Some(entry) = self.breakpoints.get_mut(&address) {
                entry.inserted = true;
            }
        }
        Ok(())
    }

    fn thread_context(&self, thread_id: u32) -> Result<CONTEXT> {
        let (handle, temporary) = self.thread_handle(thread_id)?;
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_ALL_AMD64,
            ..Default::default()
        };
        // The thread is stopped by the outstanding debug event, and CONTEXT is fully initialized.
        unsafe { GetThreadContext(handle, &mut context) }
            .with_context(|| format!("GetThreadContext({thread_id})"))?;
        drop(temporary);
        Ok(context)
    }

    fn set_thread_context(&self, thread_id: u32, context: &CONTEXT) -> Result<()> {
        let (handle, temporary) = self.thread_handle(thread_id)?;
        // The context belongs to this x86-64 thread and its ContextFlags select valid fields.
        unsafe { SetThreadContext(handle, context) }
            .with_context(|| format!("SetThreadContext({thread_id})"))?;
        drop(temporary);
        Ok(())
    }

    fn set_trap_flag(&self, thread_id: u32, enabled: bool) -> Result<()> {
        let mut context = self.thread_context(thread_id)?;
        if enabled {
            context.EFlags |= TRAP_FLAG;
        } else {
            context.EFlags &= !TRAP_FLAG;
        }
        self.set_thread_context(thread_id, &context)
    }

    fn thread_handle(&self, thread_id: u32) -> Result<(HANDLE, Option<OwnedHandle>)> {
        if let Some(handle) = self.threads.get(&thread_id) {
            return Ok((handle.raw(), None));
        }

        // OpenThread supplies a temporary context handle when an event arrived before tracking it.
        let handle =
            unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, thread_id) }
                .with_context(|| format!("OpenThread({thread_id})"))?;
        let temporary = OwnedHandle::new(handle)?;
        Ok((temporary.raw(), Some(temporary)))
    }

    fn restore_all_breakpoints(&mut self) {
        let addresses: Vec<u64> = self.breakpoints.keys().copied().collect();
        for address in addresses {
            if let Err(error) = self.remove_breakpoint(address) {
                self.emit(DebuggerEvent::Error(format!(
                    "restore breakpoint {address:#x} during detach: {error}"
                )));
            }
        }
    }

    fn clear_owned_trap_flags(&mut self) {
        let thread_ids: Vec<u32> = self.trap_threads.iter().copied().collect();
        for thread_id in thread_ids {
            if let Err(error) = self.set_trap_flag(thread_id, false) {
                self.emit(DebuggerEvent::Error(format!(
                    "clear trap flag on thread {thread_id} during detach: {error}"
                )));
            }
        }
        self.trap_threads.clear();
    }

    fn detach(&mut self) {
        if !self.attached {
            return;
        }

        self.restore_all_breakpoints();
        self.clear_owned_trap_flags();

        if let Some(held) = self.held.take()
            && let Err(error) = continue_debug_event(held.process_id, held.thread_id, DBG_CONTINUE)
            {
                self.emit(DebuggerEvent::Error(error.to_string()));
            }

        // Kill-on-exit is disabled; stopping the debug relationship never terminates CoE5.
        if let Err(error) = unsafe { DebugActiveProcessStop(self.pid) } {
            self.emit(DebuggerEvent::Error(format!(
                "DebugActiveProcessStop({}) failed: {error}",
                self.pid
            )));
        }
        self.attached = false;
        self.pending_reinsert.clear();
        self.explicit_steps.clear();
        self.modules.clear();
        self.threads.clear();
        self.emit(DebuggerEvent::Detached);
    }

    fn emit(&self, event: DebuggerEvent) {
        let _ = self.events.send(event);
    }
}

impl Registers {
    fn from_context(context: &CONTEXT) -> Self {
        Self {
            rip: context.Rip,
            rsp: context.Rsp,
            rbp: context.Rbp,
            rax: context.Rax,
            rbx: context.Rbx,
            rcx: context.Rcx,
            rdx: context.Rdx,
            rsi: context.Rsi,
            rdi: context.Rdi,
            r8: context.R8,
            r9: context.R9,
            r10: context.R10,
            r11: context.R11,
            r12: context.R12,
            r13: context.R13,
            r14: context.R14,
            r15: context.R15,
            eflags: context.EFlags,
        }
    }
}

fn continue_debug_event(process_id: u32, thread_id: u32, status: NTSTATUS) -> Result<()> {
    // The IDs and status come from the one outstanding DEBUG_EVENT being released.
    unsafe { ContinueDebugEvent(process_id, thread_id, status) }
        .with_context(|| format!("ContinueDebugEvent({process_id}, {thread_id})"))
}

fn read_process_memory(handle: HANDLE, address: u64, length: usize) -> Result<Vec<u8>> {
    if length > MAX_MEMORY_READ {
        bail!("memory read length {length} exceeds the 1 MiB limit");
    }
    if length == 0 {
        return Ok(Vec::new());
    }

    let mut bytes = vec![0_u8; length];
    let mut bytes_read = 0_usize;
    // The destination owns `length` initialized bytes, and the remote address is never dereferenced
    // by Rust; ReadProcessMemory validates it in the target process.
    unsafe {
        ReadProcessMemory(
            handle,
            address as usize as *const c_void,
            bytes.as_mut_ptr().cast(),
            length,
            Some(&mut bytes_read),
        )
    }
    .with_context(|| format!("ReadProcessMemory({address:#x}, {length})"))?;
    bytes.truncate(bytes_read.min(length));
    Ok(bytes)
}

fn write_process_byte(handle: HANDLE, address: u64, byte: u8) -> Result<()> {
    let mut bytes_written = 0_usize;
    // The source is one live byte, and Windows validates the remote destination address.
    unsafe {
        WriteProcessMemory(
            handle,
            address as usize as *const c_void,
            (&byte as *const u8).cast(),
            1,
            Some(&mut bytes_written),
        )
    }
    .with_context(|| format!("WriteProcessMemory({address:#x})"))?;
    if bytes_written != 1 {
        bail!("WriteProcessMemory({address:#x}) wrote {bytes_written} bytes instead of 1");
    }

    // The modified byte is executable code, so discard stale instructions before resuming it.
    unsafe { FlushInstructionCache(handle, Some(address as usize as *const c_void), 1) }
        .with_context(|| format!("FlushInstructionCache({address:#x})"))
}

fn module_path(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0_u16; 32_768];
    // `buffer` is writable UTF-16 storage and the event file handle remains live for this call.
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }

    let path = String::from_utf16_lossy(&buffer[..length]);
    let path = match path.strip_prefix(r"\\?\") {
        Some(stripped) => stripped,
        None => &path,
    };
    Some(path.to_owned())
}
