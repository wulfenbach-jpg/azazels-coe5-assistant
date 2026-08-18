mod hooks;
mod state;

use std::{
    ffi::c_void,
    io,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{
    CapabilityReport, DiagnosticEntry, DiagnosticLevel, Diagnostics, Envelope, FrameCodec, Hello,
    Message, ProcessRole, RemoteError, RestartMode, RestartResult, RestartState,
    pipe::{OverlappedPipe, PipeReader, PipeWriter},
};
use crossbeam_channel::{Receiver, Sender, bounded};
use hooks::HookManager;
use state::RuntimeState;
use windows::{
    Win32::{
        Foundation::{HINSTANCE, HMODULE},
        System::{LibraryLoader::DisableThreadLibraryCalls, SystemServices::DLL_PROCESS_ATTACH},
    },
    core::PCWSTR,
};

const OUTBOUND_CAPACITY: usize = 1024;
static INITIALIZATION_STATE: AtomicU8 = AtomicU8::new(0);

/// Windows loader entry point. Must only be invoked by the loader itself.
///
/// # Safety
///
/// `instance` must be the module handle assigned by the loader during
/// `DLL_PROCESS_ATTACH`; the function must not be called from arbitrary
/// application code.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    instance: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            let _ = DisableThreadLibraryCalls(HMODULE(instance.0));
        }
    }
    1
}

/// Exported initializer invoked by the assistant after the DLL is loaded into
/// the host process. Runs the injected runtime on the calling thread.
///
/// # Safety
///
/// Caller must have loaded this module into the CoE5 process matching the
/// embedded manifest and must pass a null `_parameter`. The function blocks
/// until the named-pipe session ends.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AzazelInitialize(_parameter: *mut c_void) -> u32 {
    if INITIALIZATION_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return 2;
    }
    let result = run();
    INITIALIZATION_STATE.store(2, Ordering::Release);
    if let Err(error) = result {
        debug_message(&format!(
            "Azazel CoE5 injected initialization failed: {error:#}"
        ));
        return 1;
    }
    0
}

fn run() -> Result<()> {
    let state = Arc::new(RuntimeState::initialize()?);
    let pipe = connect_pipe(std::process::id())?;

    // Write the Hello synchronously BEFORE entering the read loop so the
    // assistant always reads it as the first frame. The pipe itself uses
    // overlapped I/O so the reader loop and the writer thread may operate
    // concurrently (blocking I/O on this Windows build serializes reads and
    // writes on a connection and deadlocks under concurrent load).
    let hello = Envelope::event(Message::Hello(Hello {
        role: ProcessRole::Injected,
        pid: std::process::id(),
        fingerprint: state.manifest().target.clone(),
        capabilities: state.capability_report(|_| false),
    }));
    let mut hello_writer = PipeWriter::new(Arc::clone(&pipe));
    FrameCodec::write(&mut hello_writer, &hello).context("write hello frame")?;
    drop(hello_writer);

    let (outbound_tx, outbound_rx) = bounded::<Envelope>(OUTBOUND_CAPACITY);
    HookManager::set_event_sender(outbound_tx.clone())?;

    let writer_pipe = Arc::clone(&pipe);
    let writer = thread::Builder::new()
        .name("azazel-coe5-pipe-writer".into())
        .spawn(move || writer_loop(writer_pipe, outbound_rx))
        .context("spawn pipe writer")?;

    let mut hooks = HookManager::default();
    let mut reader = PipeReader::new(pipe);
    let mut accepted = false;
    loop {
        let request = FrameCodec::read(&mut reader).context("read named-pipe frame")?;
        match &request.body {
            Message::HelloAck(ack) => {
                if !ack.accepted {
                    bail!(
                        "Assistant rejected injected handshake: {}",
                        ack.reason.as_deref().unwrap_or("no reason")
                    );
                }
                accepted = true;
            }
            Message::Shutdown if accepted => break,
            Message::Ping { nonce } if accepted => {
                send_response(&outbound_tx, &request, Message::Pong { nonce: *nonce })?;
            }
            Message::SnapshotRequest if accepted => match state.snapshot() {
                Ok(snapshot) => send_response(&outbound_tx, &request, Message::Snapshot(snapshot))?,
                Err(error) => send_remote_error(&outbound_tx, &request, "snapshot_failed", error)?,
            },
            Message::ReadMemory(memory) if accepted => {
                match state.read_bytes(memory.rva, memory.length as usize) {
                    Ok(bytes) => send_response(
                        &outbound_tx,
                        &request,
                        Message::Memory(azazel_coe5_protocol::MemoryResponse {
                            rva: memory.rva,
                            bytes,
                        }),
                    )?,
                    Err(error) => {
                        send_remote_error(&outbound_tx, &request, "memory_read_failed", error)?
                    }
                }
            }
            Message::SetHook(control) if accepted => {
                match hooks.set_enabled(&state, &control.symbol, control.enabled) {
                    Ok(()) => send_response(
                        &outbound_tx,
                        &request,
                        Message::CapabilityReport(state.capability_report(|id| {
                            hooks.is_installed(id)
                        })),
                    )?,
                    Err(error) => {
                        send_remote_error(&outbound_tx, &request, "hook_transition_failed", error)?
                    }
                }
            }
            Message::Restart(_) if accepted => {
                let reason = state
                    .manifest()
                    .capability_disabled_reason("internal.restart")
                    .unwrap_or("internal restart is unavailable")
                    .to_owned();
                send_response(
                    &outbound_tx,
                    &request,
                    Message::RestartResult(RestartResult {
                        mode: RestartMode::Internal,
                        state: RestartState::Rejected,
                        reason: Some(reason),
                    }),
                )?;
            }
            _ if !accepted => {
                send_remote_error(
                    &outbound_tx,
                    &request,
                    "handshake_required",
                    anyhow::anyhow!("HelloAck must be accepted before requests"),
                )?;
            }
            other => {
                send_remote_error(
                    &outbound_tx,
                    &request,
                    "unsupported_message",
                    anyhow::anyhow!("unsupported injected message: {other:?}"),
                )?;
            }
        }
    }

    hooks.disable_all();
    drop(outbound_tx);
    let _ = writer.join();
    Ok(())
}

fn connect_pipe(pid: u32) -> Result<Arc<OverlappedPipe>> {
    let path = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut last_error = None;
    while std::time::Instant::now() < deadline {
        match OverlappedPipe::open_client(&path) {
            Ok(pipe) => return Ok(Arc::new(pipe)),
            Err(error) if is_pipe_not_ready(&error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error).with_context(|| format!("open named pipe {path}")),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "pipe timeout")))
        .with_context(|| format!("connect named pipe {path}"))
}

fn is_pipe_not_ready(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(2 | 231))
}

fn writer_loop(pipe: Arc<OverlappedPipe>, outbound: Receiver<Envelope>) {
    let mut writer = PipeWriter::new(pipe);
    while let Ok(envelope) = outbound.recv() {
        if FrameCodec::write(&mut writer, &envelope).is_err() {
            break;
        }
    }
}

fn send_response(sender: &Sender<Envelope>, request: &Envelope, body: Message) -> Result<()> {
    sender
        .send(Envelope::response(request, body))
        .context("queue response")
}

fn send_remote_error(
    sender: &Sender<Envelope>,
    request: &Envelope,
    code: &str,
    error: impl std::fmt::Display,
) -> Result<()> {
    send_response(
        sender,
        request,
        Message::Error(RemoteError {
            code: code.into(),
            message: error.to_string(),
        }),
    )
}

fn debug_message(message: &str) {
    use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
    let wide = message.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    unsafe { OutputDebugStringW(PCWSTR(wide.as_ptr())) };
}

pub fn unavailable_capabilities() -> CapabilityReport {
    CapabilityReport {
        entries: vec![azazel_coe5_protocol::CapabilityStatus {
            id: "injection".into(),
            state: azazel_coe5_protocol::CapabilityState::Failed,
            reason: Some("injected runtime did not initialize".into()),
        }],
    }
}

pub fn initialization_diagnostic(error: impl std::fmt::Display) -> Diagnostics {
    Diagnostics {
        entries: vec![DiagnosticEntry {
            level: DiagnosticLevel::Error,
            component: "injected".into(),
            message: error.to_string(),
        }],
    }
}
