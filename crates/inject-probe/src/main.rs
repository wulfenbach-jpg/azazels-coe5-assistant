//! Headless verification probe for the CoE5 injected runtime.
//!
//! Drives the same path the Assistant uses: discovers CoE5, verifies the
//! executable fingerprint, creates the versioned named pipe, injects the
//! cdylib, completes the handshake, and exercises snapshot, hook, and ping
//! round trips. Prints `EVIDENCE` lines for machine-readable verification.
//!
//! Modes:
//! * default  — full accept path (handshake, snapshot, hook, ping, shutdown)
//! * `--reject` — send `HelloAck { accepted: false }` and confirm the injected
//!   client tears the session down cleanly (fallback behavior)

use std::{
    ffi::c_void,
    fs::File,
    io::{BufReader, Read},
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    os::windows::io::FromRawHandle,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{
    CapabilityState, Envelope, FrameCodec, HelloAck, HookControl, Message, ProcessRole,
};
use sha2::{Digest, Sha256};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        },
        Storage::FileSystem::PIPE_ACCESS_DUPLEX,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPMODULE,
                TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{
                CreateRemoteThread, GetExitCodeThread, OpenProcess, PROCESS_CREATE_THREAD,
                PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION,
                PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
            },
        },
    },
    core::{HRESULT, PCSTR, PCWSTR, w},
};

const SUPPORTED_SHA256: &str = "0b422183ca978551f104db865d1869eddfd4301ab160cd28c18a6783ec4ddf03";
const INJECTION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct Args {
    pid: Option<u32>,
    dll: PathBuf,
    reject: bool,
    server: bool,
    client: bool,
    direct_client: bool,
    raw_client: bool,
    diag_window_seconds: u64,
}

fn main() -> Result<()> {
    let args = parse_args()?;
    if args.server {
        return run_server(args.pid.context("--server requires --pid")?);
    }
    if args.client {
        return run_client(args.pid.context("--client requires --pid")?);
    }
    if args.direct_client {
        return run_direct_client(args.pid.context("--direct-client requires --pid")?);
    }
    if args.raw_client {
        return run_raw_client(args.pid.context("--raw-client requires --pid")?);
    }
    match run(&args) {
        Ok(()) => {
            println!("EVIDENCE RESULT PASS");
            Ok(())
        }
        Err(error) => {
            println!("EVIDENCE RESULT FAIL {error:#}");
            Err(error)
        }
    }
}

/// Server-only mode: create the pipe for `pid` and read one frame, then reply.
fn run_server(pid: u32) -> Result<()> {
    let pipe = create_pipe(pid)?;
    println!(r"EVIDENCE server pipe=\\.\pipe\azazel-coe5-assistant-{pid} created");
    let result = unsafe { ConnectNamedPipe(pipe, None) };
    if let Err(error) = result
        && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
    {
        unsafe {
            let _ = CloseHandle(pipe);
        }
        return Err(error).context("ConnectNamedPipe");
    }
    println!("EVIDENCE server connected");
    let mut stream = unsafe { File::from_raw_handle(pipe.0 as _) };
    let envelope = FrameCodec::read(&mut stream).context("server read frame")?;
    println!("EVIDENCE server read {:?}", envelope.body);
    FrameCodec::write(
        &mut stream,
        &Envelope::response(
            &envelope,
            Message::HelloAck(HelloAck {
                accepted: true,
                peer_pid: std::process::id(),
                reason: None,
            }),
        ),
    )?;
    println!("EVIDENCE server acked");
    Ok(())
}

/// Client-only mode: connect to the pipe for `pid` and write one Hello frame
/// through a cloned writer handle, exactly like the injected runtime.
fn run_client(pid: u32) -> Result<()> {
    let start = std::time::Instant::now();
    let _stamp = |message: &str| println!("[{:>8.3}] {message}", start.elapsed().as_secs_f64());
    let path = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("client open {path}"))?;
    println!("EVIDENCE client connected");
    let writer_pipe = pipe.try_clone().context("client clone")?;
    let writer = std::thread::spawn(move || {
        let envelope = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
            role: ProcessRole::Injected,
            pid,
            fingerprint: azazel_coe5_symbols::BuildFingerprint {
                product: "probe".into(),
                version: "0".into(),
                architecture: "x86_64".into(),
                sha256: "deadbeef".into(),
                image_base: azazel_coe5_symbols::Rva(0x140000000),
                file_size: 0,
                size_of_image: 0,
            },
            capabilities: azazel_coe5_protocol::CapabilityReport::default(),
        }));
        let mut pipe = writer_pipe;
        println!("EVIDENCE client writing hello");
        FrameCodec::write(&mut pipe, &envelope).expect("client write hello");
        println!("EVIDENCE client wrote hello");
        pipe
    });
    let mut reader = pipe;
    let ack = FrameCodec::read(&mut reader).context("client read ack")?;
    println!("EVIDENCE client read {:?}", ack.body);
    let _ = writer.join();
    Ok(())
}

/// Direct client: OpenOptions + FrameCodec on one handle, one thread.
fn run_direct_client(pid: u32) -> Result<()> {
    let path = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
    let mut client = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("client open {path}"))?;
    println!("EVIDENCE direct client connected");
    let envelope = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
        role: ProcessRole::Injected,
        pid,
        fingerprint: azazel_coe5_symbols::BuildFingerprint {
            product: "probe".into(),
            version: "0".into(),
            architecture: "x86_64".into(),
            sha256: "deadbeef".into(),
            image_base: azazel_coe5_symbols::Rva(0x140000000),
            file_size: 0,
            size_of_image: 0,
        },
        capabilities: azazel_coe5_protocol::CapabilityReport::default(),
    }));
    println!("EVIDENCE direct client writing hello");
    FrameCodec::write(&mut client, &envelope)?;
    println!("EVIDENCE direct client wrote hello");
    let ack = FrameCodec::read(&mut client).context("direct client read ack")?;
    println!("EVIDENCE direct client read {:?}", ack.body);
    Ok(())
}

/// Raw client diagnostic: step-by-step Win32 pipe operations with errors.
fn run_raw_client(pid: u32) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WriteFile,
    };
    use windows::Win32::System::Pipes::PeekNamedPipe;
    let path = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
    let wide = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let access = windows::Win32::Foundation::GENERIC_READ
        .0
        | windows::Win32::Foundation::GENERIC_WRITE.0;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    };
    if handle.is_err() {
        let error = unsafe { windows::Win32::Foundation::GetLastError() };
        bail!("CreateFileW failed: {error:?} (0x{:08x})", error.0);
    }
    let handle = handle?;
    println!("EVIDENCE raw client handle={handle:?}");
    let envelope = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
        role: ProcessRole::Injected,
        pid,
        fingerprint: azazel_coe5_symbols::BuildFingerprint {
            product: "probe".into(),
            version: "0".into(),
            architecture: "x86_64".into(),
            sha256: "deadbeef".into(),
            image_base: azazel_coe5_symbols::Rva(0x140000000),
            file_size: 0,
            size_of_image: 0,
        },
        capabilities: azazel_coe5_protocol::CapabilityReport::default(),
    }));
    let mut bytes = Vec::new();
    FrameCodec::write(&mut bytes, &envelope)?;
    println!("EVIDENCE raw client payload {} bytes", bytes.len());
    let mut written = 0u32;
    let write_result = unsafe {
        WriteFile(
            handle,
            Some(&bytes),
            Some(&mut written),
            None,
        )
    };
    match write_result {
        Ok(()) => println!("EVIDENCE raw client WriteFile ok written={written}"),
        Err(error) => println!(
            "EVIDENCE raw client WriteFile failed: {error:?} (0x{:08x})",
            error.code().0
        ),
    }
    let mut available = 0u32;
    let mut remaining = 0u32;
    let message_bytes = 0u32;
    unsafe {
        PeekNamedPipe(
            handle,
            None,
            0,
            None,
            Some(&mut available),
            Some(&mut remaining),
        )
    }?;
    let _ = message_bytes;
    println!(
        "EVIDENCE raw client peek available={available} remaining={remaining} message_bytes={message_bytes}"
    );
    unsafe { CloseHandle(handle) }?;
    println!("EVIDENCE raw client closed");
    Ok(())
}

fn run(args: &Args) -> Result<()> {
    let (pid, executable, module_base, module_size) = match args.pid {
        Some(pid) => {
            let (_, executable, base, size) =
                find_main_module(pid)?.context("target process has no main module")?;
            (pid, executable, base, size)
        }
        None => find_coe5()?.context("CoE5.exe is not running")?,
    };
    let sha256 = sha256_file(&executable)?;
    println!(
        "EVIDENCE target pid={pid} exe={} base=0x{module_base:x} size={module_size} sha256={sha256}",
        executable.display()
    );

    let dll = args.dll.canonicalize().with_context(|| {
        format!(
            "canonicalize injected DLL {} (build the workspace first)",
            args.dll.display()
        )
    })?;
    if !dll.is_file() {
        bail!("injected DLL does not exist at {}", dll.display());
    }
    let initializer_rva = pe_export_rva(&dll, b"AzazelInitialize")?;
    println!(
        "EVIDENCE dll={} initializer_rva=0x{initializer_rva:x}",
        dll.display()
    );

    // Mirror the Assistant's safety gate: only inject into the known build.
    if !sha256.eq_ignore_ascii_case(SUPPORTED_SHA256) {
        bail!("unsupported CoE5 hash {sha256}; refusing to inject");
    }

    let pipe_name = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
    let server_pipe = Arc::new(
        azazel_coe5_protocol::pipe::OverlappedPipe::create_server(&pipe_name)
            .with_context(|| format!("create server pipe {pipe_name}"))?,
    );
    println!("EVIDENCE pipe={pipe_name} created");

    inject(pid, &dll, initializer_rva)?;
    let remote_module = wait_for_module(pid, "azazel_coe5_injected.dll", INJECTION_TIMEOUT)?;
    println!(
        "EVIDENCE injected module={} base=0x{:x} size={}",
        remote_module.name, remote_module.module_base, remote_module.module_size
    );

    server_pipe.connect().context("ConnectNamedPipe")?;
    println!("EVIDENCE pipe connected by injected client");

    let mut reader = azazel_coe5_protocol::pipe::PipeReader::new(Arc::clone(&server_pipe));
    let hello_envelope = FrameCodec::read(&mut reader).context("read injected Hello")?;
    hello_envelope
        .validate_version()
        .context("injected Hello protocol version")?;
    let Message::Hello(hello) = &hello_envelope.body else {
        bail!("first injected frame was not Hello");
    };
    println!(
        "EVIDENCE hello role={:?} pid={} fingerprint_sha={}",
        hello.role, hello.pid, hello.fingerprint.sha256
    );
    if hello.role != ProcessRole::Injected || hello.pid != pid {
        bail!(
            "Hello identity mismatch: role={:?} pid={} expected pid={pid}",
            hello.role,
            hello.pid
        );
    }
    if !hello
        .fingerprint
        .sha256
        .eq_ignore_ascii_case(&sha256)
    {
        bail!(
            "Hello fingerprint {} does not match executable {}",
            hello.fingerprint.sha256,
            sha256
        );
    }

    let accepted = !args.reject;
    let mut writer = azazel_coe5_protocol::pipe::PipeWriter::new(Arc::clone(&server_pipe));
    FrameCodec::write(
        &mut writer,
        &Envelope::response(
            &hello_envelope,
            Message::HelloAck(HelloAck {
                accepted,
                peer_pid: std::process::id(),
                reason: (!accepted).then(|| "probe rejection test".into()),
            }),
        ),
    )?;

    if args.reject {
        // The injected client must observe the rejection and close the pipe.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match FrameCodec::read(&mut reader) {
                Ok(_) => {}
                Err(_) => {
                    println!(
                        "EVIDENCE rejection acknowledged: injected client closed session in {:?}",
                        deadline.elapsed()
                    );
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                bail!("injected client did not close the session after rejection");
            }
        }
    }

    print_capabilities(&hello.capabilities);
    verify_capability(&hello.capabilities, "memory.read", CapabilityState::Available)?;

    let snapshot = round_trip(&server_pipe, Message::SnapshotRequest)?;
    match snapshot {
        Message::Snapshot(snapshot) => {
            let active = snapshot
                .participants
                .iter()
                .filter(|participant| participant.active)
                .count();
            let human = snapshot
                .participants
                .iter()
                .find(|participant| participant.controller == 0);
            println!(
                "EVIDENCE snapshot turn={} plane={} map={}x{} real_width={} active={} human_class={:?}",
                snapshot.lifecycle.turn,
                snapshot.lifecycle.plane,
                snapshot.map.width,
                snapshot.map.height,
                snapshot.map.real_width,
                active,
                human.map(|participant| participant.class_id),
            );
            let world_state = snapshot.lifecycle.world_state_unknown_abc;
            println!("EVIDENCE snapshot world_state={world_state} society={} north={} south={}",
                snapshot.options.society,
                snapshot.options.north_percent_ui,
                snapshot.options.south_percent_ui);
        }
        other => bail!("expected Snapshot response, received {other:?}"),
    }

    let report = round_trip(
        &server_pipe,
        Message::SetHook(HookControl {
            symbol: "world_reset_static_state".into(),
            enabled: true,
        }),
    )?;
    match report {
        Message::CapabilityReport(report) => {
            let hook = report
                .status("hook.world_reset")
                .context("hook.world_reset capability missing from report")?;
            println!(
                "EVIDENCE hook world_reset_static_state state={:?} reason={:?}",
                hook.state, hook.reason
            );
            if hook.state == CapabilityState::Failed {
                // Dump the bytes the injected process sees at the target RVA.
                let memory = round_trip(
                    &server_pipe,
                    Message::ReadMemory(azazel_coe5_protocol::ReadMemoryRequest {
                        rva: azazel_coe5_symbols::Rva(0x1c6d10),
                        length: 32,
                    }),
                )?;
                if let Message::Memory(memory) = memory {
                    let hex = memory
                        .bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    println!("EVIDENCE live bytes at 0x1c6d10: {hex}");
                }
            }
            if hook.state != CapabilityState::Available {
                bail!("hook did not reach Available: {hook:?}");
            }
        }
        other => bail!("expected CapabilityReport response, received {other:?}"),
    }

    // Diagnostic window: keep the session open so the operator can click the
    // game while the UI dispatcher's return values are logged.
    if args.diag_window_seconds > 0 {
        eprintln!(
            "DIAG: holding session for {}s; click the game window now",
            args.diag_window_seconds
        );
        std::thread::sleep(std::time::Duration::from_secs(args.diag_window_seconds));
    }

    let pong = round_trip(&server_pipe, Message::Ping { nonce: 0x51E5 })?;
    match pong {
        Message::Pong { nonce } if nonce == 0x51E5 => {
            println!("EVIDENCE ping pong nonce={nonce}");
        }
        other => bail!("expected Pong, received {other:?}"),
    }

    let mut shutdown_writer =
        azazel_coe5_protocol::pipe::PipeWriter::new(Arc::clone(&server_pipe));
    FrameCodec::write(&mut shutdown_writer, &Envelope::event(Message::Shutdown))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match FrameCodec::read(&mut reader) {
            Ok(_) => {}
            Err(_) => {
                println!(
                    "EVIDENCE shutdown clean: injected client closed session in {:?}",
                    deadline.elapsed()
                );
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!("injected client did not close after Shutdown");
        }
    }
}

fn round_trip(
    pipe: &Arc<azazel_coe5_protocol::pipe::OverlappedPipe>,
    message: Message,
) -> Result<Message> {
    let mut writer = azazel_coe5_protocol::pipe::PipeWriter::new(Arc::clone(pipe));
    FrameCodec::write(&mut writer, &Envelope::request(message))?;
    let mut reader = azazel_coe5_protocol::pipe::PipeReader::new(Arc::clone(pipe));
    let envelope = FrameCodec::read(&mut reader).context("read response frame")?;
    envelope.validate_version()?;
    match envelope.body {
        Message::Error(error) => bail!("remote error {}: {}", error.code, error.message),
        body => Ok(body),
    }
}

fn print_capabilities(report: &azazel_coe5_protocol::CapabilityReport) {
    println!("EVIDENCE capabilities count={}", report.entries.len());
    for entry in &report.entries {
        println!(
            "EVIDENCE capability id={} state={:?} reason={:?}",
            entry.id, entry.state, entry.reason
        );
    }
}

fn verify_capability(
    report: &azazel_coe5_protocol::CapabilityReport,
    id: &str,
    expected: CapabilityState,
) -> Result<()> {
    let status = report.status(id).context("capability missing")?;
    if status.state != expected {
        bail!("capability {id} is {:?}, expected {expected:?}", status.state);
    }
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut pid = None;
    let mut reject = false;
    let mut server = false;
    let mut client = false;
    let mut direct_client = false;
    let mut raw_client = false;
    let mut diag_window_seconds = 0u64;
    let mut dll = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/azazel_coe5_injected.dll");
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--pid" => {
                let value = arguments.next().context("--pid requires a value")?;
                pid = Some(value.parse().context("--pid must be numeric")?);
            }
            "--dll" => {
                dll = PathBuf::from(arguments.next().context("--dll requires a value")?);
            }
            "--reject" => reject = true,
            "--server" => server = true,
            "--client" => client = true,
            "--direct-client" => direct_client = true,
            "--raw-client" => raw_client = true,
            "--diag-seconds" => {
                diag_window_seconds = arguments
                    .next()
                    .context("--diag-seconds requires a value")?
                    .parse()
                    .context("--diag-seconds must be numeric")?;
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(Args {
        pid,
        dll,
        reject,
        server,
        client,
        direct_client,
        raw_client,
        diag_window_seconds,
    })
}

// --- process discovery (mirrors the Assistant's process module) ---

fn find_coe5() -> Result<Option<(u32, PathBuf, usize, u32)>> {
    let snapshot = OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) }.is_err() {
        return Ok(None);
    }
    loop {
        if utf16_z(&entry.szExeFile).eq_ignore_ascii_case("CoE5.exe") {
            let module = find_main_module(entry.th32ProcessID)?;
            return Ok(module);
        }
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) }.is_err() {
            return Ok(None);
        }
    }
}

fn find_main_module(pid: u32) -> Result<Option<(u32, PathBuf, usize, u32)>> {
    let Some(module) = modules(pid)?.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some((pid, module.executable, module.module_base, module.module_size)))
}

fn wait_for_module(pid: u32, name: &str, timeout: Duration) -> Result<ModuleInfo> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(module) = modules(pid)?
            .into_iter()
            .find(|module| module.name.eq_ignore_ascii_case(name))
        {
            return Ok(module);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    bail!("timed out waiting for remote module {name}")
}

#[derive(Debug)]
struct ModuleInfo {
    name: String,
    executable: PathBuf,
    module_base: usize,
    module_size: u32,
}

fn modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    let snapshot = OwnedHandle(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    }?);
    let mut entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Module32FirstW(snapshot.raw(), &mut entry) }.is_err() {
        return Ok(Vec::new());
    }
    let mut modules = Vec::new();
    loop {
        modules.push(ModuleInfo {
            name: utf16_z(&entry.szModule),
            executable: PathBuf::from(utf16_z(&entry.szExePath)),
            module_base: entry.modBaseAddr as usize,
            module_size: entry.modBaseSize,
        });
        if unsafe { Module32NextW(snapshot.raw(), &mut entry) }.is_err() {
            break;
        }
    }
    Ok(modules)
}

// --- injection (mirrors the Assistant's process::inject) ---

fn inject(pid: u32, dll: &Path, initializer_rva: u32) -> Result<()> {
    let process_handle = OwnedHandle(unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }?);

    let wide_path = dll
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let allocation_size = wide_path.len() * size_of::<u16>();
    let remote_path = unsafe {
        VirtualAllocEx(
            process_handle.raw(),
            None,
            allocation_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_path.is_null() {
        bail!("VirtualAllocEx for DLL path failed");
    }
    let remote_path_guard = RemoteAllocation {
        process: process_handle.raw(),
        address: remote_path,
    };
    let mut bytes_written = 0usize;
    unsafe {
        windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
            process_handle.raw(),
            remote_path,
            wide_path.as_ptr().cast(),
            allocation_size,
            Some(&mut bytes_written),
        )
    }?;
    if bytes_written != allocation_size {
        bail!("short DLL path write: expected {allocation_size}, wrote {bytes_written}");
    }

    let kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }?;
    let load_library = unsafe { GetProcAddress(kernel32, PCSTR(c"LoadLibraryW".as_ptr().cast())) }
        .context("GetProcAddress(LoadLibraryW)")?;
    let load_library_thread = unsafe {
        std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut c_void) -> u32,
        >(load_library)
    };
    let load_thread = OwnedHandle(unsafe {
        CreateRemoteThread(
            process_handle.raw(),
            None,
            0,
            Some(load_library_thread),
            Some(remote_path),
            0,
            None,
        )
    }?);
    let wait = unsafe { WaitForSingleObject(load_thread.raw(), INJECTION_TIMEOUT.as_millis() as u32) };
    if wait != WAIT_OBJECT_0 {
        bail!("remote LoadLibraryW timed out");
    }
    let mut load_result = 0u32;
    unsafe { GetExitCodeThread(load_thread.raw(), &mut load_result) }?;
    if load_result == 0 {
        bail!("remote LoadLibraryW returned null");
    }
    drop(remote_path_guard);

    let initializer_address = wait_for_module(pid, "azazel_coe5_injected.dll", INJECTION_TIMEOUT)?
        .module_base
        .checked_add(initializer_rva as usize)
        .context("remote initializer address overflow")?;
    let initializer: unsafe extern "system" fn(*mut c_void) -> u32 =
        unsafe { std::mem::transmute(initializer_address) };
    let initializer_thread = OwnedHandle(unsafe {
        CreateRemoteThread(
            process_handle.raw(),
            None,
            0,
            Some(initializer),
            None,
            0,
            None,
        )
    }?);
    let _ = initializer_thread;
    Ok(())
}

// --- named pipe (mirrors the Assistant's IpcServer) ---

fn create_pipe(pid: u32) -> Result<HANDLE> {
    let path = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
    let wide = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            64 * 1024,
            64 * 1024,
            0,
            None,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("CreateNamedPipeW failed for {path}");
    }
    Ok(handle)
}

// --- PE export lookup (mirrors the Assistant's process module) ---

fn pe_export_rva(path: &Path, export: &[u8]) -> Result<u32> {
    let blob = std::fs::read(path)?;
    let pe = read_u32(&blob, 0x3c)? as usize;
    if blob.get(pe..pe + 4) != Some(b"PE\0\0") {
        bail!("{} is not a PE image", path.display());
    }
    let section_count = read_u16(&blob, pe + 6)? as usize;
    let optional_size = read_u16(&blob, pe + 20)? as usize;
    let optional = pe + 24;
    if read_u16(&blob, optional)? != 0x20b {
        bail!("{} is not PE32+", path.display());
    }
    let export_rva = read_u32(&blob, optional + 112)?;
    let section_table = optional + optional_size;
    let sections = (0..section_count)
        .map(|index| {
            let offset = section_table + index * 40;
            Ok(PeSection {
                virtual_size: read_u32(&blob, offset + 8)?,
                rva: read_u32(&blob, offset + 12)?,
                raw_size: read_u32(&blob, offset + 16)?,
                raw_offset: read_u32(&blob, offset + 20)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let export_offset = rva_to_offset(export_rva, &sections)? as usize;
    let function_count = read_u32(&blob, export_offset + 20)?;
    let name_count = read_u32(&blob, export_offset + 24)?;
    let functions_rva = read_u32(&blob, export_offset + 28)?;
    let names_rva = read_u32(&blob, export_offset + 32)?;
    let ordinals_rva = read_u32(&blob, export_offset + 36)?;
    let functions_offset = rva_to_offset(functions_rva, &sections)? as usize;
    let names_offset = rva_to_offset(names_rva, &sections)? as usize;
    let ordinals_offset = rva_to_offset(ordinals_rva, &sections)? as usize;

    for index in 0..name_count as usize {
        let name_rva = read_u32(&blob, names_offset + index * 4)?;
        let name_offset = rva_to_offset(name_rva, &sections)? as usize;
        if read_c_string(&blob, name_offset)? != export {
            continue;
        }
        let ordinal = read_u16(&blob, ordinals_offset + index * 2)? as u32;
        if ordinal >= function_count {
            bail!("export ordinal {ordinal} exceeds function table");
        }
        return read_u32(&blob, functions_offset + ordinal as usize * 4);
    }
    bail!(
        "export '{}' not found in {}",
        String::from_utf8_lossy(export),
        path.display()
    )
}

#[derive(Debug, Clone, Copy)]
struct PeSection {
    virtual_size: u32,
    rva: u32,
    raw_size: u32,
    raw_offset: u32,
}

fn rva_to_offset(rva: u32, sections: &[PeSection]) -> Result<u32> {
    for section in sections {
        let extent = section.virtual_size.max(section.raw_size);
        if section.rva <= rva && rva < section.rva.saturating_add(extent) {
            return Ok(section.raw_offset + rva - section.rva);
        }
    }
    bail!("RVA 0x{rva:x} is outside every section")
}

fn read_u16(blob: &[u8], offset: usize) -> Result<u16> {
    let bytes = blob
        .get(offset..offset + 2)
        .context("truncated PE u16")?
        .try_into()
        .expect("slice length checked");
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(blob: &[u8], offset: usize) -> Result<u32> {
    let bytes = blob
        .get(offset..offset + 4)
        .context("truncated PE u32")?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(bytes))
}

fn read_c_string(blob: &[u8], offset: usize) -> Result<&[u8]> {
    let tail = blob.get(offset..).context("truncated PE string")?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated PE string")?;
    Ok(&tail[..length])
}

fn utf16_z(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    std::ffi::OsString::from_wide(&value[..length])
        .to_string_lossy()
        .into_owned()
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct RemoteAllocation {
    process: HANDLE,
    address: *mut c_void,
}

impl Drop for RemoteAllocation {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFreeEx(self.process, self.address, 0, MEM_RELEASE);
        }
    }
}

trait UnwrapHello {
    #[allow(dead_code)]
    fn unwrap_hello(self) -> azazel_coe5_protocol::Hello;
}

impl UnwrapHello for Message {
    #[allow(dead_code)]
    fn unwrap_hello(self) -> azazel_coe5_protocol::Hello {
        match self {
            Message::Hello(hello) => hello,
            other => panic!("expected Hello, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azazel_coe5_protocol::{CapabilityReport, Hello};


    #[test]
    fn pipe_clone_no_thread_round_trip() {
        // Open, clone, write via the CLONE on the main thread, read via the original.
        let pipe = create_pipe(57082).expect("create pipe");
        let client = std::thread::spawn(move || {
            let client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57082")
                .expect("client open");
            let mut writer_pipe = client.try_clone().expect("client clone");
            let hello = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
                role: ProcessRole::Injected,
                pid: 57082,
                fingerprint: azazel_coe5_symbols::BuildFingerprint {
                    product: "probe".into(),
                    version: "0".into(),
                    architecture: "x86_64".into(),
                    sha256: "deadbeef".into(),
                    image_base: azazel_coe5_symbols::Rva(0x140000000),
                    file_size: 0,
                    size_of_image: 0,
                },
                capabilities: azazel_coe5_protocol::CapabilityReport::default(),
            }));
            FrameCodec::write(&mut writer_pipe, &hello).expect("clone write hello");
            drop(writer_pipe);
            let mut reader = client;
            
            FrameCodec::read(&mut reader).expect("reader read ack")
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        let received = FrameCodec::read(&mut server).expect("server read hello");
        FrameCodec::write(
            &mut server,
            &Envelope::response(
                &received,
                Message::HelloAck(HelloAck {
                    accepted: true,
                    peer_pid: 1,
                    reason: None,
                }),
            ),
        )
        .expect("server write ack");
        let ack = client.join().expect("client thread");
        match ack.body {
            Message::HelloAck(ack) => assert!(ack.accepted),
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    #[test]
    fn pipe_writer_thread_no_clone_round_trip() {
        // Open, move the SINGLE handle into a writer thread, write there,
        // move it back, then read on the main thread. No clone.
        let pipe = create_pipe(57083).expect("create pipe");
        let client = std::thread::spawn(move || {
            let mut client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57083")
                .expect("client open");
            let hello = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
                role: ProcessRole::Injected,
                pid: 57083,
                fingerprint: azazel_coe5_symbols::BuildFingerprint {
                    product: "probe".into(),
                    version: "0".into(),
                    architecture: "x86_64".into(),
                    sha256: "deadbeef".into(),
                    image_base: azazel_coe5_symbols::Rva(0x140000000),
                    file_size: 0,
                    size_of_image: 0,
                },
                capabilities: azazel_coe5_protocol::CapabilityReport::default(),
            }));
            let writer = std::thread::spawn(move || {
                FrameCodec::write(&mut client, &hello).expect("writer write hello");
                client
            });
            let mut reader = writer.join().expect("writer thread");
            
            FrameCodec::read(&mut reader).expect("reader read ack")
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        let received = FrameCodec::read(&mut server).expect("server read hello");
        FrameCodec::write(
            &mut server,
            &Envelope::response(
                &received,
                Message::HelloAck(HelloAck {
                    accepted: true,
                    peer_pid: 1,
                    reason: None,
                }),
            ),
        )
        .expect("server write ack");
        let ack = client.join().expect("client thread");
        match ack.body {
            Message::HelloAck(ack) => assert!(ack.accepted),
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }


    #[test]
    fn pipe_write_blocked_by_pending_client_read() {
        // DECISIVE: does a blocking WriteFile block while a ReadFile is
        // pending on the same connection? Client thread A reads 4 bytes
        // (completed by the server writing), thread B writes 4 bytes.
        let pipe = create_pipe(57085).expect("create pipe");
        let client = std::thread::spawn(move || {
            let client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57085")
                .expect("client open");
            let writer_pipe = client.try_clone().expect("client clone");
            let writer = std::thread::spawn(move || {
                let mut writer_ref: &std::fs::File = &writer_pipe;
                let payload = [0xAAu8; 4];
                std::io::Write::write_all(&mut writer_ref, &payload)
                    .expect("writer write 4 bytes");
                eprintln!("WRITER: write completed");
            });
            let mut reader_ref: &std::fs::File = &client;
            let mut byte = [0u8; 4];
            std::io::Read::read_exact(&mut reader_ref, &mut byte).expect("client read 4 bytes");
            eprintln!("CLIENT: read completed");
            writer.join().expect("writer thread");
            eprintln!("CLIENT: writer joined");
            byte
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        std::thread::sleep(std::time::Duration::from_secs(3));
        eprintln!("SERVER: writing 4 bytes to client");
        std::io::Write::write_all(&mut server, &[0xBBu8; 4]).expect("server write");
        eprintln!("SERVER: wrote, now reading");
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut server, &mut buf).expect("server read 4 bytes");
        eprintln!("SERVER: read {:?}", buf);
        let byte = client.join().expect("client thread");
        assert_eq!(byte, [0xBBu8; 4]);
    }

    #[test]
    fn pipe_client_write_blocked_by_server_read() {
        // Client writes via a clone while the SERVER holds a pending read.
        // The client itself does NOT read. If the write blocks, the server's
        // pending read is the blocker.
        let pipe = create_pipe(57086).expect("create pipe");
        let client = std::thread::spawn(move || {
            let client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57086")
                .expect("client open");
            let writer_pipe = client.try_clone().expect("client clone");
            let writer = std::thread::spawn(move || {
                let mut writer_ref: &std::fs::File = &writer_pipe;
                let payload = [0xAAu8; 4];
                std::io::Write::write_all(&mut writer_ref, &payload)
                    .expect("writer write 4 bytes");
                eprintln!("WRITER: write completed");
            });
            // Client does NOT read; just wait for the writer.
            std::thread::sleep(std::time::Duration::from_secs(4));
            eprintln!("CLIENT: slept 4s, joining writer");
            let _ = writer.join();
            eprintln!("CLIENT: writer joined");
            true
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        eprintln!("SERVER: reading immediately");
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut server, &mut buf).expect("server read 4 bytes");
        eprintln!("SERVER: read {:?}", buf);
        let _ = client.join().expect("client thread");
    }

    #[test]
    fn pipe_write_before_read_loop_avoids_deadlock() {
        // The DLL pattern, but the Hello write COMPLETES before the read loop
        // starts (join the writer first). Then the read loop runs while the
        // server acks. Does the full exchange complete?
        let pipe = create_pipe(57087).expect("create pipe");
        let client = std::thread::spawn(move || {
            let client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57087")
                .expect("client open");
            let writer_pipe = client.try_clone().expect("client clone");
            let hello = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
                role: ProcessRole::Injected,
                pid: 57087,
                fingerprint: azazel_coe5_symbols::BuildFingerprint {
                    product: "probe".into(),
                    version: "0".into(),
                    architecture: "x86_64".into(),
                    sha256: "deadbeef".into(),
                    image_base: azazel_coe5_symbols::Rva(0x140000000),
                    file_size: 0,
                    size_of_image: 0,
                },
                capabilities: azazel_coe5_protocol::CapabilityReport::default(),
            }));
            let writer = std::thread::spawn(move || {
                let mut writer_ref: &std::fs::File = &writer_pipe;
                FrameCodec::write(&mut writer_ref, &hello).expect("writer write hello");
                eprintln!("CLIENT: hello written");
            });
            writer.join().expect("writer join");
            eprintln!("CLIENT: writer joined, starting read loop");
            let mut reader_ref: &std::fs::File = &client;
            let ack = FrameCodec::read(&mut reader_ref).expect("reader read ack");
            eprintln!("CLIENT: read ack");
            ack
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        eprintln!("SERVER: reading hello");
        let received = FrameCodec::read(&mut server).expect("server read hello");
        eprintln!("SERVER: read hello, writing ack");
        FrameCodec::write(
            &mut server,
            &Envelope::response(
                &received,
                Message::HelloAck(HelloAck {
                    accepted: true,
                    peer_pid: 1,
                    reason: None,
                }),
            ),
        )
        .expect("server write ack");
        eprintln!("SERVER: acked");
        let ack = client.join().expect("client thread");
        match ack.body {
            Message::HelloAck(ack) => assert!(ack.accepted),
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    #[test]
    fn pipe_response_write_while_read_pending() {
        // After the handshake, the server sends a Ping. The client's read loop
        // is pending when the writer thread must send the Pong. This is the
        // exact DLL runtime shape. Does the Pong write complete?
        let pipe = create_pipe(57088).expect("create pipe");
        let client = std::thread::spawn(move || {
            let client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57088")
                .expect("client open");
            let client = std::sync::Arc::new(client);
            let hello = Envelope::event(Message::Hello(azazel_coe5_protocol::Hello {
                role: ProcessRole::Injected,
                pid: 57088,
                fingerprint: azazel_coe5_symbols::BuildFingerprint {
                    product: "probe".into(),
                    version: "0".into(),
                    architecture: "x86_64".into(),
                    sha256: "deadbeef".into(),
                    image_base: azazel_coe5_symbols::Rva(0x140000000),
                    file_size: 0,
                    size_of_image: 0,
                },
                capabilities: azazel_coe5_protocol::CapabilityReport::default(),
            }));
            let (outbound_tx, outbound_rx) = std::sync::mpsc::channel::<Envelope>();
            let writer_file = std::sync::Arc::clone(&client);
            let writer = std::thread::spawn(move || {
                while let Ok(envelope) = outbound_rx.recv() {
                    let mut writer_ref: &std::fs::File = &writer_file;
                    FrameCodec::write(&mut writer_ref, &envelope).expect("writer write");
                    eprintln!("CLIENT: writer wrote {:?}", envelope.body);
                }
            });
            // Write the Hello synchronously BEFORE the read loop.
            let mut hello_ref: &std::fs::File = &client;
            FrameCodec::write(&mut hello_ref, &hello).expect("hello write");
            eprintln!("CLIENT: hello written");
            // Read loop with a writer thread (the DLL shape).
            let mut reader_ref: &std::fs::File = &client;
            let ack = FrameCodec::read(&mut reader_ref).expect("read ack");
            eprintln!("CLIENT: read ack, waiting for ping");
            let ping = FrameCodec::read(&mut reader_ref).expect("read ping");
            eprintln!("CLIENT: got ping, queuing pong");
            let Message::Ping { nonce } = ping.body else {
                panic!("expected ping");
            };
            outbound_tx
                .send(Envelope::event(Message::Pong { nonce }))
                .expect("queue pong");
            // Wait for the writer to flush the pong, then exit.
            std::thread::sleep(std::time::Duration::from_secs(2));
            drop(outbound_tx);
            writer.join().expect("writer join");
            eprintln!("CLIENT: writer joined after pong");
            ack
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        let received = FrameCodec::read(&mut server).expect("server read hello");
        FrameCodec::write(
            &mut server,
            &Envelope::response(
                &received,
                Message::HelloAck(HelloAck {
                    accepted: true,
                    peer_pid: 1,
                    reason: None,
                }),
            ),
        )
        .expect("server write ack");
        eprintln!("SERVER: acked, sending ping");
        FrameCodec::write(&mut server, &Envelope::request(Message::Ping { nonce: 0x51E5 }))
            .expect("server write ping");
        let pong = FrameCodec::read(&mut server).expect("server read pong");
        eprintln!("SERVER: read pong {:?}", pong.body);
        let _ = client.join().expect("client thread");
        match pong.body {
            Message::Pong { nonce } => assert_eq!(nonce, 0x51E5),
            other => panic!("expected Pong, got {other:?}"),
        }
    }


    #[test]
    fn pipe_overlapped_concurrent_read_write() {
        // Overlapped I/O test: client opens with FILE_FLAG_OVERLAPPED, issues
        // an overlapped READ (pending) and an overlapped WRITE concurrently.
        // Expected: the write completes despite the pending read AND the
        // server's pending read.
        let pipe = create_pipe(57090).expect("create pipe");
        let client = std::thread::spawn(move || {
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            };
            use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
            use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
            let wide = r"\\.\pipe\azazel-coe5-assistant-57090"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    windows::Win32::Foundation::GENERIC_READ.0 | windows::Win32::Foundation::GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    None,
                )
            }
            .expect("client open overlapped");

            // Pending overlapped read.
            let read_event = unsafe {
                CreateEventW(None, true, false, None)
            }
            .expect("create read event");
            let mut read_ov = OVERLAPPED {
                hEvent: read_event,
                ..Default::default()
            };
            let mut read_buf = [0u8; 4];
            let mut read_bytes = 0u32;
            let read_started = unsafe {
                windows::Win32::Storage::FileSystem::ReadFile(
                    handle,
                    Some(&mut read_buf),
                    Some(&mut read_bytes),
                    Some(&mut read_ov),
                )
            };
            eprintln!("OVERLAPPED-CLIENT: read started {read_started:?}");

            // Concurrent overlapped write.
            let write_event = unsafe {
                CreateEventW(None, true, false, None)
            }
            .expect("create write event");
            let mut write_ov = OVERLAPPED {
                hEvent: write_event,
                ..Default::default()
            };
            let payload = [0xAAu8; 4];
            let mut write_bytes = 0u32;
            let write_started = unsafe {
                windows::Win32::Storage::FileSystem::WriteFile(
                    handle,
                    Some(&payload),
                    Some(&mut write_bytes),
                    Some(&mut write_ov),
                )
            };
            eprintln!("OVERLAPPED-CLIENT: write started {write_started:?}");
            let write_wait = unsafe { WaitForSingleObject(write_event, 10_000) };
            eprintln!("OVERLAPPED-CLIENT: write wait {write_wait:?}");
            let write_ok = unsafe {
                GetOverlappedResult(
                    handle,
                    &write_ov,
                    &mut write_bytes,
                    false,
                )
            };
            eprintln!("OVERLAPPED-CLIENT: write result {write_ok:?} bytes={write_bytes}");

            // Complete the read (server writes to us).
            let read_wait = unsafe { WaitForSingleObject(read_event, 10_000) };
            eprintln!("OVERLAPPED-CLIENT: read wait {read_wait:?}");
            let read_ok = unsafe {
                GetOverlappedResult(
                    handle,
                    &read_ov,
                    &mut read_bytes,
                    false,
                )
            };
            eprintln!("OVERLAPPED-CLIENT: read result {read_ok:?} bytes={read_bytes} buf={read_buf:?}");
            unsafe { windows::Win32::Foundation::CloseHandle(handle) }.ok();
            (write_ok, read_ok, write_bytes)
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        eprintln!("SERVER: reading");
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut server, &mut buf).expect("server read");
        eprintln!("SERVER: got {:?}", buf);
        std::io::Write::write_all(&mut server, &[0xBBu8; 4]).expect("server write");
        eprintln!("SERVER: wrote");
        let (write_ok, read_ok, write_bytes) = client.join().expect("client thread");
        assert!(write_ok.is_ok(), "overlapped write should complete");
        assert_eq!(write_bytes, 4);
        assert_eq!(buf, [0xAAu8; 4]);
        assert!(read_ok.is_ok());
    }

    #[test]
    fn pipe_round_trip_carries_hello_and_ack() {
        let pipe = create_pipe(57080).expect("create pipe");
        let client = std::thread::spawn(move || {
            let mut client = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\azazel-coe5-assistant-57080")
                .expect("client open");
            let hello = Envelope::event(Message::Hello(Hello {
                role: ProcessRole::Injected,
                pid: 57080,
                fingerprint: azazel_coe5_symbols::BuildFingerprint {
                    product: "probe".into(),
                    version: "0".into(),
                    architecture: "x86_64".into(),
                    sha256: "deadbeef".into(),
                    image_base: azazel_coe5_symbols::Rva(0x140000000),
                    file_size: 0,
                    size_of_image: 0,
                },
                capabilities: CapabilityReport::default(),
            }));
            FrameCodec::write(&mut client, &hello).expect("client write hello");
            let ack = FrameCodec::read(&mut client).expect("client read ack");
            (hello, ack)
        });

        let result = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = result
            && error.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            panic!("ConnectNamedPipe: {error}");
        }
        let mut server = unsafe { File::from_raw_handle(pipe.0 as _) };
        let received = FrameCodec::read(&mut server).expect("server read hello");
        FrameCodec::write(
            &mut server,
            &Envelope::response(
                &received,
                Message::HelloAck(HelloAck {
                    accepted: true,
                    peer_pid: 1,
                    reason: None,
                }),
            ),
        )
        .expect("server write ack");
        let (hello, ack) = client.join().expect("client thread");
        assert_eq!(received.body, Message::Hello(hello.body.unwrap_hello()));
        match ack.body {
            Message::HelloAck(ack) => assert!(ack.accepted),
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }
}
