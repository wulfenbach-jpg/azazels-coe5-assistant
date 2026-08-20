use std::{
    ffi::c_void,
    fs::File,
    io::{BufReader, Read},
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, LPARAM, WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM},
        System::{
            Diagnostics::{
                Debug::{ReadProcessMemory, WriteProcessMemory},
                ToolHelp::{
                    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                    PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPMODULE,
                    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
            },
            Threading::{
                CreateRemoteThread, GetExitCodeThread, OpenProcess, PEB, PROCESS_BASIC_INFORMATION,
                PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
                PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
                RTL_USER_PROCESS_PARAMETERS, TerminateProcess, WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId, PostMessageW, WM_CLOSE},
    },
    core::{PCSTR, PCWSTR, w},
};

const INJECTION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
    pub fn raw(&self) -> HANDLE {
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

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub executable: PathBuf,
    pub module_base: usize,
    pub module_size: u32,
    pub sha256: String,
}

pub fn find_coe5() -> Result<Option<ProcessInfo>> {
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
            return process_info(entry.th32ProcessID).map(Some);
        }
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) }.is_err() {
            return Ok(None);
        }
    }
}

pub fn is_alive(pid: u32) -> bool {
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else {
        return false;
    };
    let handle = OwnedHandle::new(handle);
    (unsafe { WaitForSingleObject(handle.raw(), 0) }) == WAIT_TIMEOUT
}

/// Reads a process's command line through its PEB. The typed layout of
/// [`PROCESS_BASIC_INFORMATION`], [`PEB`], and
/// [`RTL_USER_PROCESS_PARAMETERS`] mirrors the x64 structures, so the
/// `CommandLine` UNICODE_STRING is located without hardcoded offsets.
pub fn command_line(pid: u32) -> Result<String> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};

    let handle = OwnedHandle::new(unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?
    });
    let mut basic = PROCESS_BASIC_INFORMATION::default();
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessBasicInformation,
            (&mut basic as *mut PROCESS_BASIC_INFORMATION).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if !status.is_ok() {
        bail!("NtQueryInformationProcess failed with {status:?}");
    }
    let peb = basic.PebBaseAddress;
    if peb.is_null() {
        bail!("process exposes no PEB");
    }
    let peb_value = read_remote_struct::<PEB>(&handle, peb as usize)?;
    if peb_value.ProcessParameters.is_null() {
        bail!("process exposes no process parameters");
    }
    let parameters = read_remote_struct::<RTL_USER_PROCESS_PARAMETERS>(
        &handle,
        peb_value.ProcessParameters as usize,
    )?;
    let command_line = parameters.CommandLine;
    if command_line.Buffer.is_null() || command_line.Length == 0 {
        bail!("process exposes an empty command line");
    }
    let length = command_line.Length as usize;
    let mut wide = vec![0u16; length / 2 + 1];
    let mut bytes_read = 0usize;
    unsafe {
        ReadProcessMemory(
            handle.raw(),
            command_line.Buffer.0 as *const c_void,
            wide.as_mut_ptr().cast(),
            length,
            Some(&mut bytes_read),
        )?
    };
    if bytes_read != length {
        bail!("short command-line read at {bytes_read}/{length} bytes");
    }
    Ok(String::from_utf16_lossy(&wide[..length / 2]))
}

fn read_remote_struct<T: Default + Copy>(process: &OwnedHandle, address: usize) -> Result<T> {
    let mut value = T::default();
    let mut bytes_read = 0usize;
    unsafe {
        ReadProcessMemory(
            process.raw(),
            address as *const c_void,
            (&mut value as *mut T).cast(),
            size_of::<T>(),
            Some(&mut bytes_read),
        )?
    };
    if bytes_read != size_of::<T>() {
        bail!("short remote read at 0x{address:x}");
    }
    Ok(value)
}

pub fn wait_for_coe5(pid: u32, timeout: Duration) -> Result<ProcessInfo> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(info) = process_info(pid) {
            return Ok(info);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("timed out waiting for CoE5 process {pid}")
}

pub fn launch_coe5(executable: &Path, arguments: &[String]) -> Result<Child> {
    let working_directory = executable
        .parent()
        .context("CoE5 executable has no parent directory")?;
    Command::new(executable)
        .args(arguments)
        .current_dir(working_directory)
        .spawn()
        .with_context(|| format!("launch {}", executable.display()))
}

pub fn stop_coe5(pid: u32, graceful_timeout: Duration) -> Result<bool> {
    let handle =
        OwnedHandle(unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, false, pid) }?);
    let window = unsafe { FindWindowW(PCWSTR::null(), w!("CoE 5")) };
    if let Ok(window) = window {
        let mut window_pid = 0u32;
        unsafe { GetWindowThreadProcessId(window, Some(&mut window_pid)) };
        if window_pid == pid {
            unsafe { PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0)) }?;
        }
    }
    let wait = unsafe { WaitForSingleObject(handle.raw(), graceful_timeout.as_millis() as u32) };
    if wait == WAIT_OBJECT_0 {
        return Ok(false);
    }
    unsafe { TerminateProcess(handle.raw(), 0xA2A5) }?;
    Ok(true)
}

pub fn inject(process: &ProcessInfo, dll: &Path) -> Result<()> {
    let dll = dll
        .canonicalize()
        .with_context(|| format!("canonicalize injected DLL {}", dll.display()))?;
    let initializer_rva = pe_export_rva(&dll, b"AzazelInitialize")?;
    let process_handle = OwnedHandle(unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_SYNCHRONIZE,
            false,
            process.pid,
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
        WriteProcessMemory(
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
    wait_thread(&load_thread, INJECTION_TIMEOUT, "LoadLibraryW")?;
    let mut load_result = 0u32;
    unsafe { GetExitCodeThread(load_thread.raw(), &mut load_result) }?;
    if load_result == 0 {
        bail!("remote LoadLibraryW returned null");
    }
    drop(remote_path_guard);

    let module_name = dll
        .file_name()
        .and_then(|name| name.to_str())
        .context("injected DLL filename is not UTF-8")?;
    let remote_module = wait_for_module(process.pid, module_name, INJECTION_TIMEOUT)?;
    let initializer_address = remote_module
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
    drop(initializer_thread);
    Ok(())
}

fn wait_thread(thread: &OwnedHandle, timeout: Duration, operation: &str) -> Result<()> {
    let wait = unsafe { WaitForSingleObject(thread.raw(), timeout.as_millis() as u32) };
    if wait != WAIT_OBJECT_0 {
        bail!("{operation} remote thread timed out");
    }
    Ok(())
}

#[derive(Debug)]
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

fn process_info(pid: u32) -> Result<ProcessInfo> {
    let module = main_module(pid)?;
    Ok(ProcessInfo {
        pid,
        sha256: sha256_file(&module.executable)?,
        executable: module.executable,
        module_base: module.module_base,
        module_size: module.module_size,
    })
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

fn main_module(pid: u32) -> Result<ModuleInfo> {
    modules(pid)?
        .into_iter()
        .next()
        .context("target process has no modules")
}

#[derive(Debug, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_initializer_export_from_built_dll_when_available() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/azazel_coe5_injected.dll");
        if path.exists() {
            assert!(pe_export_rva(&path, b"AzazelInitialize").unwrap() > 0);
        }
    }
}
