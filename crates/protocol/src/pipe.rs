//! Overlapped named-pipe transport.
//!
//! Blocking (non-overlapped) pipe I/O on this Windows build serializes
//! outstanding operations on a connection: a pending `ReadFile` on one handle
//! makes a `WriteFile` on another handle of the same connection block until
//! the pipe's write timeout, then fail with `ERROR_NO_DATA`. Overlapped I/O
//! issues reads and writes as independent IRPs, so a writer thread can send
//! frames while the reader loop is blocked awaiting the next request.
//!
//! `OverlappedPipe` owns one handle opened with `FILE_FLAG_OVERLAPPED` and is
//! shared by reference count. `PipeReader`/`PipeWriter` adapt one side each to
//! `std::io::Read`/`std::io::Write` so the existing `FrameCodec` works
//! unchanged. Writes are serialized through a mutex; a single reader may hold
//! one pending read at a time.

use std::{
    io,
    sync::{Arc, Mutex},
};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
            HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
        },
        System::{
            IO::{GetOverlappedResult, OVERLAPPED},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{CreateEventW, WaitForSingleObject},
        },
    },
    core::{HRESULT, PCWSTR},
};

const PIPE_BUFFER_SIZE: u32 = 64 * 1024;
const OPERATION_TIMEOUT_MS: u32 = 15_000;

/// A shared, overlapped named-pipe connection handle.
pub struct OverlappedPipe {
    handle: HANDLE,
    write_lock: Mutex<()>,
}

unsafe impl Send for OverlappedPipe {}
unsafe impl Sync for OverlappedPipe {}

impl OverlappedPipe {
    /// Create the server side of `pipe_name` (single instance, duplex, byte
    /// mode, blocking connect) and return the listening handle.
    pub fn create_server(pipe_name: &str) -> io::Result<Self> {
        let wide = pipe_name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                None,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            write_lock: Mutex::new(()),
        })
    }

    /// Open the client side of `pipe_name` with overlapped I/O.
    pub fn open_client(pipe_name: &str) -> io::Result<Self> {
        let wide = pipe_name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        }?;
        Ok(Self {
            handle,
            write_lock: Mutex::new(()),
        })
    }

    /// Accept a client connection. Returns when a client connects; also
    /// succeeds when the client connected before this call.
    pub fn connect(&self) -> io::Result<()> {
        let result = unsafe { ConnectNamedPipe(self.handle, None) };
        if let Err(error) = result {
            let code = error.code();
            if code == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                return Ok(());
            }
            return Err(io::Error::from_raw_os_error(code.0 & 0xFFFF));
        }
        Ok(())
    }

    /// Perform one overlapped read, blocking until bytes arrive or EOF.
    /// Callers must not issue a second read while one is pending.
    pub fn read_some(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let event = unsafe { CreateEventW(None, true, false, None) }?;
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };
        let mut bytes_read = 0u32;
        let result = unsafe {
            ReadFile(
                self.handle,
                Some(buffer),
                Some(&mut bytes_read),
                Some(&mut overlapped),
            )
        };
        match result {
            Ok(()) => Ok(bytes_read as usize),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                self.wait_completion(&mut overlapped, &mut bytes_read)
            }
            Err(error) => Err(io::Error::from_raw_os_error(error.code().0 & 0xFFFF)),
        }
    }

    /// Write the whole buffer with one overlapped write, blocking until done.
    pub fn write_all(&self, buffer: &[u8]) -> io::Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| io::Error::other("pipe write lock poisoned"))?;
        let event = unsafe { CreateEventW(None, true, false, None) }?;
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };
        let mut bytes_written = 0u32;
        let result = unsafe {
            WriteFile(
                self.handle,
                Some(buffer),
                Some(&mut bytes_written),
                Some(&mut overlapped),
            )
        };
        match result {
            Ok(()) => self.check_written(buffer.len(), bytes_written),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                self.wait_completion(&mut overlapped, &mut bytes_written)?;
                self.check_written(buffer.len(), bytes_written)
            }
            Err(error) => Err(io::Error::from_raw_os_error(error.code().0 & 0xFFFF)),
        }
    }

    fn check_written(&self, expected: usize, written: u32) -> io::Result<()> {
        if written as usize != expected {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short pipe write: expected {expected}, wrote {written}"),
            ))
        } else {
            Ok(())
        }
    }

    fn wait_completion(
        &self,
        overlapped: &mut OVERLAPPED,
        transferred: &mut u32,
    ) -> io::Result<usize> {
        let wait = unsafe { WaitForSingleObject(overlapped.hEvent, OPERATION_TIMEOUT_MS) };
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pipe overlapped operation timed out",
            ));
        }
        unsafe { GetOverlappedResult(self.handle, overlapped, transferred, false) }?;
        Ok(*transferred as usize)
    }
}

impl Drop for OverlappedPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Read-only adapter exposing the shared pipe through `std::io::Read`.
pub struct PipeReader {
    pub pipe: Arc<OverlappedPipe>,
}

impl PipeReader {
    pub fn new(pipe: Arc<OverlappedPipe>) -> Self {
        Self { pipe }
    }
}

impl io::Read for PipeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.pipe.read_some(buffer)
    }
}

/// Write-only adapter exposing the shared pipe through `std::io::Write`.
pub struct PipeWriter {
    pub pipe: Arc<OverlappedPipe>,
}

impl PipeWriter {
    pub fn new(pipe: Arc<OverlappedPipe>) -> Self {
        Self { pipe }
    }
}

impl io::Write for PipeWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pipe.write_all(buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
