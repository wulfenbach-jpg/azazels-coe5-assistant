pub mod pipe;

use std::io::{Read, Write};

use azazel_coe5_symbols::{BuildFingerprint, Rva};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame length {actual} exceeds maximum {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("peer protocol {actual} is incompatible with protocol {expected}")]
    VersionMismatch { expected: u32, actual: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub protocol_version: u32,
    pub request_id: Option<Uuid>,
    pub body: Message,
}

impl Envelope {
    pub fn event(body: Message) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: None,
            body,
        }
    }

    pub fn request(body: Message) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: Some(Uuid::new_v4()),
            body,
        }
    }

    pub fn response(request: &Self, body: Message) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id,
            body,
        }
    }

    pub fn validate_version(&self) -> Result<(), ProtocolError> {
        if self.protocol_version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Message {
    Hello(Hello),
    HelloAck(HelloAck),
    CapabilityReport(CapabilityReport),
    SnapshotRequest,
    Snapshot(GameSnapshot),
    ReadMemory(ReadMemoryRequest),
    Memory(MemoryResponse),
    SetHook(HookControl),
    HookEvent(HookEvent),
    Restart(RestartRequest),
    RestartResult(RestartResult),
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    Diagnostics(Diagnostics),
    Shutdown,
    Error(RemoteError),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    Assistant,
    Injected,
    Plugin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hello {
    pub role: ProcessRole,
    pub pid: u32,
    pub fingerprint: BuildFingerprint,
    pub capabilities: CapabilityReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelloAck {
    pub accepted: bool,
    pub peer_pid: u32,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CapabilityReport {
    pub entries: Vec<CapabilityStatus>,
}

impl CapabilityReport {
    pub fn status(&self, id: &str) -> Option<&CapabilityStatus> {
        self.entries.iter().find(|entry| entry.id == id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityStatus {
    pub id: String,
    pub state: CapabilityState,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Disabled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameSnapshot {
    pub lifecycle: LifecycleSnapshot,
    pub map: MapSnapshot,
    pub options: OptionsSnapshot,
    pub participants: Vec<ParticipantSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleSnapshot {
    pub world_state_unknown_abc: i32,
    pub turn: i32,
    pub plane: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MapSnapshot {
    pub width: i32,
    pub height: i32,
    pub real_width: i32,
    pub random_map_launch_mode: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OptionsSnapshot {
    pub flags_a: i16,
    pub flags_b: i16,
    pub society: i16,
    pub short_0c: i16,
    pub short_0e: i16,
    pub short_10: i16,
    pub int_14: i32,
    pub common_cause: i32,
    pub score_graphs: i32,
    pub int_20: i32,
    pub int_24: i32,
    pub int_28: i32,
    pub int_2c: i32,
    pub independent_strength: i32,
    pub int_34: i32,
    pub battle_reports: i16,
    pub north_percent_ui: i32,
    pub south_percent_ui: i32,
    pub start_policy_ui: i32,
    pub unique_random_classes: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParticipantSnapshot {
    pub slot: u8,
    pub active: bool,
    pub controller: i16,
    pub class_id: i16,
    pub start_x: i16,
    pub start_y: i16,
    pub team: Option<i16>,
    pub difficulty: Option<i16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReadMemoryRequest {
    pub rva: Rva,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryResponse {
    pub rva: Rva,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookControl {
    pub symbol: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookEvent {
    pub symbol: String,
    pub rva: Rva,
    pub thread_id: u32,
    pub sequence: u64,
    pub timestamp_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RestartRequest {
    pub profile_id: Uuid,
    pub expected_map_identity: Option<String>,
    pub prefer_internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RestartResult {
    pub mode: RestartMode,
    pub state: RestartState,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestartMode {
    Internal,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestartState {
    Armed,
    Started,
    Completed,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Diagnostics {
    pub entries: Vec<DiagnosticEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticEntry {
    pub level: DiagnosticLevel,
    pub component: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteError {
    pub code: String,
    pub message: String,
}

pub struct FrameCodec;

impl FrameCodec {
    pub fn write<W: Write>(writer: &mut W, envelope: &Envelope) -> Result<(), ProtocolError> {
        envelope.validate_version()?;
        let body = serde_json::to_vec(envelope)?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge {
                actual: body.len(),
                maximum: MAX_FRAME_BYTES,
            });
        }
        writer.write_all(&(body.len() as u32).to_le_bytes())?;
        writer.write_all(&body)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Envelope, ProtocolError> {
        let mut length = [0u8; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge {
                actual: length,
                maximum: MAX_FRAME_BYTES,
            });
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body)?;
        let envelope: Envelope = serde_json::from_slice(&body)?;
        envelope.validate_version()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn frame_round_trip_preserves_request() {
        let request = Envelope::request(Message::Ping { nonce: 42 });
        let mut bytes = Vec::new();
        FrameCodec::write(&mut bytes, &request).unwrap();
        let decoded = FrameCodec::read(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let mut bytes = Cursor::new(((MAX_FRAME_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            FrameCodec::read(&mut bytes),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn mismatched_protocol_version_is_rejected() {
        let envelope = Envelope {
            protocol_version: PROTOCOL_VERSION + 1,
            request_id: None,
            body: Message::Shutdown,
        };
        assert!(matches!(
            envelope.validate_version(),
            Err(ProtocolError::VersionMismatch { .. })
        ));
    }
}
