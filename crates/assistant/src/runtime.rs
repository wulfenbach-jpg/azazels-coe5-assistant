use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{
    CapabilityReport, DiagnosticLevel, Envelope, GameSnapshot, HookEvent, Message,
};
use azazel_coe5_symbols::BuildManifest;
use crossbeam_channel::{Receiver, Sender, unbounded};
use parking_lot::RwLock;

use crate::{
    config::{AppConfig, ProfileDifference, SettingsSource},
    input::InputRemapper,
    ipc::{IpcEvent, IpcServer},
    process::{ProcessInfo, find_coe5, inject, is_alive},
    restart::{ExternalRestartResult, RestartGuard, RestartPlan, RestartPress, execute_external},
};

const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);
const LOG_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
pub enum ConnectionState {
    NoGame,
    Connecting,
    Injected,
    Degraded(String),
    Restarting,
}

#[derive(Debug, Clone)]
pub struct RuntimeLog {
    pub level: DiagnosticLevel,
    pub component: String,
    pub message: String,
}

pub struct RuntimeController {
    pub connection: ConnectionState,
    pub process: Option<ProcessInfo>,
    pub capabilities: CapabilityReport,
    pub snapshot: Arc<RwLock<Option<GameSnapshot>>>,
    pub hook_events: VecDeque<HookEvent>,
    pub logs: VecDeque<RuntimeLog>,
    pub restart_result: Option<ExternalRestartResult>,
    ipc: Option<IpcServer>,
    input: Option<InputRemapper>,
    restart_guard: RestartGuard,
    restart_tx: Sender<Result<ExternalRestartResult, String>>,
    restart_rx: Receiver<Result<ExternalRestartResult, String>>,
    last_snapshot_request: Instant,
    injected_dll: PathBuf,
}

impl RuntimeController {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let (restart_tx, restart_rx) = unbounded();
        let injected_dll = std::env::current_exe()?
            .parent()
            .context("Assistant executable has no parent")?
            .join("azazel_coe5_injected.dll");
        let input = match InputRemapper::start(0, config.remaps.clone()) {
            Ok(input) => Some(input),
            Err(error) => {
                tracing::error!("input remapper unavailable: {error:#}");
                None
            }
        };
        Ok(Self {
            connection: ConnectionState::NoGame,
            process: None,
            capabilities: CapabilityReport::default(),
            snapshot: Arc::new(RwLock::new(None)),
            hook_events: VecDeque::new(),
            logs: VecDeque::new(),
            restart_result: None,
            ipc: None,
            input,
            restart_guard: RestartGuard::new(Duration::from_millis(config.restart_double_tap_ms)),
            restart_tx,
            restart_rx,
            last_snapshot_request: Instant::now() - SNAPSHOT_INTERVAL,
            injected_dll,
        })
    }

    pub fn tick(&mut self, config: &mut AppConfig) {
        self.poll_restart_result();
        self.monitor_process();
        self.poll_ipc(config);
        if matches!(self.connection, ConnectionState::Injected)
            && self.last_snapshot_request.elapsed() >= SNAPSHOT_INTERVAL
            && let Some(ipc) = &self.ipc {
                let _ = ipc.send(Message::SnapshotRequest);
                self.last_snapshot_request = Instant::now();
            }
    }

    pub fn retry_injection(&mut self) -> Result<()> {
        let process = self.process.clone().context("CoE5 is not running")?;
        self.prepare_injection(process)
    }

    pub fn restart_press(&mut self, config: &AppConfig) -> Result<RestartPress> {
        let press = self.restart_guard.press();
        if press == RestartPress::Execute {
            self.start_external_restart(config)?;
        }
        Ok(press)
    }

    pub fn restart_armed(&self) -> bool {
        self.restart_guard.armed()
    }

    pub fn request_snapshot(&self) -> Result<Envelope> {
        self.ipc
            .as_ref()
            .context("injected pipe is unavailable")?
            .send(Message::SnapshotRequest)
    }

    pub fn set_hook(&self, symbol: &str, enabled: bool) -> Result<Envelope> {
        self.ipc
            .as_ref()
            .context("injected pipe is unavailable")?
            .send(Message::SetHook(azazel_coe5_protocol::HookControl {
                symbol: symbol.into(),
                enabled,
            }))
    }

    pub fn profile_differences(&self, config: &AppConfig) -> Vec<ProfileDifference> {
        let Some(snapshot) = self.snapshot.read().clone() else {
            return Vec::new();
        };
        config
            .active_profile()
            .map(|profile| profile.differences(&snapshot))
            .unwrap_or_default()
    }

    pub fn update_remaps(&self, config: &AppConfig) {
        if let Some(input) = &self.input {
            input.update_rules(config.remaps.clone());
        }
    }

    fn monitor_process(&mut self) {
        if let Some(process) = &self.process {
            if is_alive(process.pid) {
                return;
            }
            self.log(DiagnosticLevel::Info, "process", "CoE5 exited");
            self.process = None;
            self.ipc = None;
            *self.snapshot.write() = None;
            self.capabilities = CapabilityReport::default();
            self.connection = ConnectionState::NoGame;
            if let Some(input) = &self.input {
                input.set_target_pid(0);
            }
        }

        match find_coe5() {
            Ok(Some(process)) => {
                if let Err(error) = self.prepare_injection(process.clone()) {
                    self.connection = ConnectionState::Degraded(error.to_string());
                    self.log(DiagnosticLevel::Error, "injection", error.to_string());
                    self.process = Some(process.clone());
                    if let Some(input) = &self.input {
                        input.set_target_pid(process.pid);
                    }
                }
            }
            Ok(None) => {}
            Err(error) => self.log(DiagnosticLevel::Error, "process", error.to_string()),
        }
    }

    fn prepare_injection(&mut self, process: ProcessInfo) -> Result<()> {
        let manifest = BuildManifest::embedded_5_39()?;
        if !manifest.supports_sha256(&process.sha256) {
            bail!("unsupported CoE5 executable hash {}", process.sha256);
        }
        if !self.injected_dll.exists() {
            bail!("injected DLL not found at {}", self.injected_dll.display());
        }
        self.connection = ConnectionState::Connecting;
        self.process = Some(process.clone());
        if let Some(input) = &self.input {
            input.set_target_pid(process.pid);
        }
        let ipc = IpcServer::start(process.pid, process.sha256.clone())?;
        inject(&process, &self.injected_dll)?;
        self.ipc = Some(ipc);
        self.log(
            DiagnosticLevel::Info,
            "injection",
            format!("loaded injected runtime into process {}", process.pid),
        );
        Ok(())
    }

    fn poll_ipc(&mut self, config: &mut AppConfig) {
        let events = self
            .ipc
            .as_ref()
            .map(|ipc| ipc.events().try_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        for event in events {
            match event {
                IpcEvent::Connected(hello) => {
                    self.capabilities = hello.capabilities;
                    self.connection = ConnectionState::Injected;
                    self.log(
                        DiagnosticLevel::Info,
                        "ipc",
                        format!("injected handshake accepted for process {}", hello.pid),
                    );
                    let _ = self.set_hook("world_reset_static_state", true);
                    let _ = self.request_snapshot();
                }
                IpcEvent::Message(envelope) => self.handle_message(envelope, config),
                IpcEvent::Disconnected(reason) => {
                    self.connection = ConnectionState::Degraded(reason.clone());
                    self.log(DiagnosticLevel::Error, "ipc", reason);
                }
            }
        }
    }

    fn handle_message(&mut self, envelope: Envelope, config: &mut AppConfig) {
        match envelope.body {
            Message::Snapshot(snapshot) => {
                config.auto_select(&snapshot);
                *self.snapshot.write() = Some(snapshot);
            }
            Message::CapabilityReport(report) => self.capabilities = report,
            Message::HookEvent(event) => {
                self.push_hook_event(event);
            }
            Message::Diagnostics(diagnostics) => {
                for entry in diagnostics.entries {
                    self.log(entry.level, entry.component, entry.message);
                }
            }
            Message::Error(error) => {
                self.log(
                    DiagnosticLevel::Error,
                    format!("remote:{}", error.code),
                    error.message,
                );
            }
            Message::Pong { .. } | Message::HelloAck(_) => {}
            other => self.log(
                DiagnosticLevel::Debug,
                "ipc",
                format!("unhandled message: {other:?}"),
            ),
        }
    }

    fn start_external_restart(&mut self, config: &AppConfig) -> Result<()> {
        let process = self.process.clone().context("CoE5 is not running")?;
        let profile = config
            .active_profile()
            .cloned()
            .context("no active restart profile")?;
        let snapshot = self.snapshot.read().clone();
        let mut plan = match config.restart_settings_source {
            SettingsSource::CopyLastGame => {
                RestartPlan::capture(&process, snapshot.as_ref(), &profile)
            }
            SettingsSource::UseProfile => RestartPlan::from_profile(&profile),
        };
        plan.launch_via_steam = config.launch_via_steam;
        let executable = config.coe5_executable.clone();
        if let Some(ipc) = &self.ipc {
            ipc.shutdown();
        }
        self.connection = ConnectionState::Restarting;
        let result_tx = self.restart_tx.clone();
        thread::Builder::new()
            .name("azazel-coe5-external-restart".into())
            .spawn(move || {
                let result = execute_external(&process, &executable, &plan)
                    .map_err(|error| format!("{error:#}"));
                let _ = result_tx.send(result);
            })
            .context("spawn external restart")?;
        Ok(())
    }

    fn poll_restart_result(&mut self) {
        while let Ok(result) = self.restart_rx.try_recv() {
            match result {
                Ok(result) => {
                    self.log(
                        DiagnosticLevel::Info,
                        "restart",
                        format!(
                            "external restart created process {} ({} map settings, {} participant roster)",
                            result.pid,
                            if result.live_map_settings {
                                "live"
                            } else {
                                "profile"
                            },
                            if result.live_roster {
                                "live"
                            } else {
                                "profile"
                            },
                        ),
                    );
                    self.restart_result = Some(result);
                    self.process = None;
                    self.ipc = None;
                    self.connection = ConnectionState::NoGame;
                }
                Err(error) => {
                    self.connection = ConnectionState::Degraded(error.clone());
                    self.log(DiagnosticLevel::Error, "restart", error);
                }
            }
        }
    }

    fn push_hook_event(&mut self, event: HookEvent) {
        if self.hook_events.len() == LOG_CAPACITY {
            self.hook_events.pop_front();
        }
        self.hook_events.push_back(event);
    }

    fn log(
        &mut self,
        level: DiagnosticLevel,
        component: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.logs.len() == LOG_CAPACITY {
            self.logs.pop_front();
        }
        self.logs.push_back(RuntimeLog {
            level,
            component: component.into(),
            message: message.into(),
        });
    }
}
