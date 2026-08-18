use std::{
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::Arc,
    thread,
};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{Envelope, FrameCodec, HelloAck, Message, ProcessRole};
use crossbeam_channel::{Receiver, Sender, unbounded};
use parking_lot::Mutex;

#[derive(Debug)]
pub enum PluginEvent {
    Connected { executable: PathBuf, pid: u32 },
    Message(Envelope),
    Exited { executable: PathBuf, reason: String },
}

impl PluginEvent {
    pub fn summary(&self) -> String {
        match self {
            Self::Connected { executable, pid } => {
                format!("connected pid={pid} {}", executable.display())
            }
            Self::Message(envelope) => format!("message {:?}", envelope.body),
            Self::Exited { executable, reason } => {
                format!("exited {}: {reason}", executable.display())
            }
        }
    }
}

pub struct PluginHost {
    executable: PathBuf,
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    events: Receiver<PluginEvent>,
    _event_sender: Sender<PluginEvent>,
}

impl PluginHost {
    pub fn start(executable: &Path) -> Result<Self> {
        let mut child = Command::new(executable)
            .arg("--azazel-plugin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("start plugin {}", executable.display()))?;
        let stdin = Arc::new(Mutex::new(
            child.stdin.take().context("plugin stdin unavailable")?,
        ));
        let mut stdout = child.stdout.take().context("plugin stdout unavailable")?;
        let hello_envelope = FrameCodec::read(&mut stdout).context("read plugin hello")?;
        let Message::Hello(hello) = &hello_envelope.body else {
            bail!("plugin first frame was not Hello");
        };
        if hello.role != ProcessRole::Plugin {
            bail!("plugin announced role {:?}", hello.role);
        }
        FrameCodec::write(
            &mut *stdin.lock(),
            &Envelope::response(
                &hello_envelope,
                Message::HelloAck(HelloAck {
                    accepted: true,
                    peer_pid: std::process::id(),
                    reason: None,
                }),
            ),
        )?;

        let (event_tx, event_rx) = unbounded();
        let thread_tx = event_tx.clone();
        let path = executable.to_owned();
        let pid = child.id();
        event_tx.send(PluginEvent::Connected {
            executable: path.clone(),
            pid,
        })?;
        thread::Builder::new()
            .name(format!("azazel-plugin-{pid}"))
            .spawn(move || {
                loop {
                    match FrameCodec::read(&mut stdout) {
                        Ok(message) => {
                            if thread_tx.send(PluginEvent::Message(message)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = thread_tx.send(PluginEvent::Exited {
                                executable: path,
                                reason: error.to_string(),
                            });
                            break;
                        }
                    }
                }
            })
            .context("spawn plugin reader")?;

        Ok(Self {
            executable: executable.to_owned(),
            child,
            stdin,
            events: event_rx,
            _event_sender: event_tx,
        })
    }

    pub fn send(&self, message: Message) -> Result<Envelope> {
        let request = Envelope::request(message);
        FrameCodec::write(&mut *self.stdin.lock(), &request)?;
        Ok(request)
    }

    pub fn events(&self) -> &Receiver<PluginEvent> {
        &self.events
    }

    pub fn stop(&mut self) -> Result<()> {
        let _ = FrameCodec::write(&mut *self.stdin.lock(), &Envelope::event(Message::Shutdown));
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        Ok(())
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl Drop for PluginHost {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
