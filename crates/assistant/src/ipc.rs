use std::{sync::Arc, thread};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{
    Envelope, FrameCodec, HelloAck, Message, PROTOCOL_VERSION, ProcessRole,
    pipe::{OverlappedPipe, PipeReader, PipeWriter},
};
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};

const COMMAND_CAPACITY: usize = 256;

#[derive(Debug)]
pub enum IpcEvent {
    Connected(azazel_coe5_protocol::Hello),
    Message(Envelope),
    Disconnected(String),
}

pub struct IpcServer {
    commands: Sender<Envelope>,
    events: Receiver<IpcEvent>,
}

impl IpcServer {
    pub fn start(pid: u32, expected_sha256: String) -> Result<Self> {
        let path = format!(r"\\.\pipe\azazel-coe5-assistant-{pid}");
        let pipe = OverlappedPipe::create_server(&path)
            .with_context(|| format!("create named pipe {path}"))?;

        let (command_tx, command_rx) = bounded(COMMAND_CAPACITY);
        let (event_tx, event_rx) = unbounded();
        thread::Builder::new()
            .name(format!("azazel-coe5-pipe-{pid}"))
            .spawn(move || {
                if let Err(error) = session(pipe, command_rx, &event_tx, &expected_sha256) {
                    let _ = event_tx.send(IpcEvent::Disconnected(format!("{error:#}")));
                }
            })
            .context("spawn named-pipe session")?;

        Ok(Self {
            commands: command_tx,
            events: event_rx,
        })
    }

    pub fn send(&self, message: Message) -> Result<Envelope> {
        let envelope = Envelope::request(message);
        self.commands
            .send(envelope.clone())
            .context("queue IPC command")?;
        Ok(envelope)
    }

    pub fn shutdown(&self) {
        let _ = self.commands.send(Envelope::event(Message::Shutdown));
    }

    pub fn events(&self) -> &Receiver<IpcEvent> {
        &self.events
    }
}

fn session(
    pipe: OverlappedPipe,
    commands: Receiver<Envelope>,
    events: &Sender<IpcEvent>,
    expected_sha256: &str,
) -> Result<()> {
    let pipe = Arc::new(pipe);
    pipe.connect().context("ConnectNamedPipe")?;

    let mut reader = PipeReader::new(Arc::clone(&pipe));
    let hello_envelope = FrameCodec::read(&mut reader).context("read injected hello")?;
    let Message::Hello(hello) = &hello_envelope.body else {
        bail!("first injected frame was not Hello");
    };
    let accepted = hello.role == ProcessRole::Injected
        && hello
            .fingerprint
            .sha256
            .eq_ignore_ascii_case(expected_sha256)
        && hello_envelope.protocol_version == PROTOCOL_VERSION;
    let reason = (!accepted).then(|| {
        format!(
            "handshake mismatch: role={:?}, protocol={}, sha256={}",
            hello.role, hello_envelope.protocol_version, hello.fingerprint.sha256
        )
    });
    let mut writer = PipeWriter::new(Arc::clone(&pipe));
    FrameCodec::write(
        &mut writer,
        &Envelope::response(
            &hello_envelope,
            Message::HelloAck(HelloAck {
                accepted,
                peer_pid: std::process::id(),
                reason: reason.clone(),
            }),
        ),
    )
    .context("write HelloAck")?;
    if !accepted {
        bail!("{}", reason.unwrap_or_else(|| "handshake rejected".into()));
    }
    events.send(IpcEvent::Connected(hello.clone()))?;

    let command_writer = Arc::clone(&pipe);
    let command_thread = thread::Builder::new()
        .name("azazel-coe5-command-writer".into())
        .spawn(move || {
            let mut writer = PipeWriter::new(command_writer);
            while let Ok(command) = commands.recv() {
                let shutdown = matches!(command.body, Message::Shutdown);
                if FrameCodec::write(&mut writer, &command).is_err() || shutdown {
                    break;
                }
            }
        })
        .context("spawn pipe command writer")?;

    let mut reader = reader;
    loop {
        match FrameCodec::read(&mut reader) {
            Ok(message) => events.send(IpcEvent::Message(message))?,
            Err(error) => {
                let _ = command_thread.join();
                return Err(error).context("read injected response");
            }
        }
    }
}
