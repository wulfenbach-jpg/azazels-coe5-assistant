use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result};
use azazel_coe5_protocol::{CapabilityState, DiagnosticLevel, Message};
use azazel_coe5_symbols::BuildManifest;
use eframe::egui::{self, RichText, ScrollArea, TextEdit, ViewportCommand};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer};
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState, hotkey::HotKey};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuId, MenuItem},
};

#[cfg(debug_assertions)]
static LOGIC_WITNESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(debug_assertions)]
static UI_WITNESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(debug_assertions)]
static SCREENSHOT_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

use crate::{
    config::{
        AppConfig, InputAction, InputTrigger, Modifier, MouseButton, Profile, RemapRule,
        SettingsSource,
    },
    debugger::{DebuggerCommand, DebuggerEvent, DebuggerSession, DisassemblyLine},
    lua::LuaEngine,
    plugins::PluginHost,
    runtime::{ConnectionState, RuntimeController},
    theme,
    update::{UpdateEnvelope, verify_artifact},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Tab {
    Status,
    Profiles,
    Hotkeys,
    Memory,
    Symbols,
    Hooks,
    Debugger,
    Lua,
    Plugins,
    Logs,
    Updates,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Profiles => "Profiles",
            Self::Hotkeys => "Hotkeys",
            Self::Memory => "Memory",
            Self::Symbols => "Symbols",
            Self::Hooks => "Hooks",
            Self::Debugger => "Debugger",
            Self::Lua => "Lua",
            Self::Plugins => "Plugins",
            Self::Logs => "Logs",
            Self::Updates => "Updates",
        }
    }
}

struct DebugUi {
    session: Option<DebuggerSession>,
    events: VecDeque<DebuggerEvent>,
    address: String,
    length: usize,
    breakpoint: String,
    disassembly: Vec<DisassemblyLine>,
}

impl Default for DebugUi {
    fn default() -> Self {
        Self {
            session: None,
            events: VecDeque::new(),
            address: "0x140000000".into(),
            length: 256,
            breakpoint: String::new(),
            disassembly: Vec::new(),
        }
    }
}

pub struct AssistantApp {
    config: AppConfig,
    runtime: RuntimeController,
    manifest: BuildManifest,
    lua: LuaEngine,
    dock: DockState<Tab>,
    hotkey_manager: GlobalHotKeyManager,
    restart_hotkey: HotKey,
    hotkey_text: String,
    _tray: TrayIcon,
    tray_open: MenuId,
    tray_quit: MenuId,
    window_visible: bool,
    should_quit: bool,
    lua_source: String,
    lua_output: String,
    plugin_path: String,
    plugin: Option<PluginHost>,
    update_json: String,
    update_artifact_path: String,
    update_result: String,
    debugger: DebugUi,
    last_error: Option<String>,
}

impl AssistantApp {
    pub fn new(context: &eframe::CreationContext<'_>) -> Result<Self> {
        theme::apply(&context.egui_ctx);
        let mut config = AppConfig::load().unwrap_or_else(|error| {
            tracing::error!("configuration load failed: {error:#}");
            AppConfig::default()
        });
        if config.active_profile.is_none() {
            config.active_profile = config.profiles.first().map(|profile| profile.id);
        }
        let runtime = RuntimeController::new(&config)?;
        let lua = LuaEngine::new(runtime.snapshot.clone())?;
        let manifest = BuildManifest::embedded_5_39()?;
        let hotkey_text = hotkey_string(&config);
        let restart_hotkey = HotKey::from_str(&hotkey_text)
            .with_context(|| format!("parse restart hotkey {hotkey_text}"))?;
        let hotkey_manager = GlobalHotKeyManager::new()?;
        hotkey_manager.register(restart_hotkey)?;
        let (tray, tray_open, tray_quit) = create_tray()?;
        let mut dock = DockState::new(vec![Tab::Status, Tab::Profiles, Tab::Hotkeys, Tab::Symbols]);
        let surface = dock.main_surface_mut();
        let [left, right] =
            surface.split_right(NodeIndex::root(), 0.72, vec![Tab::Debugger, Tab::Memory]);
        let _ = surface.split_below(left, 0.62, vec![Tab::Logs, Tab::Hooks]);
        let _ = surface.split_below(right, 0.68, vec![Tab::Lua, Tab::Plugins, Tab::Updates]);

        Ok(Self {
            config,
            runtime,
            manifest,
            lua,
            dock,
            hotkey_manager,
            restart_hotkey,
            hotkey_text,
            _tray: tray,
            tray_open,
            tray_quit,
            window_visible: true,
            should_quit: false,
            lua_source: "return assistant.snapshot_json()".into(),
            lua_output: String::new(),
            plugin_path: String::new(),
            plugin: None,
            update_json: String::new(),
            update_artifact_path: String::new(),
            update_result: String::new(),
            debugger: DebugUi::default(),
            last_error: None,
        })
    }

    fn poll_events(&mut self, context: &egui::Context) {
        self.runtime.tick(&mut self.config);
        if let Some(session) = &self.debugger.session {
            for event in session.events().try_iter() {
                if self.debugger.events.len() == 256 {
                    self.debugger.events.pop_front();
                }
                self.debugger.events.push_back(event);
            }
        }
        while let Ok(event) = GlobalHotKeyEvent::receiver().try_recv() {
            if event.id == self.restart_hotkey.id() && event.state == HotKeyState::Pressed
                && let Err(error) = self.runtime.restart_press(&self.config) {
                    self.last_error = Some(error.to_string());
                }
        }
        while TrayIconEvent::receiver().try_recv().is_ok() {
            self.show_window(context);
        }
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.tray_open {
                self.show_window(context);
            } else if event.id == self.tray_quit {
                self.should_quit = true;
            }
        }
        context.request_repaint_after(Duration::from_millis(100));
    }

    fn show_window(&mut self, context: &egui::Context) {
        self.window_visible = true;
        context.send_viewport_cmd(ViewportCommand::Visible(true));
        context.send_viewport_cmd(ViewportCommand::Focus);
    }

    fn rebind_restart_hotkey(&mut self) -> Result<()> {
        let replacement = HotKey::from_str(&self.hotkey_text)?;
        self.hotkey_manager.unregister(self.restart_hotkey)?;
        if let Err(error) = self.hotkey_manager.register(replacement) {
            let _ = self.hotkey_manager.register(self.restart_hotkey);
            return Err(error.into());
        }
        self.restart_hotkey = replacement;
        self.config.restart_hotkey = binding_from_string(&self.hotkey_text)?;
        self.config.save()
    }
}

impl eframe::App for AssistantApp {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(debug_assertions)]
        if !LOGIC_WITNESS.swap(true, std::sync::atomic::Ordering::Relaxed) {
            let _ = std::fs::write(
                r"C:\Users\alex3\AppData\Local\Temp\azazel-logic-witness.txt",
                "logic called",
            );
        }
        self.poll_events(context);
        #[cfg(debug_assertions)]
        {
            context.input(|input| {
                for event in &input.events {
                    if let egui::Event::Screenshot { image, .. } = event {
                        let rgba = image
                            .pixels
                            .iter()
                            .flat_map(|pixel| pixel.to_array())
                            .collect::<Vec<_>>();
                        let _ = image::save_buffer(
                            r"C:\Users\alex3\AppData\Local\Temp\azazel-egui-screenshot.png",
                            &rgba,
                            image.size[0] as u32,
                            image.size[1] as u32,
                            image::ColorType::Rgba8,
                        );
                    }
                }
            });
            if UI_WITNESS.load(std::sync::atomic::Ordering::Relaxed)
                && !SCREENSHOT_REQUESTED.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                context.send_viewport_cmd(ViewportCommand::Screenshot(Default::default()));
            }
        }
        if context.input(|input| input.viewport().close_requested()) && !self.should_quit {
            context.send_viewport_cmd(ViewportCommand::CancelClose);
            context.send_viewport_cmd(ViewportCommand::Visible(false));
            self.window_visible = false;
        }
        if self.should_quit {
            context.send_viewport_cmd(ViewportCommand::Close);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        #[cfg(debug_assertions)]
        if !UI_WITNESS.swap(true, std::sync::atomic::Ordering::Relaxed) {
            let _ = std::fs::write(
                r"C:\Users\alex3\AppData\Local\Temp\azazel-ui-witness.txt",
                "ui called",
            );
        }
        egui::CentralPanel::default().show(ui, |ui| {
            let workspace_height = ui.available_height();
            #[cfg(debug_assertions)]
            let _ = std::fs::write(
                r"C:\Users\alex3\AppData\Local\Temp\azazel-ui-stage-panel.txt",
                "panel",
            );
            ui.horizontal(|ui| {
                ui.set_min_height(workspace_height);
                spine(
                    ui,
                    &self.runtime.connection,
                    self.runtime.process.as_ref().map(|p| p.pid),
                );
                ui.separator();
                let mut rebind = false;
                let mut viewer = AssistantTabs {
                    config: &mut self.config,
                    runtime: &mut self.runtime,
                    manifest: &self.manifest,
                    lua: &self.lua,
                    lua_source: &mut self.lua_source,
                    lua_output: &mut self.lua_output,
                    plugin_path: &mut self.plugin_path,
                    plugin: &mut self.plugin,
                    update_json: &mut self.update_json,
                    update_artifact_path: &mut self.update_artifact_path,
                    update_result: &mut self.update_result,
                    debugger: &mut self.debugger,
                    hotkey_text: &mut self.hotkey_text,
                    rebind_hotkey: &mut rebind,
                    last_error: &mut self.last_error,
                };
                #[cfg(debug_assertions)]
                let _ = std::fs::write(
                    r"C:\Users\alex3\AppData\Local\Temp\azazel-ui-stage-before-dock.txt",
                    "before dock",
                );
                let workspace = ui.available_size();
                ui.allocate_ui_with_layout(
                    workspace,
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        DockArea::new(&mut self.dock)
                            .style(Style::from_egui(ui.style().as_ref()))
                            .show_inside(ui, &mut viewer);
                    },
                );
                #[cfg(debug_assertions)]
                let _ = std::fs::write(
                    r"C:\Users\alex3\AppData\Local\Temp\azazel-ui-stage-after-dock.txt",
                    "after dock",
                );
                if rebind && let Err(error) = self.rebind_restart_hotkey() {
                    self.last_error = Some(error.to_string());
                }
            });
            if let Some(error) = &self.last_error {
                ui.separator();
                ui.colored_label(theme::CINNABAR, error);
            }
        });
        #[cfg(debug_assertions)]
        let _ = std::fs::write(
            r"C:\Users\alex3\AppData\Local\Temp\azazel-ui-stage-after-panel.txt",
            "after panel",
        );
    }
}

struct AssistantTabs<'a> {
    config: &'a mut AppConfig,
    runtime: &'a mut RuntimeController,
    manifest: &'a BuildManifest,
    lua: &'a LuaEngine,
    lua_source: &'a mut String,
    lua_output: &'a mut String,
    plugin_path: &'a mut String,
    plugin: &'a mut Option<PluginHost>,
    update_json: &'a mut String,
    update_artifact_path: &'a mut String,
    update_result: &'a mut String,
    debugger: &'a mut DebugUi,
    hotkey_text: &'a mut String,
    rebind_hotkey: &'a mut bool,
    last_error: &'a mut Option<String>,
}

impl TabViewer for AssistantTabs<'_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Self::Tab) -> egui::Id {
        egui::Id::new(*tab)
    }

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        tab.label().into()
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Self::Tab) {
        match tab {
            Tab::Status => self.status(ui),
            Tab::Profiles => self.profiles(ui),
            Tab::Hotkeys => self.hotkeys(ui),
            Tab::Memory => self.memory(ui),
            Tab::Symbols => self.symbols(ui),
            Tab::Hooks => self.hooks(ui),
            Tab::Debugger => self.debugger(ui),
            Tab::Lua => self.lua(ui),
            Tab::Plugins => self.plugins(ui),
            Tab::Logs => self.logs(ui),
            Tab::Updates => self.updates(ui),
        }
    }
}

impl AssistantTabs<'_> {
    fn status(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("status-grid").striped(true).show(ui, |ui| {
            ui.strong("STATE");
            ui.monospace(connection_label(&self.runtime.connection));
            ui.end_row();
            ui.strong("PID");
            ui.monospace(
                self.runtime
                    .process
                    .as_ref()
                    .map(|process| process.pid.to_string())
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("HASH");
            ui.monospace(
                self.runtime
                    .process
                    .as_ref()
                    .map(|process| short_hash(&process.sha256))
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("EXE");
            ui.monospace(
                self.runtime
                    .process
                    .as_ref()
                    .map(|process| process.executable.display().to_string())
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("IMAGE");
            ui.monospace(
                self.runtime
                    .process
                    .as_ref()
                    .map(|process| format!("{} bytes", process.module_size))
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("PROFILE");
            ui.label(
                self.config
                    .active_profile()
                    .map(|profile| profile.name.as_str())
                    .unwrap_or("—"),
            );
            ui.end_row();
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Retry injection").clicked()
                && let Err(error) = self.runtime.retry_injection()
            {
                *self.last_error = Some(error.to_string());
            }
            if ui.button("Snapshot").clicked()
                && let Err(error) = self.runtime.request_snapshot()
            {
                *self.last_error = Some(error.to_string());
            }
            let restart_label = if self.runtime.restart_armed() {
                "RESTART ARMED"
            } else {
                "Restart"
            };
            if ui
                .add(
                    egui::Button::new(restart_label).fill(if self.runtime.restart_armed() {
                        theme::CINNABAR
                    } else {
                        theme::RAISED_IRON
                    }),
                )
                .clicked()
                && let Err(error) = self.runtime.restart_press(self.config)
            {
                *self.last_error = Some(error.to_string());
            }
        });
        if let Some(result) = &self.runtime.restart_result {
            ui.monospace(format!(
                "restart pid={} forced={} setup={} map={} roster={}",
                result.pid,
                result.forced_termination,
                result.participant_setup_applied,
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
            ));
        }
        ui.separator();
        ui.label("Restart settings source");
        let source = &mut self.config.restart_settings_source;
        let copy_live = ui.selectable_value(
            source,
            SettingsSource::CopyLastGame,
            "Copy last played game settings",
        );
        let use_profile = ui.selectable_value(
            source,
            SettingsSource::UseProfile,
            "Use set profile settings",
        );
        let launch_steam = ui.checkbox(
            &mut self.config.launch_via_steam,
            "Launch restarts through Steam",
        );
        if (copy_live.changed() || use_profile.changed() || launch_steam.changed())
            && let Err(error) = self.config.save()
        {
            *self.last_error = Some(error.to_string());
        }
        for difference in self.runtime.profile_differences(self.config) {
            ui.horizontal(|ui| {
                ui.colored_label(theme::BRASS, difference.field);
                ui.monospace(difference.profile);                ui.label("→");
                ui.monospace(difference.live);
            });
        }
    }

    fn profiles(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let mut delete = None;
            for (index, profile) in self.config.profiles.iter().enumerate() {
                let selected = self.config.active_profile == Some(profile.id);
                if ui.selectable_label(selected, &profile.name).clicked() {
                    self.config.active_profile = Some(profile.id);
                }
                if self.config.profiles.len() > 1 && ui.small_button("×").on_hover_text("Delete profile").clicked() {
                    delete = Some(index);
                }
            }
            if ui.button("+").clicked() {
                let mut profile = self
                    .config
                    .active_profile()
                    .cloned()
                    .unwrap_or_else(Profile::default);
                profile.id = uuid::Uuid::new_v4();
                profile.name = format!("Profile {}", self.config.profiles.len() + 1);
                self.config.active_profile = Some(profile.id);
                self.config.profiles.push(profile);
            }
            ui.checkbox(&mut self.config.profile_lock, "Lock");
            if let Some(index) = delete {
                let removed = self.config.profiles.remove(index);
                if self.config.active_profile == Some(removed.id) {
                    self.config.active_profile =
                        self.config.profiles.first().map(|profile| profile.id);
                }
                if let Err(error) = self.config.save() {
                    *self.last_error = Some(error.to_string());
                }
            }
        });
        ui.separator();
        let Some(profile) = self.config.active_profile_mut() else {
            ui.label("No profile");
            return;
        };
        egui::Grid::new("profile-fields")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut profile.name);
                ui.end_row();
                ui.label("Class");
                egui::ComboBox::from_id_salt("profile-class")
                    .selected_text(crate::classes::class_name(profile.human_class_id))
                    .show_ui(ui, |ui| {
                        for (id, name) in crate::classes::CLASS_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut profile.human_class_id, id as i16, *name);
                        }
                    });
                ui.end_row();
                ui.label("Players");
                ui.add(egui::DragValue::new(&mut profile.participant_count).range(2..=24));
                ui.end_row();
                ui.label("AI difficulty");
                ui.add(egui::DragValue::new(&mut profile.ai_difficulty).range(1..=12));
                ui.end_row();
                ui.label("Map");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut profile.map.width).range(20..=100));
                    ui.label("×");
                    ui.add(egui::DragValue::new(&mut profile.map.height).range(20..=100));
                });
                ui.end_row();
                ui.label("Society");
                ui.add(egui::DragValue::new(&mut profile.map.society).range(0..=6));
                ui.end_row();
                ui.label("North / South");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut profile.map.north_percent).range(0..=100));
                    ui.add(egui::DragValue::new(&mut profile.map.south_percent).range(0..=100));
                });
                ui.end_row();
                ui.label("Wilder");
                let mut wilder = profile.rules.independent_strength > 1;
                if ui.checkbox(&mut wilder, "").changed() {
                    profile.rules.independent_strength = if wilder { 2 } else { 1 };
                }
                ui.end_row();
                ui.label("Common cause");
                ui.checkbox(&mut profile.rules.common_cause, "");
                ui.end_row();
                ui.label("Unique classes");
                ui.checkbox(&mut profile.rules.unique_random_classes, "");
                ui.end_row();
            });
        if ui.button("Save changes").clicked()
            && let Err(error) = self.config.save()
        {
            *self.last_error = Some(error.to_string());
        }
    }

    fn hotkeys(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Restart");
            ui.text_edit_singleline(self.hotkey_text);
            if ui.button("Bind").clicked() {
                *self.rebind_hotkey = true;
            }
        });
        ui.separator();
        let mut remove = None;
        for (index, rule) in self.config.remaps.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.checkbox(&mut rule.enabled, "");
                match &mut rule.trigger {
                    InputTrigger::Keyboard {
                        virtual_key,
                        control,
                        alt,
                        shift,
                    } => {
                        ui.label("Key");
                        ui.add(egui::DragValue::new(virtual_key));
                        ui.checkbox(control, "Ctrl");
                        ui.checkbox(alt, "Alt");
                        ui.checkbox(shift, "Shift");
                    }
                    InputTrigger::MouseButton { button } => {
                        egui::ComboBox::from_id_salt(("mouse", index))
                            .selected_text(format!("{button:?}"))
                            .show_ui(ui, |ui| {
                                for candidate in [
                                    MouseButton::Left,
                                    MouseButton::Right,
                                    MouseButton::Middle,
                                    MouseButton::X1,
                                    MouseButton::X2,
                                ] {
                                    ui.selectable_value(
                                        button,
                                        candidate,
                                        format!("{candidate:?}"),
                                    );
                                }
                            });
                    }
                }
                ui.label("→");
                ui.add(egui::DragValue::new(&mut rule.action.virtual_key));
                if ui.button("×").clicked() {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = remove {
            self.config.remaps.remove(index);
            self.runtime.update_remaps(self.config);
        }
        ui.horizontal(|ui| {
            if ui.button("Add key").clicked() {
                self.config.remaps.push(RemapRule {
                    enabled: true,
                    trigger: InputTrigger::Keyboard {
                        virtual_key: b'Q' as u16,
                        control: false,
                        alt: false,
                        shift: false,
                    },
                    action: InputAction {
                        virtual_key: b'W' as u16,
                        control: false,
                        alt: false,
                        shift: false,
                    },
                });
            }
            if ui.button("Add mouse").clicked() {
                self.config.remaps.push(RemapRule {
                    enabled: true,
                    trigger: InputTrigger::MouseButton {
                        button: MouseButton::X1,
                    },
                    action: InputAction {
                        virtual_key: b'Q' as u16,
                        control: false,
                        alt: false,
                        shift: false,
                    },
                });
            }
            if ui.button("Save").clicked() {
                self.runtime.update_remaps(self.config);
                if let Err(error) = self.config.save() {
                    *self.last_error = Some(error.to_string());
                }
            }
        });
    }

    fn memory(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.runtime.snapshot.read();
        let Some(snapshot) = snapshot.as_ref() else {
            ui.label("No snapshot");
            return;
        };
        egui::Grid::new("memory-grid").striped(true).show(ui, |ui| {
            ui.label("Turn");
            ui.monospace(snapshot.lifecycle.turn.to_string());
            ui.end_row();
            ui.label("Plane");
            ui.monospace(snapshot.lifecycle.plane.to_string());
            ui.end_row();
            ui.label("World");
            ui.monospace(format!(
                "{} × {} / {}",
                snapshot.map.width, snapshot.map.height, snapshot.map.real_width
            ));
            ui.end_row();
            ui.label("Society");
            ui.monospace(snapshot.options.society.to_string());
            ui.end_row();
        });
        ui.separator();
        ScrollArea::vertical().show(ui, |ui| {
            for participant in &snapshot.participants {
                ui.monospace(format!(
                    "{:02}  ctl={:>3}  class={:>3} {:<16}  start=({:>3},{:>3})  team={:?}  diff={:?}",
                    participant.slot,
                    participant.controller,
                    participant.class_id,
                    crate::classes::class_name(participant.class_id),
                    participant.start_x,
                    participant.start_y,
                    participant.team,
                    participant.difficulty,
                ));
            }
        });
    }

    fn symbols(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            for function in &self.manifest.functions {
                ui.horizontal(|ui| {
                    ui.monospace(function.rva.to_string());
                    ui.strong(&function.id);
                    ui.colored_label(theme::DIM_BONE, &function.subsystem);
                });
            }
            ui.separator();
            for global in &self.manifest.globals {
                ui.horizontal(|ui| {
                    ui.monospace(global.rva.to_string());
                    ui.label(&global.id);
                    ui.colored_label(theme::DIM_BONE, &global.data_type);
                });
            }
        });
    }

    fn hooks(&mut self, ui: &mut egui::Ui) {
        for capability in &self.runtime.capabilities.entries {
            ui.horizontal(|ui| {
                let color = match capability.state {
                    CapabilityState::Available => theme::VERDIGRIS,
                    CapabilityState::Disabled => theme::BRASS,
                    CapabilityState::Failed => theme::CINNABAR,
                };
                ui.colored_label(color, &capability.id);
                if capability.id.starts_with("hook.")
                    && capability.state == CapabilityState::Available
                {
                    let symbol = capability_symbol(&capability.id);
                    if ui.button("Enable").clicked()
                        && let Err(error) = self.runtime.set_hook(symbol, true)
                    {
                        *self.last_error = Some(error.to_string());
                    }
                    if ui.button("Disable").clicked()
                        && let Err(error) = self.runtime.set_hook(symbol, false)
                    {
                        *self.last_error = Some(error.to_string());
                    }
                }
                if let Some(reason) = &capability.reason {
                    ui.colored_label(theme::DIM_BONE, reason);
                }
            });
        }
        ui.separator();
        ScrollArea::vertical().show(ui, |ui| {
            for event in self.runtime.hook_events.iter().rev() {
                ui.monospace(format!(
                    "#{:06} t{:>4} {:>10} {}",
                    event.sequence, event.thread_id, event.rva, event.symbol
                ));
            }
        });
    }

    fn debugger(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.debugger.session.is_none() {
                if ui.button("Attach").clicked() {
                    match self.runtime.process.as_ref() {
                        Some(process) => match DebuggerSession::attach(process.pid) {
                            Ok(session) => self.debugger.session = Some(session),
                            Err(error) => *self.last_error = Some(error.to_string()),
                        },
                        None => *self.last_error = Some("CoE5 is not running".into()),
                    }
                }
            } else if ui.button("Detach").clicked()
                && let Some(session) = self.debugger.session.take() {
                    let _ = session.send(DebuggerCommand::Detach);
                }
            if let Some(session) = &self.debugger.session {
                if ui.button("Pause").clicked() {
                    let _ = session.send(DebuggerCommand::Pause);
                }
                if ui.button("Continue").clicked() {
                    let _ = session.send(DebuggerCommand::Continue);
                }
                let step_thread = self
                    .debugger
                    .events
                    .iter()
                    .rev()
                    .find_map(DebuggerEvent::thread_id);
                if ui.button("Step").clicked()
                    && let Some(thread_id) = step_thread
                {
                    let _ = session.send(DebuggerCommand::Step { thread_id });
                }
            }
        });
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.debugger.address);
            ui.add(egui::DragValue::new(&mut self.debugger.length).range(1..=65536));
            if ui.button("Disassemble").clicked()
                && let Some(session) = &self.debugger.session
            {
                match parse_address(&self.debugger.address)
                    .and_then(|address| session.disassemble(address, self.debugger.length))
                {
                    Ok(lines) => self.debugger.disassembly = lines,
                    Err(error) => *self.last_error = Some(error.to_string()),
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Breakpoint");
            ui.text_edit_singleline(&mut self.debugger.breakpoint);
            if ui.button("Add").clicked()
                && let Some(session) = &self.debugger.session
                && let Ok(address) = parse_address(&self.debugger.breakpoint)
            {
                let _ = session.send(DebuggerCommand::AddBreakpoint { address });
            }
            if ui.button("Remove").clicked()
                && let Some(session) = &self.debugger.session
                && let Ok(address) = parse_address(&self.debugger.breakpoint)
            {
                let _ = session.send(DebuggerCommand::RemoveBreakpoint { address });
            }
        });
        ScrollArea::vertical().show(ui, |ui| {
            for line in &self.debugger.disassembly {
                ui.horizontal(|ui| {
                    ui.monospace(format!("{:016x}", line.address));
                    ui.colored_label(
                        theme::DIM_BONE,
                        line.bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    ui.monospace(&line.text);
                });
            }
            for event in self.debugger.events.iter().rev().take(64) {
                ui.monospace(event.summary());
            }
        });
    }

    fn lua(&mut self, ui: &mut egui::Ui) {
        ui.add(
            TextEdit::multiline(self.lua_source)
                .font(egui::TextStyle::Monospace)
                .desired_rows(12),
        );
        if ui.button("Run").clicked() {
            *self.lua_output = self
                .lua
                .execute(self.lua_source)
                .unwrap_or_else(|error| format!("{error:#}"));
        }
        ui.separator();
        ui.monospace(self.lua_output.as_str());
    }

    fn plugins(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.text_edit_singleline(self.plugin_path);
            if self.plugin.is_none() && ui.button("Start").clicked() {
                match PluginHost::start(PathBuf::from(&*self.plugin_path).as_path()) {
                    Ok(plugin) => *self.plugin = Some(plugin),
                    Err(error) => *self.last_error = Some(error.to_string()),
                }
            }
            if self.plugin.is_some() && ui.button("Stop").clicked() {
                *self.plugin = None;
            }
        });
        if let Some(plugin) = self.plugin.as_ref() {
            ui.monospace(plugin.executable().display().to_string());
            if ui.button("Ping").clicked() {
                let _ = plugin.send(Message::Ping { nonce: 1 });
            }
            for event in plugin.events().try_iter() {
                ui.monospace(event.summary());
            }
        }
    }

    fn logs(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for entry in &self.runtime.logs {
                let color = match entry.level {
                    DiagnosticLevel::Error => theme::CINNABAR,
                    DiagnosticLevel::Warning => theme::BRASS,
                    DiagnosticLevel::Info => theme::BONE,
                    _ => theme::DIM_BONE,
                };
                ui.horizontal(|ui| {
                    ui.colored_label(color, format!("{:?}", entry.level));
                    ui.monospace(&entry.component);
                    ui.label(&entry.message);
                });
            }
        });
    }

    fn updates(&mut self, ui: &mut egui::Ui) {
        ui.add(
            TextEdit::multiline(self.update_json)
                .font(egui::TextStyle::Monospace)
                .desired_rows(12),
        );
        ui.text_edit_singleline(self.update_artifact_path);
        if ui.button("Verify manifest").clicked() {
            *self.update_result = match serde_json::from_str::<UpdateEnvelope>(self.update_json) {
                Ok(envelope) => envelope
                    .verify(&self.config.update.public_key_base64)
                    .map(|_| format!("Verified {}", envelope.signed.version))
                    .unwrap_or_else(|error| format!("{error:#}")),
                Err(error) => error.to_string(),
            };
        }
        if ui.button("Verify artifact").clicked() {
            *self.update_result = match serde_json::from_str::<UpdateEnvelope>(self.update_json) {
                Ok(envelope) => envelope
                    .signed
                    .artifacts
                    .first()
                    .context("manifest has no artifacts")
                    .and_then(|artifact| {
                        verify_artifact(Path::new(self.update_artifact_path), artifact)
                    })
                    .map(|_| "Artifact verified".into())
                    .unwrap_or_else(|error| format!("{error:#}")),
                Err(error) => error.to_string(),
            };
        }
        ui.monospace(self.update_result.as_str());
    }
}

fn spine(ui: &mut egui::Ui, state: &ConnectionState, pid: Option<u32>) {
    ui.vertical(|ui| {
        ui.set_width(86.0);
        ui.label(
            RichText::new("AZAZEL")
                .size(18.0)
                .color(theme::BRASS)
                .strong(),
        );
        ui.label(RichText::new("COE5").size(12.0).color(theme::DIM_BONE));
        ui.add_space(12.0);
        let stages = [
            ("PROC", pid.is_some()),
            ("HASH", pid.is_some()),
            (
                "PIPE",
                matches!(
                    state,
                    ConnectionState::Connecting | ConnectionState::Injected
                ),
            ),
            ("HOOK", matches!(state, ConnectionState::Injected)),
        ];
        for (label, active) in stages {
            let degraded = matches!(state, ConnectionState::Degraded(_));
            let color = if label == "PIPE" && active && !degraded {
                theme::LAPIS
            } else {
                theme::state_color(active, degraded)
            };
            ui.colored_label(color, "◆");
            ui.monospace(label);
            ui.add_space(8.0);
        }
    });
}

fn create_tray() -> Result<(TrayIcon, MenuId, MenuId)> {
    let menu = Menu::new();
    let open = MenuItem::with_id("open", "Open", true, None);
    let quit = MenuItem::with_id("quit", "Quit", true, None);
    menu.append(&open)?;
    menu.append(&quit)?;
    let open_id = open.id().clone();
    let quit_id = quit.id().clone();
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("Azazel's CoE5 Assistant")
        .with_icon(codex_icon()?)
        .build()?;
    Ok((tray, open_id, quit_id))
}

fn codex_icon() -> Result<Icon> {
    let size = 32usize;
    let mut rgba = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let index = (y * size + x) * 4;
            let border = x < 2 || y < 2 || x >= size - 2 || y >= size - 2;
            let stroke = (x as isize - 16).abs() <= 1
                || (y > 7 && y < 25 && (x as isize - y as isize + 7).abs() <= 1)
                || (y > 7 && y < 25 && (x as isize + y as isize - 39).abs() <= 1);
            let color = if stroke {
                [187, 143, 70, 255]
            } else if border {
                [62, 139, 124, 255]
            } else {
                [18, 19, 24, 255]
            };
            rgba[index..index + 4].copy_from_slice(&color);
        }
    }
    Ok(Icon::from_rgba(rgba, size as u32, size as u32)?)
}

fn hotkey_string(config: &AppConfig) -> String {
    let mut parts = config
        .restart_hotkey
        .modifiers
        .iter()
        .map(|modifier| match modifier {
            Modifier::Control => "control",
            Modifier::Alt => "alt",
            Modifier::Shift => "shift",
            Modifier::Super => "super",
        })
        .collect::<Vec<_>>();
    parts.push(&config.restart_hotkey.code);
    parts.join("+")
}

fn binding_from_string(value: &str) -> Result<crate::config::HotkeyBinding> {
    let tokens = value.split('+').map(str::trim).collect::<Vec<_>>();
    let code = tokens.last().context("hotkey has no key")?.to_string();
    let modifiers = tokens[..tokens.len().saturating_sub(1)]
        .iter()
        .map(|modifier| match modifier.to_ascii_lowercase().as_str() {
            "control" | "ctrl" => Ok(Modifier::Control),
            "alt" => Ok(Modifier::Alt),
            "shift" => Ok(Modifier::Shift),
            "super" | "win" => Ok(Modifier::Super),
            other => anyhow::bail!("unknown modifier {other}"),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(crate::config::HotkeyBinding { modifiers, code })
}

fn connection_label(state: &ConnectionState) -> String {
    match state {
        ConnectionState::NoGame => "NO GAME".into(),
        ConnectionState::Connecting => "CONNECTING".into(),
        ConnectionState::Injected => "INJECTED".into(),
        ConnectionState::Degraded(reason) => format!("DEGRADED · {reason}"),
        ConnectionState::Restarting => "RESTARTING".into(),
    }
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

fn capability_symbol(capability: &str) -> &'static str {
    match capability {
        "hook.game_loop" => "game_main_loop_run_turns",
        "hook.world_reset" => "world_reset_static_state",
        "hook.participant_defaults" => "newgame_apply_participant_defaults",
        "hook.game_over" => "game_over_detect_and_announce",
        "hook.rng_stack" => "rng_state_stack_push",
        _ => "",
    }
}

fn parse_address(value: &str) -> Result<u64> {
    let value = value.trim();
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
        .with_context(|| format!("invalid address {value}"))
}
