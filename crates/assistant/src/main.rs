#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod classes;
mod config;
mod debugger;
mod icons;
mod input;
mod ipc;
mod lua;
mod plugins;
mod process;
mod restart;
mod runtime;
mod theme;
mod update;

use app::AssistantApp;

fn main() -> eframe::Result {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "azazel_coe5_assistant=info".into()),
        )
        .try_init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Azazel's CoE5 Assistant")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1024.0, 680.0]),
        renderer: eframe::Renderer::Glow,
        centered: true,
        run_and_return: false,
        ..Default::default()
    };

    eframe::run_native(
        "Azazel's CoE5 Assistant",
        options,
        Box::new(|context| {
            icons::install(&context.egui_ctx);
            Ok(Box::new(AssistantApp::new(context)?))
        }),
    )
}
