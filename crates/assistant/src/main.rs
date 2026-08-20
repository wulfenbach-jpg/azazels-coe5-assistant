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
use windows::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError},
    System::Threading::CreateMutexW,
    UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_SHOWNORMAL},
};
use windows::core::w;

fn main() -> eframe::Result {
    if !acquire_single_instance() {
        // Another Assistant already runs; surface its window and leave.
        if let Ok(window) = unsafe { FindWindowW(None, w!("Azazel's CoE5 Assistant")) } {
            unsafe {
                let _ = ShowWindow(window, SW_SHOWNORMAL);
                let _ = SetForegroundWindow(window);
            }
        }
        return Ok(());
    }
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

/// Claims the single-instance named mutex. Returns `false` when another
/// Assistant already holds it. The handle is intentionally leaked so the
/// mutex stays held for the process lifetime.
fn acquire_single_instance() -> bool {
    let Ok(_mutex) = (unsafe {
        CreateMutexW(None, true, w!("Azazel.CoE5Assistant.SingleInstance"))
    }) else {
        return true;
    };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return false;
    }
    // The raw HANDLE is never closed (the windows crate has no RAII for it),
    // so the mutex stays held for the process lifetime.
    true
}
