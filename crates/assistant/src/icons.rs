//! Real icon glyphs from the Windows **Segoe MDL2 Assets** icon font
//! (`C:\Windows\Fonts\segmdl2.ttf`, present on Windows 10/11). The font's
//! glyphs live in the Private Use Area; the codepoints below come from the
//! authoritative MDL2 symbol list (Microsoft docs / reflectronic's complete
//! enum). The font is loaded from the system at startup — Segoe fonts are
//! not freely redistributable, so it is never embedded.

use std::sync::Arc;

pub const GAME: &str = "\u{E7FC}"; // Game — PROC stage
pub const SHIELD: &str = "\u{EA18}"; // Shield — HASH stage
pub const LINK: &str = "\u{E71B}"; // Link — PIPE stage
pub const REPAIR: &str = "\u{E90F}"; // Repair/wrench — HOOK stage
pub const STATUS_CHECK: &str = "\u{F13E}"; // StatusCircleCheckmark — Status tab
pub const CONTACT: &str = "\u{E77B}"; // Contact — Profiles tab
pub const KEYBOARD: &str = "\u{E765}"; // KeyboardClassic — Hotkeys tab
pub const DIAGNOSTIC: &str = "\u{E9D9}"; // Diagnostic — Memory tab
pub const CODE: &str = "\u{E943}"; // Code — Symbols tab
pub const PUZZLE: &str = "\u{EA86}"; // Puzzle — Plugins tab
pub const COMMAND_PROMPT: &str = "\u{E756}"; // CommandPrompt — Debugger tab
pub const PLAY: &str = "\u{E768}"; // Play — Lua tab
pub const DOCUMENT: &str = "\u{E8A5}"; // Document — Logs tab
pub const DOWNLOAD: &str = "\u{E896}"; // Download — Updates tab
pub const REFRESH: &str = "\u{E72C}"; // Refresh — retry injection
pub const CAMERA: &str = "\u{E722}"; // Camera — snapshot
pub const REPLAY: &str = "\u{EF3B}"; // Replay — restart
pub const DELETE: &str = "\u{E74D}"; // Delete (trash) — remove buttons
pub const CHEVRON_RIGHT: &str = "\u{E76C}"; // ChevronRight — mapping arrows
pub const CHECK_MARK: &str = "\u{E73E}"; // CheckMark — completed result
pub const ERROR: &str = "\u{E783}"; // Error — degraded connection

/// Registers the system Segoe MDL2 Assets font as a fallback family so the
/// icon codepoints render as real glyphs. If the font cannot be read the UI
/// degrades gracefully to text-only labels.
pub fn install(context: &egui::Context) {
    let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segmdl2.ttf") else {
        tracing::warn!("Segoe MDL2 Assets icon font not found; running without icons");
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert("mdl2".to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("mdl2".to_owned());
    context.set_fonts(fonts);
}
