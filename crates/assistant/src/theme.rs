use egui::{Color32, Context, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Theme, Visuals};

pub const INK: Color32 = Color32::from_rgb(18, 19, 24);
pub const IRON: Color32 = Color32::from_rgb(30, 31, 37);
pub const RAISED_IRON: Color32 = Color32::from_rgb(40, 41, 47);
pub const BONE: Color32 = Color32::from_rgb(218, 211, 194);
pub const DIM_BONE: Color32 = Color32::from_rgb(157, 153, 143);
pub const VERDIGRIS: Color32 = Color32::from_rgb(62, 139, 124);
pub const BRASS: Color32 = Color32::from_rgb(187, 143, 70);
pub const CINNABAR: Color32 = Color32::from_rgb(196, 72, 58);
pub const LAPIS: Color32 = Color32::from_rgb(75, 101, 153);

pub fn apply(context: &Context) {
    context.set_theme(Theme::Dark);
    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(BONE);
    visuals.panel_fill = INK;
    visuals.window_fill = IRON;
    visuals.extreme_bg_color = Color32::from_rgb(10, 11, 15);
    visuals.faint_bg_color = RAISED_IRON;
    visuals.code_bg_color = Color32::from_rgb(12, 13, 17);
    visuals.selection.bg_fill = VERDIGRIS;
    visuals.selection.stroke = Stroke::new(1.0, BONE);
    visuals.hyperlink_color = BRASS;
    visuals.warn_fg_color = BRASS;
    visuals.error_fg_color = CINNABAR;
    visuals.widgets.noninteractive.bg_fill = IRON;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(59, 58, 56));
    visuals.widgets.inactive.bg_fill = RAISED_IRON;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(68, 67, 63));
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(47, 61, 61);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, VERDIGRIS);
    visuals.widgets.active.bg_fill = Color32::from_rgb(57, 76, 72);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, BRASS);
    visuals.window_corner_radius = CornerRadius::ZERO;
    visuals.menu_corner_radius = CornerRadius::ZERO;

    let mut style = (*context.style_of(Theme::Dark)).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.window_margin = egui::Margin::same(10);
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(20.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.0, FontFamily::Monospace),
    );
    style.visuals = visuals;
    context.set_style_of(Theme::Dark, style);
}

pub fn state_color(healthy: bool, degraded: bool) -> Color32 {
    if degraded {
        CINNABAR
    } else if healthy {
        VERDIGRIS
    } else {
        DIM_BONE
    }
}
