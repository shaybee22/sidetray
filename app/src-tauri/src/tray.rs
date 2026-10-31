//! System tray icon: Open / Quit menu, and the unread count as a red badge on
//! the icon and in the tooltip.

use crate::db;
use crate::state::App;
use anyhow::Result;
use image::{imageops::FilterType, Rgba, RgbaImage};
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

const TRAY_ID: &str = "main";
/// The monogram without its frame, made from app-icon.png by icons/make-tray-icon.py.
const TRAY_ICON: &[u8] = include_bytes!("../icons/tray.png");

pub fn create(handle: &AppHandle) -> Result<()> {
    let open = MenuItem::with_id(handle, "open", "Open Side Tray", true, None::<&str>)?;
    let quit = MenuItem::with_id(handle, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(handle, &[&open, &PredefinedMenuItem::separator(handle)?, &quit])?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(0))
        .tooltip("Side Tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id.as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                show_main(tray.app_handle());
            }
        })
        .build(handle)?;
    Ok(())
}

/// Bring the main window back from the tray (or from behind other windows).
pub fn show_main(handle: &AppHandle) {
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Whether the person is looking at the app right now.
pub fn main_window_focused(handle: &AppHandle) -> bool {
    handle.get_webview_window("main").is_some_and(|w| {
        w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false) && is_foreground(&w)
    })
}

/// Ask Windows which window is in front: `is_focused` can say yes for a window
/// that started behind others (Windows refuses to bring a background launch forward).
#[cfg(windows)]
fn is_foreground(w: &tauri::WebviewWindow) -> bool {
    #[link(name = "user32")]
    extern "system" {
        fn GetForegroundWindow() -> *mut std::ffi::c_void;
    }
    // SAFETY: no arguments; returns a window handle or null.
    let front = unsafe { GetForegroundWindow() };
    w.hwnd().is_ok_and(|h| !front.is_null() && h.0 == front)
}

#[cfg(not(windows))]
fn is_foreground(w: &tauri::WebviewWindow) -> bool {
    w.is_focused().unwrap_or(false)
}

/// Redraw the badge and tooltip from the unread count and pending joins.
pub fn refresh(handle: &AppHandle, app: &App) {
    let unread = db::unread(&app.db()).unwrap_or(0).max(0) as u32;
    let joins = app.pending_joins.load(Ordering::SeqCst);
    let Some(tray) = handle.tray_by_id(TRAY_ID) else { return };
    let mut tip = String::from("Side Tray");
    match unread {
        0 => {}
        1 => tip.push_str(" — 1 new post or comment"),
        n => tip.push_str(&format!(" — {n} new posts and comments")),
    }
    match joins {
        0 => {}
        1 => tip.push_str("\n1 join request waiting"),
        n => tip.push_str(&format!("\n{n} join requests waiting")),
    }
    let _ = tray.set_tooltip(Some(&tip));
    let _ = tray.set_icon(Some(icon(unread + joins as u32)));
}

/// The tray icon's pixel size: Windows asks for a small icon (16 px at 100%
/// scaling, 24 at 150%...), and drawing at that size keeps the badge digits sharp
/// instead of letting Windows shrink a bigger image.
fn size() -> u32 {
    static SIZE: OnceLock<u32> = OnceLock::new();
    *SIZE.get_or_init(|| system_small_icon().clamp(16, 64))
}

#[cfg(windows)]
fn system_small_icon() -> u32 {
    #[link(name = "user32")]
    extern "system" {
        fn GetSystemMetrics(index: i32) -> i32;
    }
    const SM_CXSMICON: i32 = 49;
    // SAFETY: a plain metrics query.
    unsafe { GetSystemMetrics(SM_CXSMICON) }.max(0) as u32
}

#[cfg(not(windows))]
fn system_small_icon() -> u32 {
    32
}

fn base() -> &'static RgbaImage {
    static BASE: OnceLock<RgbaImage> = OnceLock::new();
    BASE.get_or_init(|| render_base(size()))
}

/// The monogram (icons/tray.png) at `s` px with a thin dark edge, so the gold
/// stands out on light taskbars as well as dark ones.
fn render_base(s: u32) -> RgbaImage {
    let Ok(src) = image::load_from_memory(TRAY_ICON) else {
        return RgbaImage::from_pixel(s, s, Rgba([190, 140, 40, 255]));
    };
    let logo = image::imageops::resize(&src.to_rgba8(), s, s, FilterType::Lanczos3);
    let mut out = RgbaImage::new(s, s);
    for (x, y, px) in out.enumerate_pixels_mut() {
        let mut edge = 0u8;
        for ny in y.saturating_sub(1)..=(y + 1).min(s - 1) {
            for nx in x.saturating_sub(1)..=(x + 1).min(s - 1) {
                edge = edge.max(logo.get_pixel(nx, ny)[3]);
            }
        }
        *px = over(*logo.get_pixel(x, y), Rgba([70, 40, 0, (edge as u32 * 85 / 100) as u8]));
    }
    out
}

/// `top` composited over `bottom` (straight alpha).
fn over(top: Rgba<u8>, bottom: Rgba<u8>) -> Rgba<u8> {
    let (ta, ba) = (top[3] as f32 / 255.0, bottom[3] as f32 / 255.0);
    let a = ta + ba * (1.0 - ta);
    if a <= 0.0 {
        return Rgba([0, 0, 0, 0]);
    }
    let mix = |t: u8, b: u8| ((t as f32 * ta + b as f32 * ba * (1.0 - ta)) / a).round() as u8;
    Rgba([mix(top[0], bottom[0]), mix(top[1], bottom[1]), mix(top[2], bottom[2]), (a * 255.0).round() as u8])
}

fn icon(count: u32) -> Image<'static> {
    let mut img = base().clone();
    if count > 0 {
        draw_badge(&mut img, count);
    }
    let (w, h) = img.dimensions();
    Image::new_owned(img.into_raw(), w, h)
}

/// 3×5 pixel digits (and "+"), one row per u8, high bit on the left.
const GLYPHS: [[u8; 5]; 11] = [
    [0b111, 0b101, 0b101, 0b101, 0b111],
    [0b010, 0b110, 0b010, 0b010, 0b111],
    [0b111, 0b001, 0b111, 0b100, 0b111],
    [0b111, 0b001, 0b111, 0b001, 0b111],
    [0b101, 0b101, 0b111, 0b001, 0b001],
    [0b111, 0b100, 0b111, 0b001, 0b111],
    [0b111, 0b100, 0b111, 0b101, 0b111],
    [0b111, 0b001, 0b001, 0b010, 0b010],
    [0b111, 0b101, 0b111, 0b101, 0b111],
    [0b111, 0b101, 0b111, 0b001, 0b111],
    [0b000, 0b010, 0b111, 0b010, 0b000],
];

const BADGE_RED: Rgba<u8> = Rgba([214, 40, 40, 255]);

/// A red disc (a pill for "9+") in the bottom-right corner with the count in
/// white, cut out of the icon by a transparent gap so it reads on any taskbar.
/// Everything is laid out on whole pixels, so at 16 px the digits stay crisp.
fn draw_badge(img: &mut RgbaImage, count: u32) {
    let s = img.width();
    let scale = (s / 16).max(1);
    let glyphs: Vec<usize> = if count > 9 { vec![9, 10] } else { vec![count as usize] };
    let n = glyphs.len() as u32;
    let text_w = n * 3 * scale + (n - 1) * scale;
    let pad = 2 * scale;
    let h = 5 * scale + 2 * pad;
    let w = (text_w + 2 * pad).max(h);
    let (bx, by) = (s - w, s - h);

    // Distance from each pixel centre to the pill's spine, for an anti-aliased edge.
    let r = h as f32 / 2.0;
    let (cy, cx0, cx1) = (by as f32 + r, bx as f32 + r, (bx + w) as f32 - r);
    let gap = scale as f32;
    let y_from = by.saturating_sub(scale + 1);
    let x_from = bx.saturating_sub(scale + 1);
    for y in y_from..s {
        for x in x_from..s {
            let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
            let d = ((px - px.clamp(cx0, cx1)).powi(2) + (py - cy).powi(2)).sqrt();
            let fill = (r - d + 0.5).clamp(0.0, 1.0);
            let keep = (d - r - gap + 0.5).clamp(0.0, 1.0);
            let p = img.get_pixel_mut(x, y);
            p[3] = (p[3] as f32 * keep).round() as u8;
            if fill > 0.0 {
                let red = Rgba([BADGE_RED[0], BADGE_RED[1], BADGE_RED[2], (fill * 255.0).round() as u8]);
                *p = over(red, *p);
            }
        }
    }

    let (x0, y0) = (bx + (w - text_w) / 2, by + pad);
    for (i, g) in glyphs.iter().enumerate() {
        let gx = x0 + i as u32 * 4 * scale;
        for (row, bits) in GLYPHS[*g].iter().enumerate() {
            for col in 0..3 {
                if bits & (0b100 >> col) != 0 {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            img.put_pixel(gx + col * scale + dx, y0 + row as u32 * scale + dy, Rgba([255, 255, 255, 255]));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_draws_inside_the_icon() {
        for s in [16, 20, 24, 32, 48] {
            let base = render_base(s);
            for n in [1, 7, 9, 10, 250] {
                let mut img = base.clone();
                draw_badge(&mut img, n);
                assert_eq!(img.dimensions(), (s, s));
                // The badge's right edge, halfway down, is (near enough) solid red.
                let h = 9 * (s / 16);
                let p = img.get_pixel(s - 1, s - h + h / 2);
                assert_eq!(p.0[..3], BADGE_RED.0[..3]);
                assert!(p[3] > 240, "{s} px, count {n}: alpha {}", p[3]);
            }
        }
    }

    /// Writes the tray icon at each size and count as PNGs, to look at:
    /// SIDETRAY_TRAY_PREVIEW=<dir> cargo test tray_previews -- --ignored
    #[test]
    #[ignore]
    fn tray_previews() {
        let dir = std::path::PathBuf::from(std::env::var("SIDETRAY_TRAY_PREVIEW").expect("set SIDETRAY_TRAY_PREVIEW"));
        std::fs::create_dir_all(&dir).unwrap();
        for s in [16, 20, 24, 32] {
            let base = render_base(s);
            for n in [0, 1, 3, 9, 12] {
                let mut img = base.clone();
                if n > 0 {
                    draw_badge(&mut img, n);
                }
                img.save(dir.join(format!("tray-{s}-{n}.png"))).unwrap();
            }
        }
    }
}
