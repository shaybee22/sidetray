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
const SIZE: u32 = 32;
const APP_ICON: &[u8] = include_bytes!("../icons/icon.png");

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

fn base() -> &'static RgbaImage {
    static BASE: OnceLock<RgbaImage> = OnceLock::new();
    BASE.get_or_init(|| match image::load_from_memory(APP_ICON) {
        Ok(img) => image::imageops::resize(&img.to_rgba8(), SIZE, SIZE, FilterType::Lanczos3),
        Err(_) => RgbaImage::from_pixel(SIZE, SIZE, Rgba([60, 90, 160, 255])),
    })
}

fn icon(count: u32) -> Image<'static> {
    let mut img = base().clone();
    if count > 0 {
        draw_badge(&mut img, count);
    }
    Image::new_owned(img.into_raw(), SIZE, SIZE)
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

/// A red disc in the bottom-right corner with the count in white ("9+" past nine).
fn draw_badge(img: &mut RgbaImage, count: u32) {
    let (cx, cy, r) = (22.5f32, 22.5f32, 9.5f32);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let d = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
            if d <= r + 1.0 {
                // A white ring keeps the badge readable on any icon colour.
                let px = if d <= r { Rgba([214, 40, 40, 255]) } else { Rgba([255, 255, 255, 255]) };
                img.put_pixel(x, y, px);
            }
        }
    }
    let glyphs: Vec<usize> = if count > 9 { vec![9, 10] } else { vec![count as usize] };
    let scale = 2u32;
    let width = glyphs.len() as u32 * 3 * scale + (glyphs.len() as u32 - 1) * scale;
    let (x0, y0) = ((cx - width as f32 / 2.0).round() as u32, (cy - 5.0).round() as u32);
    for (i, g) in glyphs.iter().enumerate() {
        let gx = x0 + i as u32 * 4 * scale;
        for (row, bits) in GLYPHS[*g].iter().enumerate() {
            for col in 0..3 {
                if bits & (0b100 >> col) != 0 {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let (x, y) = (gx + col * scale + dx, y0 + row as u32 * scale + dy);
                            if x < SIZE && y < SIZE {
                                img.put_pixel(x, y, Rgba([255, 255, 255, 255]));
                            }
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
        for n in [0, 1, 7, 9, 10, 250] {
            let img = icon(n);
            assert_eq!((img.width(), img.height()), (SIZE, SIZE));
        }
        let mut img = RgbaImage::new(SIZE, SIZE);
        draw_badge(&mut img, 5);
        assert_eq!(*img.get_pixel(17, 17), Rgba([214, 40, 40, 255]));
    }
}
