//! A phone has no tray. These keep the desktop call sites working: there's
//! one window, always shown, and the app only runs (syncs) while it's open.

use crate::state::App;
use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::AppHandle;

/// The app is in the foreground (Android's onResume / onPause).
static FOREGROUND: AtomicBool = AtomicBool::new(true);

pub fn set_foreground(yes: bool) {
    FOREGROUND.store(yes, Ordering::SeqCst);
}

pub fn create(_handle: &AppHandle) -> Result<()> {
    Ok(())
}

pub fn show_main(_handle: &AppHandle) {}

pub fn set_update(_handle: &AppHandle, _version: Option<&str>) {}

pub fn refresh(_handle: &AppHandle, _app: &App) {}

/// Whether the person is looking at the app right now.
pub fn main_window_focused(_handle: &AppHandle) -> bool {
    FOREGROUND.load(Ordering::SeqCst)
}
