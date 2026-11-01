//! A phone has no tray. These keep the desktop call sites working: there's
//! one window, always shown while the app is in front.

use crate::state::App;
use anyhow::Result;
use tauri::AppHandle;

/// The app is in the foreground (Android's onResume / onPause, and Kotlin's
/// process lifecycle observer). Starts false: a push wake-up can start the
/// process with no window at all.
pub fn set_foreground(yes: bool) {
    #[cfg(target_os = "android")]
    crate::android::FOREGROUND.store(yes, std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(target_os = "android"))]
    let _ = yes;
}

pub fn foreground() -> bool {
    #[cfg(target_os = "android")]
    return crate::android::is_foreground();
    #[cfg(not(target_os = "android"))]
    true
}

pub fn create(_handle: &AppHandle) -> Result<()> {
    Ok(())
}

pub fn show_main(_handle: &AppHandle) {}

#[allow(dead_code)]
pub fn set_update(_handle: &AppHandle, _version: Option<&str>) {}

pub fn refresh(_handle: &AppHandle, _app: &App) {}

/// Whether the person is looking at the app right now.
#[allow(dead_code)]
pub fn main_window_focused(_handle: &AppHandle) -> bool {
    foreground()
}
