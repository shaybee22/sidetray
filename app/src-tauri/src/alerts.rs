//! After each sync: native notifications, the tray badge, and where a click on
//! a notification should take you.
//!
//! Notified: posts by others, comments by others on my posts, direct
//! messages, and (Key Masters) new join requests. Not while the window is focused (the feed is
//! right there), and not on a new device's first sync (that's the backlog).

use crate::feed::SyncReport;
use crate::state::App;
use crate::tray;
use serde::Serialize;
use std::sync::atomic::Ordering;
use tauri::{AppHandle, Emitter};

/// More notices than this in one sync become a single summary.
const MAX_SEPARATE: usize = 3;

/// Where a click on a notification goes; sent to the UI as "open-item".
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Post { post_id: String },
    Feed,
    Joins,
    /// The conversation with this member.
    Dm { member_id: String },
    Messages,
    /// A downloaded update is ready to install.
    Update,
}

pub fn after_sync(app: &App, r: &SyncReport) {
    app.pending_joins.store(r.pending_joins, Ordering::SeqCst);
    let new_joins: Vec<String> = {
        let mut seen = app.seen_pending.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = r.pending.iter().filter(|(d, _)| !seen.contains(d)).map(|(_, name)| name.clone()).collect();
        // Forget requests that were handled, so the set doesn't grow forever.
        *seen = r.pending.iter().map(|(d, _)| d.clone()).collect();
        fresh
    };
    let Some(handle) = app.handle.get() else { return };
    tray::refresh(handle, app);
    if r.initial || tray::main_window_focused(handle) {
        return;
    }

    let notable: Vec<_> = r.notices.iter().filter(|n| n.notify).collect();
    if notable.len() > MAX_SEPARATE {
        show(handle, "Side Tray", &format!("{} new posts and comments", notable.len()), Target::Feed);
    } else {
        for n in notable {
            let title = if n.comment { format!("{} commented on your post", n.author) } else { format!("{} posted", n.author) };
            show(handle, &title, &n.text, Target::Post { post_id: n.post_id.clone() });
        }
    }
    if r.dm_notices.len() > MAX_SEPARATE {
        show(handle, "Side Tray", &format!("{} new messages", r.dm_notices.len()), Target::Messages);
    } else {
        for n in &r.dm_notices {
            show(handle, &format!("{} sent you a message", n.author), &n.text, Target::Dm { member_id: n.member_id.clone() });
        }
    }
    match new_joins.len() {
        0 => {}
        1 => show(
            handle,
            &format!("{} wants to join", new_joins[0]),
            "Phone them and check their safety code before approving.",
            Target::Joins,
        ),
        n => show(handle, &format!("{n} people want to join"), &new_joins.join(", "), Target::Joins),
    }
}

/// Bring the window up and tell the UI what to show.
pub fn open(handle: &AppHandle, target: &Target) {
    tray::show_main(handle);
    let _ = handle.emit("open-item", target);
}

#[cfg(windows)]
pub fn show(handle: &AppHandle, title: &str, body: &str, target: Target) {
    use tauri_winrt_notification::{Sound, Toast};
    let aumid = handle.config().identifier.clone();
    let (title, body, h) = (title.to_string(), body.to_string(), handle.clone());
    // WinRT calls block briefly; keep them off the async runtime.
    std::thread::spawn(move || {
        let toast = Toast::new(&aumid).title(&title).text1(&body).sound(Some(Sound::Default)).on_activated(move |_| {
            open(&h, &target);
            Ok(())
        });
        if let Err(e) = toast.show() {
            eprintln!("notification: {e}");
        }
    });
}

#[cfg(not(windows))]
pub fn show(handle: &AppHandle, title: &str, body: &str, _target: Target) {
    // The plugin can't report clicks on desktop; the tray badge leads people back.
    use tauri_plugin_notification::NotificationExt;
    if let Err(e) = handle.notification().builder().title(title).body(body).show() {
        eprintln!("notification: {e}");
    }
}

/// Windows shows toasts only for a registered AppUserModelID. The installer
/// registers it (in HKCU, next to its Start menu shortcut); a copy run
/// straight from a build registers it per user here (name and icon for the toast).
#[cfg(windows)]
pub fn register_app_id(handle: &AppHandle, data_dir: &std::path::Path) -> anyhow::Result<()> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    let icon = data_dir.join("notification-icon.png");
    std::fs::write(&icon, include_bytes!("../icons/icon.png"))?;
    let path = format!(r"Software\Classes\AppUserModelId\{}", handle.config().identifier);
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&path)?;
    key.set_value("DisplayName", &"Side Tray")?;
    key.set_value("IconUri", &icon.to_string_lossy().to_string())?;
    Ok(())
}
