//! After each sync: native notifications, the tray badge, and where a click on
//! a notification should take you.
//!
//! Notified: posts by others, comments by others on my posts, direct
//! messages, and (Key Masters) new join requests. Not while the window is focused (the feed is
//! right there), and not on a new device's first sync (that's the backlog).
//!
//! On Android the notifications go through Kotlin (`android::notify`), which
//! works without the window: a push wake-up may sync in a process where it
//! never opened (A3). Tapping one opens the app at its `Target`.

use crate::feed::SyncReport;
use crate::state::App;
use crate::tray;
use serde::Serialize;
use std::sync::atomic::Ordering;
use tauri::{AppHandle, Emitter};

/// More notices than this in one sync become a single summary.
const MAX_SEPARATE: usize = 3;

/// Where a click on a notification goes; sent to the UI as "open-item".
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
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

/// Which kind of notification (an Android notification channel).
#[derive(Clone, Copy)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub enum Kind {
    Post,
    Comment,
    Message,
    Join,
    Account,
}

pub fn after_sync(app: &App, r: &SyncReport) {
    app.pending_joins.store(r.pending_joins, Ordering::SeqCst);
    let new_joins = new_join_requests(app, &r.pending);
    #[cfg(not(target_os = "android"))]
    let Some(handle) = app.handle.get() else { return };
    #[cfg(not(target_os = "android"))]
    tray::refresh(handle, app);
    #[cfg(not(target_os = "android"))]
    let focused = tray::main_window_focused(handle);
    #[cfg(target_os = "android")]
    let focused = crate::android::is_foreground();
    if r.initial || focused {
        return;
    }

    let mut out: Vec<(String, String, Target, Kind)> = Vec::new();
    let notable: Vec<_> = r.notices.iter().filter(|n| n.notify).collect();
    if notable.len() > MAX_SEPARATE {
        out.push(("Side Tray".into(), format!("{} new posts and comments", notable.len()), Target::Feed, Kind::Post));
    } else {
        for n in notable {
            let (title, kind) = if n.comment {
                (format!("{} commented on your post", n.author), Kind::Comment)
            } else {
                (format!("{} posted", n.author), Kind::Post)
            };
            out.push((title, n.text.clone(), Target::Post { post_id: n.post_id.clone() }, kind));
        }
    }
    if r.dm_notices.len() > MAX_SEPARATE {
        out.push(("Side Tray".into(), format!("{} new messages", r.dm_notices.len()), Target::Messages, Kind::Message));
    } else {
        for n in &r.dm_notices {
            out.push((
                format!("{} sent you a message", n.author),
                n.text.clone(),
                Target::Dm { member_id: n.member_id.clone() },
                Kind::Message,
            ));
        }
    }
    match new_joins.len() {
        0 => {}
        1 => out.push((
            format!("{} wants to join", new_joins[0]),
            "Phone them and check their safety code before approving.".into(),
            Target::Joins,
            Kind::Join,
        )),
        n => out.push((format!("{n} people want to join"), new_joins.join(", "), Target::Joins, Kind::Join)),
    }

    #[cfg(not(target_os = "android"))]
    for (title, body, target, _) in out {
        show(handle, &title, &body, target);
    }
    #[cfg(target_os = "android")]
    android_notify(out);
}

/// Names of join requests not notified about yet. Each pops up once: per run
/// on a computer; on a phone, where every wake-up may be a new process, the
/// list is kept in the database.
fn new_join_requests(app: &App, pending: &[(String, String)]) -> Vec<String> {
    let mut seen = app.seen_pending.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(target_os = "android")]
    if seen.is_empty() {
        if let Ok(Some(v)) = crate::db::kv_get(&app.db(), "notified_joins") {
            seen.extend(serde_json::from_str::<Vec<String>>(&v).unwrap_or_default());
        }
    }
    let fresh = pending.iter().filter(|(d, _)| !seen.contains(d)).map(|(_, name)| name.clone()).collect();
    // Forget requests that were handled, so the set doesn't grow forever.
    *seen = pending.iter().map(|(d, _)| d.clone()).collect();
    #[cfg(target_os = "android")]
    {
        let list: Vec<&String> = seen.iter().collect();
        let _ = crate::db::kv_set(&app.db(), "notified_joins", Some(&serde_json::to_string(&list).unwrap_or_default()));
    }
    fresh
}

/// The relay says this device was removed or revoked (`status`): tell the person.
pub fn removed(app: &App, status: &str) {
    let group = app.identity().ok().flatten().map(|i| i.group_name).unwrap_or_default();
    let (title, body) = if status == "removed" {
        (format!("You've been removed from {group}"), "Posts already on this device are kept.")
    } else {
        (format!("This device was disconnected from {group}"), "A Key Master revoked it. Posts already on it are kept.")
    };
    #[cfg(target_os = "android")]
    android_notify(vec![(title, body.to_string(), Target::Feed, Kind::Account)]);
    #[cfg(not(target_os = "android"))]
    if let Some(h) = app.handle.get() {
        show(h, &title, body, Target::Feed);
    }
}

#[cfg(target_os = "android")]
fn android_notify(items: Vec<(String, String, Target, Kind)>) {
    let notes: Vec<crate::android::Note> = items
        .into_iter()
        .map(|(title, body, target, kind)| {
            let target = serde_json::to_string(&target).unwrap_or_default();
            crate::android::Note {
                // The same post or conversation replaces its older notification.
                id: (fnv(&target) & 0x7fff_ffff) as i32,
                channel: match kind {
                    Kind::Post => "posts",
                    Kind::Comment => "comments",
                    Kind::Message => "messages",
                    Kind::Join => "joins",
                    Kind::Account => "account",
                },
                title,
                body,
                target,
            }
        })
        .collect();
    if let Err(e) = crate::android::notify(&notes) {
        eprintln!("notification: {e:#}");
    }
}

#[cfg(target_os = "android")]
fn fnv(s: &str) -> u32 {
    s.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

/// Bring the window up and tell the UI what to show (a toast was clicked).
#[cfg(windows)]
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

#[cfg(all(not(windows), not(target_os = "android")))]
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
