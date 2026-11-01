//! Notifications while the app is closed, on Android (SPEC.md "Android app", A3).
//!
//! With a UnifiedPush distributor on the phone (the ntfy app), the app
//! registers the endpoint the distributor gives it with the relay (`POST
//! /push`). The relay POSTs an empty wake-up there whenever something happens
//! and this phone has no /ws socket open; Kotlin turns the wake-up into an
//! expedited background job that calls `background_sync`, which syncs as usual
//! (decrypting on the phone) and shows the notifications (`alerts`).
//!
//! Without a distributor, or when the relay won't send to it, a periodic job
//! syncs about every 15 minutes (WorkManager's minimum) instead.
//!
//! The app also closes its /ws socket whenever it leaves the foreground: a
//! frozen background app would otherwise hold a socket that the relay counts
//! as connected (so no wake-ups) until it times out.
//!
//! State lives in the local database's `kv` table:
//! - `push_distributor`: the distributor app's package
//! - `push_endpoint`: the latest endpoint it gave us
//! - `push_registered`: the endpoint the relay accepted (instant when it equals `push_endpoint`)
//! - `push_reason`: why not instant: no_distributor, registering, server_off,
//!   server_refused, failed, offline
//! - `push_detail`: what the relay said when it refused the endpoint
//! - `push_fresh_at`: when we last asked for a fresh endpoint
//! - `push_ntfy`: the relay's own push server, for the instructions
//! - `notif_asked`: the in-app offer to turn notifications on was answered
//! - `push_note_seen`: the one-time note about getting instant notifications was read
//! - `battery_later`: "Not now" on the card about battery restrictions

use crate::state::{self, App};
use crate::{android, api, db, feed, manage};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

const DISTRIBUTOR: &str = "push_distributor";
const ENDPOINT: &str = "push_endpoint";
const REGISTERED: &str = "push_registered";
const REASON: &str = "push_reason";
const DETAIL: &str = "push_detail";
const FRESH_AT: &str = "push_fresh_at";
const NTFY: &str = "push_ntfy";
pub const NOTIF_ASKED: &str = "notif_asked";
pub const NOTE_SEEN: &str = "push_note_seen";
/// "Not now" on the battery card (Device → Settings still shows it).
pub const BATTERY_LATER: &str = "battery_later";

/// An "unregistered" that follows our own request for a fresh endpoint this soon is expected.
const FRESH_GRACE_SECS: i64 = 60;

fn get(app: &App, k: &str) -> Option<String> {
    db::kv_get(&app.db(), k).ok().flatten()
}

fn set(app: &App, k: &str, v: Option<&str>) {
    if let Err(e) = db::kv_set(&app.db(), k, v) {
        eprintln!("push: saving {k}: {e:#}");
    }
}

fn active(app: &App) -> bool {
    matches!(app.identity(), Ok(Some(id)) if id.status == "active")
}

fn instant(app: &App) -> bool {
    let (e, r) = (get(app, ENDPOINT), get(app, REGISTERED));
    e.is_some() && e == r
}

/// The periodic sync runs whenever wake-ups don't (or the device isn't active: then neither).
fn update_periodic(app: &App) {
    let on = active(app) && !instant(app);
    if let Err(e) = android::periodic_sync(on) {
        eprintln!("push: periodic sync: {e:#}");
    }
}

/// At start, on coming back to the foreground, and once the device becomes
/// active: (re-)register with the distributor and check the relay still has
/// our endpoint. Quick; the network part runs in the background.
pub fn setup(app: &Arc<App>) {
    setup_with(app, false)
}

/// `fresh`: ask the distributor for a new endpoint even if it gave one before
/// (*Check again*: the person may have changed ntfy's server).
pub fn setup_with(app: &Arc<App>, fresh: bool) {
    if !active(app) {
        update_periodic(app);
        return;
    }
    // The relay refused the endpoint (say ntfy's default server is another
    // one): ask the distributor for a new one, in case its settings changed.
    let fresh = fresh || get(app, REASON).as_deref() == Some("server_refused");
    if fresh {
        set(app, FRESH_AT, Some(&crate::now().to_string()));
    }
    match android::push_register(fresh) {
        Ok(Some(d)) => {
            set(app, DISTRIBUTOR, Some(&d));
            if get(app, ENDPOINT).is_none() {
                set(app, REASON, Some("registering"));
            }
        }
        Ok(None) => {
            let had = get(app, REGISTERED).is_some();
            for k in [DISTRIBUTOR, ENDPOINT, REGISTERED, DETAIL] {
                set(app, k, None);
            }
            set(app, REASON, Some("no_distributor"));
            if had {
                let a = app.clone();
                tauri::async_runtime::spawn(async move { forget_on_relay(&a).await });
            }
        }
        Err(e) => eprintln!("push: registering with the distributor: {e:#}"),
    }
    update_periodic(app);
    if instant(app) {
        let a = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = verify(&a).await {
                eprintln!("push: checking the relay has our endpoint: {e:#}");
            }
        });
    }
}

/// The relay forgets endpoints a push server calls gone: register again if so.
async fn verify(app: &App) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct PushInfo {
        endpoint: Option<String>,
        ntfy: Option<String>,
    }
    let id = app.require_active()?;
    let info: PushInfo = app.api(&id)?.get("/push").await?;
    set(app, NTFY, info.ntfy.as_deref());
    let mine = get(app, ENDPOINT);
    if info.endpoint != mine {
        if let Some(ep) = mine {
            register(app, &ep).await;
        }
    }
    Ok(())
}

async fn forget_on_relay(app: &App) {
    let Ok(id) = app.require_active() else { return };
    if let Ok(api) = app.api(&id) {
        let r: Result<serde_json::Value> = api.delete("/push").await;
        if let Err(e) = r {
            eprintln!("push: removing the endpoint from the relay: {e:#}");
        }
    }
}

/// Give the relay this endpoint and record what it said.
async fn register(app: &App, endpoint: &str) {
    set(app, ENDPOINT, Some(endpoint));
    let Ok(id) = app.require_active() else { return };
    let r: Result<serde_json::Value> = match app.api(&id) {
        Ok(api) => api.post("/push", &serde_json::json!({ "endpoint": endpoint })).await,
        Err(e) => Err(e),
    };
    match r {
        Ok(_) => {
            set(app, REGISTERED, Some(endpoint));
            set(app, REASON, None);
            set(app, DETAIL, None);
        }
        Err(e) => {
            set(app, REGISTERED, None);
            let refused = e.chain().find_map(|c| c.downcast_ref::<api::HttpError>()).map(|h| (h.status, h.detail.clone()));
            match refused {
                Some((404, _)) => set(app, REASON, Some("server_off")),
                Some((400, detail)) => {
                    set(app, REASON, Some("server_refused"));
                    set(app, DETAIL, Some(&detail));
                    // Where it does send them, for the instructions.
                    if let Ok(api) = app.api(&id) {
                        if let Ok(v) = api.get::<serde_json::Value>("/push").await {
                            set(app, NTFY, v.get("ntfy").and_then(|n| n.as_str()));
                        }
                    }
                }
                _ => {
                    eprintln!("push: registering the endpoint: {e:#}");
                    set(app, REASON, Some("offline"));
                }
            }
        }
    }
    update_periodic(app);
}

/// From Kotlin (a background job): the distributor's news.
pub fn push_event(dir: PathBuf, kind: &str, value: &str) -> String {
    let app = match state::shared(dir) {
        Ok(a) => a,
        Err(e) => return format!("push: opening the app's data: {e:#}"),
    };
    match kind {
        "endpoint" => {
            tauri::async_runtime::block_on(register(&app, value));
            format!("push: endpoint {}", if instant(&app) { "registered with the relay" } else { "not accepted" })
        }
        "unregistered" | "failed" => {
            let since_fresh = get(&app, FRESH_AT).and_then(|t| t.parse::<i64>().ok()).map(|t| crate::now() - t);
            if kind == "unregistered" && since_fresh.is_some_and(|s| s < FRESH_GRACE_SECS) {
                return "push: unregistered (expected: asked for a fresh endpoint)".into();
            }
            let had = get(&app, REGISTERED).is_some();
            set(&app, ENDPOINT, None);
            set(&app, REGISTERED, None);
            set(&app, REASON, Some(if kind == "failed" { "failed" } else { "no_distributor" }));
            set(&app, DETAIL, if kind == "failed" { Some(value) } else { None });
            if had {
                tauri::async_runtime::block_on(forget_on_relay(&app));
            }
            update_periodic(&app);
            format!("push: {kind} {value}")
        }
        _ => format!("push: unknown event {kind}"),
    }
}

/// From Kotlin (a background job): a wake-up, or the periodic sync.
pub fn background_sync(dir: PathBuf) -> String {
    let app = match state::shared(dir) {
        Ok(a) => a,
        Err(e) => return format!("sync: opening the app's data: {e:#}"),
    };
    if !active(&app) {
        return "sync: not an active member; nothing to do".into();
    }
    tauri::async_runtime::block_on(async {
        match feed::sync_once(&app).await {
            Ok(r) => {
                if let Some(h) = app.handle.get() {
                    use tauri::Emitter;
                    let _ = h.emit("synced", &r);
                }
                format!("sync: {} new events, {} new messages", r.new_events, r.new_dms)
            }
            Err(e) if api::is_status(&e, 401) => {
                // Removed or revoked while away: record it and say so.
                match manage::check_standing(&app).await {
                    Ok(Some(status)) => {
                        crate::alerts::removed(&app, &status);
                        let _ = android::push_unregister();
                        update_periodic(&app);
                        format!("sync: this device is {status}")
                    }
                    Ok(None) => format!("sync: {e:#}"),
                    Err(e2) => format!("sync: {e:#}; checking standing: {e2:#}"),
                }
            }
            Err(e) => format!("sync: {e:#}"),
        }
    })
}

/// Kotlin's lifecycle observer: the app came to the front, or left it.
pub fn foreground_changed(visible: bool) {
    let Some(app) = state::current() else { return };
    if visible {
        app.wake.notify_one();
        app.push_wake.notify_one();
        // The person may have installed ntfy or changed its server meanwhile.
        setup(&app);
    } else {
        // Close the socket so the relay starts sending wake-ups.
        app.push_pause.notify_one();
    }
}

#[derive(Serialize)]
pub struct PushView {
    /// "on", "ask" (Android 13+ needs the permission and we haven't offered yet), or "off".
    pub notifications: String,
    /// "instant" (wake-ups through the distributor), "periodic" (about every 15 minutes), or "none".
    pub mode: String,
    /// Why not instant (see the module docs).
    pub reason: Option<String>,
    pub distributor: Option<String>,
    /// What the relay said when it refused the endpoint.
    pub detail: Option<String>,
    /// The host of the push server the distributor uses.
    pub endpoint_host: Option<String>,
    /// The relay's own push server (what to set as ntfy's default server).
    pub ntfy: Option<String>,
    /// The one-time note about instant notifications was read.
    pub note_seen: bool,
    /// Battery restrictions on Side Tray and the push app.
    pub battery: Option<android::Battery>,
    /// "Not now" on the battery card.
    pub battery_later: bool,
}

pub fn view(app: &App) -> Result<PushView> {
    let state = android::notification_state().context("asking Android about notifications")?;
    let notifications = match state.as_str() {
        "on" => "on",
        "needs_permission" if get(app, NOTIF_ASKED).is_none() => "ask",
        _ => "off",
    };
    let mode = if !active(app) {
        "none"
    } else if instant(app) {
        "instant"
    } else {
        "periodic"
    };
    Ok(PushView {
        notifications: notifications.into(),
        mode: mode.into(),
        reason: if mode == "instant" { None } else { get(app, REASON) },
        distributor: get(app, DISTRIBUTOR),
        detail: get(app, DETAIL),
        endpoint_host: get(app, ENDPOINT).and_then(|e| reqwest::Url::parse(&e).ok()).and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        }),
        ntfy: get(app, NTFY),
        note_seen: get(app, NOTE_SEEN).is_some(),
        battery: android::battery(get(app, DISTRIBUTOR).as_deref())
            .map_err(|e| eprintln!("push: battery settings: {e:#}"))
            .ok(),
        battery_later: get(app, BATTERY_LATER).is_some(),
    })
}

/// Open the battery setting for Side Tray ("app") or the push app ("distributor").
pub fn open_battery_settings(app: &App, which: &str) -> Result<()> {
    let package = match which {
        "distributor" => get(app, DISTRIBUTOR).context("there's no push app")?,
        _ => "org.sidetray.app".to_string(),
    };
    android::open_battery_settings(&package)
}

pub fn mark(app: &App, key: &str) {
    set(app, key, Some("1"));
}
