// No console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Side Tray desktop client (SPEC.md Phases 4-5): first-run wizard, join and
//! Key Master screens, the feed, photo upload; sync on WebSocket pushes, a
//! tray icon with an unread badge, and native notifications.

mod account;
mod alerts;
mod api;
mod db;
mod feed;
mod photo;
mod push;
mod secrets;
mod state;
mod tray;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use sidetray_crypto as crypto;
use state::App;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_autostart::ManagerExt as _;

/// Sync interval while the push socket is down.
const POLL_EVERY: Duration = Duration::from_secs(30);
/// While it's up, pushes trigger syncs; this is only a safety net.
const POLL_WHEN_LIVE: Duration = Duration::from_secs(15 * 60);
/// Passed by the "start with Windows" entry: start hidden in the tray.
const MINIMIZED_ARG: &str = "--minimized";

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

type Res<T> = Result<T, String>;

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

// --- state for the UI ------------------------------------------------------------

#[derive(Serialize)]
struct AppView {
    /// setup / pending / denied / active
    stage: String,
    group_name: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    server: Option<String>,
    device_id: Option<String>,
    safety_code: Option<String>,
    keymaster: bool,
    trusted_keymasters: Vec<String>,
    key_versions: Vec<u32>,
    last_seq: i64,
    last_sync_at: Option<i64>,
    rejected: i64,
    unread: i64,
    /// The push socket is connected.
    live: bool,
}

#[tauri::command]
fn get_state(app: State<'_, Arc<App>>) -> Res<AppView> {
    let id = app.identity().map_err(err)?;
    let conn = app.db();
    let (last_seq, last_sync_at, rejected) = db::sync_info(&conn).map_err(err)?;
    let trusted = db::anchors(&conn).map_err(err)?.into_iter().map(|(_, name, _)| name).collect();
    let key_versions = secrets::key_versions(&conn).map_err(err)?;
    let unread = db::unread(&conn).map_err(err)?;
    let live = app.push_connected.load(Ordering::SeqCst);
    Ok(match id {
        None => AppView {
            stage: "setup".into(),
            group_name: None,
            display_name: None,
            email: None,
            server: None,
            device_id: None,
            safety_code: None,
            keymaster: false,
            trusted_keymasters: vec![],
            key_versions: vec![],
            last_seq,
            last_sync_at,
            rejected,
            unread,
            live,
        },
        Some(id) => AppView {
            stage: id.status.clone(),
            keymaster: id.is_keymaster(),
            safety_code: Some(crypto::safety_code(&id.public())),
            group_name: Some(id.group_name),
            display_name: Some(id.display_name),
            email: Some(id.email),
            server: Some(id.server_url),
            device_id: Some(id.device_id),
            trusted_keymasters: trusted,
            key_versions,
            last_seq,
            last_sync_at,
            rejected,
            unread,
            live,
        },
    })
}

#[derive(Serialize)]
struct Defaults {
    server: &'static str,
    has_pinned_root: bool,
}

#[tauri::command]
fn wizard_defaults() -> Defaults {
    Defaults { server: "https://10.1.1.188", has_pinned_root: !api::PINNED_ROOTS.trim().is_empty() }
}

// --- wizard and join -----------------------------------------------------------------

#[tauri::command]
async fn probe_server(server: String, ca_pem: Option<String>) -> Res<api::GroupInfo> {
    account::probe(&server, ca_pem.as_deref()).await.map_err(err)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn register(
    app: State<'_, Arc<App>>,
    server: String,
    ca_pem: Option<String>,
    group_name: String,
    display_name: String,
    email: String,
    setup_token: Option<String>,
) -> Res<String> {
    let code = account::register(
        &app,
        account::Registration {
            server: &server,
            ca_pem: ca_pem.as_deref(),
            group_name: &group_name,
            display_name: &display_name,
            email: &email,
            setup_token: setup_token.as_deref().filter(|t| !t.trim().is_empty()),
        },
    )
    .await
    .map_err(err)?;
    app.wake.notify_one();
    app.push_wake.notify_one();
    Ok(code)
}

#[tauri::command]
async fn join_progress(app: State<'_, Arc<App>>) -> Res<account::JoinProgress> {
    account::join_progress(&app).await.map_err(err)
}

#[tauri::command]
async fn confirm_approval(app: State<'_, Arc<App>>, code: String) -> Res<()> {
    account::confirm_approval(&app, &code).await.map_err(err)?;
    app.wake.notify_one();
    app.push_wake.notify_one();
    Ok(())
}

#[tauri::command]
fn reset(app: State<'_, Arc<App>>) -> Res<()> {
    account::reset(&app).map_err(err)
}

// --- Key Master ----------------------------------------------------------------------

#[tauri::command]
async fn list_pending(app: State<'_, Arc<App>>) -> Res<Vec<account::PendingView>> {
    account::list_pending(&app).await.map_err(err)
}

#[tauri::command]
async fn approve(app: State<'_, Arc<App>>, device_id: String, code: String, as_keymaster: bool) -> Res<account::Approved> {
    account::approve(&app, &device_id, &code, as_keymaster).await.map_err(err)
}

#[tauri::command]
async fn deny(app: State<'_, Arc<App>>, device_id: String) -> Res<()> {
    account::deny(&app, &device_id).await.map_err(err)
}

// --- feed ------------------------------------------------------------------------------

#[tauri::command]
async fn sync_now(handle: AppHandle, app: State<'_, Arc<App>>) -> Res<feed::SyncReport> {
    let r = feed::sync_once(&app).await.map_err(err)?;
    let _ = handle.emit("synced", &r);
    Ok(r)
}

#[tauri::command]
fn get_feed(app: State<'_, Arc<App>>, before: Option<i64>, limit: Option<i64>) -> Res<Vec<feed::PostView>> {
    let id = app.require_active().map_err(err)?;
    feed::feed(&app.db(), &id.member_id, before, limit.unwrap_or(50).clamp(1, 500)).map_err(err)
}

#[derive(Serialize)]
struct StagedView {
    id: String,
    preview: String,
    width: u32,
    height: u32,
    bytes: usize,
}

/// Takes the raw file bytes as the request body (no JSON), so large photos
/// cross the IPC bridge without being turned into number arrays.
#[tauri::command]
async fn stage_photo(app: State<'_, Arc<App>>, request: tauri::ipc::Request<'_>) -> Res<StagedView> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("expected the photo's bytes".into());
    };
    let bytes = bytes.clone();
    let p = tauri::async_runtime::spawn_blocking(move || photo::process(&bytes))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)?;
    let mut idb = [0u8; 9];
    getrandom::getrandom(&mut idb).map_err(|e| e.to_string())?;
    let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
    let view = StagedView {
        id: id.clone(),
        preview: format!("data:image/webp;base64,{}", B64.encode(&p.thumb)),
        width: p.width,
        height: p.height,
        bytes: p.full.len(),
    };
    app.staged.lock().unwrap_or_else(|e| e.into_inner()).insert(id, p);
    Ok(view)
}

#[tauri::command]
fn unstage_photo(app: State<'_, Arc<App>>, id: String) {
    app.staged.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}

#[tauri::command]
async fn create_post(app: State<'_, Arc<App>>, text: String, photos: Vec<String>) -> Res<()> {
    feed::create_post(&app, &text, &photos).await.map_err(err)
}

#[tauri::command]
async fn add_comment(app: State<'_, Arc<App>>, post_id: String, text: String) -> Res<()> {
    feed::add_comment(&app, &post_id, &text).await.map_err(err)
}

#[tauri::command]
async fn set_reaction(app: State<'_, Arc<App>>, post_id: String, emoji: String) -> Res<()> {
    feed::set_reaction(&app, &post_id, &emoji).await.map_err(err)
}

#[tauri::command]
async fn delete_post(app: State<'_, Arc<App>>, post_id: String) -> Res<()> {
    feed::delete_post(&app, &post_id).await.map_err(err)
}

/// The feed was looked at: clear the unread badge.
#[tauri::command]
fn mark_read(handle: AppHandle, app: State<'_, Arc<App>>) -> Res<()> {
    db::clear_unread(&app.db()).map_err(err)?;
    tray::refresh(&handle, &app);
    Ok(())
}

// --- settings ----------------------------------------------------------------------------

#[derive(Serialize)]
struct Settings {
    start_with_os: bool,
}

#[tauri::command]
fn get_settings(handle: AppHandle) -> Res<Settings> {
    Ok(Settings { start_with_os: handle.autolaunch().is_enabled().map_err(|e| e.to_string())? })
}

#[tauri::command]
fn set_start_with_os(handle: AppHandle, enabled: bool) -> Res<Settings> {
    let launcher = handle.autolaunch();
    if enabled { launcher.enable() } else { launcher.disable() }.map_err(|e| e.to_string())?;
    get_settings(handle)
}

// --- photos for the webview ------------------------------------------------------------

/// `media://localhost/<id>.webp` (`http://media.localhost/...` on Windows):
/// decrypted photos from the media folder, and nothing else.
fn serve_media(app: &App, path: &str) -> tauri::http::Response<Vec<u8>> {
    let name = path.trim_start_matches('/');
    let ok_name = name
        .strip_suffix(".webp")
        .is_some_and(|stem| (1..=64).contains(&stem.len()) && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    let file = if ok_name { std::fs::read(app.media_dir.join(name)).ok() } else { None };
    let builder = tauri::http::Response::builder().header("X-Content-Type-Options", "nosniff");
    match file {
        Some(bytes) => builder
            .status(200)
            .header("Content-Type", "image/webp")
            .header("Cache-Control", "max-age=31536000, immutable")
            .body(bytes),
        None => builder.status(404).body(Vec::new()),
    }
    .expect("static response parts are valid")
}

// --- background sync ---------------------------------------------------------------------

fn spawn_sync_loop(handle: AppHandle, app: Arc<App>) {
    tauri::async_runtime::spawn(async move {
        loop {
            let active = matches!(app.identity(), Ok(Some(id)) if id.status == "active");
            if active {
                match feed::sync_once(&app).await {
                    Ok(r) => {
                        let _ = handle.emit("synced", &r);
                    }
                    Err(e) => {
                        let _ = handle.emit("sync-error", format!("{e:#}"));
                    }
                }
            }
            let every = if app.push_connected.load(Ordering::SeqCst) { POLL_WHEN_LIVE } else { POLL_EVERY };
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = app.wake.notified() => {}
            }
        }
    });
}

fn main() {
    // SIDETRAY_DATA_DIR lets several copies run side by side (testing); otherwise
    // a second launch just brings the running app forward.
    let side_by_side = std::env::var_os("SIDETRAY_DATA_DIR").is_some();
    let mut builder = tauri::Builder::default();
    if !side_by_side {
        builder = builder.plugin(tauri_plugin_single_instance::init(|handle, _args, _cwd| tray::show_main(handle)));
    }
    #[cfg(not(windows))]
    {
        builder = builder.plugin(tauri_plugin_notification::init());
    }
    builder
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![MINIMIZED_ARG]),
        ))
        // Closing the window keeps the app running in the tray; Quit is in the tray menu.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .register_uri_scheme_protocol("media", |ctx, req| {
            let app = ctx.app_handle().state::<Arc<App>>();
            serve_media(&app, req.uri().path())
        })
        .setup(|tauri_app| {
            // SIDETRAY_DATA_DIR lets several copies run side by side (testing).
            let dir = match std::env::var_os("SIDETRAY_DATA_DIR") {
                Some(d) => d.into(),
                None => tauri_app.path().app_data_dir()?,
            };
            let app = Arc::new(App::open(dir.clone())?);
            let handle = tauri_app.handle().clone();
            let _ = app.handle.set(handle.clone());
            tauri_app.manage(app.clone());
            #[cfg(windows)]
            if let Err(e) = alerts::register_app_id(&handle, &dir) {
                eprintln!("registering for notifications: {e:#}");
            }
            tray::create(&handle)?;
            tray::refresh(&handle, &app);
            if !std::env::args().any(|a| a == MINIMIZED_ARG) {
                tray::show_main(&handle);
            }
            spawn_sync_loop(handle.clone(), app.clone());
            push::spawn(handle, app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            wizard_defaults,
            probe_server,
            register,
            join_progress,
            confirm_approval,
            reset,
            list_pending,
            approve,
            deny,
            sync_now,
            get_feed,
            stage_photo,
            unstage_photo,
            create_post,
            add_comment,
            set_reaction,
            delete_post,
            mark_read,
            get_settings,
            set_start_with_os,
        ])
        .build(tauri::generate_context!())
        .expect("error while starting Side Tray")
        .run(|_handle, event| {
            // Hidden windows don't count as open; only the tray's Quit (an explicit exit code) ends the app.
            if let tauri::RunEvent::ExitRequested { code: None, api, .. } = event {
                api.prevent_exit();
            }
        });
}
