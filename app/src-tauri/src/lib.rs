//! Side Tray client (SPEC.md Phases 4-6): first-run wizard, join and
//! Key Master screens, the feed, photo upload; sync on WebSocket pushes, a
//! tray icon with an unread badge, and native notifications; the member list,
//! removal, device revocation and group key rotation. Phase 6b: per-server
//! certificate trust (public roots, or a test server's pinned root), invite
//! links (`sidetray://join?...`), avatars and chosen display names.
//! Phase 5b: end-to-end encrypted direct messages.
//!
//! The same code runs on Android (SPEC.md "Android app", A1): the tray, the
//! updater, autostart and single-instance are desktop-only (`cfg(desktop)`);
//! on a phone `tray` is a small stand-in and the keys are wrapped by the
//! Android Keystore (`keystore`, `secrets`). A3: notifications while the app
//! is closed, woken through UnifiedPush or a periodic job (`mobile_push`).

mod account;
mod alerts;
#[cfg(target_os = "android")]
mod android;
mod api;
mod db;
mod dm;
mod feed;
mod invite;
#[cfg(target_os = "android")]
mod keystore;
mod manage;
#[cfg(target_os = "android")]
mod mobile_push;
mod photo;
mod profile;
mod push;
mod secrets;
mod state;
#[cfg_attr(mobile, path = "tray_mobile.rs")]
mod tray;
#[cfg_attr(mobile, path = "update_mobile.rs")]
mod update;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use sidetray_crypto as crypto;
use state::App;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
#[cfg(desktop)]
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_deep_link::DeepLinkExt as _;

/// Sync interval while the push socket is down.
const POLL_EVERY: Duration = Duration::from_secs(30);
/// While it's up, pushes trigger syncs; this is only a safety net.
const POLL_WHEN_LIVE: Duration = Duration::from_secs(15 * 60);
/// Passed by the "start with Windows" entry: start hidden in the tray.
#[cfg(desktop)]
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
    /// Unread direct messages, over every conversation.
    dm_unread: i64,
    /// The push socket is connected.
    live: bool,
    /// The relay pruned posts this device never got: (when noticed, retention days).
    missed: Option<(i64, f64)>,
    /// A test server (bare IP, or a pinned root): labelled as such on This device.
    test_server: bool,
    /// SHA-256 of the pinned root certificate, for a test server.
    cert_fingerprint: Option<String>,
    /// The server's certificate was refused on the last try (what to tell the person).
    cert_problem: Option<String>,
    /// What the group sees: the certified name (a chosen one waits for a Key Master).
    shown_name: Option<String>,
    avatar: Option<String>,
}

#[tauri::command]
fn get_state(app: State<'_, Arc<App>>) -> Res<AppView> {
    let id = app.identity().map_err(err)?;
    let conn = app.db();
    let (last_seq, last_sync_at, rejected) = db::sync_info(&conn).map_err(err)?;
    let trusted = db::anchors(&conn).map_err(err)?.into_iter().map(|(_, name, _)| name).collect();
    let key_versions = secrets::key_versions(&conn).map_err(err)?;
    let unread = db::unread(&conn).map_err(err)?;
    let dm_unread = db::dm_unread(&conn).map_err(err)?;
    let live = app.push_connected.load(Ordering::SeqCst);
    let missed = db::missed(&conn).map_err(err)?;
    drop(conn);
    let cert_problem = app.cert_problem.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mine = id.as_ref().filter(|i| i.status != "pending" && i.status != "denied").and_then(|_| profile::mine(&app).ok());
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
            dm_unread,
            live,
            missed: None,
            test_server: false,
            cert_fingerprint: None,
            cert_problem: None,
            shown_name: None,
            avatar: None,
        },
        Some(id) => AppView {
            test_server: id.ca_pem.is_some() || api::is_ip_server(&id.server_url),
            cert_fingerprint: id.ca_pem.as_deref().and_then(|p| api::fingerprint(p).ok()),
            cert_problem,
            shown_name: mine.as_ref().map(|m| m.display_name.clone()),
            avatar: mine.and_then(|m| m.avatar),
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
            dm_unread,
            live,
            missed,
        },
    })
}

// --- wizard and join -----------------------------------------------------------------

#[derive(Serialize)]
struct ServerCheck {
    server: String,
    /// A test server: the person must compare `fingerprint` with what the
    /// server's installer printed before the app trusts it.
    test_mode: bool,
    fingerprint: Option<String>,
}

/// Step 1: work out how to trust the server. A domain uses the public web
/// roots (checked by connecting); a bare IP address, or a pasted root, is a
/// test server whose root waits for the person to confirm its fingerprint.
#[tauri::command]
async fn check_server(app: State<'_, Arc<App>>, server: String, ca_pem: Option<String>) -> Res<ServerCheck> {
    let server = api::normalize_server(&server).map_err(err)?;
    let pasted = ca_pem.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
    let root_pem = match pasted {
        Some(pem) => {
            api::check_pinned(&server, &pem).await.map_err(err)?;
            Some(pem + "\n")
        }
        None if api::is_https(&server) && api::is_ip_server(&server) => Some(api::fetch_root(&server).await.map_err(err)?),
        None => {
            // A domain (or plain http to this computer): the normal checks, now.
            let health: anyhow::Result<serde_json::Value> = api::Api::new(&server, None, None).map_err(err)?.get("/health").await;
            match health {
                Ok(_) => {}
                Err(e) if e.chain().any(|c| c.downcast_ref::<api::HttpError>().is_some()) => {
                    return Err(format!("{server} answered, but it isn't a Side Tray server. Check the address."));
                }
                Err(e) => return Err(err(e)),
            }
            None
        }
    };
    let fingerprint = root_pem.as_deref().map(api::fingerprint).transpose().map_err(err)?;
    let trust =
        state::ServerTrust { server: server.clone(), confirmed: root_pem.is_none(), root_pem, fingerprint: fingerprint.clone() };
    *app.wizard_server.lock().unwrap_or_else(|e| e.into_inner()) = Some(trust);
    Ok(ServerCheck { server, test_mode: fingerprint.is_some(), fingerprint })
}

/// The person compared the fingerprint and it matches.
#[tauri::command]
fn trust_server(app: State<'_, Arc<App>>, fingerprint: String) -> Res<()> {
    let mut w = app.wizard_server.lock().unwrap_or_else(|e| e.into_inner());
    let t = w.as_mut().ok_or("check the server first")?;
    match &t.fingerprint {
        Some(fp) if api::same_fingerprint(fp, &fingerprint) => {
            t.confirmed = true;
            Ok(())
        }
        _ => Err("that isn't the certificate that was checked; start again".into()),
    }
}

fn confirmed_server(app: &App) -> Res<state::ServerTrust> {
    match app.wizard_server.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(t) if t.confirmed => Ok(t),
        Some(_) => Err("confirm the server's certificate first".into()),
        None => Err("check the server first".into()),
    }
}

#[tauri::command]
async fn probe_group(app: State<'_, Arc<App>>, group_name: String) -> Res<api::GroupInfo> {
    let t = confirmed_server(&app)?;
    account::probe(&t.server, t.root_pem.as_deref(), &group_name).await.map_err(err)
}

#[tauri::command]
async fn register(
    app: State<'_, Arc<App>>,
    group_name: String,
    display_name: String,
    email: String,
    setup_token: Option<String>,
) -> Res<String> {
    let t = confirmed_server(&app)?;
    let code = account::register(
        &app,
        account::Registration {
            server: &t.server,
            ca_pem: t.root_pem.as_deref(),
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

/// The invite link that opened the app, if the wizard hasn't taken it yet.
#[tauri::command]
fn take_invite(app: State<'_, Arc<App>>) -> Option<state::InviteMsg> {
    app.pending_invite.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// A `sidetray://` link reached the app (at launch, or from a second launch).
fn got_link(handle: &AppHandle, app: &App, url: &str) {
    let msg = match invite::parse(url) {
        Ok(i) => state::InviteMsg { invite: Some(i), error: None },
        Err(e) => state::InviteMsg { invite: None, error: Some(format!("{e:#}")) },
    };
    *app.pending_invite.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
    let _ = handle.emit("invite", ());
    tray::show_main(handle);
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
    #[cfg(target_os = "android")]
    mobile_push::setup(&app);
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

#[derive(Serialize)]
struct InviteView {
    link: String,
    qr: String,
}

#[tauri::command]
fn invite_link(app: State<'_, Arc<App>>) -> Res<InviteView> {
    let id = app.require_keymaster().map_err(err)?;
    let link = invite::link(&id.server_url, &id.group_name).map_err(err)?;
    Ok(InviteView { qr: invite::qr_data_url(&link).map_err(err)?, link })
}

// --- profile (Phase 6b) --------------------------------------------------------------

#[tauri::command]
fn get_profile(app: State<'_, Arc<App>>) -> Res<profile::MyProfile> {
    profile::mine(&app).map_err(err)
}

#[tauri::command]
async fn set_display_name(app: State<'_, Arc<App>>, name: String) -> Res<profile::MyProfile> {
    profile::save(&app, Some(&name), profile::AvatarChange::Keep).await.map_err(err)?;
    profile::mine(&app).map_err(err)
}

/// A file sent from the UI: the raw request body (desktop), or `{"b64": "..."}`
/// (Android, whose IPC carries only JSON; see `bytesArg` in app.js).
fn body_bytes(request: &tauri::ipc::Request<'_>) -> Option<Vec<u8>> {
    match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => Some(bytes.clone()),
        tauri::ipc::InvokeBody::Json(v) => B64.decode(v.get("b64")?.as_str()?).ok(),
    }
}

/// The cropped photo from the app's canvas (a PNG; see `body_bytes`).
#[tauri::command]
async fn set_avatar(app: State<'_, Arc<App>>, request: tauri::ipc::Request<'_>) -> Res<profile::MyProfile> {
    let bytes = body_bytes(&request).ok_or("expected the cropped photo")?;
    profile::save(&app, None, profile::AvatarChange::New(bytes)).await.map_err(err)?;
    profile::mine(&app).map_err(err)
}

#[tauri::command]
async fn remove_avatar(app: State<'_, Arc<App>>) -> Res<profile::MyProfile> {
    profile::save(&app, None, profile::AvatarChange::Remove).await.map_err(err)?;
    profile::mine(&app).map_err(err)
}

#[tauri::command]
async fn accept_name(app: State<'_, Arc<App>>, member_id: String) -> Res<String> {
    let name = manage::accept_name(&app, &member_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(name)
}

// --- the server's certificate (test servers) -------------------------------------------

#[derive(Serialize)]
struct CertCheck {
    pinned: Option<String>,
    current: String,
    same: bool,
}

/// Fetch a test server's current root certificate to compare with the pinned one.
#[tauri::command]
async fn check_server_cert(app: State<'_, Arc<App>>) -> Res<CertCheck> {
    let id = app.require_identity().map_err(err)?;
    if id.ca_pem.is_none() && !api::is_ip_server(&id.server_url) {
        return Err("this server uses a publicly trusted certificate; there's nothing to pin".into());
    }
    let pem = api::fetch_root(&id.server_url).await.map_err(err)?;
    let current = api::fingerprint(&pem).map_err(err)?;
    let pinned = id.ca_pem.as_deref().and_then(|p| api::fingerprint(p).ok());
    let same = pinned.as_deref().is_some_and(|p| api::same_fingerprint(p, &current));
    *app.repin.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(state::ServerTrust { server: id.server_url, root_pem: Some(pem), fingerprint: Some(current.clone()), confirmed: false });
    Ok(CertCheck { pinned, current, same })
}

/// The server's operator confirmed the new fingerprint: pin that root instead.
#[tauri::command]
fn repin_server_cert(app: State<'_, Arc<App>>, fingerprint: String) -> Res<()> {
    let id = app.require_identity().map_err(err)?;
    let t = app.repin.lock().unwrap_or_else(|e| e.into_inner()).take().ok_or("check the certificate first")?;
    let (Some(pem), Some(fp)) = (t.root_pem, t.fingerprint) else { return Err("check the certificate first".into()) };
    if t.server != id.server_url || !api::same_fingerprint(&fp, &fingerprint) {
        return Err("that isn't the certificate that was checked; check again".into());
    }
    db::set_ca_pem(&app.db(), &pem).map_err(err)?;
    app.set_cert_problem(None);
    app.wake.notify_one();
    app.push_wake.notify_one();
    Ok(())
}

// --- members (Phase 6) ------------------------------------------------------------------

#[tauri::command]
async fn list_members(app: State<'_, Arc<App>>) -> Res<Vec<manage::MemberView>> {
    manage::list_members(&app).await.map_err(err)
}

#[tauri::command]
async fn promote_member(app: State<'_, Arc<App>>, member_id: String) -> Res<String> {
    let name = manage::promote(&app, &member_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(name)
}

#[tauri::command]
async fn remove_member(app: State<'_, Arc<App>>, member_id: String) -> Res<manage::Change> {
    let c = manage::remove_member(&app, &member_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(c)
}

#[tauri::command]
async fn revoke_device(app: State<'_, Arc<App>>, device_id: String) -> Res<manage::Change> {
    let c = manage::revoke_device(&app, &device_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(c)
}

#[tauri::command]
fn dismiss_missed(app: State<'_, Arc<App>>) -> Res<()> {
    db::clear_missed(&app.db()).map_err(err)
}

/// After a `removed` push or a 401: ask the relay where this device stands. If
/// it was removed, that's recorded (syncing stops; the archive stays), and the
/// UI and a notification say so.
pub async fn removed_check(handle: &AppHandle, app: &App) {
    match manage::check_standing(app).await {
        Ok(Some(status)) => {
            alerts::removed(app, &status);
            app.push_wake.notify_one();
            tray::refresh(handle, app);
            let _ = handle.emit("removed", status);
        }
        Ok(None) => {}
        Err(e) => eprintln!("checking whether this device was removed: {e:#}"),
    }
}

// --- feed ------------------------------------------------------------------------------

#[tauri::command]
async fn sync_now(handle: AppHandle, app: State<'_, Arc<App>>) -> Res<feed::SyncReport> {
    match feed::sync_once(&app).await {
        Ok(r) => {
            app.set_cert_problem(None);
            let _ = handle.emit("synced", &r);
            Ok(r)
        }
        Err(e) => {
            note_sync_error(&app, &e);
            let _ = handle.emit("sync-error", format!("{e:#}"));
            if api::is_status(&e, 401) {
                removed_check(&handle, &app).await;
            }
            Err(err(e))
        }
    }
}

#[tauri::command]
fn get_feed(app: State<'_, Arc<App>>, before: Option<i64>, limit: Option<i64>) -> Res<Vec<feed::PostView>> {
    // A removed device can still read what it saved.
    let id = app.require_archive().map_err(err)?;
    feed::feed(&app.db(), &id.member_id, id.is_keymaster(), before, limit.unwrap_or(50).clamp(1, 500)).map_err(err)
}

#[derive(Serialize)]
struct StagedView {
    id: String,
    preview: String,
    width: u32,
    height: u32,
    bytes: usize,
    /// It was animated and only the first frame will be sent.
    still: bool,
}

fn staged_view(id: &str, p: &photo::Processed) -> StagedView {
    StagedView {
        id: id.to_string(),
        preview: format!("data:image/webp;base64,{}", B64.encode(&p.thumb)),
        width: p.width,
        height: p.height,
        bytes: p.full.len(),
        still: p.still,
    }
}

/// Photos still waiting to be sent, for a page that was reloaded with drafts
/// (Android may rebuild the window, e.g. moving between a flip phone's screens).
/// `None` for any that are gone.
#[tauri::command]
fn staged_photos(app: State<'_, Arc<App>>, ids: Vec<String>) -> Vec<Option<StagedView>> {
    let staged = app.staged.lock().unwrap_or_else(|e| e.into_inner());
    ids.iter().map(|id| staged.get(id).map(|p| staged_view(id, p))).collect()
}

/// Run the photo pipeline on `bytes` and keep the result until it's posted.
async fn stage(app: &App, bytes: Vec<u8>) -> Res<StagedView> {
    let p = tauri::async_runtime::spawn_blocking(move || photo::process(&bytes))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)?;
    let mut idb = [0u8; 9];
    getrandom::getrandom(&mut idb).map_err(|e| e.to_string())?;
    let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
    let view = staged_view(&id, &p);
    app.staged.lock().unwrap_or_else(|e| e.into_inner()).insert(id, p);
    Ok(view)
}

/// Takes the raw file bytes as the request body (no JSON), so large photos
/// cross the IPC bridge without being turned into number arrays.
#[tauri::command]
async fn stage_photo(app: State<'_, Arc<App>>, request: tauri::ipc::Request<'_>) -> Res<StagedView> {
    let bytes = body_bytes(&request).ok_or("expected the photo's bytes")?;
    stage(&app, bytes).await
}

/// An image dragged in from a web page that came with only its address:
/// download it (http or https, at most `photo::MAX_INPUT_BYTES`) and stage it.
#[tauri::command]
async fn stage_photo_url(app: State<'_, Arc<App>>, url: String) -> Res<StagedView> {
    let bytes = download_image(&url).await.map_err(err)?;
    stage(&app, bytes).await
}

async fn download_image(url: &str) -> anyhow::Result<Vec<u8>> {
    use anyhow::{bail, Context};
    let u = reqwest::Url::parse(url.trim()).context("that isn't a web address")?;
    if !matches!(u.scheme(), "http" | "https") {
        bail!("can't fetch a picture from that kind of address");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("SideTray/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut resp = client.get(u).send().await.context("couldn't download that picture")?;
    if !resp.status().is_success() {
        bail!("couldn't download that picture (the site said {})", resp.status());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("couldn't download that picture")? {
        out.extend_from_slice(&chunk);
        if out.len() > photo::MAX_INPUT_BYTES {
            bail!("that picture is over {} MB", photo::MAX_INPUT_BYTES / 1024 / 1024);
        }
    }
    Ok(out)
}

// --- Android: Share → Side Tray, the back button, the camera (A2) ------------------------

/// What another app shared to Side Tray, if anything. Nothing on a computer.
#[cfg(target_os = "android")]
#[tauri::command]
fn take_share() -> Res<Option<android::ShareView>> {
    android::take_share().map_err(err)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn take_share() -> Res<Option<()>> {
    Ok(None)
}

/// Shared picture number `index`, through the same pipeline as any photo.
#[tauri::command]
async fn stage_shared_photo(app: State<'_, Arc<App>>, index: usize) -> Res<StagedView> {
    #[cfg(target_os = "android")]
    {
        let bytes = tauri::async_runtime::spawn_blocking(move || android::take_shared_photo(index))
            .await
            .map_err(|e| e.to_string())?
            .map_err(err)?;
        stage(&app, bytes).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, index);
        Err("nothing was shared".into())
    }
}

/// Done with what was shared (sent, or set aside): delete what's left of it.
#[tauri::command]
fn end_share() {
    #[cfg(target_os = "android")]
    android::end_share();
}

/// The back button with nothing left to close or go back to: background the app.
#[tauri::command]
fn leave_app() -> Res<()> {
    #[cfg(target_os = "android")]
    android::move_to_background().map_err(err)?;
    Ok(())
}

/// How many times the page has started in this run of the app: more than one
/// means Android rebuilt the window (the page then puts its view back).
#[tauri::command]
fn page_boot() -> u32 {
    static BOOTS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    BOOTS.fetch_add(1, Ordering::SeqCst) + 1
}

/// The phone's system bars and cutouts in CSS pixels (top, right, bottom, left).
#[tauri::command]
fn system_insets() -> Option<[f32; 4]> {
    #[cfg(target_os = "android")]
    return android::insets().unwrap_or_else(|e| {
        eprintln!("reading window insets: {e:#}");
        None
    });
    #[cfg(not(target_os = "android"))]
    None
}

/// Delete the camera's full-size originals once their photos are staged.
#[tauri::command]
fn forget_captures() {
    #[cfg(target_os = "android")]
    if let Err(e) = android::clean_captures() {
        eprintln!("deleting camera originals: {e:#}");
    }
}

/// A photo the webview can't show (HEIC on a phone) as WebP, for the profile
/// photo cropper. Resized and stripped like any photo.
#[tauri::command]
async fn photo_preview(request: tauri::ipc::Request<'_>) -> Res<String> {
    let bytes = body_bytes(&request).ok_or("expected the photo's bytes")?;
    let p = tauri::async_runtime::spawn_blocking(move || photo::process(&bytes))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)?;
    Ok(format!("data:image/webp;base64,{}", B64.encode(&p.full)))
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
async fn add_comment(app: State<'_, Arc<App>>, post_id: String, text: String, photos: Option<Vec<String>>) -> Res<()> {
    feed::add_comment(&app, &post_id, &text, &photos.unwrap_or_default()).await.map_err(err)
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

// --- direct messages (Phase 5b) -------------------------------------------------------------

#[tauri::command]
fn list_conversations(app: State<'_, Arc<App>>) -> Res<Vec<dm::ConversationView>> {
    app.require_archive().map_err(err)?;
    dm::conversations(&app.db()).map_err(err)
}

#[tauri::command]
fn open_chat(app: State<'_, Arc<App>>, member_id: String) -> Res<dm::ChatView> {
    let id = app.require_archive().map_err(err)?;
    dm::chat(&app.db(), &id, &member_id).map_err(err)
}

#[tauri::command]
fn dm_recipients(app: State<'_, Arc<App>>) -> Res<Vec<dm::Recipient>> {
    let id = app.require_active().map_err(err)?;
    dm::recipients(&app.db(), &id.member_id).map_err(err)
}

#[tauri::command]
async fn send_dm(app: State<'_, Arc<App>>, member_id: String, text: String, photos: Vec<String>) -> Res<()> {
    dm::send(&app, &member_id, &text, &photos).await.map_err(err)
}

/// The conversation was looked at: clear its unread count (and the badge).
#[tauri::command]
fn mark_dm_read(handle: AppHandle, app: State<'_, Arc<App>>, member_id: String) -> Res<()> {
    dm::mark_read(&app.db(), &member_id).map_err(err)?;
    tray::refresh(&handle, &app);
    Ok(())
}

// --- notifications on a phone (A3) ------------------------------------------------------------

/// Notifications and how they're delivered (instant through UnifiedPush, or
/// the periodic sync). None on a computer.
#[cfg(target_os = "android")]
#[tauri::command]
fn push_status(app: State<'_, Arc<App>>) -> Res<Option<mobile_push::PushView>> {
    mobile_push::view(&app).map(Some).map_err(err)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn push_status() -> Res<Option<()>> {
    Ok(None)
}

/// Register with the distributor again, asking it for a fresh endpoint (the
/// person installed ntfy, or changed its server).
#[tauri::command]
fn push_setup(app: State<'_, Arc<App>>) {
    #[cfg(target_os = "android")]
    mobile_push::setup_with(&app, true);
    #[cfg(not(target_os = "android"))]
    let _ = app;
}

/// Battery settings for Side Tray ("app") or the push app ("distributor").
#[tauri::command]
fn open_battery_settings(app: State<'_, Arc<App>>, which: String) -> Res<()> {
    #[cfg(target_os = "android")]
    mobile_push::open_battery_settings(&app, &which).map_err(err)?;
    #[cfg(not(target_os = "android"))]
    let _ = (app, which);
    Ok(())
}

/// The person chose to turn notifications on: Android's permission prompt.
#[tauri::command]
fn request_notifications(app: State<'_, Arc<App>>) -> Res<String> {
    #[cfg(target_os = "android")]
    {
        mobile_push::mark(&app, mobile_push::NOTIF_ASKED);
        android::request_notification_permission().map_err(err)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Ok(String::new())
    }
}

/// "Not now" on the offer, or the one-time note about instant notifications was read.
#[tauri::command]
fn dismiss_notice(app: State<'_, Arc<App>>, which: String) {
    #[cfg(target_os = "android")]
    match which.as_str() {
        "notifications" => mobile_push::mark(&app, mobile_push::NOTIF_ASKED),
        "push_note" => mobile_push::mark(&app, mobile_push::NOTE_SEEN),
        "battery" => mobile_push::mark(&app, mobile_push::BATTERY_LATER),
        _ => {}
    }
    #[cfg(not(target_os = "android"))]
    let _ = (app, which);
}

#[tauri::command]
fn open_notification_settings() -> Res<()> {
    #[cfg(target_os = "android")]
    android::open_notification_settings().map_err(err)?;
    Ok(())
}

/// What a tapped notification was about, if the app was opened by one.
#[tauri::command]
fn take_open() -> Res<Option<alerts::Target>> {
    #[cfg(target_os = "android")]
    {
        let Some(t) = android::take_open().map_err(err)? else { return Ok(None) };
        Ok(serde_json::from_str(&t).ok())
    }
    #[cfg(not(target_os = "android"))]
    Ok(None)
}

// --- settings ----------------------------------------------------------------------------

#[derive(Serialize)]
struct Settings {
    start_with_os: bool,
    /// A phone: no tray, no autostart, no self-update; the UI hides those.
    mobile: bool,
}

#[cfg(desktop)]
#[tauri::command]
fn get_settings(handle: AppHandle) -> Res<Settings> {
    Ok(Settings { start_with_os: handle.autolaunch().is_enabled().map_err(|e| e.to_string())?, mobile: false })
}

#[cfg(mobile)]
#[tauri::command]
fn get_settings(_handle: AppHandle) -> Res<Settings> {
    Ok(Settings { start_with_os: false, mobile: true })
}

#[cfg(desktop)]
#[tauri::command]
fn set_start_with_os(handle: AppHandle, enabled: bool) -> Res<Settings> {
    let launcher = handle.autolaunch();
    if enabled { launcher.enable() } else { launcher.disable() }.map_err(|e| e.to_string())?;
    get_settings(handle)
}

#[cfg(mobile)]
#[tauri::command]
fn set_start_with_os(_handle: AppHandle, _enabled: bool) -> Res<Settings> {
    Err("not on a phone".into())
}

// --- updates -----------------------------------------------------------------------------

#[tauri::command]
fn update_status(handle: AppHandle) -> update::View {
    update::view(&handle)
}

#[tauri::command]
async fn check_for_updates(handle: AppHandle) -> update::View {
    update::check(&handle).await
}

#[tauri::command]
fn install_update(handle: AppHandle) -> Res<()> {
    update::install(&handle).map_err(err)
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

/// Remember a refused certificate, so the app can say so plainly (and keep saying it).
fn note_sync_error(app: &App, e: &anyhow::Error) {
    if let Some(c) = e.chain().find_map(|c| c.downcast_ref::<api::CertError>()) {
        app.set_cert_problem(Some(c.to_string()));
    }
}

fn spawn_sync_loop(handle: AppHandle, app: Arc<App>) {
    tauri::async_runtime::spawn(async move {
        loop {
            let active = matches!(app.identity(), Ok(Some(id)) if id.status == "active");
            if active {
                match feed::sync_once(&app).await {
                    Ok(r) => {
                        app.set_cert_problem(None);
                        let _ = handle.emit("synced", &r);
                    }
                    Err(e) => {
                        note_sync_error(&app, &e);
                        if api::is_status(&e, 401) {
                            // Token refused: removed or revoked while we weren't connected?
                            removed_check(&handle, &app).await;
                        }
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();
    #[cfg(desktop)]
    {
        // SIDETRAY_DATA_DIR lets several copies run side by side (testing); otherwise
        // a second launch just brings the running app forward.
        if std::env::var_os("SIDETRAY_DATA_DIR").is_none() {
            // With the deep-link feature, a second launch's sidetray:// link reaches this copy's on_open_url.
            builder = builder.plugin(tauri_plugin_single_instance::init(|handle, _args, _cwd| tray::show_main(handle)));
        }
        builder = builder
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec![MINIMIZED_ARG])))
            // Closing the window keeps the app running in the tray; Quit is in the tray menu.
            .on_window_event(|window, event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            });
    }
    builder = builder.plugin(tauri_plugin_deep_link::init());
    #[cfg(not(windows))]
    {
        builder = builder.plugin(tauri_plugin_notification::init());
    }
    builder
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
            // A push wake-up may have opened it already, in this process (Android).
            let app = state::shared(dir.clone())?;
            let handle = tauri_app.handle().clone();
            let _ = app.handle.set(handle.clone());
            tauri_app.manage(app.clone());
            tauri_app.manage(update::Updates::default());
            // The installer registers the notification app id and sidetray:// links
            // against the installed exe; a copy run from a build does it itself.
            #[cfg_attr(not(any(windows, target_os = "linux")), allow(unused_variables))]
            let installed = update::installed();
            #[cfg(windows)]
            if !installed {
                if let Err(e) = alerts::register_app_id(&handle, &dir) {
                    eprintln!("registering for notifications: {e:#}");
                }
            }
            tray::create(&handle)?;
            tray::refresh(&handle, &app);
            #[cfg(desktop)]
            if !std::env::args().any(|a| a == MINIMIZED_ARG) {
                tray::show_main(&handle);
            }
            // Not installed (a build run from a checkout): register sidetray:// for this
            // user (HKCU on Windows) at every start. An AppImage registers itself too.
            #[cfg(any(windows, target_os = "linux"))]
            if !installed || cfg!(target_os = "linux") {
                if let Err(e) = tauri_app.deep_link().register_all() {
                    eprintln!("registering sidetray:// links: {e}");
                }
            }
            {
                let (h, a) = (handle.clone(), app.clone());
                tauri_app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        got_link(&h, &a, url.as_str());
                    }
                });
            }
            // Started by clicking a link.
            if let Ok(Some(urls)) = tauri_app.deep_link().get_current() {
                for url in urls {
                    got_link(&handle, &app, url.as_str());
                }
            }
            spawn_sync_loop(handle.clone(), app.clone());
            update::spawn(handle.clone());
            #[cfg(target_os = "android")]
            {
                android::ANDROID_CONTEXT_READY.store(true, Ordering::SeqCst);
                mobile_push::setup(&app);
            }
            push::spawn(handle, app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            check_server,
            trust_server,
            probe_group,
            register,
            take_invite,
            invite_link,
            get_profile,
            set_display_name,
            set_avatar,
            remove_avatar,
            accept_name,
            check_server_cert,
            repin_server_cert,
            join_progress,
            confirm_approval,
            reset,
            list_pending,
            approve,
            deny,
            list_members,
            promote_member,
            remove_member,
            revoke_device,
            dismiss_missed,
            sync_now,
            get_feed,
            stage_photo,
            stage_photo_url,
            unstage_photo,
            staged_photos,
            take_share,
            take_open,
            push_status,
            push_setup,
            request_notifications,
            dismiss_notice,
            open_notification_settings,
            open_battery_settings,
            stage_shared_photo,
            end_share,
            leave_app,
            forget_captures,
            system_insets,
            page_boot,
            photo_preview,
            create_post,
            add_comment,
            set_reaction,
            delete_post,
            mark_read,
            list_conversations,
            open_chat,
            dm_recipients,
            send_dm,
            mark_dm_read,
            get_settings,
            set_start_with_os,
            update_status,
            check_for_updates,
            install_update,
        ])
        .build(tauri::generate_context!())
        .expect("error while starting Side Tray")
        .run(|_handle, event| {
            // Hidden windows don't count as open; only the tray's Quit (an explicit exit code) ends the app.
            #[cfg(desktop)]
            if let tauri::RunEvent::ExitRequested { code: None, api, .. } = event {
                api.prevent_exit();
            }
            // Coming back to the foreground: sync now, and reconnect the push socket
            // (a phone closes it in the background; wake-ups or the periodic sync take over).
            #[cfg(mobile)]
            match event {
                tauri::RunEvent::Resumed => {
                    tray::set_foreground(true);
                    // Maybe brought back by "Share → Side Tray": the page checks.
                    let _ = _handle.emit("resumed", ());
                    if let Some(app) = _handle.try_state::<Arc<App>>() {
                        app.wake.notify_one();
                        app.push_wake.notify_one();
                    }
                }
                _ => {}
            }
        });
}
