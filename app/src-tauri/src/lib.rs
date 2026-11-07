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
mod profiles;
mod push;
mod secrets;
mod state;
#[cfg_attr(mobile, path = "tray_mobile.rs")]
mod tray;
#[cfg_attr(mobile, path = "update_mobile.rs")]
mod update;
mod video;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use sidetray_crypto as crypto;
use profiles::Profiles;
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

/// The profile the window shows (SPEC.md Phase 8): what every UI command acts on.
pub struct Active(Arc<App>);

impl std::ops::Deref for Active {
    type Target = App;
    fn deref(&self) -> &App {
        &self.0
    }
}

impl<'de, R: tauri::Runtime> tauri::ipc::CommandArg<'de, R> for Active {
    fn from_command(command: tauri::ipc::CommandItem<'de, R>) -> Result<Self, tauri::ipc::InvokeError> {
        let p = command
            .message
            .webview_ref()
            .try_state::<Arc<Profiles>>()
            .ok_or_else(|| tauri::ipc::InvokeError::from_anyhow(anyhow::anyhow!("the app isn't ready yet")))?;
        Ok(Active(p.active()))
    }
}

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
    /// This profile (SPEC.md Phase 8).
    profile: String,
    /// Other profiles that joined (or asked to join) a group: the group menu shows when there are any.
    other_groups: usize,
    /// The wizard for another group can go back to this profile.
    previous: Option<String>,
}

#[tauri::command]
fn get_state(app: Active, profiles: State<'_, Arc<Profiles>>) -> Res<AppView> {
    let id = app.identity().map_err(err)?;
    let profile = app.profile_id.clone();
    let other_groups = profiles
        .all()
        .iter()
        .filter(|a| a.profile_id != profile && matches!(a.identity(), Ok(Some(_))))
        .count();
    let previous = profiles.previous();
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
            profile,
            other_groups,
            previous,
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
            profile,
            other_groups,
            previous: None,
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
async fn check_server(app: Active, server: String, ca_pem: Option<String>) -> Res<ServerCheck> {
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
fn trust_server(app: Active, fingerprint: String) -> Res<()> {
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
async fn probe_group(app: Active, group_name: String) -> Res<api::GroupInfo> {
    let t = confirmed_server(&app)?;
    account::probe(&t.server, t.root_pem.as_deref(), &group_name).await.map_err(err)
}

#[tauri::command]
async fn register(
    app: Active,
    profiles: State<'_, Arc<Profiles>>,
    group_name: String,
    display_name: String,
    email: String,
    setup_token: Option<String>,
) -> Res<String> {
    let t = confirmed_server(&app)?;
    if let Some(other) = profiles.find_group(&t.server, &group_name, &app.profile_id) {
        let name = other.identity().ok().flatten().map(|i| i.group_name).unwrap_or_default();
        return Err(format!("This app is already in “{name}”. Pick it from the group menu at the top."));
    }
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
    profiles.remember();
    app.wake.notify_one();
    app.push_wake.notify_one();
    Ok(code)
}

/// The invite link that opened the app, if the wizard hasn't taken it yet.
#[tauri::command]
fn take_invite(profiles: State<'_, Arc<Profiles>>) -> Option<state::InviteMsg> {
    profiles.pending_invite.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// A `sidetray://` link reached the app (at launch, or from a second launch).
fn got_link(handle: &AppHandle, profiles: &Profiles, url: &str) {
    let msg = match invite::parse(url) {
        Ok(i) => state::InviteMsg { invite: Some(i), error: None },
        Err(e) => state::InviteMsg { invite: None, error: Some(format!("{e:#}")) },
    };
    *profiles.pending_invite.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
    let _ = handle.emit("invite", ());
    tray::show_main(handle);
}

#[tauri::command]
async fn join_progress(app: Active) -> Res<account::JoinProgress> {
    account::join_progress(&app).await.map_err(err)
}

#[tauri::command]
async fn confirm_approval(app: Active, code: String) -> Res<()> {
    account::confirm_approval(&app, &code).await.map_err(err)?;
    app.wake.notify_one();
    app.push_wake.notify_one();
    #[cfg(target_os = "android")]
    mobile_push::setup(&app.0);
    Ok(())
}

// --- groups (Phase 8) ------------------------------------------------------------------

#[derive(Serialize)]
struct GroupView {
    id: String,
    /// None: the wizard hasn't joined anything yet.
    group_name: Option<String>,
    server: Option<String>,
    /// setup / pending / denied / active / removed / revoked / left
    stage: String,
    active: bool,
    /// Unread posts, messages or join requests.
    unread: bool,
}

#[tauri::command]
fn list_groups(profiles: State<'_, Arc<Profiles>>) -> Vec<GroupView> {
    let active = profiles.active_id();
    let mut out: Vec<GroupView> = profiles
        .all()
        .iter()
        .map(|a| {
            let id = a.identity().ok().flatten();
            let unread = {
                let conn = a.db();
                db::unread(&conn).unwrap_or(0) + db::dm_unread(&conn).unwrap_or(0) > 0
            } || a.pending_joins.load(Ordering::SeqCst) > 0;
            GroupView {
                id: a.profile_id.clone(),
                stage: id.as_ref().map_or("setup".into(), |i| i.status.clone()),
                server: id.as_ref().map(|i| i.server_url.clone()),
                group_name: id.map(|i| i.group_name),
                active: a.profile_id == active,
                unread,
            }
        })
        .collect();
    out.sort_by_key(|g| (g.group_name.is_none(), g.group_name.clone().unwrap_or_default().to_lowercase()));
    out
}

#[tauri::command]
fn switch_group(handle: AppHandle, profiles: State<'_, Arc<Profiles>>, id: String) -> Res<()> {
    let app = profiles.switch(&id).map_err(err)?;
    app.wake.notify_one();
    tray::refresh(&handle, &app);
    Ok(())
}

/// "Join another group" (or an invite link while in a group): an empty
/// profile, shown in the wizard.
#[tauri::command]
fn start_join(handle: AppHandle, profiles: State<'_, Arc<Profiles>>) -> Res<()> {
    let (app, new) = profiles.start_join().map_err(err)?;
    if new {
        start_profile(&handle, &app);
    }
    Ok(())
}

/// What the app shows when the relay refuses /leave (409).
const ONLY_KEYMASTER: &str = "You’re the only Key Master. Promote someone else before leaving.";

/// Leave the group shown (SPEC.md Phase 8, "Leaving a group"): tell the relay
/// if this device is still in it, then delete everything this app saved from
/// it. Also how a denied, cancelled, removed or abandoned profile is deleted.
#[tauri::command]
async fn leave_group(handle: AppHandle, app: Active, profiles: State<'_, Arc<Profiles>>) -> Res<()> {
    let id = app.identity().map_err(err)?;
    if let Some(id) = &id {
        if id.status == "active" {
            let api = app.api(id).map_err(err)?;
            app.set_leaving(true);
            let left: anyhow::Result<serde_json::Value> = api.post("/leave", &serde_json::json!({})).await;
            if let Err(e) = left {
                app.set_leaving(false);
                // 409 is the relay's only refusal here: the last Key Master with others still in the group.
                if api::is_status(&e, 409) {
                    return Err(ONLY_KEYMASTER.into());
                }
                return Err(err(e));
            }
        }
    }
    #[cfg(target_os = "android")]
    mobile_push::forget(&app.0);
    profiles.remove(&app.profile_id).map_err(err)?;
    let next = profiles.active();
    next.wake.notify_one();
    #[cfg(target_os = "android")]
    mobile_push::setup(&next);
    tray::refresh(&handle, &next);
    let _ = handle.emit("groups-changed", ());
    Ok(())
}

// --- Key Master ----------------------------------------------------------------------

#[tauri::command]
async fn list_pending(app: Active) -> Res<Vec<account::PendingView>> {
    account::list_pending(&app).await.map_err(err)
}

#[tauri::command]
async fn approve(app: Active, device_id: String, code: String, as_keymaster: bool) -> Res<account::Approved> {
    account::approve(&app, &device_id, &code, as_keymaster).await.map_err(err)
}

#[tauri::command]
async fn deny(app: Active, device_id: String) -> Res<()> {
    account::deny(&app, &device_id).await.map_err(err)
}

#[derive(Serialize)]
struct InviteView {
    link: String,
    qr: String,
}

#[tauri::command]
fn invite_link(app: Active) -> Res<InviteView> {
    let id = app.require_keymaster().map_err(err)?;
    let link = invite::link(&id.server_url, &id.group_name).map_err(err)?;
    Ok(InviteView { qr: invite::qr_data_url(&link).map_err(err)?, link })
}

// --- profile (Phase 6b) --------------------------------------------------------------

#[tauri::command]
fn get_profile(app: Active) -> Res<profile::MyProfile> {
    profile::mine(&app).map_err(err)
}

#[tauri::command]
async fn set_display_name(app: Active, name: String) -> Res<profile::MyProfile> {
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
async fn set_avatar(app: Active, request: tauri::ipc::Request<'_>) -> Res<profile::MyProfile> {
    let bytes = body_bytes(&request).ok_or("expected the cropped photo")?;
    profile::save(&app, None, profile::AvatarChange::New(bytes)).await.map_err(err)?;
    profile::mine(&app).map_err(err)
}

#[tauri::command]
async fn remove_avatar(app: Active) -> Res<profile::MyProfile> {
    profile::save(&app, None, profile::AvatarChange::Remove).await.map_err(err)?;
    profile::mine(&app).map_err(err)
}

#[tauri::command]
async fn accept_name(app: Active, member_id: String) -> Res<String> {
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
async fn check_server_cert(app: Active) -> Res<CertCheck> {
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
fn repin_server_cert(app: Active, fingerprint: String) -> Res<()> {
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
async fn list_members(app: Active) -> Res<Vec<manage::MemberView>> {
    manage::list_members(&app).await.map_err(err)
}

#[tauri::command]
async fn promote_member(app: Active, member_id: String) -> Res<String> {
    let name = manage::promote(&app, &member_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(name)
}

#[tauri::command]
async fn remove_member(app: Active, member_id: String) -> Res<manage::Change> {
    let c = manage::remove_member(&app, &member_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(c)
}

#[tauri::command]
async fn revoke_device(app: Active, device_id: String) -> Res<manage::Change> {
    let c = manage::revoke_device(&app, &device_id).await.map_err(err)?;
    app.wake.notify_one();
    Ok(c)
}

#[tauri::command]
fn dismiss_missed(app: Active) -> Res<()> {
    db::clear_missed(&app.db()).map_err(err)
}

/// After a `removed` push or a 401: ask the relay where this device stands. If
/// it was removed, that's recorded (syncing stops; the archive stays), and the
/// UI and a notification say so.
pub async fn removed_check(handle: &AppHandle, app: &App) {
    if app.is_leaving() {
        return;
    }
    match manage::check_standing(app).await {
        Ok(Some(status)) => {
            alerts::removed(app, &status);
            app.push_wake.notify_one();
            tray::refresh(handle, app);
            profiles::emit(handle, app, "removed", status);
        }
        Ok(None) => {}
        Err(e) => eprintln!("checking whether this device was removed: {e:#}"),
    }
}

// --- feed ------------------------------------------------------------------------------

#[tauri::command]
async fn sync_now(handle: AppHandle, app: Active) -> Res<feed::SyncReport> {
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
fn get_feed(app: Active, before: Option<i64>, limit: Option<i64>) -> Res<Vec<feed::PostView>> {
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
fn staged_photos(app: Active, ids: Vec<String>) -> Vec<Option<StagedView>> {
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
async fn stage_photo(app: Active, request: tauri::ipc::Request<'_>) -> Res<StagedView> {
    let bytes = body_bytes(&request).ok_or("expected the photo's bytes")?;
    stage(&app, bytes).await
}

/// An image dragged in from a web page that came with only its address:
/// download it (http or https, at most `photo::MAX_INPUT_BYTES`) and stage it.
#[tauri::command]
async fn stage_photo_url(app: Active, url: String) -> Res<StagedView> {
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
async fn stage_shared_photo(app: Active, index: usize) -> Res<StagedView> {
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
fn unstage_photo(app: Active, id: String) {
    app.staged.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}

/// Whether this computer can send videos (Phase 9), and if not, why.
#[tauri::command]
async fn video_support() -> video::Support {
    video::support().await
}

#[derive(Serialize)]
struct StagedVideoView {
    id: String,
    /// The poster frame.
    preview: String,
    width: u32,
    height: u32,
    duration_ms: u64,
    bytes: u64,
}

fn staged_video_view(id: &str, v: &video::Prepared) -> StagedVideoView {
    StagedVideoView {
        id: id.to_string(),
        preview: format!("data:image/webp;base64,{}", B64.encode(&v.thumb)),
        width: v.width,
        height: v.height,
        duration_ms: v.duration_ms,
        bytes: v.size,
    }
}

/// `needs_trim` (the clip's length) when it's over 60 s and the person hasn't
/// said yet to use its first 60 seconds; otherwise the prepared video.
#[derive(Serialize)]
struct StageVideoResult {
    needs_trim: Option<u64>,
    video: Option<StagedVideoView>,
}

/// The native file dialog for a video; its path, or None if cancelled.
#[tauri::command]
async fn pick_video(handle: AppHandle) -> Option<String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_dialog::DialogExt;
        let (tx, rx) = tokio::sync::oneshot::channel();
        handle
            .dialog()
            .file()
            .set_title("Choose a video")
            .add_filter("Videos", &["mp4", "mov", "m4v", "mkv", "webm", "avi", "3gp", "mts", "m2ts", "wmv", "mpg", "mpeg"])
            .pick_file(move |f| {
                let _ = tx.send(f);
            });
        rx.await.ok().flatten().and_then(|f| f.into_path().ok()).map(|p| p.display().to_string())
    }
    #[cfg(not(desktop))]
    {
        let _ = handle;
        None
    }
}

/// Prepare the video at `path` for sending (SPEC "Transcoding"), reporting
/// progress as `video-progress` events, and keep it until it's posted.
#[tauri::command]
async fn stage_video(handle: AppHandle, app: Active, path: String, trim: Option<bool>) -> Res<StageVideoResult> {
    let ffmpeg = video::ffmpeg_path().ok_or("This copy of Side Tray can't prepare videos.")?;
    let source = std::path::PathBuf::from(&path);
    let info = video::probe(&ffmpeg, &source).await.map_err(err)?;
    if info.duration_ms > video::MAX_DURATION_MS + video::TRIM_SLACK_MS && trim != Some(true) {
        return Ok(StageVideoResult { needs_trim: Some(info.duration_ms), video: None });
    }
    let cancel = video::Cancel::default();
    if let Some(old) = app.transcode.lock().unwrap_or_else(|e| e.into_inner()).replace(cancel.clone()) {
        old.notify_one();
    }
    let mut idb = [0u8; 9];
    getrandom::getrandom(&mut idb).map_err(|e| e.to_string())?;
    let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
    let dir = app.dir.join(video::STAGING_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = dir.join(format!("{id}.mp4"));
    let (h, profile) = (handle.clone(), app.profile_id.clone());
    let result = video::prepare(&ffmpeg, &source, &out, &cancel, move |fraction| {
        let _ = h.emit("video-progress", serde_json::json!({ "profile": profile, "fraction": fraction }));
    })
    .await;
    {
        let mut slot = app.transcode.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, &cancel)) {
            *slot = None;
        }
    }
    let v = result.map_err(err)?;
    let view = staged_video_view(&id, &v);
    app.staged_videos.lock().unwrap_or_else(|e| e.into_inner()).insert(id, v);
    Ok(StageVideoResult { needs_trim: None, video: Some(view) })
}

#[tauri::command]
fn cancel_transcode(app: Active) {
    if let Some(c) = app.transcode.lock().unwrap_or_else(|e| e.into_inner()).take() {
        c.notify_one();
    }
}

#[tauri::command]
fn unstage_video(app: Active, id: String) {
    if let Some(v) = app.staged_videos.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
        let _ = std::fs::remove_file(v.path);
    }
}

/// Like `staged_photos`, for a reloaded page's draft video.
#[tauri::command]
fn staged_video(app: Active, id: String) -> Option<StagedVideoView> {
    app.staged_videos.lock().unwrap_or_else(|e| e.into_inner()).get(&id).map(|v| staged_video_view(&id, v))
}

#[tauri::command]
async fn create_post(app: Active, text: String, photos: Vec<String>) -> Res<()> {
    feed::create_post(&app, &text, &photos).await.map_err(err)
}

#[tauri::command]
async fn add_comment(app: Active, post_id: String, text: String, photos: Option<Vec<String>>) -> Res<()> {
    feed::add_comment(&app, &post_id, &text, &photos.unwrap_or_default()).await.map_err(err)
}

#[tauri::command]
async fn set_reaction(app: Active, post_id: String, emoji: String) -> Res<()> {
    feed::set_reaction(&app, &post_id, &emoji).await.map_err(err)
}

#[tauri::command]
async fn delete_post(app: Active, post_id: String) -> Res<()> {
    feed::delete_post(&app, &post_id).await.map_err(err)
}

/// The feed was looked at: clear the unread badge.
#[tauri::command]
fn mark_read(handle: AppHandle, app: Active) -> Res<()> {
    db::clear_unread(&app.db()).map_err(err)?;
    tray::refresh(&handle, &app);
    Ok(())
}

// --- direct messages (Phase 5b) -------------------------------------------------------------

#[tauri::command]
fn list_conversations(app: Active) -> Res<Vec<dm::ConversationView>> {
    app.require_archive().map_err(err)?;
    dm::conversations(&app.db()).map_err(err)
}

#[tauri::command]
fn open_chat(app: Active, member_id: String) -> Res<dm::ChatView> {
    let id = app.require_archive().map_err(err)?;
    dm::chat(&app.db(), &id, &member_id).map_err(err)
}

#[tauri::command]
fn dm_recipients(app: Active) -> Res<Vec<dm::Recipient>> {
    let id = app.require_active().map_err(err)?;
    dm::recipients(&app.db(), &id.member_id).map_err(err)
}

#[tauri::command]
async fn send_dm(app: Active, member_id: String, text: String, photos: Vec<String>) -> Res<()> {
    dm::send(&app, &member_id, &text, &photos).await.map_err(err)
}

/// The conversation was looked at: clear its unread count (and the badge).
#[tauri::command]
fn mark_dm_read(handle: AppHandle, app: Active, member_id: String) -> Res<()> {
    dm::mark_read(&app.db(), &member_id).map_err(err)?;
    tray::refresh(&handle, &app);
    Ok(())
}

// --- notifications on a phone (A3) ------------------------------------------------------------

/// Notifications and how they're delivered (instant through UnifiedPush, or
/// the periodic sync). None on a computer.
#[cfg(target_os = "android")]
#[tauri::command]
fn push_status(app: Active) -> Res<Option<mobile_push::PushView>> {
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
fn push_setup(app: Active) {
    #[cfg(target_os = "android")]
    mobile_push::setup_with(&app.0, true);
    #[cfg(not(target_os = "android"))]
    let _ = app;
}

/// Battery settings for Side Tray ("app") or the push app ("distributor").
#[tauri::command]
fn open_battery_settings(app: Active, which: String) -> Res<()> {
    #[cfg(target_os = "android")]
    mobile_push::open_battery_settings(&app, &which).map_err(err)?;
    #[cfg(not(target_os = "android"))]
    let _ = (app, which);
    Ok(())
}

/// The person chose to turn notifications on: Android's permission prompt.
#[tauri::command]
fn request_notifications(app: Active) -> Res<String> {
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
fn dismiss_notice(app: Active, which: String) {
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

/// What a tapped notification was about, if the app was opened by one: an
/// `alerts::Target`, plus the group it's in (`group`, see `alerts::target_json`).
#[tauri::command]
fn take_open() -> Res<Option<serde_json::Value>> {
    #[cfg(target_os = "android")]
    {
        let Some(t) = android::take_open().map_err(err)? else { return Ok(None) };
        let v: Option<serde_json::Value> = serde_json::from_str(&t).ok();
        Ok(v.filter(|v| serde_json::from_value::<alerts::Target>(v.clone()).is_ok()))
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

/// New installs start at sign-in; installs from before 0.2.0 keep what they had.
/// Decided once per data folder (a marker file), and only for an installed copy:
/// a build run from a checkout, or a test copy with its own data folder, never
/// registers itself.
#[cfg(desktop)]
fn autostart_default(handle: &AppHandle, app: &App, dir: &std::path::Path) {
    let marker = dir.join("autostart-default");
    let installed_copy = update::installed()
        || (cfg!(target_os = "linux") && std::env::current_exe().is_ok_and(|p| p.starts_with("/usr/")));
    if marker.exists() || !installed_copy || std::env::var_os("SIDETRAY_DATA_DIR").is_some() {
        return;
    }
    // No identity yet: a new install (or one that never joined). Otherwise it's an update.
    let fresh = matches!(app.identity(), Ok(None));
    if fresh {
        if let Err(e) = handle.autolaunch().enable() {
            eprintln!("turning on start at sign-in: {e}");
            return;
        }
    }
    let _ = std::fs::write(&marker, if fresh { "on" } else { "kept" });
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

/// Desktop: install the downloaded update (the app restarts). Phone: download the
/// new APK if needed and open Android's installer; returns "started",
/// "needs_permission" (allow "install unknown apps" first) or "no_window".
#[tauri::command]
async fn install_update(handle: AppHandle) -> Res<String> {
    update::install(&handle).await.map_err(err)
}

/// Android's "Install unknown apps" switch for Side Tray. Nothing on a computer.
#[tauri::command]
fn open_install_settings() -> Res<()> {
    #[cfg(target_os = "android")]
    update::open_install_settings().map_err(err)?;
    Ok(())
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

/// A profile's background work: its sync loop and push socket (every
/// profile syncs, shown or not). Both stop when it's closed.
fn start_profile(handle: &AppHandle, app: &Arc<App>) {
    spawn_sync_loop(handle.clone(), app.clone());
    push::spawn(handle.clone(), app.clone());
}

fn spawn_sync_loop(handle: AppHandle, app: Arc<App>) {
    tauri::async_runtime::spawn(async move {
        loop {
            if app.is_closed() {
                break;
            }
            let active = matches!(app.identity(), Ok(Some(id)) if id.status == "active");
            if active {
                match feed::sync_once(&app).await {
                    Ok(r) => {
                        app.set_cert_problem(None);
                        profiles::emit(&handle, &app, "synced", &r);
                    }
                    Err(e) => {
                        note_sync_error(&app, &e);
                        if api::is_status(&e, 401) && !app.is_closed() {
                            // Token refused: removed or revoked while we weren't connected?
                            removed_check(&handle, &app).await;
                        }
                        profiles::emit(&handle, &app, "sync-error", format!("{e:#}"));
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
            .plugin(tauri_plugin_dialog::init())
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
            let app = ctx.app_handle().state::<Arc<Profiles>>().active();
            serve_media(&app, req.uri().path())
        })
        .setup(|tauri_app| {
            // SIDETRAY_DATA_DIR lets several copies run side by side (testing).
            let dir = match std::env::var_os("SIDETRAY_DATA_DIR") {
                Some(d) => d.into(),
                None => tauri_app.path().app_data_dir()?,
            };
            // A push wake-up may have opened them already, in this process (Android).
            let profiles = profiles::shared(dir.clone())?;
            let handle = tauri_app.handle().clone();
            state::set_handle(handle.clone());
            let app = profiles.active();
            tauri_app.manage(profiles.clone());
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
            #[cfg(desktop)]
            autostart_default(&handle, &app, &dir);
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
                let (h, p) = (handle.clone(), profiles.clone());
                tauri_app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        got_link(&h, &p, url.as_str());
                    }
                });
            }
            // Started by clicking a link.
            if let Ok(Some(urls)) = tauri_app.deep_link().get_current() {
                for url in urls {
                    got_link(&handle, &profiles, url.as_str());
                }
            }
            for a in profiles.all() {
                start_profile(&handle, &a);
            }
            update::spawn(handle.clone());
            #[cfg(target_os = "android")]
            {
                android::ANDROID_CONTEXT_READY.store(true, Ordering::SeqCst);
                for a in profiles.all() {
                    mobile_push::setup(&a);
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            video_support,
            pick_video,
            stage_video,
            cancel_transcode,
            unstage_video,
            staged_video,
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
            list_groups,
            switch_group,
            start_join,
            leave_group,
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
            open_install_settings,
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
                    if let Some(p) = _handle.try_state::<Arc<Profiles>>() {
                        for app in p.all() {
                            app.wake.notify_one();
                            app.push_wake.notify_one();
                        }
                    }
                    update::resumed(_handle);
                }
                _ => {}
            }
        });
}
