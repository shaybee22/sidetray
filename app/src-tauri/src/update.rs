//! Self-update (tauri-plugin-updater): check a signed `latest.json`, download
//! the new installer in the background, then offer "Restart to update" in the
//! window and the tray menu. Nothing installs without that click.
//!
//! The update is checked against the public key compiled in from
//! tauri.conf.json, so wherever the manifest comes from, only a bundle signed
//! with our private key installs.
//!
//! Where to look, first match wins:
//! 1. `SIDETRAY_UPDATE_URL` in the environment when the app starts,
//! 2. `SIDETRAY_UPDATE_URL` in the environment when the app was built,
//! 3. `plugins.updater.endpoints` in tauri.conf.json (the GitHub release).
//!
//! Only an installed copy updates itself (the NSIS install on Windows, an
//! AppImage on Linux); a `cargo build` from a checkout never does.

use crate::alerts::{self, Target};
use crate::tray;
use anyhow::{Context, Result};
use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

/// First check this long after startup (let the first sync go first), then every few hours.
const FIRST_CHECK: Duration = Duration::from_secs(20);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    /// Not an installed copy: updates come from wherever it was built.
    Off,
    Idle { checked_at: Option<i64> },
    Checking,
    Downloading { version: String },
    /// Downloaded and verified; installs on "Restart to update".
    Ready { version: String, notes: Option<String> },
    Failed { message: String },
}

#[derive(Serialize, Clone)]
pub struct View {
    pub current_version: String,
    #[serde(flatten)]
    pub status: Status,
}

#[derive(Default)]
pub struct Updates {
    status: Mutex<Option<Status>>,
    ready: Mutex<Option<(Update, Vec<u8>)>>,
    /// One check at a time (timer and button).
    checking: tokio::sync::Mutex<()>,
}

/// Is this an installed copy that may replace itself?
pub fn installed() -> bool {
    #[cfg(windows)]
    {
        // The NSIS installer puts uninstall.exe next to the app.
        std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("uninstall.exe").is_file())).unwrap_or(false)
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("APPIMAGE").is_some()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

fn endpoint_override() -> Option<String> {
    let runtime = std::env::var("SIDETRAY_UPDATE_URL").ok();
    let built = option_env!("SIDETRAY_UPDATE_URL").map(str::to_string);
    runtime.into_iter().chain(built).map(|s| s.trim().to_string()).find(|s| !s.is_empty())
}

fn updater(handle: &AppHandle) -> Result<tauri_plugin_updater::Updater> {
    let mut b = handle.updater_builder().timeout(Duration::from_secs(60));
    if let Some(url) = endpoint_override() {
        let url = url.parse().with_context(|| format!("SIDETRAY_UPDATE_URL is not a URL: {url}"))?;
        b = b.endpoints(vec![url])?;
    }
    Ok(b.build()?)
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn view(handle: &AppHandle) -> View {
    let u = handle.state::<Updates>();
    let status = u.status.lock().unwrap_or_else(|e| e.into_inner()).clone();
    View {
        current_version: handle.package_info().version.to_string(),
        status: status.unwrap_or(if installed() { Status::Idle { checked_at: None } } else { Status::Off }),
    }
}

fn set(handle: &AppHandle, status: Status) {
    *handle.state::<Updates>().status.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
    let _ = handle.emit("update", view(handle));
}

/// Check now; download what's new. Returns the resulting view.
pub async fn check(handle: &AppHandle) -> View {
    if !installed() {
        return view(handle);
    }
    let u = handle.state::<Updates>();
    let _one = u.checking.lock().await;
    if matches!(view(handle).status, Status::Ready { .. }) {
        return view(handle);
    }
    set(handle, Status::Checking);
    match check_inner(handle).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("update check: {e:#}");
            set(handle, Status::Failed { message: format!("{e:#}") });
        }
    }
    view(handle)
}

async fn check_inner(handle: &AppHandle) -> Result<()> {
    let Some(update) = updater(handle)?.check().await.context("couldn't reach the update server")? else {
        set(handle, Status::Idle { checked_at: Some(now()) });
        return Ok(());
    };
    let version = update.version.clone();
    set(handle, Status::Downloading { version: version.clone() });
    // download() checks the signature before returning the bytes.
    let bytes = update.download(|_, _| {}, || {}).await.context("download or signature check failed")?;
    let notes = update.body.clone().filter(|s| !s.trim().is_empty());
    *handle.state::<Updates>().ready.lock().unwrap_or_else(|e| e.into_inner()) = Some((update, bytes));
    set(handle, Status::Ready { version: version.clone(), notes });
    tray::set_update(handle, Some(&version));
    if !tray::main_window_focused(handle) {
        alerts::show(
            handle,
            "Side Tray update ready",
            &format!("Version {version} is downloaded. Choose Restart to update when it suits you."),
            Target::Update,
        );
    }
    Ok(())
}

/// Install the downloaded update. On Windows the installer takes over (the app
/// exits and comes back afterwards); elsewhere, restart into the new version.
pub fn install(handle: &AppHandle) -> Result<()> {
    let ready = handle.state::<Updates>().ready.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some((update, bytes)) = ready else { anyhow::bail!("no update is ready") };
    if let Err(e) = update.install(&bytes) {
        // Keep it for another try.
        let msg = format!("{e:#}");
        *handle.state::<Updates>().ready.lock().unwrap_or_else(|e| e.into_inner()) = Some((update, bytes));
        anyhow::bail!("couldn't install the update: {msg}");
    }
    handle.restart();
}

pub fn spawn(handle: AppHandle) {
    if !installed() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            check(&handle).await;
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}
