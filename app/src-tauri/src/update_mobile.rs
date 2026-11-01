//! Updates on a phone (SPEC.md "Android app", A4). Each GitHub release carries
//! `SideTray.apk` and a small manifest, `android.json`:
//!
//! ```json
//! {"version": "0.2.0", "url": "https://.../SideTray.apk", "sha256": "<hex>", "size": 12345678}
//! ```
//!
//! The app reads the newest published one at every start and then once a day.
//! When it's newer, the page offers it (a card on the feed and *Device →
//! Settings*); on *Download and install* Rust downloads the APK into the app's
//! cache, checks its SHA-256, and Kotlin hands it to Android's installer (after
//! the person allows "install unknown apps" for Side Tray, once).
//!
//! The checksum only catches a damaged download. What keeps anyone else's APK
//! out is Android itself: it installs an update only if it's signed with the
//! same key as the installed app.
//!
//! Where to look: `SIDETRAY_ANDROID_UPDATE_URL` when the app was built (test
//! builds; plain `http://` is accepted then), else the GitHub release. A debug
//! build without that override doesn't look at all: it's signed with the debug
//! key, so a release APK couldn't replace it anyway.

use crate::android;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

const RELEASE_MANIFEST: &str = "https://github.com/shaybee22/sidetray/releases/latest/download/android.json";
/// First check this long after startup (let the first sync go first).
const FIRST_CHECK: Duration = Duration::from_secs(15);
/// After a check that worked, the next one a day later; after a failed one (offline, or
/// Android cut the network while the phone dozed), ten minutes later.
const CHECK_EVERY: i64 = 24 * 3600;
const RETRY_AFTER: i64 = 10 * 60;
/// How often the background loop looks at the clock (a sleeping phone doesn't advance tokio's timers).
const TICK: Duration = Duration::from_secs(15 * 60);
const MAX_APK_BYTES: u64 = 300 * 1024 * 1024;

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    /// A debug build without a test endpoint: doesn't look for updates.
    Off,
    Idle { checked_at: Option<i64> },
    Checking,
    /// Newer version found; nothing downloaded yet. `error`: the last download attempt failed.
    Available { version: String, size: Option<u64>, error: Option<String> },
    Downloading { version: String, percent: Option<u8> },
    /// Downloaded and checked; waiting for the person (and Android's installer).
    Downloaded { version: String },
    Failed { message: String },
}

#[derive(Serialize, Clone)]
pub struct View {
    pub current_version: String,
    #[serde(flatten)]
    pub status: Status,
    /// Android lets Side Tray install APKs ("install unknown apps" is on for it).
    pub installer_allowed: bool,
}

#[derive(Clone, Debug)]
struct Found {
    version: String,
    url: reqwest::Url,
    sha256: String,
    size: Option<u64>,
}

#[derive(Default)]
pub struct Updates {
    status: Mutex<Option<Status>>,
    found: Mutex<Option<Found>>,
    /// Unix time of the next due check.
    next_check: Mutex<i64>,
    /// One check at a time (timer, resume and button).
    checking: tokio::sync::Mutex<()>,
    /// One download at a time.
    downloading: tokio::sync::Mutex<()>,
}

#[derive(Deserialize)]
struct Manifest {
    version: String,
    url: String,
    sha256: String,
    size: Option<u64>,
}

fn test_endpoint() -> Option<&'static str> {
    option_env!("SIDETRAY_ANDROID_UPDATE_URL").map(str::trim).filter(|s| !s.is_empty())
}

fn manifest_url() -> Option<&'static str> {
    match test_endpoint() {
        Some(u) => Some(u),
        None if cfg!(debug_assertions) => None,
        None => Some(RELEASE_MANIFEST),
    }
}

/// Does this build look for updates?
pub fn installed() -> bool {
    manifest_url().is_some()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn view(handle: &AppHandle) -> View {
    let u = handle.state::<Updates>();
    let status = lock(&u.status).clone();
    View {
        current_version: handle.package_info().version.to_string(),
        status: status.unwrap_or(if installed() { Status::Idle { checked_at: None } } else { Status::Off }),
        installer_allowed: android::can_install_apks().unwrap_or(false),
    }
}

fn set(handle: &AppHandle, status: Status) {
    *lock(&handle.state::<Updates>().status) = Some(status);
    let _ = handle.emit("update", view(handle));
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(60))
        .user_agent(concat!("sidetray-app/", env!("CARGO_PKG_VERSION"), " (Android)"))
        .build()?)
}

fn allowed_scheme(u: &reqwest::Url) -> Result<()> {
    match u.scheme() {
        "https" => Ok(()),
        "http" if test_endpoint().is_some() => Ok(()),
        _ => bail!("update addresses must be https:// ({u})"),
    }
}

/// The newest release, if it's newer than this app. `Ok(None)`: up to date
/// (also when the release has no Android manifest at all).
async fn fetch(handle: &AppHandle) -> Result<Option<Found>> {
    let Some(url) = manifest_url() else { return Ok(None) };
    let base = reqwest::Url::parse(url).with_context(|| format!("the update address isn't a URL: {url}"))?;
    allowed_scheme(&base)?;
    let resp = client()?
        .get(base.clone())
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("couldn't reach the update server")?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        bail!("the update server answered {}", resp.status());
    }
    let m: Manifest = resp.json().await.context("the update information is damaged")?;
    let version = semver::Version::parse(m.version.trim()).context("the update information has no proper version")?;
    if version <= handle.package_info().version {
        return Ok(None);
    }
    let url = base.join(m.url.trim()).context("the update information has no proper download address")?;
    allowed_scheme(&url)?;
    let sha256 = m.sha256.trim().to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the update information has no proper checksum");
    }
    Ok(Some(Found { version: version.to_string(), url, sha256, size: m.size }))
}

/// Check now. Returns the resulting view.
pub async fn check(handle: &AppHandle) -> View {
    if !installed() {
        return view(handle);
    }
    let u = handle.state::<Updates>();
    let _one = u.checking.lock().await;
    let before = lock(&u.status).clone();
    // Don't interrupt a download, or flicker over an offer already on screen.
    if matches!(before, Some(Status::Downloading { .. })) {
        return view(handle);
    }
    let quiet = matches!(before, Some(Status::Available { .. } | Status::Downloaded { .. }));
    if !quiet {
        set(handle, Status::Checking);
    }
    match fetch(handle).await {
        Ok(found) => {
            *lock(&u.next_check) = now() + CHECK_EVERY;
            match found {
                None => {
                    *lock(&u.found) = None;
                    set(handle, Status::Idle { checked_at: Some(now()) });
                }
                Some(f) => {
                    let downloaded = apk_path(&f.version).ok().filter(|p| file_matches(p, &f.sha256));
                    let status = if downloaded.is_some() {
                        Status::Downloaded { version: f.version.clone() }
                    } else {
                        Status::Available { version: f.version.clone(), size: f.size, error: None }
                    };
                    *lock(&u.found) = Some(f);
                    set(handle, status);
                }
            }
        }
        Err(e) => {
            eprintln!("update check: {e:#}");
            *lock(&u.next_check) = now() + RETRY_AFTER;
            if !quiet {
                set(handle, Status::Failed { message: format!("{e:#}") });
            }
        }
    }
    view(handle)
}

fn apk_path(version: &str) -> Result<PathBuf> {
    Ok(android::update_dir()?.join(format!("SideTray-{version}.apk")))
}

fn sha256_hex(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn file_matches(path: &Path, sha256: &str) -> bool {
    path.is_file() && sha256_hex(path).is_ok_and(|h| h == sha256)
}

async fn download(handle: &AppHandle, f: &Found) -> Result<PathBuf> {
    let path = apk_path(&f.version)?;
    if file_matches(&path, &f.sha256) {
        return Ok(path);
    }
    std::fs::create_dir_all(path.parent().context("no folder for the download")?)?;
    let part = path.with_extension("apk.part");
    let mut resp = client()?.get(f.url.clone()).send().await.context("couldn't start the download")?;
    if !resp.status().is_success() {
        bail!("couldn't download the new version (the server said {})", resp.status());
    }
    let total = resp.content_length().or(f.size).filter(|&t| t > 0);
    let mut out = std::fs::File::create(&part).context("couldn't save the download")?;
    let mut hasher = Sha256::new();
    let mut got = 0u64;
    let mut shown = None;
    let result: Result<()> = async {
        while let Some(chunk) = resp.chunk().await.context("the download broke off")? {
            got += chunk.len() as u64;
            if got > MAX_APK_BYTES {
                bail!("the download is far larger than Side Tray should be");
            }
            hasher.update(&chunk);
            out.write_all(&chunk).context("couldn't save the download (is the phone full?)")?;
            let percent = total.map(|t| (got.saturating_mul(100) / t).min(100) as u8);
            if percent != shown {
                shown = percent;
                set(handle, Status::Downloading { version: f.version.clone(), percent });
            }
        }
        out.sync_all()?;
        Ok(())
    }
    .await;
    drop(out);
    let hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    if hex != f.sha256 {
        let _ = std::fs::remove_file(&part);
        bail!("the download was damaged (its checksum doesn't match); please try again");
    }
    std::fs::rename(&part, &path).context("couldn't save the download")?;
    Ok(path)
}

/// Download the new version if needed, then hand it to Android's installer.
/// "started" (Android now asks the person), "needs_permission" (they have to
/// allow Side Tray to install apps first), or "no_window".
pub async fn install(handle: &AppHandle) -> Result<String> {
    let u = handle.state::<Updates>();
    let _one = u.downloading.lock().await;
    let f = lock(&u.found).clone().context("there's no new version to install")?;
    set(handle, Status::Downloading { version: f.version.clone(), percent: Some(0) });
    let path = match download(handle, &f).await {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("{e:#}");
            set(handle, Status::Available { version: f.version.clone(), size: f.size, error: Some(msg.clone()) });
            bail!(msg);
        }
    };
    set(handle, Status::Downloaded { version: f.version.clone() });
    android::install_apk(&path)
}

/// Delete downloads that are no longer newer than this app (it was updated) and broken-off ones.
fn clean_downloads(current: &semver::Version) {
    let Ok(dir) = android::update_dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let keep = name
            .strip_prefix("SideTray-")
            .and_then(|s| s.strip_suffix(".apk"))
            .and_then(|v| semver::Version::parse(v).ok())
            .is_some_and(|v| v > *current);
        if !keep {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

fn due(handle: &AppHandle) -> bool {
    now() >= *lock(&handle.state::<Updates>().next_check)
}

static STARTED: AtomicBool = AtomicBool::new(false);

/// Check at startup, then whenever a day has passed (also on coming back to the foreground: `resumed`).
pub fn spawn(handle: AppHandle) {
    if !installed() || STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        clean_downloads(&handle.package_info().version);
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            if due(&handle) {
                check(&handle).await;
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

/// Back in the foreground: check if one is due (the phone may have slept through the timer).
pub fn resumed(handle: &AppHandle) {
    if installed() && STARTED.load(Ordering::SeqCst) && due(handle) {
        let h = handle.clone();
        tauri::async_runtime::spawn(async move {
            check(&h).await;
        });
    }
}

/// Android's "Install unknown apps" screen for Side Tray.
pub fn open_install_settings() -> Result<()> {
    android::open_install_settings()
}
