//! Shared app state: the database, cached secrets, staged photos and the sync lock.

use crate::api::Api;
use crate::db::{self, Identity};
use crate::photo::Processed;
use crate::secrets::{self, Secrets};
use anyhow::{bail, Context, Result};
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// This process's Tauri handle, once Tauri is up (a push wake-up on Android
/// may sync with no window); used for notifications and the tray from
/// background tasks. A static, never dropped, so tests can build an `App`
/// without loading any window code.
static HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

pub fn handle() -> Option<&'static tauri::AppHandle> {
    HANDLE.get()
}

pub fn set_handle(h: tauri::AppHandle) {
    let _ = HANDLE.set(h);
}

/// One profile: this install's device in one group (SPEC.md Phase 8). The
/// window shows the active one (`profiles.rs`); every profile syncs.
pub struct App {
    /// The profile's folder name, which is also its identity's `local_id`.
    pub profile_id: String,
    pub dir: PathBuf,
    pub media_dir: PathBuf,
    db: Mutex<Connection>,
    secrets: Mutex<Option<Arc<Secrets>>>,
    /// Photos picked in the composer, already resized and encoded, waiting for "Post".
    pub staged: Mutex<HashMap<String, Processed>>,
    /// Videos prepared in the composer (Phase 9), waiting for "Post" or "Send".
    pub staged_videos: Mutex<HashMap<String, crate::video::Prepared>>,
    /// Cancels the video being prepared, if any (one at a time).
    pub transcode: Mutex<Option<crate::video::Cancel>>,
    /// One sync at a time.
    pub sync_lock: tokio::sync::Mutex<()>,
    /// One key rotation at a time (after a removal, or picked up by a sync).
    pub rotate_lock: tokio::sync::Mutex<()>,
    /// Wakes the background sync loop early (after joining, a push, or "Sync now").
    pub wake: tokio::sync::Notify,
    /// Wakes the push loop (the device just became active).
    pub push_wake: tokio::sync::Notify,
    /// Tells the push loop the app left the foreground (a phone then closes the socket).
    pub push_pause: tokio::sync::Notify,
    /// The /ws socket is up; the sync loop then only polls as a slow safety net.
    pub push_connected: AtomicBool,
    /// Key Master: join requests waiting, for the tray tooltip.
    pub pending_joins: AtomicUsize,
    /// Join requests already notified about (device ids), so each pops up once per run.
    pub seen_pending: Mutex<HashSet<String>>,
    /// Wizard: the server being set up and, for a test server, its root
    /// certificate, trusted only once the person confirmed the fingerprint.
    pub wizard_server: Mutex<Option<ServerTrust>>,
    /// A test server's current root, offered to replace the pinned one.
    pub repin: Mutex<Option<ServerTrust>>,
    /// The last sync was refused over the server's certificate (the message to show).
    pub cert_problem: Mutex<Option<String>>,
    /// Set when the profile is being deleted (left the group): its loops stop.
    closed: AtomicBool,
    /// This device is leaving the group itself: the relay's "left" push that
    /// follows isn't news here.
    leaving: AtomicBool,
}

#[derive(Clone)]
pub struct ServerTrust {
    pub server: String,
    /// Test server: the root certificate (PEM). None: the public web roots.
    pub root_pem: Option<String>,
    pub fingerprint: Option<String>,
    pub confirmed: bool,
}

/// An invite link, or why it was refused.
#[derive(Clone, serde::Serialize)]
pub struct InviteMsg {
    pub invite: Option<crate::invite::Invite>,
    pub error: Option<String>,
}

impl App {
    pub fn open(data_dir: PathBuf, profile_id: String) -> Result<Self> {
        std::fs::create_dir_all(&data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
        let media_dir = data_dir.join("media");
        std::fs::create_dir_all(&media_dir)?;
        let conn = db::open(&data_dir.join("sidetray.db"))?;
        // Videos prepared but never sent in an earlier run.
        let _ = std::fs::remove_dir_all(data_dir.join(crate::video::STAGING_DIR));
        Ok(App {
            profile_id,
            dir: data_dir,
            media_dir,
            db: Mutex::new(conn),
            secrets: Mutex::new(None),
            staged: Mutex::new(HashMap::new()),
            staged_videos: Mutex::new(HashMap::new()),
            transcode: Mutex::new(None),
            sync_lock: tokio::sync::Mutex::new(()),
            rotate_lock: tokio::sync::Mutex::new(()),
            wake: tokio::sync::Notify::new(),
            push_wake: tokio::sync::Notify::new(),
            push_pause: tokio::sync::Notify::new(),
            push_connected: AtomicBool::new(false),
            pending_joins: AtomicUsize::new(0),
            seen_pending: Mutex::new(HashSet::new()),
            wizard_server: Mutex::new(None),
            repin: Mutex::new(None),
            cert_problem: Mutex::new(None),
            closed: AtomicBool::new(false),
            leaving: AtomicBool::new(false),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn set_leaving(&self, on: bool) {
        self.leaving.store(on, Ordering::SeqCst);
    }

    /// Leaving the group from this device, or already deleted.
    pub fn is_leaving(&self) -> bool {
        self.leaving.load(Ordering::SeqCst) || self.is_closed()
    }

    /// Stop this profile's loops and close its database file (an empty
    /// in-memory one takes its place), so its folder can be deleted.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        *self.db() = db::open(std::path::Path::new(":memory:"))?;
        self.set_secrets(None);
        self.wake.notify_one();
        self.push_wake.notify_one();
        self.push_pause.notify_one();
        Ok(())
    }

    /// The database. Never hold this across an `.await`.
    pub fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn identity(&self) -> Result<Option<Identity>> {
        db::identity(&self.db())
    }

    pub fn require_identity(&self) -> Result<Identity> {
        self.identity()?.context("this app hasn't joined a group yet")
    }

    pub fn require_active(&self) -> Result<Identity> {
        let id = self.require_identity()?;
        match id.status.as_str() {
            "active" => Ok(id),
            "removed" => bail!("you've been removed from {}", id.group_name),
            "revoked" => bail!("this device has been disconnected from {}", id.group_name),
            "left" => bail!("you left {}", id.group_name),
            s => bail!("this device is {s}; it can't do that until a Key Master approves it"),
        }
    }

    /// A device whose archive can be read: active, or removed with its history kept.
    pub fn require_archive(&self) -> Result<Identity> {
        let id = self.require_identity()?;
        if !matches!(id.status.as_str(), "active" | "removed" | "revoked" | "left") {
            bail!("this device hasn't joined yet");
        }
        Ok(id)
    }

    pub fn require_keymaster(&self) -> Result<Identity> {
        let id = self.require_active()?;
        if !id.is_keymaster() {
            bail!("only a Key Master can do that");
        }
        Ok(id)
    }

    pub fn secrets(&self, id: &Identity) -> Result<Arc<Secrets>> {
        let mut cache = self.secrets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = cache.as_ref() {
            return Ok(s.clone());
        }
        let s = Arc::new(secrets::load(&self.db(), &id.local_id)?);
        *cache = Some(s.clone());
        Ok(s)
    }

    pub fn set_cert_problem(&self, p: Option<String>) {
        *self.cert_problem.lock().unwrap_or_else(|e| e.into_inner()) = p;
    }

    pub fn set_secrets(&self, s: Option<Arc<Secrets>>) {
        *self.secrets.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }

    pub fn api(&self, id: &Identity) -> Result<Api> {
        let s = self.secrets(id)?;
        Api::new(&id.server_url, id.ca_pem.as_deref(), Some(&s.token))
    }
}
