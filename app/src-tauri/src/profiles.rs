//! Several groups in one install (SPEC.md Phase 8): one profile per group,
//! each in its own folder `groups/<local_id>/` with its own database, media
//! and keychain entry, and its own `App`. The window shows the active one;
//! every profile keeps syncing.
//!
//! On the first start of this version, a `sidetray.db` at the top of the data
//! folder (from before profiles) becomes the first profile (`migrate`).

use crate::secrets;
use crate::state::{App, InviteMsg};
use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use tauri::{AppHandle, Emitter};

const GROUPS: &str = "groups";
const ACTIVE_FILE: &str = "active-group";
const STAGING: &str = ".migrating";
/// A consistent copy of the database from before the move into `groups/`.
pub const BACKUP: &str = "sidetray-before-groups.db";
/// What lived at the top of the data folder before profiles.
const LEGACY: [&str; 4] = ["sidetray.db", "sidetray.db-wal", "sidetray.db-shm", "media"];

pub struct Profiles {
    root: PathBuf,
    apps: Mutex<Vec<Arc<App>>>,
    active: Mutex<String>,
    /// An invite link that opened the app, until the wizard picks it up.
    pub pending_invite: Mutex<Option<InviteMsg>>,
    /// The profile to go back to if the wizard for a new group is cancelled.
    previous: Mutex<Option<String>>,
}

/// The profiles of this process. On Android a push wake-up can start the
/// process without the window; the window, if it opens later, then uses the
/// same profiles (one database connection and one sync lock each).
static SHARED: Mutex<Option<Arc<Profiles>>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// This process's profiles, opened on `root` (the app's data folder) if they aren't yet.
pub fn shared(root: PathBuf) -> Result<Arc<Profiles>> {
    let mut g = lock(&SHARED);
    if let Some(p) = g.as_ref() {
        return Ok(p.clone());
    }
    let p = Arc::new(Profiles::open(root)?);
    *g = Some(p.clone());
    Ok(p)
}

/// This process's profiles, if they were opened.
pub fn current() -> Option<Arc<Profiles>> {
    lock(&SHARED).clone()
}

/// Whether `app` is the profile the window shows.
pub fn is_active(app: &App) -> bool {
    current().is_some_and(|p| *lock(&p.active) == app.profile_id)
}

/// How many profiles have joined (or asked to join) a group.
pub fn joined_count() -> usize {
    current().map_or(1, |p| p.all().iter().filter(|a| matches!(a.identity(), Ok(Some(_)))).count())
}

/// Send a page event about `app`: only the active profile's reach the page,
/// and any of them redraws the group menu.
pub fn emit<S: serde::Serialize + Clone>(handle: &AppHandle, app: &App, event: &str, payload: S) {
    if is_active(app) {
        let _ = handle.emit(event, payload);
    }
    let _ = handle.emit("groups-changed", ());
}

fn random_id() -> String {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).expect("OS random number generator");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Folder names we made (`local_id`s): nothing that could climb out of `groups/`.
fn valid_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Profiles {
    fn open(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        migrate(&root).context("moving this app's group into its own folder")?;
        let mut apps = Vec::new();
        for e in std::fs::read_dir(root.join(GROUPS))?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !e.path().is_dir() || !valid_id(&name) {
                continue;
            }
            apps.push(Arc::new(App::open(e.path(), name)?));
        }
        let remembered = std::fs::read_to_string(root.join(ACTIVE_FILE)).ok().map(|s| s.trim().to_string());
        // An empty profile (an abandoned wizard) goes, unless it's all there is.
        let joined = |a: &Arc<App>| matches!(a.identity(), Ok(Some(_)));
        if apps.iter().any(joined) {
            for a in apps.iter().filter(|a| !joined(a)) {
                let _ = a.close();
                if let Err(e) = std::fs::remove_dir_all(&a.dir) {
                    eprintln!("removing an unused profile {}: {e}", a.dir.display());
                }
            }
            apps.retain(joined);
        }
        let p = Profiles {
            root,
            apps: Mutex::new(apps),
            active: Mutex::new(String::new()),
            pending_invite: Mutex::new(None),
            previous: Mutex::new(None),
        };
        let active = {
            let apps = lock(&p.apps);
            remembered.filter(|r| apps.iter().any(|a| a.profile_id == *r)).or_else(|| apps.first().map(|a| a.profile_id.clone()))
        };
        match active {
            Some(id) => *lock(&p.active) = id,
            None => {
                let a = p.create()?;
                *lock(&p.active) = a.profile_id.clone();
            }
        }
        Ok(p)
    }

    /// Every profile, in the order the menu shows them.
    pub fn all(&self) -> Vec<Arc<App>> {
        lock(&self.apps).clone()
    }

    pub fn get(&self, id: &str) -> Option<Arc<App>> {
        lock(&self.apps).iter().find(|a| a.profile_id == id).cloned()
    }

    pub fn active(&self) -> Arc<App> {
        let id = lock(&self.active).clone();
        let apps = lock(&self.apps);
        apps.iter().find(|a| a.profile_id == id).or_else(|| apps.first()).cloned().expect("there is always a profile")
    }

    pub fn active_id(&self) -> String {
        lock(&self.active).clone()
    }

    /// Show this profile. Remembered for the next start once it has joined.
    pub fn switch(&self, id: &str) -> Result<Arc<App>> {
        let app = self.get(id).context("that group isn't in this app any more")?;
        *lock(&self.active) = app.profile_id.clone();
        self.remember();
        Ok(app)
    }

    /// Save the active profile for the next start (not an empty one).
    pub fn remember(&self) {
        let app = self.active();
        if matches!(app.identity(), Ok(Some(_))) {
            if let Err(e) = std::fs::write(self.root.join(ACTIVE_FILE), &app.profile_id) {
                eprintln!("remembering the active group: {e}");
            }
        }
    }

    /// A new, empty profile (for the wizard). Not active yet.
    pub fn create(&self) -> Result<Arc<App>> {
        let id = random_id();
        let app = Arc::new(App::open(self.root.join(GROUPS).join(&id), id)?);
        lock(&self.apps).push(app.clone());
        Ok(app)
    }

    /// "Join another group": an empty profile, shown in the wizard. Reuses
    /// one that's already empty. Cancelling goes back to the one shown now.
    pub fn start_join(&self) -> Result<(Arc<App>, bool)> {
        let empty = lock(&self.apps).iter().find(|a| matches!(a.identity(), Ok(None))).cloned();
        let (app, new) = match empty {
            Some(a) => (a, false),
            None => (self.create()?, true),
        };
        let now = self.active_id();
        if now != app.profile_id {
            *lock(&self.previous) = Some(now);
        }
        *lock(&self.active) = app.profile_id.clone();
        Ok((app, new))
    }

    /// The group shown before "Join another group", if it's still there.
    pub fn previous(&self) -> Option<String> {
        lock(&self.previous).clone().filter(|p| self.get(p).is_some() && *p != self.active_id())
    }

    /// Delete a profile: its loops stop, its keychain entry and folder go.
    /// Shows another profile (the one used before, or any), or a new empty one.
    pub fn remove(&self, id: &str) -> Result<()> {
        let app = self.get(id).context("that group isn't in this app any more")?;
        // Show the next profile before this one goes, so the list is never
        // empty and the active profile is never a deleted one (other threads
        // ask for it at any moment).
        if self.active_id() == id {
            let others = |joined: bool| {
                lock(&self.apps)
                    .iter()
                    .find(|a| a.profile_id != id && matches!(a.identity(), Ok(Some(_))) == joined)
                    .map(|a| a.profile_id.clone())
            };
            match self.previous().or_else(|| others(true)) {
                Some(n) => {
                    self.switch(&n)?;
                }
                None => {
                    let next = match others(false) {
                        Some(n) => n,
                        None => self.create()?.profile_id.clone(),
                    };
                    *lock(&self.active) = next;
                    let _ = std::fs::remove_file(self.root.join(ACTIVE_FILE));
                }
            }
        }
        *lock(&self.previous) = None;
        if let Some(i) = app.identity()? {
            secrets::delete(&app.db(), &i.local_id)?;
        }
        app.close()?;
        lock(&self.apps).retain(|a| a.profile_id != id);
        // Windows can hold a just-closed file for a moment.
        let mut tries = 0;
        while let Err(e) = std::fs::remove_dir_all(&app.dir) {
            tries += 1;
            if tries >= 10 || !app.dir.exists() {
                eprintln!("deleting {}: {e}", app.dir.display());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        Ok(())
    }

    /// Another profile already in this group (the same server and group name).
    pub fn find_group(&self, server: &str, group_name: &str, except: &str) -> Option<Arc<App>> {
        lock(&self.apps)
            .iter()
            .filter(|a| a.profile_id != except)
            .find(|a| {
                matches!(a.identity(), Ok(Some(i)) if i.server_url.trim_end_matches('/') == server.trim_end_matches('/')
                    && i.group_name.to_lowercase() == group_name.trim().to_lowercase())
            })
            .cloned()
    }
}

/// Move a database from before profiles into `groups/<local_id>/` (SPEC.md
/// Phase 8, "Migration"). Every step is a rename, and an interrupted move is
/// finished on the next start.
fn migrate(root: &Path) -> Result<()> {
    let groups = root.join(GROUPS);
    std::fs::create_dir_all(&groups)?;
    let interrupted = std::fs::read_dir(&groups)?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir() && p.file_name().is_some_and(|n| n.to_string_lossy().ends_with(STAGING)));
    let legacy_db = root.join(LEGACY[0]);
    let staging = match interrupted {
        Some(s) => s,
        None if legacy_db.exists() => {
            let local_id = prepare_legacy(root, &legacy_db)?;
            let s = groups.join(format!("{local_id}{STAGING}"));
            std::fs::create_dir_all(&s)?;
            s
        }
        None => return Ok(()),
    };
    for name in LEGACY {
        let from = root.join(name);
        if from.exists() {
            std::fs::rename(&from, staging.join(name)).with_context(|| format!("moving {}", from.display()))?;
        }
    }
    let name = staging.file_name().unwrap_or_default().to_string_lossy().to_string();
    let id = name.trim_end_matches(STAGING).to_string();
    let done = groups.join(&id);
    if done.exists() {
        bail!("{} is in the way of {}", done.display(), staging.display());
    }
    std::fs::rename(&staging, &done).with_context(|| format!("renaming {}", staging.display()))?;
    std::fs::write(root.join(ACTIVE_FILE), &id)?;
    eprintln!("moved this app's group into {}", done.display());
    Ok(())
}

/// Fold the WAL into the database, keep a copy, and read its `local_id`.
fn prepare_legacy(root: &Path, path: &Path) -> Result<String> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    let backup = root.join(BACKUP);
    if !backup.exists() {
        let to = backup.to_str().context("odd characters in the data folder's path")?;
        conn.execute("VACUUM INTO ?1", [to]).context("making a backup copy")?;
    }
    let has_identity: bool =
        conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'identity'", [], |_| Ok(())).optional()?.is_some();
    let local_id: Option<String> = if has_identity {
        conn.query_row("SELECT local_id FROM identity WHERE id = 1", [], |r| r.get(0)).optional()?
    } else {
        None
    };
    drop(conn);
    Ok(local_id.filter(|l| valid_id(l)).unwrap_or_else(random_id))
}

/// Make sure a test's database is a real profile database.
#[cfg(test)]
fn make_legacy(root: &Path, local_id: Option<&str>) {
    let conn = crate::db::open(&root.join("sidetray.db")).unwrap();
    if let Some(l) = local_id {
        conn.execute(
            "INSERT INTO identity (id, local_id, server_url, group_id, group_name, member_id, device_id, display_name,
                 email, status, role, enc_pubkey, sign_pubkey, created_at)
             VALUES (1, ?1, 'https://x', 'g', 'Powwow', 'm', 'd', 'Me', 'me@x', 'active', 'member', zeroblob(32), zeroblob(32), 1)",
            [l],
        )
        .unwrap();
        conn.execute("INSERT INTO posts (id, seq, author_id, author_device_id, body, created_at) VALUES ('p1', 1, 'm', 'd', 'hello', 1)", [])
            .unwrap();
    }
    std::fs::create_dir_all(root.join("media")).unwrap();
    std::fs::write(root.join("media").join("a.webp"), b"photo").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sidetray-profiles-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn legacy_database_becomes_the_first_profile() {
        let root = tmp("legacy");
        make_legacy(&root, Some("abc123"));
        let p = Profiles::open(root.clone()).unwrap();
        assert!(!root.join("sidetray.db").exists());
        assert!(root.join(BACKUP).exists());
        let dir = root.join("groups").join("abc123");
        assert_eq!(std::fs::read(dir.join("media").join("a.webp")).unwrap(), b"photo");
        let a = p.active();
        assert_eq!(a.profile_id, "abc123");
        assert_eq!(a.identity().unwrap().unwrap().group_name, "Powwow");
        let n: i64 = a.db().query_row("SELECT COUNT(*) FROM posts", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(std::fs::read_to_string(root.join(ACTIVE_FILE)).unwrap(), "abc123");
        drop(p);
        // Opening again changes nothing.
        let p = Profiles::open(root.clone()).unwrap();
        assert_eq!(p.all().len(), 1);
        drop((p, a));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_interrupted_move_is_finished() {
        let root = tmp("interrupted");
        make_legacy(&root, Some("def456"));
        let staging = root.join("groups").join(format!("def456{STAGING}"));
        std::fs::create_dir_all(&staging).unwrap();
        // The database moved; the photos didn't yet.
        std::fs::rename(root.join("sidetray.db"), staging.join("sidetray.db")).unwrap();
        let p = Profiles::open(root.clone()).unwrap();
        assert_eq!(p.active().profile_id, "def456");
        assert!(root.join("groups/def456/media/a.webp").exists());
        assert!(!staging.exists());
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn profiles_switch_and_go() {
        let root = tmp("switch");
        make_legacy(&root, Some("first"));
        let p = Profiles::open(root.clone()).unwrap();
        let (second, _) = p.start_join().unwrap();
        assert_eq!(p.active_id(), second.profile_id);
        assert_eq!(p.previous().as_deref(), Some("first"));
        // An empty profile isn't remembered.
        p.remember();
        assert_eq!(std::fs::read_to_string(root.join(ACTIVE_FILE)).unwrap(), "first");
        // Removing it goes back to the first.
        p.remove(&second.profile_id).unwrap();
        assert_eq!(p.active_id(), "first");
        assert!(!second.dir.exists());
        assert!(second.is_closed());
        // An abandoned empty profile is gone at the next start.
        let (third, _) = p.start_join().unwrap();
        drop(p);
        third.close().unwrap(); // as when the process ends
        let p = Profiles::open(root.clone()).unwrap();
        assert_eq!(p.all().len(), 1);
        assert!(!third.dir.exists());
        // Removing the last one leaves an empty profile for the wizard.
        p.remove("first").unwrap();
        assert_eq!(p.all().len(), 1);
        assert!(p.active().identity().unwrap().is_none());
        drop((p, third));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fresh_install_starts_with_an_empty_profile() {
        let root = tmp("fresh");
        let p = Profiles::open(root.clone()).unwrap();
        assert_eq!(p.all().len(), 1);
        assert!(p.active().identity().unwrap().is_none());
        assert!(!root.join(BACKUP).exists());
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }
}
