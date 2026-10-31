//! Shared app state: the database, cached secrets, staged photos and the sync lock.

use crate::api::Api;
use crate::db::{self, Identity};
use crate::photo::Processed;
use crate::secrets::{self, Secrets};
use anyhow::{bail, Context, Result};
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

pub struct App {
    pub media_dir: PathBuf,
    db: Mutex<Connection>,
    secrets: Mutex<Option<Arc<Secrets>>>,
    /// Photos picked in the composer, already resized and encoded, waiting for "Post".
    pub staged: Mutex<HashMap<String, Processed>>,
    /// One sync at a time.
    pub sync_lock: tokio::sync::Mutex<()>,
    /// Wakes the background sync loop early (after joining, or "Sync now").
    pub wake: tokio::sync::Notify,
}

impl App {
    pub fn open(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
        let media_dir = data_dir.join("media");
        std::fs::create_dir_all(&media_dir)?;
        let conn = db::open(&data_dir.join("sidetray.db"))?;
        Ok(App {
            media_dir,
            db: Mutex::new(conn),
            secrets: Mutex::new(None),
            staged: Mutex::new(HashMap::new()),
            sync_lock: tokio::sync::Mutex::new(()),
            wake: tokio::sync::Notify::new(),
        })
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
        if id.status != "active" {
            bail!("this device is {}; it can't do that until a Key Master approves it", id.status);
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

    pub fn set_secrets(&self, s: Option<Arc<Secrets>>) {
        *self.secrets.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }

    pub fn api(&self, id: &Identity) -> Result<Api> {
        let s = self.secrets(id)?;
        Api::new(&id.server_url, id.ca_pem.as_deref(), Some(&s.token))
    }
}
