//! One device's local state: a JSON file in its own directory, so several
//! CLI "devices" can run side by side (`--state km`, `--state alice`).
//!
//! Secrets are stored base64 in a 0600 file. Fine for a dev tool; the desktop
//! app keeps them in the OS keychain (SPEC.md, client `identity` table).

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sidetray_crypto::{DeviceKeys, GroupKey};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
pub struct State {
    pub server: String,
    /// Extra root certificate (PEM) to trust, e.g. Caddy's internal CA.
    pub ca_pem: Option<String>,
    pub group_id: String,
    pub group_name: String,
    pub member_id: String,
    pub device_id: String,
    pub display_name: String,
    pub email: String,
    pub token: String,
    /// "pending", "active" or "denied".
    pub status: String,
    /// "member" or "keymaster".
    pub role: String,
    enc_secret: String,
    sign_secret: String,
    /// Group keys by version (base64).
    group_keys: BTreeMap<u32, String>,
    /// Key Masters whose signing key this device has seen sign a key grant,
    /// by device id. The user checked the approver's safety code at join.
    pub trusted_keymasters: BTreeMap<String, TrustedKeymaster>,
    pub last_seq: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustedKeymaster {
    pub name: String,
    pub sign_pubkey: String,
    pub enc_pubkey: String,
}

pub struct Identity<'a> {
    pub server: &'a str,
    pub ca_pem: Option<String>,
    pub group_id: &'a str,
    pub group_name: &'a str,
    pub member_id: &'a str,
    pub device_id: &'a str,
    pub display_name: &'a str,
    pub email: &'a str,
    pub token: &'a str,
    pub status: &'a str,
    pub role: &'a str,
}

impl State {
    pub fn new(id: Identity, keys: &DeviceKeys) -> Self {
        State {
            server: id.server.to_string(),
            ca_pem: id.ca_pem,
            group_id: id.group_id.to_string(),
            group_name: id.group_name.to_string(),
            member_id: id.member_id.to_string(),
            device_id: id.device_id.to_string(),
            display_name: id.display_name.to_string(),
            email: id.email.to_string(),
            token: id.token.to_string(),
            status: id.status.to_string(),
            role: id.role.to_string(),
            enc_secret: B64.encode(*keys.enc_secret_bytes()),
            sign_secret: B64.encode(*keys.sign_secret_bytes()),
            group_keys: BTreeMap::new(),
            trusted_keymasters: BTreeMap::new(),
            last_seq: 0,
        }
    }

    pub fn device_keys(&self) -> Result<DeviceKeys> {
        Ok(DeviceKeys::from_secret_bytes(
            &decode32(&self.enc_secret).context("enc_secret")?,
            &decode32(&self.sign_secret).context("sign_secret")?,
        ))
    }

    pub fn add_group_key(&mut self, key: &GroupKey) {
        self.group_keys.insert(key.version(), B64.encode(*key.key_bytes()));
    }

    pub fn group_key(&self, version: u32) -> Result<Option<GroupKey>> {
        self.group_keys
            .get(&version)
            .map(|k| Ok(GroupKey::from_bytes(version, &decode32(k)?)))
            .transpose()
    }

    pub fn group_keys(&self) -> Result<Vec<GroupKey>> {
        self.group_keys
            .iter()
            .map(|(v, k)| Ok(GroupKey::from_bytes(*v, &decode32(k)?)))
            .collect()
    }

    pub fn latest_group_key(&self) -> Result<GroupKey> {
        match self.group_keys.keys().next_back() {
            Some(v) => Ok(self.group_key(*v)?.expect("present")),
            None => bail!("this device has no group key yet; run `status` after approval"),
        }
    }

    pub fn key_versions(&self) -> Vec<u32> {
        self.group_keys.keys().copied().collect()
    }
}

pub fn decode32(s: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s).context("bad base64")?;
    v.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))
}

fn file(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

pub fn exists(dir: &Path) -> bool {
    file(dir).exists()
}

pub fn load(dir: &Path) -> Result<State> {
    let path = file(dir);
    let raw = fs::read_to_string(&path).with_context(|| {
        format!("no device state at {} (run init-group or join first)", path.display())
    })?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

pub fn save(dir: &Path, state: &State) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join("state.json.tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(serde_json::to_string_pretty(state)?.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, file(dir))?;
    Ok(())
}
