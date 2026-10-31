//! This device's secrets: its two private keys, its bearer token, and a local
//! key that wraps the group keys stored in SQLite.
//!
//! They live in one OS keychain entry (Windows Credential Manager, macOS
//! Keychain), named after the install's random `local_id`. That entry stays the
//! same size however many group key versions pile up. Where there's no native
//! keychain (Linux for now) they go in the database's `secrets` table instead.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sidetray_crypto::{self as crypto, DeviceKeys, GroupKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Secrets {
    pub token: String,
    enc: String,
    sign: String,
    local_key: String,
}

impl Secrets {
    pub fn new(token: &str, keys: &DeviceKeys) -> Self {
        let mut local = [0u8; 32];
        getrandom::getrandom(&mut local).expect("OS random number generator");
        let s = Secrets {
            token: token.to_string(),
            enc: B64.encode(*keys.enc_secret_bytes()),
            sign: B64.encode(*keys.sign_secret_bytes()),
            local_key: B64.encode(local),
        };
        local.zeroize();
        s
    }

    pub fn device_keys(&self) -> Result<DeviceKeys> {
        Ok(DeviceKeys::from_secret_bytes(&decode32(&self.enc)?, &decode32(&self.sign)?))
    }

    /// Wrap a group key for storage in the database.
    pub fn wrap(&self, gk: &GroupKey) -> Result<Vec<u8>> {
        Ok(crypto::encrypt(&self.local_key()?, &gk.key_bytes()[..], &wrap_ad(gk.version())))
    }

    pub fn unwrap(&self, version: u32, wrapped: &[u8]) -> Result<GroupKey> {
        let raw = zeroize::Zeroizing::new(
            crypto::decrypt(&self.local_key()?, wrapped, &wrap_ad(version)).context("unwrapping a stored group key")?,
        );
        let key: [u8; 32] = raw[..].try_into().context("stored group key has the wrong length")?;
        Ok(GroupKey::from_bytes(version, &key))
    }

    fn local_key(&self) -> Result<GroupKey> {
        Ok(GroupKey::from_bytes(0, &decode32(&self.local_key)?))
    }
}

fn wrap_ad(version: u32) -> Vec<u8> {
    let mut ad = b"sidetray/local-group-key/v1:".to_vec();
    ad.extend_from_slice(&version.to_le_bytes());
    ad
}

fn decode32(s: &str) -> Result<[u8; 32]> {
    let v = zeroize::Zeroizing::new(B64.decode(s).context("bad base64 in stored secret")?);
    v[..].try_into().context("stored secret has the wrong length")
}

const SERVICE: &str = "org.sidetray.app";

pub fn store(conn: &Connection, local_id: &str, s: &Secrets) -> Result<()> {
    let json = zeroize::Zeroizing::new(serde_json::to_vec(s)?);
    store_raw(conn, local_id, &json)
}

pub fn load(conn: &Connection, local_id: &str) -> Result<Secrets> {
    let raw = zeroize::Zeroizing::new(load_raw(conn, local_id)?);
    serde_json::from_slice(&raw).context("reading this device's stored secrets")
}

#[cfg(any(windows, target_os = "macos"))]
fn entry(local_id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, &format!("device-{local_id}")).context("opening the OS keychain")
}

#[cfg(any(windows, target_os = "macos"))]
fn store_raw(_conn: &Connection, local_id: &str, bytes: &[u8]) -> Result<()> {
    entry(local_id)?.set_secret(bytes).context("saving keys to the OS keychain")
}

#[cfg(any(windows, target_os = "macos"))]
fn load_raw(_conn: &Connection, local_id: &str) -> Result<Vec<u8>> {
    entry(local_id)?
        .get_secret()
        .context("this device's keys are missing from the OS keychain")
}

#[cfg(any(windows, target_os = "macos"))]
pub fn delete(_conn: &Connection, local_id: &str) -> Result<()> {
    match entry(local_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("removing keys from the OS keychain"),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn store_raw(conn: &Connection, local_id: &str, bytes: &[u8]) -> Result<()> {
    let _ = SERVICE;
    conn.execute("INSERT OR REPLACE INTO secrets (name, value) VALUES (?1, ?2)", params![local_id, bytes])?;
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn load_raw(conn: &Connection, local_id: &str) -> Result<Vec<u8>> {
    conn.query_row("SELECT value FROM secrets WHERE name = ?1", params![local_id], |r| r.get(0))
        .optional()?
        .context("this device's keys are missing")
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn delete(conn: &Connection, local_id: &str) -> Result<()> {
    conn.execute("DELETE FROM secrets WHERE name = ?1", params![local_id])?;
    Ok(())
}

// Group keys, wrapped, in SQLite.

pub fn save_group_key(conn: &Connection, s: &Secrets, gk: &GroupKey) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO group_keys (version, wrapped) VALUES (?1, ?2)",
        params![gk.version(), s.wrap(gk)?],
    )?;
    Ok(())
}

pub fn group_key(conn: &Connection, s: &Secrets, version: u32) -> Result<Option<GroupKey>> {
    let wrapped: Option<Vec<u8>> = conn
        .query_row("SELECT wrapped FROM group_keys WHERE version = ?1", params![version], |r| r.get(0))
        .optional()?;
    wrapped.map(|w| s.unwrap(version, &w)).transpose()
}

pub fn latest_group_key(conn: &Connection, s: &Secrets) -> Result<GroupKey> {
    let v: Option<u32> = conn.query_row("SELECT MAX(version) FROM group_keys", [], |r| r.get(0))?;
    let v = v.context("this device has no group key yet")?;
    Ok(group_key(conn, s, v)?.expect("present"))
}

pub fn all_group_keys(conn: &Connection, s: &Secrets) -> Result<Vec<GroupKey>> {
    let mut st = conn.prepare("SELECT version, wrapped FROM group_keys ORDER BY version")?;
    let rows: Vec<(u32, Vec<u8>)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    rows.iter().map(|(v, w)| s.unwrap(*v, w)).collect()
}

pub fn key_versions(conn: &Connection) -> Result<Vec<u32>> {
    let mut st = conn.prepare("SELECT version FROM group_keys ORDER BY version")?;
    let rows = st.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_keys_round_trip_wrapped_and_bound_to_their_version() {
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        let s = Secrets::new("tok", &crypto::generate_device_keys());
        let k1 = crypto::generate_group_key(1);
        let k2 = crypto::generate_group_key(2);
        save_group_key(&conn, &s, &k1).unwrap();
        save_group_key(&conn, &s, &k2).unwrap();
        assert!(group_key(&conn, &s, 1).unwrap().unwrap() == k1);
        assert!(latest_group_key(&conn, &s).unwrap() == k2);
        assert_eq!(key_versions(&conn).unwrap(), vec![1, 2]);
        // A wrapped key moved to another version's row doesn't unwrap.
        let w1: Vec<u8> = conn.query_row("SELECT wrapped FROM group_keys WHERE version = 1", [], |r| r.get(0)).unwrap();
        assert!(s.unwrap(2, &w1).is_err());
        // Nothing in the table is the raw key.
        assert!(!w1.windows(32).any(|w| w == &k1.key_bytes()[..]));
    }
}
