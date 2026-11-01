//! Local SQLite archive (SPEC.md, "Client (local SQLite)").
//!
//! Plaintext on disk, like the spec says; private keys aren't here (see
//! secrets.rs) and group keys are stored wrapped under a key that lives in the
//! OS keychain.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS identity (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    local_id      TEXT NOT NULL,          -- names this install's keychain entry
    server_url    TEXT NOT NULL,
    ca_pem        TEXT,                   -- test server: the root certificate the person confirmed (pinned)
    group_id      TEXT NOT NULL,
    group_name    TEXT NOT NULL,
    member_id     TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    email         TEXT NOT NULL,
    status        TEXT NOT NULL,          -- pending / active / denied / removed / revoked
    role          TEXT NOT NULL,          -- member / keymaster
    enc_pubkey    BLOB NOT NULL,
    sign_pubkey   BLOB NOT NULL,
    created_at    INTEGER NOT NULL
);
-- Group keys by version, each encrypted under the keychain's local key.
CREATE TABLE IF NOT EXISTS group_keys (
    version  INTEGER PRIMARY KEY,
    wrapped  BLOB NOT NULL
);
-- Only used where the OS has no keychain.
CREATE TABLE IF NOT EXISTS secrets (
    name   TEXT PRIMARY KEY,
    value  BLOB NOT NULL
);
-- Key Master signing keys this device pinned itself (roster trust anchors).
CREATE TABLE IF NOT EXISTS anchors (
    device_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    sign_pubkey  BLOB NOT NULL
);
-- Cached verified roster. Rows stay after someone leaves, so old posts keep their names.
CREATE TABLE IF NOT EXISTS members (
    id            TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS member_devices (
    device_id    TEXT PRIMARY KEY,
    member_id    TEXT NOT NULL,
    sign_pubkey  BLOB NOT NULL,
    enc_pubkey   BLOB NOT NULL,
    verified     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS posts (
    id                TEXT PRIMARY KEY,   -- crypto::event_id of the post event
    seq               INTEGER NOT NULL,
    author_id         TEXT NOT NULL,      -- member id
    author_device_id  TEXT NOT NULL,
    body              TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    edited_at         INTEGER,
    deleted           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS posts_seq ON posts(seq);
CREATE TABLE IF NOT EXISTS comments (
    id          TEXT PRIMARY KEY,
    seq         INTEGER NOT NULL,
    post_id     TEXT NOT NULL,
    author_id   TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS comments_post ON comments(post_id, seq);
CREATE TABLE IF NOT EXISTS reactions (
    post_id    TEXT NOT NULL,
    author_id  TEXT NOT NULL,
    emoji      TEXT NOT NULL,
    seq        INTEGER NOT NULL,          -- the latest reaction event wins
    PRIMARY KEY (post_id, author_id)
);
-- One row per photo: the full image (id = its media id) and its thumbnail.
CREATE TABLE IF NOT EXISTS media (
    id            TEXT PRIMARY KEY,
    post_id       TEXT NOT NULL,
    idx           INTEGER NOT NULL,
    key_version   INTEGER NOT NULL,
    width         INTEGER NOT NULL,
    height        INTEGER NOT NULL,
    full_digest   BLOB NOT NULL,
    thumb_id      TEXT NOT NULL,
    thumb_digest  BLOB NOT NULL,
    local_path    TEXT,                   -- file name in the media folder once downloaded
    thumb_path    TEXT,
    attempts      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS media_post ON media(post_id, idx);
-- Phase 6b: each member's latest valid profile event (chosen name, avatar).
CREATE TABLE IF NOT EXISTS profiles (
    member_id      TEXT PRIMARY KEY,
    seq            INTEGER NOT NULL,      -- the profile event; a later one replaces it
    display_name   TEXT,                  -- NULL: the name in their certificate
    avatar_id      TEXT,                  -- media id of the encrypted 256 px WebP, NULL: initials
    avatar_digest  BLOB,
    key_version    INTEGER NOT NULL,
    avatar_path    TEXT,                  -- file name in the media folder once downloaded and checked
    attempts       INTEGER NOT NULL DEFAULT 0
);
-- Phase 5b: direct messages, plaintext on disk like posts.
CREATE TABLE IF NOT EXISTS conversations (
    id               TEXT PRIMARY KEY,      -- crypto::dm::conversation_id
    other_member_id  TEXT NOT NULL,
    last_seq         INTEGER NOT NULL DEFAULT 0,
    last_at          INTEGER NOT NULL DEFAULT 0,
    last_text        TEXT NOT NULL DEFAULT '',
    last_mine        INTEGER NOT NULL DEFAULT 0,
    unread           INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dm_messages (
    id                TEXT PRIMARY KEY,     -- crypto::event_id of the ciphertext
    seq               INTEGER NOT NULL,
    conversation_id   TEXT NOT NULL,
    sender_member_id  TEXT NOT NULL,
    sender_device_id  TEXT NOT NULL,
    body              TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    key_wrapped       BLOB NOT NULL         -- the message key, wrapped like group keys, for its photos
);
CREATE INDEX IF NOT EXISTS dm_messages_conversation ON dm_messages(conversation_id, seq);
CREATE TABLE IF NOT EXISTS dm_photos (
    id            TEXT PRIMARY KEY,         -- media id of the full image
    message_id    TEXT NOT NULL,
    idx           INTEGER NOT NULL,
    width         INTEGER NOT NULL,
    height        INTEGER NOT NULL,
    full_digest   BLOB NOT NULL,
    thumb_id      TEXT NOT NULL,
    thumb_digest  BLOB NOT NULL,
    local_path    TEXT,
    thumb_path    TEXT,
    attempts      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS dm_photos_message ON dm_photos(message_id, idx);
CREATE TABLE IF NOT EXISTS sync_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq      INTEGER NOT NULL,
    last_sync_at  INTEGER,
    rejected      INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sync_state (id, last_seq) VALUES (1, 0);
-- Small settings and state (A3: push registration, whether notifications were offered).
CREATE TABLE IF NOT EXISTS kv (
    key           TEXT PRIMARY KEY,
    value         TEXT NOT NULL
);
"#;

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(SCHEMA).context("creating tables")?;
    add_column(&conn, "sync_state", "unread", "INTEGER NOT NULL DEFAULT 0")?;
    // Phase 6: set when the relay pruned events this device never got.
    add_column(&conn, "sync_state", "missed_at", "INTEGER")?;
    add_column(&conn, "sync_state", "missed_days", "REAL")?;
    // Phase 5b: how far direct messages have synced.
    add_column(&conn, "sync_state", "dm_last_seq", "INTEGER NOT NULL DEFAULT 0")?;
    // 0.1.1: photos on comments. `post_id` stays the post (so the photos go
    // with it); `comment_id` is the comment, NULL for the post's own photos.
    add_column(&conn, "media", "comment_id", "TEXT")?;
    conn.execute_batch("CREATE INDEX IF NOT EXISTS media_comment ON media(comment_id, idx)")?;
    Ok(conn)
}

/// Phase 5+ columns, added in place so existing archives keep working.
fn add_column(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    let has: bool = conn
        .prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"))?
        .exists(params![column])?;
    if !has {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub local_id: String,
    pub server_url: String,
    pub ca_pem: Option<String>,
    pub group_id: String,
    pub group_name: String,
    pub member_id: String,
    pub device_id: String,
    pub display_name: String,
    pub email: String,
    pub status: String,
    pub role: String,
    pub enc_pubkey: [u8; 32],
    pub sign_pubkey: [u8; 32],
}

impl Identity {
    pub fn is_keymaster(&self) -> bool {
        self.status == "active" && self.role == "keymaster"
    }
    pub fn public(&self) -> sidetray_crypto::DevicePublicKeys {
        sidetray_crypto::DevicePublicKeys { enc: self.enc_pubkey, sign: self.sign_pubkey }
    }
}

fn key32(v: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    v.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

pub fn identity(conn: &Connection) -> Result<Option<Identity>> {
    conn.query_row(
        "SELECT local_id, server_url, ca_pem, group_id, group_name, member_id, device_id, display_name,
                email, status, role, enc_pubkey, sign_pubkey FROM identity WHERE id = 1",
        [],
        |r| {
            Ok(Identity {
                local_id: r.get(0)?,
                server_url: r.get(1)?,
                ca_pem: r.get(2)?,
                group_id: r.get(3)?,
                group_name: r.get(4)?,
                member_id: r.get(5)?,
                device_id: r.get(6)?,
                display_name: r.get(7)?,
                email: r.get(8)?,
                status: r.get(9)?,
                role: r.get(10)?,
                enc_pubkey: key32(r.get(11)?)?,
                sign_pubkey: key32(r.get(12)?)?,
            })
        },
    )
    .optional()
    .context("reading identity")
}

pub fn save_identity(conn: &Connection, id: &Identity) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO identity (id, local_id, server_url, ca_pem, group_id, group_name, member_id,
             device_id, display_name, email, status, role, enc_pubkey, sign_pubkey, created_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            id.local_id,
            id.server_url,
            id.ca_pem,
            id.group_id,
            id.group_name,
            id.member_id,
            id.device_id,
            id.display_name,
            id.email,
            id.status,
            id.role,
            &id.enc_pubkey[..],
            &id.sign_pubkey[..],
            crate::now(),
        ],
    )?;
    Ok(())
}

pub fn set_status(conn: &Connection, status: &str, role: &str) -> Result<()> {
    conn.execute("UPDATE identity SET status = ?1, role = ?2 WHERE id = 1", params![status, role])?;
    Ok(())
}

/// The name a Key Master certified for this device changed (they accepted the
/// name chosen in the profile).
pub fn set_display_name(conn: &Connection, name: &str) -> Result<()> {
    conn.execute("UPDATE identity SET display_name = ?1 WHERE id = 1", params![name])?;
    Ok(())
}

/// Pin a (new) root certificate for this test server, after the person confirmed its fingerprint.
pub fn set_ca_pem(conn: &Connection, pem: &str) -> Result<()> {
    conn.execute("UPDATE identity SET ca_pem = ?1 WHERE id = 1", params![pem])?;
    Ok(())
}

/// Forget everything (used to start over after a denied or abandoned join).
pub fn wipe(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "DELETE FROM identity; DELETE FROM group_keys; DELETE FROM secrets; DELETE FROM anchors;
         DELETE FROM members; DELETE FROM member_devices; DELETE FROM posts; DELETE FROM comments;
         DELETE FROM reactions; DELETE FROM media; DELETE FROM profiles;
         DELETE FROM conversations; DELETE FROM dm_messages; DELETE FROM dm_photos; DELETE FROM kv;
         UPDATE sync_state SET last_seq = 0, last_sync_at = NULL, rejected = 0, unread = 0, missed_at = NULL, missed_days = NULL, dm_last_seq = 0;",
    )?;
    Ok(())
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn kv_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| r.get(0)).optional()?)
}

/// `None` deletes the key.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn kv_set(conn: &Connection, key: &str, value: Option<&str>) -> Result<()> {
    match value {
        Some(v) => conn.execute("INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2", params![key, v])?,
        None => conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?,
    };
    Ok(())
}

pub fn pin_anchor(conn: &Connection, device_id: &str, name: &str, sign_pk: &[u8; 32]) -> Result<()> {
    conn.execute(
        "INSERT INTO anchors (device_id, name, sign_pubkey) VALUES (?1, ?2, ?3)
         ON CONFLICT(device_id) DO UPDATE SET name = excluded.name, sign_pubkey = excluded.sign_pubkey",
        params![device_id, name, &sign_pk[..]],
    )?;
    Ok(())
}

pub fn anchors(conn: &Connection) -> Result<Vec<(String, String, [u8; 32])>> {
    let mut st = conn.prepare("SELECT device_id, name, sign_pubkey FROM anchors ORDER BY device_id")?;
    let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, key32(r.get(2)?)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn last_seq(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT last_seq FROM sync_state WHERE id = 1", [], |r| r.get(0))?)
}

pub fn set_last_seq(conn: &Connection, seq: i64, rejected: i64) -> Result<()> {
    conn.execute(
        "UPDATE sync_state SET last_seq = MAX(last_seq, ?1), rejected = rejected + ?2 WHERE id = 1",
        params![seq, rejected],
    )?;
    Ok(())
}

pub fn mark_synced(conn: &Connection) -> Result<()> {
    conn.execute("UPDATE sync_state SET last_sync_at = ?1 WHERE id = 1", params![crate::now()])?;
    Ok(())
}

pub fn sync_info(conn: &Connection) -> Result<(i64, Option<i64>, i64)> {
    Ok(conn.query_row("SELECT last_seq, last_sync_at, rejected FROM sync_state WHERE id = 1", [], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?)
}

/// Posts and comments by others that arrived since the feed was last looked at.
pub fn unread(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT unread FROM sync_state WHERE id = 1", [], |r| r.get(0))?)
}

pub fn add_unread(conn: &Connection, n: i64) -> Result<()> {
    conn.execute("UPDATE sync_state SET unread = unread + ?1 WHERE id = 1", params![n])?;
    Ok(())
}

pub fn clear_unread(conn: &Connection) -> Result<()> {
    conn.execute("UPDATE sync_state SET unread = 0 WHERE id = 1", [])?;
    Ok(())
}

/// Direct messages: the highest seq stored.
pub fn dm_last_seq(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT dm_last_seq FROM sync_state WHERE id = 1", [], |r| r.get(0))?)
}

pub fn set_dm_last_seq(conn: &Connection, seq: i64) -> Result<()> {
    conn.execute("UPDATE sync_state SET dm_last_seq = MAX(dm_last_seq, ?1) WHERE id = 1", params![seq])?;
    Ok(())
}

/// Unread direct messages, over every conversation.
pub fn dm_unread(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COALESCE(SUM(unread), 0) FROM conversations", [], |r| r.get(0))?)
}

/// The relay deleted events this device never downloaded (it was away longer
/// than the retention window). Shown until dismissed.
pub fn set_missed(conn: &Connection, retention_days: f64) -> Result<()> {
    conn.execute(
        "UPDATE sync_state SET missed_at = ?1, missed_days = ?2 WHERE id = 1",
        params![crate::now(), retention_days],
    )?;
    Ok(())
}

/// (when it was noticed, the server's retention window in days)
pub fn missed(conn: &Connection) -> Result<Option<(i64, f64)>> {
    Ok(conn.query_row("SELECT missed_at, missed_days FROM sync_state WHERE id = 1", [], |r| {
        Ok(r.get::<_, Option<i64>>(0)?.map(|at| (at, r.get::<_, Option<f64>>(1).ok().flatten().unwrap_or(90.0))))
    })?)
}

pub fn clear_missed(conn: &Connection) -> Result<()> {
    conn.execute("UPDATE sync_state SET missed_at = NULL, missed_days = NULL WHERE id = 1", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unread_counts_and_survives_reopening() {
        let dir = std::env::temp_dir().join(format!("sidetray-db-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let _ = std::fs::remove_file(&path);
        {
            let conn = open(&path).unwrap();
            add_unread(&conn, 3).unwrap();
            add_unread(&conn, 2).unwrap();
        }
        let conn = open(&path).unwrap(); // the migration runs again harmlessly
        assert_eq!(unread(&conn).unwrap(), 5);
        clear_unread(&conn).unwrap();
        assert_eq!(unread(&conn).unwrap(), 0);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
