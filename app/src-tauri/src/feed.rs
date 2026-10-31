//! The feed: sync from the relay, apply events to the local archive, post.
//!
//! Event payloads (JSON, encrypted with the group key; see README "Event payloads"):
//!
//! | kind     | payload |
//! | -------- | ------- |
//! | post     | `{"text": str, "photos"?: [{"full", "full_digest", "thumb", "thumb_digest", "width", "height"}]}` |
//! | comment  | `{"post": event_id, "text": str}` |
//! | reaction | `{"post": event_id, "emoji": str}` (empty emoji removes yours) |
//! | edit     | `{"post": event_id, "text": str}` |
//! | delete   | `{"post": event_id}` |
//!
//! An event's id is `crypto::event_id(ciphertext)`. Edits and deletes only
//! count when they come from the post's author.

use crate::account;
use crate::api::*;
use crate::db::{self, Identity};
use crate::secrets::{self, Secrets};
use crate::state::App;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sidetray_crypto::roster::{Role, VerifiedDevice};
use sidetray_crypto::{self as crypto, protocol, GroupKey};
use std::collections::BTreeMap;

pub const MAX_TEXT: usize = 20_000;
pub const MAX_PHOTOS: usize = 10;
const MAX_MEDIA_ATTEMPTS: i64 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct PhotoRef {
    pub full: String,
    pub full_digest: String,
    pub thumb: String,
    pub thumb_digest: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Deserialize)]
struct PostBody {
    #[serde(default)]
    text: String,
    #[serde(default)]
    photos: Vec<PhotoRef>,
}

#[derive(Deserialize)]
struct RefBody {
    post: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    emoji: String,
}

/// Media ids become file names, so only allow what the relay hands out.
fn safe_media_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_emoji(e: &str) -> bool {
    e.chars().count() <= 8 && e.len() <= 32 && !e.chars().any(|c| c.is_ascii_alphanumeric() || c.is_control())
}

// --- sync ------------------------------------------------------------------------

#[derive(Serialize, Default, Clone)]
pub struct SyncReport {
    pub new_events: usize,
    /// Posts and comments by other people that arrived in this sync.
    pub new_from_others: usize,
    pub rejected: usize,
    pub pending_joins: usize,
    pub last_seq: i64,
}

pub async fn sync_once(app: &App) -> Result<SyncReport> {
    let _guard = app.sync_lock.lock().await;
    let id = app.require_active()?;
    let api = app.api(&id)?;
    let s = app.secrets(&id)?;
    let authors = account::refresh_roster(app, &id, &api).await?;
    // The roster refresh may have recorded a promotion.
    let id = app.require_active()?;
    let mut report = SyncReport::default();
    loop {
        let after = db::last_seq(&app.db())?;
        let page: EventPage = api.get(&format!("/events?after={after}")).await?;
        {
            let conn = app.db();
            let tx = conn.unchecked_transaction()?;
            let mut rejected = 0;
            for e in &page.events {
                report.new_events += 1;
                match apply_event(&tx, &id, &s, &authors, e) {
                    Ok(counts) => report.new_from_others += counts as usize,
                    Err(err) => {
                        rejected += 1;
                        eprintln!("event #{} rejected: {err:#}", e.seq);
                    }
                }
            }
            report.rejected += rejected;
            db::set_last_seq(&tx, page.last_seq, rejected as i64)?;
            tx.commit()?;
        }
        if page.last_seq > after {
            let _: serde_json::Value = api.post("/ack", &serde_json::json!({ "seq": page.last_seq })).await?;
        }
        if !page.has_more {
            break;
        }
    }
    download_media(app, &id, &s, &api).await;
    if id.is_keymaster() {
        if let Ok(list) = api.get::<PendingList>("/joins/pending").await {
            report.pending_joins = list.pending.len();
        }
    }
    let conn = app.db();
    db::mark_synced(&conn)?;
    report.last_seq = db::last_seq(&conn)?;
    Ok(report)
}

/// Verify, decrypt and store one event. Returns whether it's a post or comment
/// by someone else (for notifications later).
fn apply_event(
    conn: &Connection,
    id: &Identity,
    s: &Secrets,
    authors: &BTreeMap<String, VerifiedDevice>,
    e: &Event,
) -> Result<bool> {
    let author = authors
        .get(&e.author_device_id)
        .with_context(|| format!("author device {} has no valid member certificate", e.author_device_id))?;
    let ct = B64.decode(&e.ciphertext)?;
    let msg = protocol::event_message(&id.group_id, &e.author_device_id, &e.kind, e.key_version, &ct);
    crypto::verify(&author.sign_pk, &msg, &B64.decode(&e.signature)?).context("bad author signature")?;
    let gk = secrets::group_key(conn, s, e.key_version)?.with_context(|| format!("no group key v{}", e.key_version))?;
    let plain = crypto::decrypt(&gk, &ct, &protocol::event_ad(&id.group_id, &e.kind)).context("can't decrypt")?;
    let event_id = crypto::event_id(&ct);
    let member = &author.member_id;
    let by_other = *member != id.member_id;
    match e.kind.as_str() {
        "post" => {
            let body: PostBody = serde_json::from_slice(&plain).context("bad post payload")?;
            if body.text.len() > MAX_TEXT || body.photos.len() > MAX_PHOTOS * 2 {
                bail!("post too large");
            }
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO posts (id, seq, author_id, author_device_id, body, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![event_id, e.seq, member, e.author_device_id, body.text, e.created_at],
            )?;
            for (i, p) in body.photos.iter().enumerate() {
                let (Ok(fd), Ok(td)) = (account::decode32(&p.full_digest), account::decode32(&p.thumb_digest)) else {
                    continue;
                };
                if !safe_media_id(&p.full) || !safe_media_id(&p.thumb) || p.width == 0 || p.height == 0 {
                    continue;
                }
                conn.execute(
                    "INSERT OR IGNORE INTO media (id, post_id, idx, key_version, width, height, full_digest, thumb_id, thumb_digest)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![p.full, event_id, i as i64, e.key_version, p.width, p.height, &fd[..], p.thumb, &td[..]],
                )?;
            }
            Ok(inserted > 0 && by_other)
        }
        "comment" => {
            let b: RefBody = serde_json::from_slice(&plain).context("bad comment payload")?;
            if b.text.trim().is_empty() || b.text.len() > MAX_TEXT {
                bail!("empty or oversized comment");
            }
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO comments (id, seq, post_id, author_id, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![event_id, e.seq, b.post, member, b.text, e.created_at],
            )?;
            Ok(inserted > 0 && by_other)
        }
        "reaction" => {
            let b: RefBody = serde_json::from_slice(&plain).context("bad reaction payload")?;
            if b.emoji.is_empty() {
                conn.execute("DELETE FROM reactions WHERE post_id = ?1 AND author_id = ?2 AND seq < ?3", params![b.post, member, e.seq])?;
            } else if valid_emoji(&b.emoji) {
                conn.execute(
                    "INSERT INTO reactions (post_id, author_id, emoji, seq) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(post_id, author_id) DO UPDATE SET emoji = excluded.emoji, seq = excluded.seq
                     WHERE excluded.seq > reactions.seq",
                    params![b.post, member, b.emoji, e.seq],
                )?;
            } else {
                bail!("not an emoji reaction");
            }
            Ok(false)
        }
        "edit" => {
            let b: RefBody = serde_json::from_slice(&plain).context("bad edit payload")?;
            if b.text.len() > MAX_TEXT {
                bail!("edit too large");
            }
            conn.execute(
                "UPDATE posts SET body = ?1, edited_at = ?2 WHERE id = ?3 AND author_id = ?4 AND deleted = 0",
                params![b.text, e.created_at, b.post, member],
            )?;
            Ok(false)
        }
        "delete" => {
            let b: RefBody = serde_json::from_slice(&plain).context("bad delete payload")?;
            let n = conn.execute(
                "UPDATE posts SET deleted = 1, body = '' WHERE id = ?1 AND author_id = ?2",
                params![b.post, member],
            )?;
            if n > 0 {
                conn.execute("DELETE FROM comments WHERE post_id = ?1", params![b.post])?;
                conn.execute("DELETE FROM reactions WHERE post_id = ?1", params![b.post])?;
                // The files are removed by the next media pass (rows with no live post).
            }
            Ok(false)
        }
        other => bail!("unknown event kind {other}"),
    }
}

/// (full id, key version, full digest, thumb id, thumb digest, need full, need thumb)
type MediaTodo = (String, u32, Vec<u8>, String, Vec<u8>, bool, bool);

/// Fetch and decrypt photos that aren't on disk yet; drop files of deleted posts.
async fn download_media(app: &App, id: &Identity, s: &Secrets, api: &Api) {
    let todo: Vec<MediaTodo> = {
        let conn = app.db();
        if let Err(e) = remove_deleted_media(app, &conn) {
            eprintln!("cleaning up deleted photos: {e:#}");
        }
        let mut st = match conn.prepare(
            "SELECT m.id, m.key_version, m.full_digest, m.thumb_id, m.thumb_digest,
                    m.local_path IS NULL, m.thumb_path IS NULL
             FROM media m JOIN posts p ON p.id = m.post_id
             WHERE p.deleted = 0 AND (m.local_path IS NULL OR m.thumb_path IS NULL) AND m.attempts < ?1
             ORDER BY p.seq DESC",
        ) {
            Ok(st) => st,
            Err(e) => return eprintln!("{e}"),
        };
        let rows = st.query_map(params![MAX_MEDIA_ATTEMPTS], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        });
        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => return eprintln!("{e}"),
        }
    };
    let ad = protocol::media_ad(&id.group_id);
    for (full_id, version, full_digest, thumb_id, thumb_digest, need_full, need_thumb) in todo {
        let gk = match secrets::group_key(&app.db(), s, version) {
            Ok(Some(gk)) => gk,
            _ => continue,
        };
        // Thumbnail first: it's what the feed shows.
        let mut ok = true;
        if need_thumb {
            ok &= fetch_one(app, api, &gk, &ad, &full_id, &thumb_id, &thumb_digest, "thumb_path").await;
        }
        if need_full {
            ok &= fetch_one(app, api, &gk, &ad, &full_id, &full_id, &full_digest, "local_path").await;
        }
        if !ok {
            let _ = app.db().execute("UPDATE media SET attempts = attempts + 1 WHERE id = ?1", params![full_id]);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_one(app: &App, api: &Api, gk: &GroupKey, ad: &[u8], row: &str, media_id: &str, digest: &[u8], column: &str) -> bool {
    let result: Result<()> = async {
        let blob = api.download_media(media_id).await?;
        // The signed post recorded the digest of each encrypted blob, so the
        // server can't swap in another (validly encrypted) photo.
        if crypto::blob_digest(&blob)[..] != *digest {
            bail!("photo {media_id} doesn't match the digest in its post");
        }
        let plain = crypto::decrypt(gk, &blob, ad).context("can't decrypt photo")?;
        let name = format!("{media_id}.webp");
        write_file(&app.media_dir.join(&name), &plain)?;
        let sql = if column == "thumb_path" {
            "UPDATE media SET thumb_path = ?1 WHERE id = ?2"
        } else {
            "UPDATE media SET local_path = ?1 WHERE id = ?2"
        };
        app.db().execute(sql, params![name, row])?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => true,
        Err(e) => {
            eprintln!("photo {media_id}: {e:#}");
            false
        }
    }
}

fn write_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("part");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn remove_deleted_media(app: &App, conn: &Connection) -> Result<()> {
    let mut st = conn.prepare(
        "SELECT m.id, m.local_path, m.thumb_path FROM media m JOIN posts p ON p.id = m.post_id WHERE p.deleted = 1",
    )?;
    let rows: Vec<(String, Option<String>, Option<String>)> =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
    for (mid, full, thumb) in rows {
        for f in [full, thumb].into_iter().flatten() {
            let _ = std::fs::remove_file(app.media_dir.join(f));
        }
        conn.execute("DELETE FROM media WHERE id = ?1", params![mid])?;
    }
    Ok(())
}

// --- posting ----------------------------------------------------------------------

/// Encrypt, sign and append one event. Returns its event id.
async fn send_event(app: &App, kind: &str, body: &serde_json::Value, gk: &GroupKey, media_ids: Vec<String>) -> Result<String> {
    let id = app.require_active()?;
    let s = app.secrets(&id)?;
    let me = s.device_keys()?;
    let plain = serde_json::to_vec(body)?;
    let ct = crypto::encrypt(gk, &plain, &protocol::event_ad(&id.group_id, kind));
    let sig = crypto::sign(&me, &protocol::event_message(&id.group_id, &id.device_id, kind, gk.version(), &ct));
    let _: serde_json::Value = app
        .api(&id)?
        .post(
            "/events",
            &EventReq { kind, key_version: gk.version(), ciphertext: B64.encode(&ct), signature: B64.encode(sig), media_ids },
        )
        .await?;
    Ok(crypto::event_id(&ct))
}

fn latest_key(app: &App, id: &Identity) -> Result<GroupKey> {
    let s = app.secrets(id)?;
    secrets::latest_group_key(&app.db(), &s)
}

pub async fn create_post(app: &App, text: &str, staged: &[String]) -> Result<()> {
    let id = app.require_active()?;
    let text = text.trim();
    if text.len() > MAX_TEXT {
        bail!("that post is too long");
    }
    if staged.len() > MAX_PHOTOS {
        bail!("at most {MAX_PHOTOS} photos per post");
    }
    let photos: Vec<crate::photo::Processed> = {
        let map = app.staged.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(missing) = staged.iter().find(|k| !map.contains_key(*k)) {
            bail!("photo {missing} is no longer attached; add it again");
        }
        staged.iter().map(|k| map.get(k).expect("checked").clone()).collect()
    };
    if text.is_empty() && photos.is_empty() {
        bail!("write something or add a photo");
    }
    let gk = latest_key(app, &id)?;
    let api = app.api(&id)?;
    let ad = protocol::media_ad(&id.group_id);
    let mut refs = Vec::new();
    let mut local = Vec::new();
    for p in &photos {
        let enc_full = crypto::encrypt(&gk, &p.full, &ad);
        let enc_thumb = crypto::encrypt(&gk, &p.thumb, &ad);
        let (fd, td) = (crypto::blob_digest(&enc_full), crypto::blob_digest(&enc_thumb));
        let full_id = api.upload_media(enc_full).await?;
        let thumb_id = api.upload_media(enc_thumb).await?;
        if !safe_media_id(&full_id) || !safe_media_id(&thumb_id) {
            bail!("the server returned an unusable media id");
        }
        refs.push(PhotoRef {
            full: full_id,
            full_digest: B64.encode(fd),
            thumb: thumb_id,
            thumb_digest: B64.encode(td),
            width: p.width,
            height: p.height,
        });
        local.push((fd, td));
    }
    let mut body = serde_json::json!({ "text": text });
    if !refs.is_empty() {
        body["photos"] = serde_json::to_value(&refs)?;
    }
    let media_ids = refs.iter().flat_map(|r| [r.full.clone(), r.thumb.clone()]).collect();
    let post_id = send_event(app, "post", &body, &gk, media_ids).await?;

    // We already have the plaintext photos: keep them, so sync doesn't download them back.
    for (i, (p, r)) in photos.iter().zip(&refs).enumerate() {
        let (full_name, thumb_name) = (format!("{}.webp", r.full), format!("{}.webp", r.thumb));
        write_file(&app.media_dir.join(&full_name), &p.full)?;
        write_file(&app.media_dir.join(&thumb_name), &p.thumb)?;
        let (fd, td) = local[i];
        app.db().execute(
            "INSERT OR IGNORE INTO media (id, post_id, idx, key_version, width, height, full_digest, thumb_id, thumb_digest, local_path, thumb_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![r.full, post_id, i as i64, gk.version(), r.width, r.height, &fd[..], r.thumb, &td[..], full_name, thumb_name],
        )?;
    }
    {
        let mut map = app.staged.lock().unwrap_or_else(|e| e.into_inner());
        for k in staged {
            map.remove(k);
        }
    }
    sync_once(app).await?;
    Ok(())
}

fn require_post(app: &App, post_id: &str) -> Result<String> {
    app.db()
        .query_row("SELECT author_id FROM posts WHERE id = ?1 AND deleted = 0", params![post_id], |r| r.get(0))
        .optional()?
        .context("that post isn't in this app's archive")
}

pub async fn add_comment(app: &App, post_id: &str, text: &str) -> Result<()> {
    let id = app.require_active()?;
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_TEXT {
        bail!("write a comment first");
    }
    require_post(app, post_id)?;
    let gk = latest_key(app, &id)?;
    send_event(app, "comment", &serde_json::json!({ "post": post_id, "text": text }), &gk, vec![]).await?;
    sync_once(app).await?;
    Ok(())
}

pub async fn set_reaction(app: &App, post_id: &str, emoji: &str) -> Result<()> {
    let id = app.require_active()?;
    if !emoji.is_empty() && !valid_emoji(emoji) {
        bail!("not an emoji");
    }
    require_post(app, post_id)?;
    let gk = latest_key(app, &id)?;
    send_event(app, "reaction", &serde_json::json!({ "post": post_id, "emoji": emoji }), &gk, vec![]).await?;
    sync_once(app).await?;
    Ok(())
}

pub async fn delete_post(app: &App, post_id: &str) -> Result<()> {
    let id = app.require_active()?;
    if require_post(app, post_id)? != id.member_id {
        bail!("you can only delete your own posts");
    }
    let gk = latest_key(app, &id)?;
    send_event(app, "delete", &serde_json::json!({ "post": post_id }), &gk, vec![]).await?;
    sync_once(app).await?;
    Ok(())
}

// --- reading the archive ----------------------------------------------------------

#[derive(Serialize)]
pub struct PostView {
    pub id: String,
    pub seq: i64,
    pub author: String,
    pub author_keymaster: bool,
    pub mine: bool,
    pub text: String,
    pub created_at: i64,
    pub edited: bool,
    pub photos: Vec<PhotoView>,
    pub comments: Vec<CommentView>,
    pub reactions: Vec<ReactionView>,
}

#[derive(Serialize)]
pub struct PhotoView {
    pub thumb: Option<String>,
    pub full: Option<String>,
    pub width: u32,
    pub height: u32,
}

#[derive(Serialize)]
pub struct CommentView {
    pub id: String,
    pub author: String,
    pub mine: bool,
    pub text: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct ReactionView {
    pub emoji: String,
    pub count: usize,
    pub mine: bool,
    pub names: Vec<String>,
}

/// URL the webview loads a local photo file from (see the `media` protocol in main.rs).
pub fn media_url(file: &str) -> String {
    if cfg!(any(windows, target_os = "android")) {
        format!("http://media.localhost/{file}")
    } else {
        format!("media://localhost/{file}")
    }
}

const UNKNOWN: &str = "Unknown member";

/// Newest first, `limit` posts older than `before` (a seq), or the latest.
pub fn feed(conn: &Connection, me: &str, before: Option<i64>, limit: i64) -> Result<Vec<PostView>> {
    let mut st = conn.prepare(
        "SELECT p.id, p.seq, p.author_id, COALESCE(m.display_name, ?1), COALESCE(m.role, 'member'), p.body,
                p.created_at, p.edited_at IS NOT NULL
         FROM posts p LEFT JOIN members m ON m.id = p.author_id
         WHERE p.deleted = 0 AND p.seq < ?2 ORDER BY p.seq DESC LIMIT ?3",
    )?;
    let rows = st.query_map(params![UNKNOWN, before.unwrap_or(i64::MAX), limit], |r| {
        let author_id: String = r.get(2)?;
        let role: String = r.get(4)?;
        Ok(PostView {
            id: r.get(0)?,
            seq: r.get(1)?,
            mine: author_id == me,
            author: r.get(3)?,
            author_keymaster: role == Role::Keymaster.as_str(),
            text: r.get(5)?,
            created_at: r.get(6)?,
            edited: r.get(7)?,
            photos: vec![],
            comments: vec![],
            reactions: vec![],
        })
    })?;
    let mut posts: Vec<PostView> = rows.collect::<rusqlite::Result<_>>()?;

    let mut photos = conn.prepare("SELECT thumb_path, local_path, width, height FROM media WHERE post_id = ?1 ORDER BY idx")?;
    let mut comments = conn.prepare(
        "SELECT c.id, c.author_id, COALESCE(m.display_name, ?2), c.body, c.created_at
         FROM comments c LEFT JOIN members m ON m.id = c.author_id WHERE c.post_id = ?1 ORDER BY c.seq",
    )?;
    let mut reactions = conn.prepare(
        "SELECT r.emoji, r.author_id, COALESCE(m.display_name, ?2) FROM reactions r
         LEFT JOIN members m ON m.id = r.author_id WHERE r.post_id = ?1 ORDER BY r.seq",
    )?;
    for p in &mut posts {
        p.photos = photos
            .query_map(params![p.id], |r| {
                let thumb: Option<String> = r.get(0)?;
                let full: Option<String> = r.get(1)?;
                Ok(PhotoView {
                    thumb: thumb.as_deref().map(media_url),
                    full: full.as_deref().map(media_url),
                    width: r.get(2)?,
                    height: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        p.comments = comments
            .query_map(params![p.id, UNKNOWN], |r| {
                let author_id: String = r.get(1)?;
                Ok(CommentView { id: r.get(0)?, mine: author_id == me, author: r.get(2)?, text: r.get(3)?, created_at: r.get(4)? })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut grouped: Vec<ReactionView> = Vec::new();
        let rs: Vec<(String, String, String)> =
            reactions.query_map(params![p.id, UNKNOWN], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        for (emoji, author_id, name) in rs {
            let i = match grouped.iter().position(|g| g.emoji == emoji) {
                Some(i) => i,
                None => {
                    grouped.push(ReactionView { emoji, count: 0, mine: false, names: vec![] });
                    grouped.len() - 1
                }
            };
            let g = &mut grouped[i];
            g.count += 1;
            g.mine |= author_id == me;
            g.names.push(name);
        }
        p.reactions = grouped;
    }
    Ok(posts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidetray_crypto::roster::Role;

    struct Fixture {
        conn: Connection,
        id: Identity,
        s: Secrets,
        gk: GroupKey,
        authors: BTreeMap<String, VerifiedDevice>,
        ana: sidetray_crypto::DeviceKeys,
        seq: i64,
    }

    fn fixture() -> Fixture {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let mine = crypto::generate_device_keys();
        let p = mine.public();
        let id = Identity {
            local_id: "x".into(),
            server_url: "https://example.org".into(),
            ca_pem: None,
            group_id: "g_1".into(),
            group_name: "G".into(),
            member_id: "m_me".into(),
            device_id: "d_me".into(),
            display_name: "Me".into(),
            email: "me@example.org".into(),
            status: "active".into(),
            role: "member".into(),
            enc_pubkey: p.enc,
            sign_pubkey: p.sign,
        };
        let s = Secrets::new("tok", &mine);
        let gk = crypto::generate_group_key(1);
        secrets::save_group_key(&conn, &s, &gk).unwrap();
        let ana = crypto::generate_device_keys();
        let mut authors = BTreeMap::new();
        authors.insert(
            "d_ana".to_string(),
            VerifiedDevice {
                member_id: "m_ana".into(),
                device_id: "d_ana".into(),
                display_name: "Ana".into(),
                role: Role::Member,
                enc_pk: ana.public().enc,
                sign_pk: ana.public().sign,
                issuer_device_id: "d_km".into(),
            },
        );
        conn.execute("INSERT INTO members (id, display_name, role) VALUES ('m_ana', 'Ana', 'member')", []).unwrap();
        Fixture { conn, id, s, gk, authors, ana, seq: 0 }
    }

    impl Fixture {
        /// An event from Ana; returns (event, event id).
        fn event(&mut self, kind: &str, body: serde_json::Value) -> (Event, String) {
            self.seq += 1;
            let ct = crypto::encrypt(&self.gk, &serde_json::to_vec(&body).unwrap(), &protocol::event_ad("g_1", kind));
            let sig = crypto::sign(&self.ana, &protocol::event_message("g_1", "d_ana", kind, 1, &ct));
            let e = Event {
                seq: self.seq,
                kind: kind.into(),
                author_device_id: "d_ana".into(),
                key_version: 1,
                ciphertext: B64.encode(&ct),
                signature: B64.encode(sig),
                created_at: 1000 + self.seq,
            };
            (e, crypto::event_id(&ct))
        }
        fn apply(&self, e: &Event) -> Result<bool> {
            apply_event(&self.conn, &self.id, &self.s, &self.authors, e)
        }
    }

    #[test]
    fn cli_style_post_comment_reaction_edit_delete() {
        let mut f = fixture();
        let (post, pid) = f.event("post", serde_json::json!({ "text": "hello" }));
        assert!(f.apply(&post).unwrap());
        // Replaying the same event is harmless.
        assert!(!f.apply(&post).unwrap());
        let (c, _) = f.event("comment", serde_json::json!({ "post": pid, "text": "first!" }));
        assert!(f.apply(&c).unwrap());
        let (r1, _) = f.event("reaction", serde_json::json!({ "post": pid, "emoji": "👍" }));
        let (r2, _) = f.event("reaction", serde_json::json!({ "post": pid, "emoji": "❤️" }));
        f.apply(&r2).unwrap();
        f.apply(&r1).unwrap(); // older reaction arriving late doesn't win
        let (ed, _) = f.event("edit", serde_json::json!({ "post": pid, "text": "hello, edited" }));
        f.apply(&ed).unwrap();

        let view = feed(&f.conn, "m_me", None, 50).unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].author, "Ana");
        assert_eq!(view[0].text, "hello, edited");
        assert!(view[0].edited);
        assert_eq!(view[0].comments[0].text, "first!");
        assert_eq!(view[0].reactions.len(), 1);
        assert_eq!(view[0].reactions[0].emoji, "❤️");

        let (del, _) = f.event("delete", serde_json::json!({ "post": pid }));
        f.apply(&del).unwrap();
        assert!(feed(&f.conn, "m_me", None, 50).unwrap().is_empty());
    }

    #[test]
    fn forged_and_unknown_authors_are_rejected() {
        let mut f = fixture();
        let (mut e, _) = f.event("post", serde_json::json!({ "text": "hi" }));
        e.author_device_id = "d_mallory".into();
        assert!(f.apply(&e).is_err());
        let (mut e, _) = f.event("post", serde_json::json!({ "text": "hi" }));
        let mut sig = B64.decode(&e.signature).unwrap();
        sig[0] ^= 1;
        e.signature = B64.encode(sig);
        assert!(f.apply(&e).is_err());
        // Relabelled kind: the signature covers it.
        let (mut e, _) = f.event("post", serde_json::json!({ "post": "x", "text": "hi" }));
        e.kind = "comment".into();
        assert!(f.apply(&e).is_err());
    }

    #[test]
    fn edits_and_deletes_by_someone_else_are_ignored() {
        let mut f = fixture();
        f.conn
            .execute("INSERT INTO posts (id, seq, author_id, author_device_id, body, created_at) VALUES ('p_me', 0, 'm_me', 'd_me', 'mine', 1)", [])
            .unwrap();
        let (ed, _) = f.event("edit", serde_json::json!({ "post": "p_me", "text": "hacked" }));
        f.apply(&ed).unwrap();
        let (del, _) = f.event("delete", serde_json::json!({ "post": "p_me" }));
        f.apply(&del).unwrap();
        let view = feed(&f.conn, "m_me", None, 50).unwrap();
        assert_eq!(view[0].text, "mine");
        assert!(view[0].mine);
    }

    #[test]
    fn photo_refs_with_unsafe_ids_are_skipped() {
        let mut f = fixture();
        let d = B64.encode([7u8; 32]);
        let photos = serde_json::json!([
            { "full": "ok_full", "full_digest": d, "thumb": "ok_thumb", "thumb_digest": d, "width": 10, "height": 10 },
            { "full": "../../evil", "full_digest": d, "thumb": "t", "thumb_digest": d, "width": 10, "height": 10 }
        ]);
        let (post, _) = f.event("post", serde_json::json!({ "text": "pics", "photos": photos }));
        f.apply(&post).unwrap();
        let n: i64 = f.conn.query_row("SELECT COUNT(*) FROM media", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn emoji_validation() {
        assert!(valid_emoji("👍"));
        assert!(valid_emoji("❤️"));
        assert!(!valid_emoji("lol"));
        assert!(!valid_emoji("👍👍👍👍👍👍👍👍👍"));
    }
}
