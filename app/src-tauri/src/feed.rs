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
//! | profile  | `{"display_name"?: str, "avatar": {"id", "digest"} \| null}` (see profile.rs) |
//!
//! An event's id is `crypto::event_id(ciphertext)`. Edits and deletes only
//! count when they come from the post's author.

use crate::account;
use crate::api::*;
use crate::manage;
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
/// Photos one comment may carry (more arriving from another client are dropped).
pub const MAX_COMMENT_PHOTOS: usize = 4;
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
    /// Comments only (0.1.1).
    #[serde(default)]
    photos: Vec<PhotoRef>,
}

/// Media ids become file names, so only allow what the relay hands out.
pub fn safe_media_id(id: &str) -> bool {
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
    /// This sync started from nothing (a new device catching up on the backlog).
    pub initial: bool,
    /// What arrived, for the unread count and notifications.
    #[serde(skip)]
    pub notices: Vec<Notice>,
    /// Key Master: the pending join requests, as (device id, display name).
    #[serde(skip)]
    pub pending: Vec<(String, String)>,
    /// The relay had already pruned events this device never got.
    pub missed: bool,
    /// Key Master: this sync finished a pending key rotation (the new version).
    pub rotated: Option<u32>,
    /// Avatars that became available (downloaded and checked) in this sync.
    pub avatars: usize,
    /// Direct messages stored in this sync (from others, or from my other devices).
    pub new_dms: usize,
    /// New direct messages from others, for the unread count and notifications.
    #[serde(skip)]
    pub dm_notices: Vec<crate::dm::DmNotice>,
    /// A certified name or role changed (say, a Key Master accepted a new name): redraw names.
    pub names_changed: bool,
}

/// Who may author events: verified devices in the roster now, and former
/// devices (removed or revoked) for events up to the seq they were cut off at.
#[derive(Default)]
pub struct Authors {
    pub current: BTreeMap<String, VerifiedDevice>,
    pub former: BTreeMap<String, (VerifiedDevice, i64)>,
}

impl Authors {
    fn get(&self, device_id: &str, seq: i64) -> Result<&VerifiedDevice> {
        if let Some(v) = self.current.get(device_id) {
            return Ok(v);
        }
        match self.former.get(device_id) {
            Some((v, cut_off)) if seq <= *cut_off => Ok(v),
            Some(_) => bail!("author device {device_id} had been removed by the time of this event"),
            None => bail!("author device {device_id} has no valid member certificate"),
        }
    }
}

/// A new post or comment by someone else.
#[derive(Clone, Debug, PartialEq)]
pub struct Notice {
    pub post_id: String,
    pub author: String,
    /// The post or comment text, or a stand-in for a photo-only post.
    pub text: String,
    pub comment: bool,
    /// Worth a notification: any post by someone else, or a comment on one of my posts.
    pub notify: bool,
}

pub async fn sync_once(app: &App) -> Result<SyncReport> {
    let _guard = app.sync_lock.lock().await;
    let id = app.require_active()?;
    let api = app.api(&id)?;
    let s = app.secrets(&id)?;
    let names_before = roster_names(&app.db())?;
    let roster = account::refresh_roster(app, &id, &api).await?;
    let dm_former = roster.former_dm;
    let authors = Authors { current: roster.verified, former: roster.former };
    // The roster refresh may have recorded a promotion.
    let id = app.require_active()?;
    let mut report = SyncReport { initial: db::last_seq(&app.db())? == 0, ..Default::default() };
    report.names_changed = roster_names(&app.db())? != names_before;
    // Key Masters check every time, to notice a rotation left pending.
    let km_keys = if id.is_keymaster() { Some(manage::refresh_keys(app, &id, &api, &authors.current).await?) } else { None };
    let mut keys_checked = km_keys.is_some();
    let mut first_page = true;
    loop {
        let after = db::last_seq(&app.db())?;
        let page: EventPage = api.get(&format!("/events?after={after}")).await?;
        if std::mem::take(&mut first_page) && after > 0 && page.pruned_through > after {
            // Away longer than the retention window: some events were deleted unseen.
            db::set_missed(&app.db(), page.retention_days)?;
            report.missed = true;
        }
        if !keys_checked {
            let have = secrets::key_versions(&app.db())?;
            let latest = have.last().copied().unwrap_or(0);
            if page.key_version > latest || page.events.iter().any(|e| !have.contains(&e.key_version)) {
                // A Key Master rotated the group key: fetch ours before decrypting.
                manage::refresh_keys(app, &id, &api, &authors.current).await?;
                keys_checked = true;
            }
        }
        {
            let conn = app.db();
            let tx = conn.unchecked_transaction()?;
            let mut rejected = 0;
            for e in &page.events {
                report.new_events += 1;
                match apply_event(&tx, &id, &s, &authors, e) {
                    Ok(Some(notice)) => {
                        report.new_from_others += 1;
                        report.notices.push(notice);
                    }
                    Ok(None) => {}
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
    // Direct messages (Phase 5b). A failure here doesn't fail the feed sync.
    let dm_authors = crate::dm::Authors { current: authors.current.clone(), former: dm_former };
    match crate::dm::sync(app, &id, &s, &api, &dm_authors).await {
        Ok(d) => {
            report.new_dms = d.new_messages;
            report.rejected += d.rejected;
            report.dm_notices = d.notices;
        }
        Err(e) => eprintln!("syncing direct messages: {e:#}"),
    }
    download_media(app, &id, &s, &api).await;
    report.avatars = crate::profile::download(app, &id, &s, &api).await;
    if let Some(keys) = &km_keys {
        match manage::rotate_if_pending(app, keys).await {
            Some(Ok(r)) if r.devices > 0 => report.rotated = Some(r.key_version),
            Some(Err(e)) => eprintln!("finishing a pending key rotation: {e:#}"),
            _ => {}
        }
    }
    if id.is_keymaster() {
        if let Ok(list) = api.get::<PendingList>("/joins/pending").await {
            report.pending_joins = list.pending.len();
            report.pending = list.pending.into_iter().map(|p| (p.device_id, p.display_name)).collect();
        }
    }
    let conn = app.db();
    // A new device's first sync is the backlog, not news.
    if !report.initial {
        db::add_unread(&conn, report.notices.len() as i64)?;
    }
    db::mark_synced(&conn)?;
    report.last_seq = db::last_seq(&conn)?;
    drop(conn);
    crate::alerts::after_sync(app, &report);
    Ok(report)
}

/// The cached roster's names and roles, to notice when a sync changed them.
fn roster_names(conn: &Connection) -> Result<String> {
    Ok(conn.query_row(
        "SELECT COALESCE(group_concat(id || '=' || display_name || '/' || role, char(10)), '')
         FROM (SELECT * FROM members ORDER BY id)",
        [],
        |r| r.get(0),
    )?)
}

/// One line for a notification: whitespace collapsed, cut at 140 characters.
pub fn snippet(text: &str, photos: usize) -> String {
    let t = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.is_empty() {
        return match photos {
            0 => String::new(),
            1 => "shared a photo".into(),
            n => format!("shared {n} photos"),
        };
    }
    const MAX: usize = 140;
    if t.chars().count() <= MAX {
        t
    } else {
        format!("{}…", t.chars().take(MAX).collect::<String>().trim_end())
    }
}

/// Verify, decrypt and store one event. Returns a notice if it's a new post
/// or comment by someone else.
fn apply_event(
    conn: &Connection,
    id: &Identity,
    s: &Secrets,
    authors: &Authors,
    e: &Event,
) -> Result<Option<Notice>> {
    let author = authors.get(&e.author_device_id, e.seq)?;
    let ct = B64.decode(&e.ciphertext)?;
    let msg = protocol::event_message(&id.group_id, &e.author_device_id, &e.kind, e.key_version, &ct);
    crypto::verify(&author.sign_pk, &msg, &B64.decode(&e.signature)?).context("bad author signature")?;
    let gk = secrets::group_key(conn, s, e.key_version)?.with_context(|| format!("no group key v{}", e.key_version))?;
    let plain = crypto::decrypt(&gk, &ct, &protocol::event_ad(&id.group_id, &e.kind)).context("can't decrypt")?;
    let event_id = crypto::event_id(&ct);
    let member = &author.member_id;
    let by_other = *member != id.member_id;
    // Posts and notifications use the certified name: a name chosen in a
    // profile counts only once a Key Master accepts it (re-signs the certificate).
    let author_name = || author.display_name.clone();
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
            store_photo_refs(conn, &event_id, None, e.key_version, &body.photos)?;
            Ok((inserted > 0 && by_other).then(|| Notice {
                post_id: event_id.clone(),
                author: author_name(),
                text: snippet(&body.text, body.photos.len()),
                comment: false,
                notify: true,
            }))
        }
        "comment" => {
            let b: RefBody = serde_json::from_slice(&plain).context("bad comment payload")?;
            if (b.text.trim().is_empty() && b.photos.is_empty()) || b.text.len() > MAX_TEXT || b.photos.len() > MAX_PHOTOS {
                bail!("empty or oversized comment");
            }
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO comments (id, seq, post_id, author_id, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![event_id, e.seq, b.post, member, b.text, e.created_at],
            )?;
            let photos = &b.photos[..b.photos.len().min(MAX_COMMENT_PHOTOS)];
            store_photo_refs(conn, &b.post, Some(&event_id), e.key_version, photos)?;
            if inserted == 0 || !by_other {
                return Ok(None);
            }
            let post_author: Option<String> = conn
                .query_row("SELECT author_id FROM posts WHERE id = ?1 AND deleted = 0", params![b.post], |r| r.get(0))
                .optional()?;
            Ok(Some(Notice {
                post_id: b.post.clone(),
                author: author_name(),
                text: snippet(&b.text, photos.len()),
                comment: true,
                notify: post_author.as_deref() == Some(id.member_id.as_str()),
            }))
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
            Ok(None)
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
            Ok(None)
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
            Ok(None)
        }
        "profile" => {
            crate::profile::apply(conn, member, e.seq, e.key_version, &plain)?;
            Ok(None)
        }
        other => bail!("unknown event kind {other}"),
    }
}

/// Record a post's or comment's photos for download, skipping unusable references.
fn store_photo_refs(conn: &Connection, post_id: &str, comment_id: Option<&str>, key_version: u32, photos: &[PhotoRef]) -> Result<()> {
    for (i, p) in photos.iter().enumerate() {
        let (Ok(fd), Ok(td)) = (account::decode32(&p.full_digest), account::decode32(&p.thumb_digest)) else {
            continue;
        };
        if !safe_media_id(&p.full) || !safe_media_id(&p.thumb) || p.width == 0 || p.height == 0 {
            continue;
        }
        conn.execute(
            "INSERT OR IGNORE INTO media (id, post_id, comment_id, idx, key_version, width, height, full_digest, thumb_id, thumb_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![p.full, post_id, comment_id, i as i64, key_version, p.width, p.height, &fd[..], p.thumb, &td[..]],
        )?;
    }
    Ok(())
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

pub fn write_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
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
pub async fn send_event(app: &App, kind: &str, body: &serde_json::Value, gk: &GroupKey, media_ids: Vec<String>) -> Result<String> {
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

pub fn latest_key(app: &App, id: &Identity) -> Result<GroupKey> {
    let s = app.secrets(id)?;
    secrets::latest_group_key(&app.db(), &s)
}

/// What `publish_once` returns: the event id, the key it used, its photo
/// references and the digests of the encrypted blobs.
type Posted = (String, GroupKey, Vec<PhotoRef>, Vec<([u8; 32], [u8; 32])>);

/// Upload the photos, then send a post or comment carrying them, under the latest key.
async fn publish_once(app: &App, id: &Identity, kind: &str, body: &serde_json::Value, photos: &[crate::photo::Processed]) -> Result<Posted> {
    let gk = latest_key(app, id)?;
    let api = app.api(id)?;
    let ad = protocol::media_ad(&id.group_id);
    let mut refs = Vec::new();
    let mut local = Vec::new();
    for p in photos {
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
    let mut body = body.clone();
    if !refs.is_empty() {
        body["photos"] = serde_json::to_value(&refs)?;
    }
    let media_ids = refs.iter().flat_map(|r| [r.full.clone(), r.thumb.clone()]).collect();
    let event_id = send_event(app, kind, &body, &gk, media_ids).await?;
    Ok((event_id, gk, refs, local))
}

/// Send a comment, reaction or delete under the latest key. If the relay says
/// a newer key exists (a rotation not picked up yet), fetch it and try again.
async fn send_fresh(app: &App, kind: &str, body: &serde_json::Value) -> Result<String> {
    let id = app.require_active()?;
    match send_event(app, kind, body, &latest_key(app, &id)?, vec![]).await {
        Err(e) if is_stale_key(&e) => {
            manage::refresh_keys_now(app).await?;
            send_event(app, kind, body, &latest_key(app, &id)?, vec![]).await
        }
        r => r,
    }
}

/// The staged photos with these ids, in order.
fn take_staged(app: &App, staged: &[String]) -> Result<Vec<crate::photo::Processed>> {
    let map = app.staged.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(missing) = staged.iter().find(|k| !map.contains_key(*k)) {
        bail!("photo {missing} is no longer attached; add it again");
    }
    Ok(staged.iter().map(|k| map.get(k).expect("checked").clone()).collect())
}

/// Send a post (`post_id` None) or a comment on `post_id` with staged photos,
/// keep the plaintext photos locally, and sync.
async fn publish(app: &App, kind: &str, body: serde_json::Value, staged: &[String], post_id: Option<&str>) -> Result<()> {
    let id = app.require_active()?;
    let photos = take_staged(app, staged)?;
    let (event_id, gk, refs, local) = match publish_once(app, &id, kind, &body, &photos).await {
        // A rotation we hadn't picked up: get the new key and redo it (the
        // first uploads become orphans, which the relay prunes after a day).
        Err(e) if is_stale_key(&e) => {
            manage::refresh_keys_now(app).await?;
            publish_once(app, &id, kind, &body, &photos).await?
        }
        r => r?,
    };
    let (owner, comment_id) = match post_id {
        Some(post) => (post, Some(event_id.as_str())),
        None => (event_id.as_str(), None),
    };

    // We already have the plaintext photos: keep them, so sync doesn't download them back.
    for (i, (p, r)) in photos.iter().zip(&refs).enumerate() {
        let (full_name, thumb_name) = (format!("{}.webp", r.full), format!("{}.webp", r.thumb));
        write_file(&app.media_dir.join(&full_name), &p.full)?;
        write_file(&app.media_dir.join(&thumb_name), &p.thumb)?;
        let (fd, td) = local[i];
        app.db().execute(
            "INSERT OR IGNORE INTO media (id, post_id, comment_id, idx, key_version, width, height, full_digest, thumb_id, thumb_digest, local_path, thumb_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![r.full, owner, comment_id, i as i64, gk.version(), r.width, r.height, &fd[..], r.thumb, &td[..], full_name, thumb_name],
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

pub async fn create_post(app: &App, text: &str, staged: &[String]) -> Result<()> {
    let text = text.trim();
    if text.len() > MAX_TEXT {
        bail!("that post is too long");
    }
    if staged.len() > MAX_PHOTOS {
        bail!("at most {MAX_PHOTOS} photos per post");
    }
    if text.is_empty() && staged.is_empty() {
        bail!("write something or add a photo");
    }
    publish(app, "post", serde_json::json!({ "text": text }), staged, None).await
}

fn require_post(app: &App, post_id: &str) -> Result<String> {
    app.db()
        .query_row("SELECT author_id FROM posts WHERE id = ?1 AND deleted = 0", params![post_id], |r| r.get(0))
        .optional()?
        .context("that post isn't in this app's archive")
}

pub async fn add_comment(app: &App, post_id: &str, text: &str, staged: &[String]) -> Result<()> {
    app.require_active()?;
    let text = text.trim();
    if (text.is_empty() && staged.is_empty()) || text.len() > MAX_TEXT {
        bail!("write a comment first");
    }
    if staged.len() > MAX_COMMENT_PHOTOS {
        bail!("at most {MAX_COMMENT_PHOTOS} photos per comment");
    }
    require_post(app, post_id)?;
    publish(app, "comment", serde_json::json!({ "post": post_id, "text": text }), staged, Some(post_id)).await
}

pub async fn set_reaction(app: &App, post_id: &str, emoji: &str) -> Result<()> {
    app.require_active()?;
    if !emoji.is_empty() && !valid_emoji(emoji) {
        bail!("not an emoji");
    }
    require_post(app, post_id)?;
    send_fresh(app, "reaction", &serde_json::json!({ "post": post_id, "emoji": emoji })).await?;
    sync_once(app).await?;
    Ok(())
}

pub async fn delete_post(app: &App, post_id: &str) -> Result<()> {
    let id = app.require_active()?;
    if require_post(app, post_id)? != id.member_id {
        bail!("you can only delete your own posts");
    }
    send_fresh(app, "delete", &serde_json::json!({ "post": post_id })).await?;
    sync_once(app).await?;
    Ok(())
}

// --- reading the archive ----------------------------------------------------------

#[derive(Serialize)]
pub struct PostView {
    pub id: String,
    pub seq: i64,
    pub author: String,
    pub author_avatar: Option<String>,
    pub author_keymaster: bool,
    /// Key Masters only: a name the author chose that no Key Master has accepted yet.
    pub author_pending_name: Option<String>,
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
    pub author_avatar: Option<String>,
    pub mine: bool,
    pub text: String,
    pub created_at: i64,
    pub photos: Vec<PhotoView>,
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
/// Names are the certified ones; `keymaster` adds names waiting for acceptance.
pub fn feed(conn: &Connection, me: &str, keymaster: bool, before: Option<i64>, limit: i64) -> Result<Vec<PostView>> {
    let mut st = conn.prepare(
        "SELECT p.id, p.seq, p.author_id, COALESCE(m.display_name, ?1), COALESCE(m.role, 'member'), p.body,
                p.created_at, p.edited_at IS NOT NULL, pr.avatar_path,
                CASE WHEN pr.display_name IS NOT m.display_name THEN pr.display_name END
         FROM posts p LEFT JOIN members m ON m.id = p.author_id LEFT JOIN profiles pr ON pr.member_id = p.author_id
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
            author_avatar: r.get::<_, Option<String>>(8)?.as_deref().map(media_url),
            author_keymaster: role == Role::Keymaster.as_str(),
            author_pending_name: if keymaster { r.get(9)? } else { None },
            text: r.get(5)?,
            created_at: r.get(6)?,
            edited: r.get(7)?,
            photos: vec![],
            comments: vec![],
            reactions: vec![],
        })
    })?;
    let mut posts: Vec<PostView> = rows.collect::<rusqlite::Result<_>>()?;

    let mut photos =
        conn.prepare("SELECT thumb_path, local_path, width, height FROM media WHERE post_id = ?1 AND comment_id IS NULL ORDER BY idx")?;
    let mut comment_photos =
        conn.prepare("SELECT thumb_path, local_path, width, height FROM media WHERE comment_id = ?1 ORDER BY idx")?;
    let photo_view = |r: &rusqlite::Row| -> rusqlite::Result<PhotoView> {
        let thumb: Option<String> = r.get(0)?;
        let full: Option<String> = r.get(1)?;
        Ok(PhotoView {
            thumb: thumb.as_deref().map(media_url),
            full: full.as_deref().map(media_url),
            width: r.get(2)?,
            height: r.get(3)?,
        })
    };
    let mut comments = conn.prepare(
        "SELECT c.id, c.author_id, COALESCE(m.display_name, ?2), c.body, c.created_at, pr.avatar_path
         FROM comments c LEFT JOIN members m ON m.id = c.author_id LEFT JOIN profiles pr ON pr.member_id = c.author_id
         WHERE c.post_id = ?1 ORDER BY c.seq",
    )?;
    let mut reactions = conn.prepare(
        "SELECT r.emoji, r.author_id, COALESCE(m.display_name, ?2) FROM reactions r
         LEFT JOIN members m ON m.id = r.author_id
         WHERE r.post_id = ?1 ORDER BY r.seq",
    )?;
    for p in &mut posts {
        p.photos = photos.query_map(params![p.id], photo_view)?.collect::<rusqlite::Result<_>>()?;
        p.comments = comments
            .query_map(params![p.id, UNKNOWN], |r| {
                let author_id: String = r.get(1)?;
                Ok(CommentView {
                    id: r.get(0)?,
                    mine: author_id == me,
                    author: r.get(2)?,
                    author_avatar: r.get::<_, Option<String>>(5)?.as_deref().map(media_url),
                    text: r.get(3)?,
                    created_at: r.get(4)?,
                    photos: vec![],
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        for c in &mut p.comments {
            c.photos = comment_photos.query_map(params![c.id], photo_view)?.collect::<rusqlite::Result<_>>()?;
        }
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
        authors: Authors,
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
        Fixture { conn, id, s, gk, authors: Authors { current: authors, former: BTreeMap::new() }, ana, seq: 0 }
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
        fn apply(&self, e: &Event) -> Result<Option<Notice>> {
            apply_event(&self.conn, &self.id, &self.s, &self.authors, e)
        }
    }

    #[test]
    fn cli_style_post_comment_reaction_edit_delete() {
        let mut f = fixture();
        let (post, pid) = f.event("post", serde_json::json!({ "text": "hello" }));
        let n = f.apply(&post).unwrap().unwrap();
        assert_eq!((n.author.as_str(), n.text.as_str(), n.comment, n.notify), ("Ana", "hello", false, true));
        // Replaying the same event is harmless.
        assert!(f.apply(&post).unwrap().is_none());
        let (c, _) = f.event("comment", serde_json::json!({ "post": pid, "text": "first!" }));
        // A comment on someone else's post counts as unread but doesn't notify.
        let n = f.apply(&c).unwrap().unwrap();
        assert!(n.comment && !n.notify && n.post_id == pid);
        let (r1, _) = f.event("reaction", serde_json::json!({ "post": pid, "emoji": "👍" }));
        let (r2, _) = f.event("reaction", serde_json::json!({ "post": pid, "emoji": "❤️" }));
        f.apply(&r2).unwrap();
        f.apply(&r1).unwrap(); // older reaction arriving late doesn't win
        let (ed, _) = f.event("edit", serde_json::json!({ "post": pid, "text": "hello, edited" }));
        f.apply(&ed).unwrap();

        let view = feed(&f.conn, "m_me", false, None, 50).unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].author, "Ana");
        assert_eq!(view[0].text, "hello, edited");
        assert!(view[0].edited);
        assert_eq!(view[0].comments[0].text, "first!");
        assert_eq!(view[0].reactions.len(), 1);
        assert_eq!(view[0].reactions[0].emoji, "❤️");

        let (del, _) = f.event("delete", serde_json::json!({ "post": pid }));
        f.apply(&del).unwrap();
        assert!(feed(&f.conn, "m_me", false, None, 50).unwrap().is_empty());
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
        let view = feed(&f.conn, "m_me", false, None, 50).unwrap();
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
    fn comments_on_my_posts_notify() {
        let mut f = fixture();
        f.conn
            .execute("INSERT INTO posts (id, seq, author_id, author_device_id, body, created_at) VALUES ('p_me', 0, 'm_me', 'd_me', 'mine', 1)", [])
            .unwrap();
        let (c, _) = f.event("comment", serde_json::json!({ "post": "p_me", "text": "  nice\n photo  " }));
        let n = f.apply(&c).unwrap().unwrap();
        assert_eq!(n, Notice { post_id: "p_me".into(), author: "Ana".into(), text: "nice photo".into(), comment: true, notify: true });
        let d = B64.encode([7u8; 32]);
        let photo = serde_json::json!({ "full": "f1", "full_digest": d, "thumb": "t1", "thumb_digest": d, "width": 1, "height": 1 });
        let (p, _) = f.event("post", serde_json::json!({ "text": "", "photos": [photo] }));
        assert_eq!(f.apply(&p).unwrap().unwrap().text, "shared a photo");
        assert_eq!(snippet(&"x".repeat(200), 0).chars().count(), 141);
    }

    #[test]
    fn comments_carry_photos_kept_apart_from_the_posts() {
        let mut f = fixture();
        let d = B64.encode([7u8; 32]);
        let photo = |n: u32| serde_json::json!({ "full": format!("cf{n}"), "full_digest": d, "thumb": format!("ct{n}"), "thumb_digest": d, "width": 4, "height": 3 });
        let (post, _) = f.event("post", serde_json::json!({ "text": "pics", "photos": [photo(0)] }));
        f.apply(&post).unwrap();
        let post_id = crypto::event_id(&B64.decode(&post.ciphertext).unwrap());

        // A photo-only comment is fine, and more than MAX_COMMENT_PHOTOS are cut.
        let six: Vec<_> = (1..=6).map(photo).collect();
        let (c, _) = f.event("comment", serde_json::json!({ "post": post_id, "text": "", "photos": six }));
        assert_eq!(f.apply(&c).unwrap().unwrap().text, format!("shared {MAX_COMMENT_PHOTOS} photos"));
        // Empty with no photos is still refused.
        let (empty, _) = f.event("comment", serde_json::json!({ "post": post_id, "text": " " }));
        assert!(f.apply(&empty).is_err());

        let posts = feed(&f.conn, "m_me", false, None, 10).unwrap();
        assert_eq!(posts[0].photos.len(), 1);
        assert_eq!(posts[0].comments.len(), 1);
        assert_eq!(posts[0].comments[0].photos.len(), MAX_COMMENT_PHOTOS);
    }

    #[test]
    fn removed_authors_count_only_up_to_their_cut_off() {
        let mut f = fixture();
        let (before, _) = f.event("post", serde_json::json!({ "text": "before I left" }));
        let (after, _) = f.event("post", serde_json::json!({ "text": "after" }));
        let ana = f.authors.current.remove("d_ana").unwrap();
        f.authors.former.insert("d_ana".into(), (ana, before.seq));
        assert!(f.apply(&before).unwrap().is_some());
        let err = f.apply(&after).unwrap_err();
        assert!(format!("{err}").contains("removed"), "{err}");
    }

    #[test]
    fn chosen_names_wait_for_a_key_master() {
        let mut f = fixture();
        // Ana renames herself "Mom": nobody sees it until a Key Master accepts it.
        let (pr, _) = f.event("profile", serde_json::json!({ "display_name": "Mom", "avatar": null }));
        assert!(f.apply(&pr).unwrap().is_none());
        let (post, pid) = f.event("post", serde_json::json!({ "text": "hi" }));
        assert_eq!(f.apply(&post).unwrap().unwrap().author, "Ana");
        let (c, _) = f.event("comment", serde_json::json!({ "post": pid, "text": "me again" }));
        f.apply(&c).unwrap();
        let view = feed(&f.conn, "m_me", false, None, 50).unwrap();
        assert_eq!(view[0].author, "Ana");
        assert_eq!(view[0].comments[0].author, "Ana");
        assert_eq!(view[0].author_pending_name, None);
        assert_eq!(view[0].author_avatar, None);
        // Key Masters see that a change is waiting.
        let view = feed(&f.conn, "m_me", true, None, 50).unwrap();
        assert_eq!(view[0].author, "Ana");
        assert_eq!(view[0].author_pending_name.as_deref(), Some("Mom"));
        // Once accepted, the certificate (and so the roster cache) carries it.
        f.conn.execute("UPDATE members SET display_name = 'Mom' WHERE id = 'm_ana'", []).unwrap();
        let view = feed(&f.conn, "m_me", true, None, 50).unwrap();
        assert_eq!((view[0].author.as_str(), view[0].author_pending_name.as_deref()), ("Mom", None));
        // A malformed profile event is rejected like any other bad event.
        let (bad, _) = f.event("profile", serde_json::json!({ "display_name": "" }));
        assert!(f.apply(&bad).is_err());
    }

    #[test]
    fn emoji_validation() {
        assert!(valid_emoji("👍"));
        assert!(valid_emoji("❤️"));
        assert!(!valid_emoji("lol"));
        assert!(!valid_emoji("👍👍👍👍👍👍👍👍👍"));
    }
}
