//! Direct messages (SPEC "Phase 5b: Direct messages"): one-to-one, text and
//! photos, end-to-end encrypted to the two people's devices only.
//!
//! Sending: a fresh message key encrypts the text and photos; it's sealed to
//! every device of the recipient and every other device of the sender, taken
//! from the *verified* roster (member certificates chaining to a pinned Key
//! Master), never from the server's word; the sending device signs it all
//! (`crypto::dm::seal_dm`). The relay checks the device list covers exactly
//! both members' active devices.
//!
//! Receiving: a message counts only if its sender device has a valid
//! certificate (or had one, for messages up to the seq it was removed at),
//! the signature over the whole recipient list verifies, this device is on
//! the list, and the conversation id is the one for the two members.
//!
//! Payload (JSON, encrypted with the message key, AD `protocol::dm_ad`):
//! `{"text", "photos"?: [{"full", "full_digest", "thumb", "thumb_digest", "width", "height"}]}`,
//! the same photo references as posts, but the blobs are encrypted with the
//! message key (AD `protocol::dm_media_ad`).

use crate::account::{self, CheckedRoster};
use crate::api::*;
use crate::db::{self, Identity};
use crate::feed::{self, media_url, safe_media_id, write_file, PhotoRef, PhotoView, MAX_PHOTOS, MAX_TEXT};
use crate::secrets::Secrets;
use crate::state::App;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sidetray_crypto::dm::{self as cdm, MessageKey};
use sidetray_crypto::roster::VerifiedDevice;
use sidetray_crypto::{self as crypto, protocol, DeviceKeys};
use std::collections::BTreeMap;

const MAX_PHOTO_ATTEMPTS: i64 = 5;
/// How many messages a chat screen loads (the newest).
const CHAT_LIMIT: i64 = 1000;
const UNKNOWN: &str = "Unknown member";

#[derive(Deserialize)]
struct DmBody {
    #[serde(default)]
    text: String,
    #[serde(default)]
    photos: Vec<PhotoRef>,
}

/// Who may send: verified devices now, and former ones for messages up to
/// the seq they were cut off at.
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
            Some(_) => bail!("sender device {device_id} had been removed by the time of this message"),
            None => bail!("sender device {device_id} has no valid member certificate"),
        }
    }
}

/// A new message from someone else, for the notification.
#[derive(Clone, Debug, PartialEq)]
pub struct DmNotice {
    pub member_id: String,
    pub author: String,
    pub text: String,
}

#[derive(Default)]
pub struct DmReport {
    pub new_messages: usize,
    pub rejected: usize,
    pub notices: Vec<DmNotice>,
}

// --- receiving -----------------------------------------------------------------------

/// Pull the direct messages sealed to this device, verify and store them, ack, fetch photos.
pub async fn sync(app: &App, id: &Identity, s: &Secrets, api: &Api, authors: &Authors) -> Result<DmReport> {
    let me = s.device_keys()?;
    let mut report = DmReport::default();
    loop {
        let after = db::dm_last_seq(&app.db())?;
        let page: DmPage = api.get(&format!("/dms?after={after}")).await?;
        {
            let conn = app.db();
            let tx = conn.unchecked_transaction()?;
            let mut rejected = 0;
            for m in &page.messages {
                match apply(&tx, id, s, &me, authors, m) {
                    Ok((inserted, notice)) => {
                        report.new_messages += usize::from(inserted);
                        report.notices.extend(notice);
                    }
                    Err(e) => {
                        rejected += 1;
                        eprintln!("direct message #{} rejected: {e:#}", m.seq);
                    }
                }
            }
            report.rejected += rejected;
            db::set_dm_last_seq(&tx, page.last_seq)?;
            tx.execute("UPDATE sync_state SET rejected = rejected + ?1 WHERE id = 1", params![rejected as i64])?;
            tx.commit()?;
        }
        if page.last_seq > after {
            let _: serde_json::Value = api.post("/dms/ack", &serde_json::json!({ "seq": page.last_seq })).await?;
        }
        if !page.has_more {
            break;
        }
    }
    download_photos(app, id, s, api).await;
    Ok(report)
}

/// Verify, decrypt and store one message. Returns whether it was new, and a
/// notice if it's from someone else.
fn apply(conn: &Connection, id: &Identity, s: &Secrets, me: &DeviceKeys, authors: &Authors, m: &Dm) -> Result<(bool, Option<DmNotice>)> {
    let sender = authors.get(&m.sender_device_id, m.seq)?;
    if sender.member_id != m.sender_member_id {
        bail!("the relay says it's from {}, but the device belongs to {}", m.sender_member_id, sender.member_id);
    }
    // From one of my own other devices: the other person is the recipient,
    // which the conversation id (signed) pins down.
    let from_me = sender.member_id == id.member_id;
    let other = if from_me { m.recipient_member_id.clone() } else { sender.member_id.clone() };
    if other == id.member_id || (!from_me && m.recipient_member_id != id.member_id) {
        bail!("not a conversation this member is part of");
    }
    let conv = cdm::conversation_id(&id.group_id, &id.member_id, &other);
    if conv != m.conversation_id {
        bail!("the conversation id isn't the one for these two members");
    }
    let ct = B64.decode(&m.ciphertext)?;
    let keys: Vec<(String, Vec<u8>)> =
        m.sealed_keys.iter().map(|k| Ok((k.device_id.clone(), B64.decode(&k.sealed_key)?))).collect::<Result<_>>()?;
    let sig = B64.decode(&m.signature)?;
    let (key, plain) = cdm::open_dm(me, &id.device_id, &id.group_id, &conv, &m.sender_device_id, &sender.sign_pk, &ct, &keys, &sig)
        .context("signature, recipient list or encryption doesn't check out")?;
    let body: DmBody = serde_json::from_slice(&plain).context("bad message payload")?;
    if body.text.len() > MAX_TEXT || body.photos.len() > MAX_PHOTOS || (body.text.trim().is_empty() && body.photos.is_empty()) {
        bail!("empty or oversized message");
    }
    let msg_id = crypto::event_id(&ct);
    let inserted = store(conn, s, &msg_id, m.seq, &conv, &sender.member_id, &m.sender_device_id, &body.text, m.created_at, &key)?;
    if !inserted {
        return Ok((false, None));
    }
    for (i, p) in body.photos.iter().enumerate() {
        let (Ok(fd), Ok(td)) = (account::decode32(&p.full_digest), account::decode32(&p.thumb_digest)) else { continue };
        if !safe_media_id(&p.full) || !safe_media_id(&p.thumb) || p.width == 0 || p.height == 0 {
            continue;
        }
        conn.execute(
            "INSERT OR IGNORE INTO dm_photos (id, message_id, idx, width, height, full_digest, thumb_id, thumb_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![p.full, msg_id, i as i64, p.width, p.height, &fd[..], p.thumb, &td[..]],
        )?;
    }
    let text = snippet(&body.text, body.photos.len());
    record(conn, &conv, &other, m.seq, m.created_at, &text, from_me, !from_me)?;
    Ok((true, (!from_me).then(|| DmNotice { member_id: other, author: sender.display_name.clone(), text })))
}

#[allow(clippy::too_many_arguments)]
fn store(
    conn: &Connection,
    s: &Secrets,
    msg_id: &str,
    seq: i64,
    conv: &str,
    sender_member: &str,
    sender_device: &str,
    text: &str,
    created_at: i64,
    key: &MessageKey,
) -> Result<bool> {
    let wrapped = s.wrap_message_key(msg_id, key)?;
    Ok(conn.execute(
        "INSERT OR IGNORE INTO dm_messages (id, seq, conversation_id, sender_member_id, sender_device_id, body, created_at, key_wrapped)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![msg_id, seq, conv, sender_member, sender_device, text, created_at, wrapped],
    )? > 0)
}

/// Keep the conversation list's last message (and unread count) up to date.
#[allow(clippy::too_many_arguments)]
fn record(conn: &Connection, conv: &str, other: &str, seq: i64, at: i64, text: &str, mine: bool, unread: bool) -> Result<()> {
    conn.execute(
        "INSERT INTO conversations (id, other_member_id) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
        params![conv, other],
    )?;
    conn.execute(
        "UPDATE conversations SET last_seq = ?2, last_at = ?3, last_text = ?4, last_mine = ?5 WHERE id = ?1 AND last_seq < ?2",
        params![conv, seq, at, text, mine],
    )?;
    if unread {
        conn.execute("UPDATE conversations SET unread = unread + 1 WHERE id = ?1", params![conv])?;
    }
    Ok(())
}

/// One line for the conversation list and notifications.
fn snippet(text: &str, photos: usize) -> String {
    let t = feed::snippet(text, 0);
    if !t.is_empty() {
        return t;
    }
    match photos {
        1 => "Photo".into(),
        n => format!("{n} photos"),
    }
}

/// (photo id, message id, conversation, wrapped key, full digest, thumb id, thumb digest, need full, need thumb)
type PhotoTodo = (String, String, String, Vec<u8>, Vec<u8>, String, Vec<u8>, bool, bool);

/// Fetch and decrypt message photos that aren't on disk yet.
async fn download_photos(app: &App, id: &Identity, s: &Secrets, api: &Api) {
    let todo: Vec<PhotoTodo> = {
        let conn = app.db();
        let rows = conn
            .prepare(
                "SELECT p.id, p.message_id, m.conversation_id, m.key_wrapped, p.full_digest, p.thumb_id, p.thumb_digest,
                        p.local_path IS NULL, p.thumb_path IS NULL
                 FROM dm_photos p JOIN dm_messages m ON m.id = p.message_id
                 WHERE (p.local_path IS NULL OR p.thumb_path IS NULL) AND p.attempts < ?1
                 ORDER BY m.seq DESC",
            )
            .and_then(|mut st| {
                st.query_map(params![MAX_PHOTO_ATTEMPTS], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
            });
        match rows {
            Ok(r) => r,
            Err(e) => return eprintln!("message photos: {e}"),
        }
    };
    for (photo, msg_id, conv, wrapped, full_digest, thumb_id, thumb_digest, need_full, need_thumb) in todo {
        let key = match s.unwrap_message_key(&msg_id, &wrapped) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("message photo {photo}: {e:#}");
                continue;
            }
        };
        let ad = protocol::dm_media_ad(&id.group_id, &conv);
        let mut ok = true;
        if need_thumb {
            ok &= fetch_one(app, api, &key, &ad, &photo, &thumb_id, &thumb_digest, true).await;
        }
        if need_full {
            ok &= fetch_one(app, api, &key, &ad, &photo, &photo, &full_digest, false).await;
        }
        if !ok {
            let _ = app.db().execute("UPDATE dm_photos SET attempts = attempts + 1 WHERE id = ?1", params![photo]);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_one(app: &App, api: &Api, key: &MessageKey, ad: &[u8], row: &str, media_id: &str, digest: &[u8], thumb: bool) -> bool {
    let result: Result<()> = async {
        let blob = api.download_media(media_id).await?;
        // The signed message recorded each blob's digest, so the server can't swap photos.
        if crypto::blob_digest(&blob)[..] != *digest {
            bail!("photo {media_id} doesn't match the digest in its message");
        }
        let plain = key.decrypt(&blob, ad).context("can't decrypt photo")?;
        let name = format!("{media_id}.webp");
        write_file(&app.media_dir.join(&name), &plain)?;
        let sql = if thumb {
            "UPDATE dm_photos SET thumb_path = ?1 WHERE id = ?2"
        } else {
            "UPDATE dm_photos SET local_path = ?1 WHERE id = ?2"
        };
        app.db().execute(sql, params![name, row])?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => true,
        Err(e) => {
            eprintln!("message photo {media_id}: {e:#}");
            false
        }
    }
}

// --- sending -------------------------------------------------------------------------

/// Every device the message key must be sealed to: all of the recipient's,
/// and this member's other devices, each from the verified roster. Refuses
/// if any of them has no valid certificate (the relay would insist on it, and
/// sealing to an unverified key could hand the message to an impostor).
fn recipients_for(id: &Identity, roster: &CheckedRoster, member_id: &str) -> Result<Vec<(String, [u8; 32])>> {
    if member_id == id.member_id {
        bail!("pick someone else to message");
    }
    let them = roster.raw.members.iter().find(|m| m.id == member_id).context("that person isn't in the group any more")?;
    let name = them
        .devices
        .iter()
        .find_map(|d| roster.verified.get(&d.id).map(|v| v.display_name.clone()))
        .unwrap_or_else(|| "they".into());
    let mut out = Vec::new();
    for d in &them.devices {
        let v = roster
            .verified
            .get(&d.id)
            .filter(|v| v.member_id == member_id)
            .with_context(|| format!("{name} has a device without a valid certificate, so the app won't send to it; ask a Key Master"))?;
        out.push((d.id.clone(), v.enc_pk));
    }
    if out.is_empty() {
        bail!("{name} has no devices that can receive messages");
    }
    if let Some(mine) = roster.raw.members.iter().find(|m| m.id == id.member_id) {
        for d in mine.devices.iter().filter(|d| d.id != id.device_id) {
            let v = roster.verified.get(&d.id).filter(|v| v.member_id == id.member_id).with_context(|| {
                format!("your device {} has no valid certificate, so the app won't send to it; ask a Key Master", d.id)
            })?;
            out.push((d.id.clone(), v.enc_pk));
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct SeqResp {
    seq: i64,
}

/// Send a message to `member_id` with text and photos already staged (and
/// resized, EXIF stripped) by `stage_photo`.
pub async fn send(app: &App, member_id: &str, text: &str, staged: &[String]) -> Result<()> {
    let id = app.require_active()?;
    let text = text.trim();
    if text.len() > MAX_TEXT {
        bail!("that message is too long");
    }
    if staged.len() > MAX_PHOTOS {
        bail!("at most {MAX_PHOTOS} photos per message");
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
    match send_once(app, &id, member_id, text, &photos).await {
        // Someone's devices changed between our roster refresh and the send: once more.
        Err(e) if is_status(&e, 422) && format!("{e:#}").contains("sealed to exactly") => {
            send_once(app, &id, member_id, text, &photos).await?
        }
        r => r?,
    }
    let mut map = app.staged.lock().unwrap_or_else(|e| e.into_inner());
    for k in staged {
        map.remove(k);
    }
    Ok(())
}

async fn send_once(app: &App, id: &Identity, member_id: &str, text: &str, photos: &[crate::photo::Processed]) -> Result<()> {
    let api = app.api(id)?;
    let s = app.secrets(id)?;
    let me = s.device_keys()?;
    let roster = account::refresh_roster(app, id, &api).await?;
    let recipients = recipients_for(id, &roster, member_id)?;
    let conv = cdm::conversation_id(&id.group_id, &id.member_id, member_id);
    let key = MessageKey::generate();
    let ad = protocol::dm_media_ad(&id.group_id, &conv);
    let mut refs = Vec::new();
    let mut digests = Vec::new();
    for p in photos {
        let (enc_full, enc_thumb) = (key.encrypt(&p.full, &ad), key.encrypt(&p.thumb, &ad));
        let (fd, td) = (crypto::blob_digest(&enc_full), crypto::blob_digest(&enc_thumb));
        let full_id = api.upload_media(enc_full).await?;
        let thumb_id = api.upload_media(enc_thumb).await?;
        if !safe_media_id(&full_id) || !safe_media_id(&thumb_id) {
            bail!("the server returned an unusable media id");
        }
        refs.push(PhotoRef { full: full_id, full_digest: B64.encode(fd), thumb: thumb_id, thumb_digest: B64.encode(td), width: p.width, height: p.height });
        digests.push((fd, td));
    }
    let mut body = serde_json::json!({ "text": text });
    if !refs.is_empty() {
        body["photos"] = serde_json::to_value(&refs)?;
    }
    let plain = serde_json::to_vec(&body)?;
    let sealed = cdm::seal_dm(&me, &id.group_id, &conv, &id.device_id, &key, &plain, &recipients)?;
    let resp: SeqResp = api
        .post(
            "/dms",
            &DmReq {
                conversation_id: &conv,
                recipient_member_id: member_id,
                ciphertext: B64.encode(&sealed.ciphertext),
                signature: B64.encode(sealed.signature),
                media_ids: refs.iter().flat_map(|r| [r.full.clone(), r.thumb.clone()]).collect(),
                sealed_keys: sealed.sealed_keys.iter().map(|(d, k)| DmKey { device_id: d.clone(), sealed_key: B64.encode(k) }).collect(),
            },
        )
        .await?;

    // Keep our own copy: the relay never sends a message back to the device that wrote it.
    let msg_id = crypto::event_id(&sealed.ciphertext);
    for (p, r) in photos.iter().zip(&refs) {
        write_file(&app.media_dir.join(format!("{}.webp", r.full)), &p.full)?;
        write_file(&app.media_dir.join(format!("{}.webp", r.thumb)), &p.thumb)?;
    }
    let conn = app.db();
    let tx = conn.unchecked_transaction()?;
    store(&tx, &s, &msg_id, resp.seq, &conv, &id.member_id, &id.device_id, text, crate::now(), &key)?;
    for (i, (r, (fd, td))) in refs.iter().zip(&digests).enumerate() {
        tx.execute(
            "INSERT OR IGNORE INTO dm_photos (id, message_id, idx, width, height, full_digest, thumb_id, thumb_digest, local_path, thumb_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![r.full, msg_id, i as i64, r.width, r.height, &fd[..], r.thumb, &td[..], format!("{}.webp", r.full), format!("{}.webp", r.thumb)],
        )?;
    }
    record(&tx, &conv, member_id, resp.seq, crate::now(), &snippet(text, photos.len()), true, false)?;
    tx.commit()?;
    Ok(())
}

// --- reading -------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ConversationView {
    pub member_id: String,
    pub name: String,
    pub avatar: Option<String>,
    pub last_text: String,
    pub last_at: i64,
    pub last_mine: bool,
    pub unread: i64,
    /// They're still a verified member, so new messages can go to them.
    pub can_message: bool,
}

/// Every conversation, newest first. Names are the certified ones.
pub fn conversations(conn: &Connection) -> Result<Vec<ConversationView>> {
    let mut st = conn.prepare(
        "SELECT c.other_member_id, COALESCE(m.display_name, ?1), pr.avatar_path, c.last_text, c.last_at, c.last_mine, c.unread,
                EXISTS (SELECT 1 FROM member_devices d WHERE d.member_id = c.other_member_id AND d.verified = 1)
         FROM conversations c LEFT JOIN members m ON m.id = c.other_member_id
         LEFT JOIN profiles pr ON pr.member_id = c.other_member_id
         ORDER BY c.last_at DESC",
    )?;
    let rows = st.query_map(params![UNKNOWN], |r| {
        Ok(ConversationView {
            member_id: r.get(0)?,
            name: r.get(1)?,
            avatar: r.get::<_, Option<String>>(2)?.as_deref().map(media_url),
            last_text: r.get(3)?,
            last_at: r.get(4)?,
            last_mine: r.get(5)?,
            unread: r.get(6)?,
            can_message: r.get(7)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[derive(Serialize)]
pub struct ChatView {
    pub member_id: String,
    pub name: String,
    pub avatar: Option<String>,
    pub can_message: bool,
    pub messages: Vec<MessageView>,
}

#[derive(Serialize)]
pub struct MessageView {
    pub id: String,
    pub seq: i64,
    pub mine: bool,
    pub text: String,
    pub created_at: i64,
    pub photos: Vec<PhotoView>,
}

/// The conversation with one member, oldest first (it may not have started yet).
pub fn chat(conn: &Connection, id: &Identity, member_id: &str) -> Result<ChatView> {
    let conv = cdm::conversation_id(&id.group_id, &id.member_id, member_id);
    let (name, avatar, can_message): (String, Option<String>, bool) = conn.query_row(
        "SELECT COALESCE((SELECT display_name FROM members WHERE id = ?1), ?2),
                (SELECT avatar_path FROM profiles WHERE member_id = ?1),
                EXISTS (SELECT 1 FROM member_devices WHERE member_id = ?1 AND verified = 1)",
        params![member_id, UNKNOWN],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let mut st = conn.prepare(
        "SELECT id, seq, sender_member_id, body, created_at FROM
           (SELECT * FROM dm_messages WHERE conversation_id = ?1 ORDER BY seq DESC LIMIT ?2)
         ORDER BY seq",
    )?;
    let mut messages: Vec<MessageView> = st
        .query_map(params![conv, CHAT_LIMIT], |r| {
            let sender: String = r.get(2)?;
            Ok(MessageView { id: r.get(0)?, seq: r.get(1)?, mine: sender == id.member_id, text: r.get(3)?, created_at: r.get(4)?, photos: vec![] })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut photos = conn.prepare("SELECT thumb_path, local_path, width, height FROM dm_photos WHERE message_id = ?1 ORDER BY idx")?;
    for m in &mut messages {
        m.photos = photos
            .query_map(params![m.id], |r| {
                Ok(PhotoView {
                    thumb: r.get::<_, Option<String>>(0)?.as_deref().map(media_url),
                    full: r.get::<_, Option<String>>(1)?.as_deref().map(media_url),
                    width: r.get(2)?,
                    height: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
    }
    Ok(ChatView { member_id: member_id.to_string(), name, avatar: avatar.as_deref().map(media_url), can_message, messages })
}

/// The conversation with this member was looked at.
pub fn mark_read(conn: &Connection, member_id: &str) -> Result<()> {
    conn.execute("UPDATE conversations SET unread = 0 WHERE other_member_id = ?1", params![member_id])?;
    Ok(())
}

#[derive(Serialize)]
pub struct Recipient {
    pub member_id: String,
    pub name: String,
    pub avatar: Option<String>,
}

/// Who can be messaged: verified members other than me (from the cached roster).
pub fn recipients(conn: &Connection, me: &str) -> Result<Vec<Recipient>> {
    let mut st = conn.prepare(
        "SELECT m.id, m.display_name, pr.avatar_path FROM members m LEFT JOIN profiles pr ON pr.member_id = m.id
         WHERE m.id != ?1 AND EXISTS (SELECT 1 FROM member_devices d WHERE d.member_id = m.id AND d.verified = 1)
         ORDER BY m.display_name COLLATE NOCASE",
    )?;
    let rows = st.query_map(params![me], |r| {
        Ok(Recipient { member_id: r.get(0)?, name: r.get(1)?, avatar: r.get::<_, Option<String>>(2)?.as_deref().map(media_url) })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidetray_crypto::roster::Role;

    struct Fixture {
        conn: Connection,
        id: Identity,
        s: Secrets,
        me: DeviceKeys,
        ana: DeviceKeys,
        authors: Authors,
        seq: i64,
    }

    fn verified(member: &str, device: &str, name: &str, k: &DeviceKeys) -> VerifiedDevice {
        VerifiedDevice {
            member_id: member.into(),
            device_id: device.into(),
            display_name: name.into(),
            role: Role::Member,
            enc_pk: k.public().enc,
            sign_pk: k.public().sign,
            issuer_device_id: "d_km".into(),
        }
    }

    fn fixture() -> Fixture {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let me = crypto::generate_device_keys();
        let p = me.public();
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
        let s = Secrets::new("tok", &me);
        let ana = crypto::generate_device_keys();
        let mut authors = Authors::default();
        authors.current.insert("d_ana".into(), verified("m_ana", "d_ana", "Ana", &ana));
        conn.execute("INSERT INTO members (id, display_name, role) VALUES ('m_ana', 'Ana', 'member')", []).unwrap();
        conn.execute(
            "INSERT INTO member_devices (device_id, member_id, sign_pubkey, enc_pubkey) VALUES ('d_ana', 'm_ana', x'00', x'00')",
            [],
        )
        .unwrap();
        Fixture { conn, id, s, me, ana, authors, seq: 0 }
    }

    impl Fixture {
        /// A message from `from` (device id, keys, member) to `to`, sealed to `devices`.
        fn dm(&mut self, from: (&str, &DeviceKeys, &str), to: &str, devices: &[(&str, &DeviceKeys)], body: serde_json::Value) -> Dm {
            self.seq += 1;
            let conv = cdm::conversation_id("g_1", from.2, to);
            let recipients: Vec<(String, [u8; 32])> = devices.iter().map(|(d, k)| (d.to_string(), k.public().enc)).collect();
            let key = MessageKey::generate();
            let m = cdm::seal_dm(from.1, "g_1", &conv, from.0, &key, &serde_json::to_vec(&body).unwrap(), &recipients).unwrap();
            Dm {
                seq: self.seq,
                conversation_id: conv,
                sender_device_id: from.0.into(),
                sender_member_id: from.2.into(),
                recipient_member_id: to.into(),
                ciphertext: B64.encode(&m.ciphertext),
                signature: B64.encode(m.signature),
                created_at: 1000 + self.seq,
                sealed_keys: m.sealed_keys.iter().map(|(d, k)| DmKey { device_id: d.clone(), sealed_key: B64.encode(k) }).collect(),
            }
        }
        fn apply(&self, m: &Dm) -> Result<(bool, Option<DmNotice>)> {
            apply(&self.conn, &self.id, &self.s, &self.me, &self.authors, m)
        }
    }

    #[test]
    fn a_message_from_ana_lands_in_our_conversation() {
        let mut f = fixture();
        let ana = f.ana.clone_keys();
        let me = f.me.clone_keys();
        let m = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "  hi\nthere " }));
        let (new, notice) = f.apply(&m).unwrap();
        assert!(new);
        assert_eq!(notice, Some(DmNotice { member_id: "m_ana".into(), author: "Ana".into(), text: "hi there".into() }));
        // Replaying it changes nothing.
        assert_eq!(f.apply(&m).unwrap(), (false, None));
        let list = conversations(&f.conn).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].member_id.as_str(), list[0].name.as_str(), list[0].unread, list[0].can_message), ("m_ana", "Ana", 1, true));
        let chat = chat(&f.conn, &f.id, "m_ana").unwrap();
        assert_eq!(chat.messages.len(), 1);
        assert_eq!(chat.messages[0].text, "  hi\nthere ");
        assert!(!chat.messages[0].mine);
        mark_read(&f.conn, "m_ana").unwrap();
        assert_eq!(db::dm_unread(&f.conn).unwrap(), 0);
    }

    #[test]
    fn forged_misdirected_and_unknown_messages_are_rejected() {
        let mut f = fixture();
        let (ana, me) = (f.ana.clone_keys(), f.me.clone_keys());
        let mallory = crypto::generate_device_keys();
        // Unknown sender device.
        let m = f.dm(("d_mallory", &mallory, "m_mallory"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "hi" }));
        assert!(f.apply(&m).is_err());
        // The relay claims a verified device's message comes from someone else.
        let mut m = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "hi" }));
        m.sender_member_id = "m_bo".into();
        assert!(f.apply(&m).is_err());
        // Ana's message to Bo (sealed to us anyway): the conversation isn't ours.
        let m = f.dm(("d_ana", &ana, "m_ana"), "m_bo", &[("d_me", &me)], serde_json::json!({ "text": "hi" }));
        assert!(f.apply(&m).is_err());
        // Not sealed to this device.
        let m = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_other", &mallory)], serde_json::json!({ "text": "hi" }));
        assert!(f.apply(&m).is_err());
        // A recipient dropped by the relay breaks the signature.
        let mut m = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me), ("d_other", &mallory)], serde_json::json!({ "text": "hi" }));
        m.sealed_keys.retain(|k| k.device_id == "d_me");
        assert!(f.apply(&m).is_err());
        // Empty messages.
        let m = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "  " }));
        assert!(f.apply(&m).is_err());
        assert!(conversations(&f.conn).unwrap().is_empty());
    }

    #[test]
    fn my_other_devices_messages_show_as_mine() {
        let mut f = fixture();
        let me = f.me.clone_keys();
        let laptop = crypto::generate_device_keys();
        f.authors.current.insert("d_laptop".into(), verified("m_me", "d_laptop", "Me", &laptop));
        let ana = f.ana.clone_keys();
        let m = f.dm(("d_laptop", &laptop, "m_me"), "m_ana", &[("d_me", &me), ("d_ana", &ana)], serde_json::json!({ "text": "from my laptop" }));
        let (new, notice) = f.apply(&m).unwrap();
        assert!(new && notice.is_none());
        let list = conversations(&f.conn).unwrap();
        assert_eq!((list[0].member_id.as_str(), list[0].unread, list[0].last_mine), ("m_ana", 0, true));
        assert!(chat(&f.conn, &f.id, "m_ana").unwrap().messages[0].mine);
    }

    #[test]
    fn removed_senders_count_up_to_their_cut_off() {
        let mut f = fixture();
        let (ana, me) = (f.ana.clone_keys(), f.me.clone_keys());
        let before = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "before" }));
        let after = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "after" }));
        let v = f.authors.current.remove("d_ana").unwrap();
        f.authors.former.insert("d_ana".into(), (v, before.seq));
        assert!(f.apply(&before).unwrap().0);
        assert!(format!("{:#}", f.apply(&after).unwrap_err()).contains("removed"));
        // Their old messages stay readable; they just can't be messaged any more.
        f.conn.execute("UPDATE member_devices SET verified = 0", []).unwrap();
        let c = chat(&f.conn, &f.id, "m_ana").unwrap();
        assert_eq!((c.messages.len(), c.can_message), (1, false));
        assert!(recipients(&f.conn, "m_me").unwrap().is_empty());
    }

    #[test]
    fn photo_references_are_stored_safely() {
        let mut f = fixture();
        let (ana, me) = (f.ana.clone_keys(), f.me.clone_keys());
        let d = B64.encode([7u8; 32]);
        let photos = serde_json::json!([
            { "full": "ok_full", "full_digest": d, "thumb": "ok_thumb", "thumb_digest": d, "width": 10, "height": 10 },
            { "full": "../../evil", "full_digest": d, "thumb": "t", "thumb_digest": d, "width": 10, "height": 10 }
        ]);
        let m = f.dm(("d_ana", &ana, "m_ana"), "m_me", &[("d_me", &me)], serde_json::json!({ "text": "", "photos": photos }));
        let (_, notice) = f.apply(&m).unwrap();
        assert_eq!(notice.unwrap().text, "2 photos");
        let n: i64 = f.conn.query_row("SELECT COUNT(*) FROM dm_photos", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        // The wrapped key comes back, so the photo can be fetched later.
        let (id, wrapped): (String, Vec<u8>) =
            f.conn.query_row("SELECT id, key_wrapped FROM dm_messages", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert!(f.s.unwrap_message_key(&id, &wrapped).is_ok());
        assert!(f.s.unwrap_message_key("another", &wrapped).is_err());
    }

    #[test]
    fn recipients_need_verified_devices_on_both_sides() {
        let f = fixture();
        let raw_member = |id: &str, devices: &[&str]| crate::api::Member {
            id: id.into(),
            display_name: id.into(),
            devices: devices
                .iter()
                .map(|d| crate::api::MemberDevice {
                    id: d.to_string(),
                    enc_pubkey: String::new(),
                    sign_pubkey: String::new(),
                    certs: vec![],
                    last_seen: None,
                    joined_at: None,
                    revoked_seq: None,
                    revoked_dm_seq: None,
                })
                .collect(),
        };
        let laptop = crypto::generate_device_keys();
        let mut verified_map = f.authors.current.clone();
        verified_map.insert("d_laptop".into(), verified("m_me", "d_laptop", "Me", &laptop));
        let roster = CheckedRoster {
            raw: crate::api::Roster { members: vec![raw_member("m_me", &["d_me", "d_laptop"]), raw_member("m_ana", &["d_ana"])], former: vec![] },
            verified: verified_map.clone(),
            former: BTreeMap::new(),
            former_dm: BTreeMap::new(),
        };
        let mut got: Vec<String> = recipients_for(&f.id, &roster, "m_ana").unwrap().into_iter().map(|(d, _)| d).collect();
        got.sort();
        assert_eq!(got, vec!["d_ana", "d_laptop"]);
        assert!(recipients_for(&f.id, &roster, "m_me").is_err());
        assert!(recipients_for(&f.id, &roster, "m_gone").is_err());
        // One of Ana's devices doesn't verify: refuse rather than seal to it.
        let roster = CheckedRoster {
            raw: crate::api::Roster { members: vec![raw_member("m_me", &["d_me"]), raw_member("m_ana", &["d_ana", "d_ana_new"])], former: vec![] },
            verified: verified_map,
            former: BTreeMap::new(),
            former_dm: BTreeMap::new(),
        };
        assert!(format!("{:#}", recipients_for(&f.id, &roster, "m_ana").unwrap_err()).contains("valid certificate"));
    }

    trait CloneKeys {
        fn clone_keys(&self) -> DeviceKeys;
    }
    impl CloneKeys for DeviceKeys {
        fn clone_keys(&self) -> DeviceKeys {
            DeviceKeys::from_secret_bytes(&self.enc_secret_bytes(), &self.sign_secret_bytes())
        }
    }
}
