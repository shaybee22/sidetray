//! Avatars and display names (SPEC "Avatars and display names").
//!
//! A `profile` event (signed and encrypted like any other) carries a member's
//! whole profile: `{"display_name"?, "avatar": {"id", "digest"} | null}`.
//! The latest valid one per member wins outright, which is also all the relay
//! keeps once older ones are pruned, so every event states both fields. No
//! `display_name` means the name in the member's certificate.
//!
//! A chosen name is only a request: everyone keeps seeing the certified name
//! until a Key Master accepts the new one (which re-signs the member's
//! certificates with it), so nobody can rename themselves "Mom" to fool
//! people. Key Masters see that a change is pending. Avatars apply at once.
//!
//! The avatar is a 256x256 WebP, cropped in the app, encrypted with the group
//! key (AD `protocol::media_ad`) and uploaded like a photo; `digest` is the
//! `blob_digest` of the encrypted blob, checked before decrypting. Until it's
//! downloaded and checked (or if it fails), initials stand in.

use crate::api::Api;
use crate::db::Identity;
use crate::feed::{self, safe_media_id, write_file};
use crate::secrets::{self, Secrets};
use crate::state::App;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sidetray_crypto::{self as crypto, protocol};

pub const AVATAR_SIDE: u32 = 256;
const AVATAR_QUALITY: f32 = 85.0;
const MAX_NAME: usize = 100;
const MAX_ATTEMPTS: i64 = 5;
/// The cropped image from the app's canvas; far smaller in practice.
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AvatarRef {
    pub id: String,
    pub digest: String,
}

#[derive(Deserialize)]
struct ProfileBody {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    avatar: Option<AvatarRef>,
}

pub fn valid_name(name: &str) -> Option<String> {
    let n = name.split_whitespace().collect::<Vec<_>>().join(" ");
    (!n.is_empty() && n.chars().count() <= MAX_NAME && !n.chars().any(char::is_control)).then_some(n)
}

/// File name of a downloaded avatar in the media folder.
fn avatar_file(media_id: &str) -> String {
    format!("avatar_{media_id}.webp")
}

// --- receiving -------------------------------------------------------------------------

/// Store a verified, decrypted profile event if it's newer than what we have.
pub fn apply(conn: &Connection, member_id: &str, seq: i64, key_version: u32, plain: &[u8]) -> Result<()> {
    let body: ProfileBody = serde_json::from_slice(plain).context("bad profile payload")?;
    let name = match &body.display_name {
        Some(n) => Some(valid_name(n).context("profile name is empty, too long or has control characters")?),
        None => None,
    };
    let avatar = match &body.avatar {
        Some(a) => {
            if !safe_media_id(&a.id) {
                bail!("bad avatar id");
            }
            Some((a.id.clone(), crate::account::decode32(&a.digest).context("bad avatar digest")?))
        }
        None => None,
    };
    conn.execute(
        "INSERT INTO profiles (member_id, seq, display_name, avatar_id, avatar_digest, key_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(member_id) DO UPDATE SET
             seq = excluded.seq, display_name = excluded.display_name, key_version = excluded.key_version,
             avatar_path = CASE WHEN profiles.avatar_id IS excluded.avatar_id THEN profiles.avatar_path END,
             attempts = 0, avatar_id = excluded.avatar_id, avatar_digest = excluded.avatar_digest
         WHERE excluded.seq > profiles.seq",
        params![member_id, seq, name, avatar.as_ref().map(|a| &a.0), avatar.as_ref().map(|a| a.1.to_vec()), key_version],
    )?;
    Ok(())
}

/// The name a member chose in their profile, if any (shown only once a Key Master accepts it).
pub fn chosen_name(conn: &Connection, member_id: &str) -> Option<String> {
    conn.query_row("SELECT display_name FROM profiles WHERE member_id = ?1", [member_id], |r| r.get(0)).ok().flatten()
}

/// (avatar url once downloaded, chosen name)
pub fn view(conn: &Connection, member_id: &str) -> (Option<String>, Option<String>) {
    conn.query_row("SELECT avatar_path, display_name FROM profiles WHERE member_id = ?1", [member_id], |r| {
        Ok((r.get::<_, Option<String>>(0)?.as_deref().map(feed::media_url), r.get(1)?))
    })
    .unwrap_or((None, None))
}

/// Fetch, check and decrypt avatars not on disk yet; delete replaced ones.
/// Returns how many became available.
pub async fn download(app: &App, id: &Identity, s: &Secrets, api: &Api) -> usize {
    let todo: Vec<(String, String, Vec<u8>, u32)> = {
        let conn = app.db();
        let rows = conn
            .prepare(
                "SELECT member_id, avatar_id, avatar_digest, key_version FROM profiles
                 WHERE avatar_id IS NOT NULL AND avatar_path IS NULL AND attempts < ?1",
            )
            .and_then(|mut st| {
                st.query_map(params![MAX_ATTEMPTS], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            });
        match rows {
            Ok(r) => r,
            Err(e) => {
                eprintln!("avatars: {e}");
                return 0;
            }
        }
    };
    let mut ready = 0;
    for (member, media_id, digest, version) in todo {
        let name = avatar_file(&media_id);
        let path = app.media_dir.join(&name);
        let result: Result<()> = async {
            // Our own, written when we saved it.
            if !path.exists() {
                let gk = secrets::group_key(&app.db(), s, version)?.with_context(|| format!("no group key v{version}"))?;
                let blob = api.download_media(&media_id).await?;
                if crypto::blob_digest(&blob)[..] != digest[..] {
                    bail!("avatar {media_id} doesn't match the digest in its profile event");
                }
                let plain = crypto::decrypt(&gk, &blob, &protocol::media_ad(&id.group_id)).context("can't decrypt avatar")?;
                check_avatar(&plain)?;
                write_file(&path, &plain)?;
            }
            app.db().execute(
                "UPDATE profiles SET avatar_path = ?1 WHERE member_id = ?2 AND avatar_id = ?3",
                params![name, member, media_id],
            )?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => ready += 1,
            Err(e) => {
                eprintln!("avatar of {member}: {e:#}");
                let _ = app.db().execute("UPDATE profiles SET attempts = attempts + 1 WHERE member_id = ?1", [&member]);
            }
        }
    }
    cleanup(app);
    ready
}

/// A decrypted avatar must be a small WebP image.
fn check_avatar(plain: &[u8]) -> Result<()> {
    let img = image::load_from_memory_with_format(plain, image::ImageFormat::WebP).context("the avatar isn't a WebP image")?;
    if img.width() > 2 * AVATAR_SIDE || img.height() > 2 * AVATAR_SIDE {
        bail!("the avatar is larger than {AVATAR_SIDE} px");
    }
    Ok(())
}

/// Remove avatar files no profile points at any more.
fn cleanup(app: &App) {
    let keep: std::collections::HashSet<String> = {
        let conn = app.db();
        let Ok(mut st) = conn.prepare("SELECT avatar_id FROM profiles WHERE avatar_id IS NOT NULL") else { return };
        let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) else { return };
        rows.flatten().map(|id| avatar_file(&id)).collect()
    };
    let Ok(dir) = std::fs::read_dir(&app.media_dir) else { return };
    for f in dir.flatten() {
        let name = f.file_name().to_string_lossy().into_owned();
        if name.starts_with("avatar_") && name.ends_with(".webp") && !keep.contains(&name) {
            let _ = std::fs::remove_file(f.path());
        }
    }
}

// --- my own profile ------------------------------------------------------------------------

pub enum AvatarChange {
    Keep,
    Remove,
    /// The cropped image from the app (PNG from its canvas, 256x256).
    New(Vec<u8>),
}

/// Crop to a centred square if needed, scale to 256 px and encode WebP. The
/// output is encoded from raw pixels, so no metadata survives.
pub fn prepare_avatar(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_INPUT_BYTES {
        bail!("that image is too large");
    }
    let img = image::load_from_memory(bytes).context("reading the cropped photo")?;
    let side = img.width().min(img.height());
    if side == 0 {
        bail!("the cropped photo is empty");
    }
    let square = img.crop_imm((img.width() - side) / 2, (img.height() - side) / 2, side, side);
    let out = if side == AVATAR_SIDE { square } else { square.resize_exact(AVATAR_SIDE, AVATAR_SIDE, image::imageops::FilterType::Lanczos3) };
    // Avatars sit on any background: flatten transparency onto white.
    let rgb = image::DynamicImage::ImageRgb8(flatten(&out));
    Ok(crate::photo::encode_webp(&rgb, AVATAR_QUALITY))
}

fn flatten(img: &image::DynamicImage) -> image::RgbImage {
    let rgba = img.to_rgba8();
    image::RgbImage::from_fn(rgba.width(), rgba.height(), |x, y| {
        let p = rgba.get_pixel(x, y).0;
        let a = u16::from(p[3]);
        let mix = |c: u8| ((u16::from(c) * a + 255 * (255 - a)) / 255) as u8;
        image::Rgb([mix(p[0]), mix(p[1]), mix(p[2])])
    })
}

#[derive(Serialize)]
pub struct MyProfile {
    /// What the group sees: the certified name.
    pub display_name: String,
    /// The name in this device's certificate (what a Key Master approved).
    pub certified_name: String,
    /// A chosen name a Key Master hasn't accepted yet.
    pub pending_name: Option<String>,
    pub avatar: Option<String>,
    /// There's an avatar, but it hasn't downloaded yet.
    pub avatar_pending: bool,
}

pub fn mine(app: &App) -> Result<MyProfile> {
    let id = app.require_archive()?;
    let conn = app.db();
    let row: Option<(Option<String>, Option<String>, Option<String>)> = conn
        .query_row("SELECT display_name, avatar_id, avatar_path FROM profiles WHERE member_id = ?1", [&id.member_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let (chosen, avatar_id, avatar_path) = row.unwrap_or((None, None, None));
    Ok(MyProfile {
        display_name: id.display_name.clone(),
        pending_name: chosen.filter(|c| *c != id.display_name),
        certified_name: id.display_name,
        avatar_pending: avatar_id.is_some() && avatar_path.is_none(),
        avatar: avatar_path.as_deref().map(feed::media_url),
    })
}

/// Publish a new profile event: `name` (None keeps the current one) and the avatar change.
pub async fn save(app: &App, name: Option<&str>, avatar: AvatarChange) -> Result<()> {
    let id = app.require_active()?;
    let (current_name, current_file, current_id) = {
        let conn = app.db();
        conn.query_row("SELECT display_name, avatar_path, avatar_id FROM profiles WHERE member_id = ?1", [&id.member_id], |r| {
            Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?))
        })
        .optional()?
        .unwrap_or((None, None, None))
    };
    let new_name = match name {
        Some(n) => {
            let n = valid_name(n).context("a name needs 1 to 100 characters")?;
            // Back to the certified name: nothing to state.
            (n != id.display_name).then_some(n)
        }
        None => current_name,
    };
    let picture: Option<Vec<u8>> = match avatar {
        AvatarChange::Remove => None,
        AvatarChange::New(bytes) => Some(tauri::async_runtime::spawn_blocking(move || prepare_avatar(&bytes)).await??),
        // Each event states the whole profile, so the current photo goes again,
        // encrypted under the current key.
        AvatarChange::Keep => match (current_file, current_id) {
            (Some(f), _) => Some(std::fs::read(app.media_dir.join(f)).context("reading your current photo")?),
            (None, Some(_)) => bail!("your current photo hasn't downloaded to this device yet; try again in a moment"),
            (None, None) => None,
        },
    };
    let mut retried = false;
    loop {
        match send(app, &id, new_name.as_deref(), picture.as_deref()).await {
            Err(e) if crate::api::is_stale_key(&e) && !retried => {
                crate::manage::refresh_keys_now(app).await?;
                retried = true;
            }
            r => break r?,
        }
    }
    feed::sync_once(app).await?;
    Ok(())
}

async fn send(app: &App, id: &Identity, name: Option<&str>, picture: Option<&[u8]>) -> Result<()> {
    let gk = feed::latest_key(app, id)?;
    let mut body = serde_json::json!({ "avatar": null });
    if let Some(n) = name {
        body["display_name"] = n.into();
    }
    let mut media_ids = vec![];
    if let Some(plain) = picture {
        let blob = crypto::encrypt(&gk, plain, &protocol::media_ad(&id.group_id));
        let digest = crypto::blob_digest(&blob);
        let media_id = app.api(id)?.upload_media(blob).await?;
        if !safe_media_id(&media_id) {
            bail!("the server returned an unusable media id");
        }
        // Keep the plaintext, so sync doesn't download our own photo back.
        write_file(&app.media_dir.join(avatar_file(&media_id)), plain)?;
        body["avatar"] = serde_json::to_value(AvatarRef { id: media_id.clone(), digest: B64.encode(digest) })?;
        media_ids.push(media_id);
    }
    feed::send_event(app, "profile", &body, &gk, media_ids).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        crate::db::open(std::path::Path::new(":memory:")).unwrap()
    }

    fn body(name: Option<&str>, avatar: Option<&str>) -> Vec<u8> {
        let mut b = serde_json::json!({ "avatar": null });
        if let Some(n) = name {
            b["display_name"] = n.into();
        }
        if let Some(a) = avatar {
            b["avatar"] = serde_json::json!({ "id": a, "digest": B64.encode([1u8; 32]) });
        }
        serde_json::to_vec(&b).unwrap()
    }

    #[test]
    fn latest_profile_wins_whole() {
        let c = conn();
        apply(&c, "m_a", 5, 1, &body(Some("  Ana   B "), Some("av1"))).unwrap();
        assert_eq!(chosen_name(&c, "m_a").as_deref(), Some("Ana B"));
        c.execute("UPDATE profiles SET avatar_path = 'avatar_av1.webp'", []).unwrap();
        // An older event arriving late changes nothing.
        apply(&c, "m_a", 3, 1, &body(Some("Old"), None)).unwrap();
        assert_eq!(chosen_name(&c, "m_a").as_deref(), Some("Ana B"));
        // Same avatar, new name: the downloaded file stays.
        apply(&c, "m_a", 6, 1, &body(None, Some("av1"))).unwrap();
        assert_eq!(view(&c, "m_a"), (Some(feed::media_url("avatar_av1.webp")), None));
        // A new avatar has to be downloaded; null removes it.
        apply(&c, "m_a", 7, 1, &body(None, Some("av2"))).unwrap();
        assert_eq!(view(&c, "m_a").0, None);
        apply(&c, "m_a", 8, 1, &body(None, None)).unwrap();
        let id: Option<String> = c.query_row("SELECT avatar_id FROM profiles", [], |r| r.get(0)).unwrap();
        assert_eq!(id, None);
    }

    #[test]
    fn bad_profiles_are_rejected() {
        let c = conn();
        assert!(apply(&c, "m", 1, 1, &body(Some(""), None)).is_err());
        assert!(apply(&c, "m", 1, 1, &body(Some(&"x".repeat(101)), None)).is_err());
        assert!(apply(&c, "m", 1, 1, &body(Some("a\u{7}b"), None)).is_err());
        assert!(apply(&c, "m", 1, 1, &body(None, Some("../../x"))).is_err());
        assert!(apply(&c, "m", 1, 1, b"not json").is_err());
    }

    #[test]
    fn avatars_are_256_px_webp_without_metadata() {
        let img = image::RgbaImage::from_fn(300, 200, |x, _| image::Rgba([x as u8, 10, 200, 128]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgba8(img).write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png).unwrap();
        let out = prepare_avatar(&png).unwrap();
        assert_eq!(&out[8..12], b"WEBP");
        let back = image::load_from_memory_with_format(&out, image::ImageFormat::WebP).unwrap();
        assert_eq!((back.width(), back.height()), (AVATAR_SIDE, AVATAR_SIDE));
        check_avatar(&out).unwrap();
        assert!(check_avatar(b"nope").is_err());
        assert!(prepare_avatar(b"nope").is_err());
    }
}
