//! Short videos (SPEC "Phase 9"): preparing a clip on this computer with the
//! bundled ffmpeg.
//!
//! The Windows app ships a trimmed, LGPL-only `ffmpeg.exe` next to its own
//! executable (`scripts/build-ffmpeg.sh`, `tauri.ffmpeg.conf.json`). It encodes
//! H.264 with Windows' own Media Foundation encoder (`h264_mf`) and AAC with
//! ffmpeg's. `SIDETRAY_FFMPEG` points at another ffmpeg instead (for
//! development and tests). Elsewhere there's no ffmpeg yet: videos can be
//! watched but not sent.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::PathBuf;

/// The ffmpeg this app uses, if there is one.
pub fn ffmpeg_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SIDETRAY_FFMPEG").map(PathBuf::from) {
        return p.is_file().then_some(p);
    }
    let exe = std::env::current_exe().ok()?;
    let bundled = exe.parent()?.join(if cfg!(windows) { "ffmpeg.exe" } else { "ffmpeg" });
    bundled.is_file().then_some(bundled)
}

/// A command for ffmpeg that opens no console window.
pub fn command(ffmpeg: &std::path::Path) -> tokio::process::Command {
    #[allow(unused_mut)]
    let mut c = tokio::process::Command::new(ffmpeg);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c.kill_on_drop(true).stdin(std::process::Stdio::null());
    c
}

/// Whether this computer can send videos, and if not, why (shown in the composer).
#[derive(Serialize, Clone, Debug)]
pub struct Support {
    pub can_send: bool,
    pub reason: Option<String>,
}

/// Windows "N" editions lack Media Foundation until the Media Feature Pack is installed.
#[cfg(windows)]
fn media_foundation_missing() -> bool {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    !root.join("System32").join("mfplat.dll").is_file()
}

pub async fn support() -> Support {
    let no = |reason: &str| Support { can_send: false, reason: Some(reason.to_string()) };
    if cfg!(any(target_os = "android", target_os = "ios")) {
        return no("Sending videos from this phone isn't ready yet.");
    }
    let Some(ffmpeg) = ffmpeg_path() else {
        return no("This copy of Side Tray can't prepare videos (it has no video encoder). You can still watch them.");
    };
    #[cfg(windows)]
    if media_foundation_missing() {
        return no("Windows' video encoder is missing. On Windows N editions, install the Media Feature Pack (Settings > Apps > Optional features), then restart Side Tray.");
    }
    match encoders(&ffmpeg).await {
        Ok(list) if list.iter().any(|e| e == H264_ENCODER) && list.iter().any(|e| e == "aac") => Support { can_send: true, reason: None },
        Ok(_) => no("The bundled video encoder doesn't have H.264 and AAC."),
        Err(e) => no(&format!("The video encoder didn't start: {e:#}")),
    }
}

/// The H.264 encoder: the operating system's own (no GPL code in the bundled ffmpeg).
#[cfg(windows)]
pub const H264_ENCODER: &str = "h264_mf";
#[cfg(target_os = "macos")]
pub const H264_ENCODER: &str = "h264_videotoolbox";
#[cfg(not(any(windows, target_os = "macos")))]
pub const H264_ENCODER: &str = "libopenh264";

/// The names of the encoders this ffmpeg has.
async fn encoders(ffmpeg: &std::path::Path) -> Result<Vec<String>> {
    let out = command(ffmpeg).args(["-hide_banner", "-encoders"]).output().await.context("running ffmpeg")?;
    if !out.status.success() {
        bail!("ffmpeg -encoders failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Lines look like " V....D h264_mf   H264 via MediaFoundation (codec h264)".
    Ok(text.lines().filter_map(|l| l.split_whitespace().nth(1)).map(str::to_string).collect())
}

// --- probing ----------------------------------------------------------------------

/// The longest clip that's sent; longer ones are offered trimmed to this.
pub const MAX_DURATION_MS: u64 = 60_000;
/// A clip this little over 60 s is just cut without asking (containers round).
pub const TRIM_SLACK_MS: u64 = 500;
/// Prepared videos wait here (in the profile folder) until they're sent.
pub const STAGING_DIR: &str = "staging";

/// What `ffmpeg -i` says about a file.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub duration_ms: u64,
    /// As displayed: already swapped for a clip recorded rotated by 90 degrees.
    pub width: u32,
    pub height: u32,
    pub audio_channels: Option<u32>,
}

pub async fn probe(ffmpeg: &std::path::Path, file: &std::path::Path) -> Result<Probe> {
    // With no output file ffmpeg exits with an error after printing the input's details.
    let out = command(ffmpeg).arg("-hide_banner").arg("-i").arg(file).output().await.context("running ffmpeg")?;
    parse_probe(&String::from_utf8_lossy(&out.stderr))
}

pub fn parse_probe(text: &str) -> Result<Probe> {
    let mut duration_ms = None;
    let mut video: Option<(u32, u32)> = None;
    let mut rotation = 0i32;
    let mut audio_channels = None;
    let mut in_first_video = false;
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("Duration:") {
            duration_ms = parse_duration(rest.split(',').next().unwrap_or("").trim());
        } else if l.starts_with("Stream #") {
            in_first_video = false;
            if l.contains(": Video:") && video.is_none() && !l.contains("(attached pic)") {
                video = dimensions(l);
                in_first_video = video.is_some();
            } else if l.contains(": Audio:") && audio_channels.is_none() {
                let d = l.split(": Audio:").nth(1).unwrap_or("");
                audio_channels = Some(if d.split(',').any(|p| p.trim() == "mono") { 1 } else { 2 });
            }
        } else if in_first_video {
            let lower = l.to_ascii_lowercase();
            if let Some(i) = lower.find("rotation of ") {
                let deg: f64 = lower[i + 12..].split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
                rotation = deg.round() as i32;
            }
        }
    }
    if text.contains("Invalid data found") || text.contains("No such file") {
        bail!("that isn't a video this app can read");
    }
    let Some((w, h)) = video else { bail!("that file has no video in it") };
    let duration_ms = duration_ms.context("can't tell how long that video is")?;
    let (width, height) = if rotation.rem_euclid(180) == 90 { (h, w) } else { (w, h) };
    Ok(Probe { duration_ms, width, height, audio_channels })
}

/// "00:01:10.03" -> 70030.
fn parse_duration(s: &str) -> Option<u64> {
    let mut parts = s.split(':');
    let (h, m, sec) = (parts.next()?, parts.next()?, parts.next()?);
    let total = h.parse::<f64>().ok()? * 3600.0 + m.parse::<f64>().ok()? * 60.0 + sec.parse::<f64>().ok()?;
    (total > 0.0).then(|| (total * 1000.0).round() as u64)
}

/// The first "1920x1080" in a stream line.
fn dimensions(line: &str) -> Option<(u32, u32)> {
    line.split([' ', ',']).find_map(|tok| {
        let (w, h) = tok.split_once('x')?;
        let (w, h) = (w.parse::<u32>().ok()?, h.parse::<u32>().ok()?);
        (w > 0 && h > 0).then_some((w, h))
    })
}

// --- the encoding plan ----------------------------------------------------------

/// The MP4 the encoder aims for: room for the encryption and container
/// overhead under the relay's 10 MB limit.
pub const TARGET_BYTES: u64 = 9_500_000;
/// The relay's limit for one file (`SIDETRAY_MAX_MEDIA_BYTES`), less the encryption overhead.
pub const MAX_BYTES: u64 = 10 * 1024 * 1024 - 64;
pub const AUDIO_KBPS: u64 = 96;
const MAX_VIDEO_KBPS: u64 = 2_500;
const MIN_720P_KBPS: u64 = 1_500;
const MIN_VIDEO_KBPS: u64 = 400;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Plan {
    pub video_kbps: u64,
    /// The longest side of the output.
    pub max_side: u32,
}

/// SPEC "Transcoding": the bitrate that fills `TARGET_BYTES` over `duration_ms`
/// (after trimming), at 720p when that's at least 1,500 kb/s and 480p otherwise.
pub fn plan(duration_ms: u64, has_audio: bool) -> Result<Plan> {
    let secs = (duration_ms.max(1) as f64) / 1000.0;
    let total_kbps = (TARGET_BYTES as f64 * 8.0 / 1000.0 / secs) as u64;
    let audio = if has_audio { AUDIO_KBPS } else { 0 };
    let video_kbps = total_kbps.saturating_sub(audio).min(MAX_VIDEO_KBPS);
    if video_kbps < MIN_VIDEO_KBPS {
        bail!("that video is too long to send");
    }
    Ok(Plan { video_kbps, max_side: if video_kbps >= MIN_720P_KBPS { 1280 } else { 854 } })
}

// --- transcoding -------------------------------------------------------------------

/// A prepared clip, ready to encrypt and send.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// The MP4, in the profile's staging folder.
    pub path: PathBuf,
    /// The poster frame: a WebP thumbnail like a photo's.
    pub thumb: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub size: u64,
}

/// Cancels a running `prepare` when notified.
pub type Cancel = std::sync::Arc<tokio::sync::Notify>;

/// Transcode `source` into `out` (an MP4) per SPEC, keeping at most the first
/// 60 seconds, then grab the poster frame. `progress` gets 0.0..=1.0.
pub async fn prepare(
    ffmpeg: &std::path::Path,
    source: &std::path::Path,
    out: &std::path::Path,
    cancel: &Cancel,
    progress: impl Fn(f64),
) -> Result<Prepared> {
    let info = probe(ffmpeg, source).await?;
    let duration_ms = info.duration_ms.min(MAX_DURATION_MS);
    let has_audio = info.audio_channels.is_some();
    let mut plan = plan(duration_ms, has_audio)?;
    let mut size = 0;
    for attempt in 0..2 {
        encode(ffmpeg, source, out, &info, duration_ms, plan, cancel, &progress).await?;
        size = std::fs::metadata(out).context("reading the prepared video")?.len();
        if size <= TARGET_BYTES {
            break;
        }
        // Hardware bitrate control is loose: once more at 85% of the bitrate.
        if attempt == 0 {
            plan.video_kbps = plan.video_kbps * 85 / 100;
        }
    }
    if size > MAX_BYTES {
        let _ = std::fs::remove_file(out);
        bail!("the prepared video came out too large to send ({:.1} MB)", size as f64 / 1e6);
    }
    let made = probe(ffmpeg, out).await.context("checking the prepared video")?;
    let frame = poster_frame(ffmpeg, out, made.duration_ms).await?;
    let thumb = tauri::async_runtime::spawn_blocking(move || crate::photo::poster(&frame)).await??;
    progress(1.0);
    Ok(Prepared { path: out.to_path_buf(), thumb, width: made.width, height: made.height, duration_ms: made.duration_ms, size })
}

/// The ffmpeg arguments for one encode (after `-i source`).
pub fn encode_args(info: &Probe, duration_ms: u64, plan: Plan) -> Vec<String> {
    let side = plan.max_side;
    // Longest side at most `side`, never upscaled, even dimensions. Rotation
    // was applied already (ffmpeg's autorotate), so iw/ih are as displayed.
    let scale = format!("scale='if(gte(iw,ih),min({side},iw),-2)':'if(gte(iw,ih),-2,min({side},ih))',format=nv12");
    let mut a: Vec<String> = vec![
        "-map".into(), "0:v:0".into(), "-map".into(), "0:a:0?".into(),
        "-map_metadata".into(), "-1".into(), "-map_chapters".into(), "-1".into(), "-sn".into(), "-dn".into(),
        "-t".into(), format!("{:.3}", duration_ms as f64 / 1000.0),
        "-vf".into(), scale, "-fpsmax".into(), "30".into(),
        "-c:v".into(), H264_ENCODER.into(),
        "-b:v".into(), format!("{}k", plan.video_kbps),
        "-maxrate".into(), format!("{}k", plan.video_kbps * 3 / 2),
        "-bufsize".into(), format!("{}k", plan.video_kbps * 2),
        "-g".into(), "60".into(),
    ];
    if H264_ENCODER == "h264_mf" {
        // High profile (100), peak-constrained VBR.
        a.extend(["-profile:v", "100", "-rate_control", "pc_vbr", "-scenario", "archive"].map(String::from));
    }
    match info.audio_channels {
        Some(ch) => a.extend(["-c:a".into(), "aac".into(), "-b:a".into(), format!("{AUDIO_KBPS}k"), "-ac".into(), ch.min(2).to_string()]),
        None => a.push("-an".into()),
    }
    a.extend(["-movflags", "+faststart", "-f", "mp4"].map(String::from));
    a
}

#[allow(clippy::too_many_arguments)]
async fn encode(
    ffmpeg: &std::path::Path,
    source: &std::path::Path,
    out: &std::path::Path,
    info: &Probe,
    duration_ms: u64,
    plan: Plan,
    cancel: &Cancel,
    progress: &impl Fn(f64),
) -> Result<()> {
    use tokio::io::AsyncBufReadExt;
    let mut cmd = command(ffmpeg);
    cmd.args(["-hide_banner", "-nostats", "-loglevel", "error", "-y", "-progress", "pipe:1"])
        .arg("-i")
        .arg(source)
        .args(encode_args(info, duration_ms, plan))
        .arg(out)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("starting ffmpeg")?;
    let stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let errors = tokio::spawn(async move {
        let mut s = String::new();
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut s).await;
        s
    });
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let total_us = (duration_ms * 1000).max(1) as f64;
    let read = async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(us) = progress_us(&line) {
                progress((us as f64 / total_us).clamp(0.0, 0.99));
            }
        }
    };
    let cancelled = tokio::select! {
        _ = read => false,
        _ = cancel.notified() => true,
    };
    if cancelled {
        // Stop it before removing the half-written file.
        let _ = child.kill().await;
        let _ = std::fs::remove_file(out);
        bail!("{CANCELLED}");
    }
    let status = child.wait().await.context("waiting for ffmpeg")?;
    if !status.success() {
        let _ = std::fs::remove_file(out);
        let msg = errors.await.unwrap_or_default();
        let last = msg.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no details");
        bail!("preparing the video failed: {last}");
    }
    Ok(())
}

pub const CANCELLED: &str = "cancelled";

/// `out_time_us=1234567` (or `out_time_ms=`, which is also in microseconds).
pub fn progress_us(line: &str) -> Option<u64> {
    let (k, v) = line.trim().split_once('=')?;
    matches!(k, "out_time_us" | "out_time_ms").then(|| v.parse().ok()).flatten()
}

/// A JPEG of the frame at 1 s (the first frame for shorter clips).
async fn poster_frame(ffmpeg: &std::path::Path, mp4: &std::path::Path, duration_ms: u64) -> Result<Vec<u8>> {
    let at = if duration_ms > 1500 { "1" } else { "0" };
    let out = command(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-ss", at, "-i"])
        .arg(mp4)
        .args(["-frames:v", "1", "-f", "image2pipe", "-c:v", "mjpeg", "-q:v", "3", "pipe:1"])
        .output()
        .await
        .context("running ffmpeg")?;
    if !out.status.success() || out.stdout.is_empty() {
        bail!("couldn't take the poster frame: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(out.stdout)
}

// --- in posts and messages ------------------------------------------------------------

/// The `video` field of a post or direct message (SPEC "Format on the wire").
/// `digest` covers the encrypted file, so the relay can't swap it.
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct VideoRef {
    pub id: String,
    pub digest: String,
    pub thumb: String,
    pub thumb_digest: String,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub size: u64,
}

/// What a video belongs to, which also says how it's encrypted.
#[derive(Clone, Copy)]
pub enum Owner<'a> {
    /// A feed post: the group key of that version.
    Post { post_id: &'a str, key_version: u32 },
    /// A direct message: its message key.
    Message { message_id: &'a str },
}

/// Allow a little over the limits for another app's rounding.
const MAX_REF_DURATION_MS: u64 = MAX_DURATION_MS + 5_000;
const MAX_REF_BYTES: u64 = 11 * 1024 * 1024;

/// Record a received (or, with `mine`, just sent) video. An unusable
/// reference is skipped, like a bad photo reference: the text still shows.
pub fn store_ref(conn: &rusqlite::Connection, owner: Owner, v: &VideoRef, mine: bool) -> Result<bool> {
    use crate::account::decode32;
    let (Ok(d), Ok(td)) = (decode32(&v.digest), decode32(&v.thumb_digest)) else { return Ok(false) };
    let ok = crate::feed::safe_media_id(&v.id)
        && crate::feed::safe_media_id(&v.thumb)
        && v.width > 0
        && v.height > 0
        && (1..=MAX_REF_DURATION_MS).contains(&v.duration_ms)
        && (1..=MAX_REF_BYTES).contains(&v.size);
    if !ok {
        return Ok(false);
    }
    let (post_id, message_id, key_version) = match owner {
        Owner::Post { post_id, key_version } => (Some(post_id), None, key_version),
        Owner::Message { message_id } => (None, Some(message_id), 0),
    };
    let (state, local, thumb) = if mine {
        ("ready", Some(format!("{}.mp4", v.id)), Some(format!("{}.webp", v.thumb)))
    } else {
        ("pending", None, None)
    };
    let n = conn.execute(
        "INSERT OR IGNORE INTO videos (id, post_id, message_id, key_version, digest, thumb_id, thumb_digest, width, height,
                                       duration_ms, size, state, local_path, thumb_path, acked, thumb_acked, mine)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15, ?15)",
        rusqlite::params![
            v.id, post_id, message_id, key_version, &d[..], v.thumb, &td[..], v.width, v.height,
            v.duration_ms as i64, v.size as i64, state, local, thumb, mine
        ],
    )?;
    Ok(n > 0)
}

/// What the feed or a chat shows for a video.
#[derive(Serialize, Clone, Debug)]
pub struct VideoView {
    pub id: String,
    /// The poster frame, once downloaded.
    pub thumb: Option<String>,
    /// pending, downloading, ready, expired or failed.
    pub state: String,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub size: u64,
    pub mine: bool,
}

/// The video of a post (`post`) or message, if it has one.
pub fn view(conn: &rusqlite::Connection, owner_column: &str, owner_id: &str) -> Result<Option<VideoView>> {
    use rusqlite::OptionalExtension;
    let column = if owner_column == "post_id" { "post_id" } else { "message_id" };
    Ok(conn
        .query_row(
            &format!("SELECT id, thumb_path, state, width, height, duration_ms, size, mine FROM videos WHERE {column} = ?1 LIMIT 1"),
            [owner_id],
            |r| {
                Ok(VideoView {
                    id: r.get(0)?,
                    thumb: r.get::<_, Option<String>>(1)?.as_deref().map(crate::feed::media_url),
                    state: r.get(2)?,
                    width: r.get(3)?,
                    height: r.get(4)?,
                    duration_ms: r.get::<_, i64>(5)? as u64,
                    size: r.get::<_, i64>(6)? as u64,
                    mine: r.get(7)?,
                })
            },
        )
        .optional()?)
}

/// A message asking the poster to send a video again (SPEC "Expired"):
/// `post_id` is the post's (or message's) id, `video_id` the expired file.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct VideoRequest {
    pub post_id: String,
    pub video_id: String,
}

impl VideoRequest {
    pub fn valid(&self) -> bool {
        crate::feed::safe_media_id(&self.video_id) && (1..=128).contains(&self.post_id.len())
    }
}

/// Whether this device can answer a request for `video_id`: it has the file,
/// and it's this member's own video (a post or message they sent).
pub fn can_resend(conn: &rusqlite::Connection, my_member_id: &str, video_id: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM videos v LEFT JOIN posts p ON p.id = v.post_id LEFT JOIN dm_messages m ON m.id = v.message_id
         WHERE v.id = ?1 AND v.state = 'ready' AND v.local_path IS NOT NULL
           AND (p.author_id = ?2 OR m.sender_member_id = ?2)",
        rusqlite::params![video_id, my_member_id],
        |_| Ok(()),
    )
    .is_ok()
}

/// Stage a copy of a video already on this device (to send it again as a new
/// direct message: a new file, new key, nothing reused).
pub fn stage_local(app: &crate::state::App, video_id: &str) -> Result<(String, Prepared)> {
    let (local, thumb, width, height, duration_ms): (Option<String>, Option<String>, u32, u32, i64) = app.db().query_row(
        "SELECT local_path, thumb_path, width, height, duration_ms FROM videos WHERE id = ?1 AND state = 'ready'",
        [video_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    ).map_err(|_| anyhow::anyhow!("This video isn't on this device."))?;
    let (Some(local), Some(thumb)) = (local, thumb) else { bail!("This video isn't on this device.") };
    let mut idb = [0u8; 9];
    getrandom::getrandom(&mut idb).map_err(|e| anyhow::anyhow!("random number generator: {e}"))?;
    let id: String = idb.iter().map(|b| format!("{b:02x}")).collect();
    let dir = app.dir.join(STAGING_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{id}.mp4"));
    std::fs::copy(app.media_dir.join(&local), &path).context("copying the video")?;
    let thumb = std::fs::read(app.media_dir.join(thumb)).context("reading the poster frame")?;
    let size = std::fs::metadata(&path)?.len();
    let p = Prepared { path, thumb, width, height, duration_ms: duration_ms as u64, size };
    app.staged_videos.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), p.clone());
    Ok((id, p))
}

/// The decrypted MP4 of a downloaded (or sent) video, for playback.
pub fn read(app: &crate::state::App, video_id: &str) -> Result<Vec<u8>> {
    use rusqlite::OptionalExtension;
    let path: Option<String> = app
        .db()
        .query_row("SELECT local_path FROM videos WHERE id = ?1 AND state = 'ready'", [video_id], |r| r.get(0))
        .optional()?
        .flatten();
    let name = path.context("that video isn't on this device")?;
    std::fs::read(app.media_dir.join(name)).context("reading the video file")
}

const MAX_ATTEMPTS: i64 = 5;

/// How a video's files are decrypted.
enum Key {
    Group(sidetray_crypto::GroupKey),
    Message(sidetray_crypto::dm::MessageKey),
}

impl Key {
    fn decrypt(&self, blob: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Key::Group(gk) => sidetray_crypto::decrypt(gk, blob, ad).context("can't decrypt"),
            Key::Message(k) => k.decrypt(blob, ad).context("can't decrypt"),
        }
    }
}

/// One row to fetch something for.
struct Todo {
    id: String,
    thumb_id: String,
    post_id: Option<String>,
    message_id: Option<String>,
    key_version: u32,
    digest: Vec<u8>,
    thumb_digest: Vec<u8>,
    size: u64,
}

fn todo(conn: &rusqlite::Connection, filter: &str) -> Result<Vec<Todo>> {
    // Newest first: posts by their seq, messages by theirs.
    let sql = format!(
        "SELECT v.id, v.thumb_id, v.post_id, v.message_id, v.key_version, v.digest, v.thumb_digest, v.size
         FROM videos v LEFT JOIN posts p ON p.id = v.post_id LEFT JOIN dm_messages m ON m.id = v.message_id
         WHERE (p.deleted = 0 OR m.id IS NOT NULL) AND {filter}
         ORDER BY COALESCE(p.seq, m.seq) DESC"
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(rusqlite::params![MAX_ATTEMPTS], |r| {
        Ok(Todo {
            id: r.get(0)?,
            thumb_id: r.get(1)?,
            post_id: r.get(2)?,
            message_id: r.get(3)?,
            key_version: r.get(4)?,
            digest: r.get(5)?,
            thumb_digest: r.get(6)?,
            size: r.get::<_, i64>(7)? as u64,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The key and associated data for a row's files.
fn key_for(app: &crate::state::App, id: &crate::db::Identity, s: &crate::secrets::Secrets, t: &Todo) -> Result<(Key, Vec<u8>)> {
    use sidetray_crypto::protocol;
    if t.post_id.is_some() {
        let gk = crate::secrets::group_key(&app.db(), s, t.key_version)?.with_context(|| format!("no group key v{}", t.key_version))?;
        return Ok((Key::Group(gk), protocol::media_ad(&id.group_id)));
    }
    let msg = t.message_id.as_deref().context("a video with no post or message")?;
    let (wrapped, conv): (Vec<u8>, String) = app.db().query_row(
        "SELECT key_wrapped, conversation_id FROM dm_messages WHERE id = ?1",
        [msg],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((Key::Message(s.unwrap_message_key(msg, &wrapped)?), protocol::dm_media_ad(&id.group_id, &conv)))
}

/// Tell the window a video changed (state or download progress).
fn emit(app: &crate::state::App, video_id: &str, received: Option<u64>, total: u64) {
    use tauri::Emitter;
    if let Some(h) = crate::state::handle() {
        let _ = h.emit(
            "video-state",
            serde_json::json!({ "profile": app.profile_id, "id": video_id, "received": received, "total": total }),
        );
    }
}

/// Fetch the poster frames that aren't here yet (before the DM ack, which
/// lets the relay drop a message's photos).
pub async fn fetch_thumbs(app: &crate::state::App, id: &crate::db::Identity, s: &crate::secrets::Secrets, api: &crate::api::Api) {
    let rows = match todo(&app.db(), "v.thumb_path IS NULL AND v.thumb_attempts < ?1") {
        Ok(r) => r,
        Err(e) => return eprintln!("video poster frames: {e:#}"),
    };
    for t in rows {
        let result: Result<()> = async {
            let (key, ad) = key_for(app, id, s, &t)?;
            let blob = api.download_media(&t.thumb_id).await?;
            if sidetray_crypto::blob_digest(&blob)[..] != t.thumb_digest[..] {
                bail!("doesn't match the digest it was sent with");
            }
            let plain = key.decrypt(&blob, &ad)?;
            let name = format!("{}.webp", t.thumb_id);
            crate::feed::write_file(&app.media_dir.join(&name), &plain)?;
            app.db().execute("UPDATE videos SET thumb_path = ?1 WHERE id = ?2", rusqlite::params![name, t.id])?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            eprintln!("video poster frame {}: {e:#}", t.thumb_id);
            let _ = app.db().execute("UPDATE videos SET thumb_attempts = thumb_attempts + 1 WHERE id = ?1", [&t.id]);
        }
        emit(app, &t.id, None, t.size);
    }
}

/// Download the videos not here yet, newest first, one at a time, so this
/// device acks soon and the relay can let them go. A 410 means the relay
/// already did (delivered to everyone else, too old, or over its cap).
pub async fn fetch_videos(app: &crate::state::App, id: &crate::db::Identity, s: &crate::secrets::Secrets, api: &crate::api::Api) {
    if let Err(e) = remove_deleted(app) {
        eprintln!("cleaning up deleted videos: {e:#}");
    }
    let rows = match todo(&app.db(), "v.state IN ('pending', 'downloading') AND v.attempts < ?1") {
        Ok(r) => r,
        Err(e) => return eprintln!("videos: {e:#}"),
    };
    for t in rows {
        let _ = app.db().execute("UPDATE videos SET state = 'downloading' WHERE id = ?1", [&t.id]);
        emit(app, &t.id, Some(0), t.size);
        let result: Result<()> = async {
            let (key, ad) = key_for(app, id, s, &t)?;
            let blob = api.download_media_progress(&t.id, |n| emit(app, &t.id, Some(n), t.size)).await?;
            if sidetray_crypto::blob_digest(&blob)[..] != t.digest[..] {
                bail!("doesn't match the digest it was sent with");
            }
            let plain = key.decrypt(&blob, &ad)?;
            let name = format!("{}.mp4", t.id);
            crate::feed::write_file(&app.media_dir.join(&name), &plain)?;
            app.db().execute("UPDATE videos SET local_path = ?1, state = 'ready' WHERE id = ?2", rusqlite::params![name, t.id])?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {}
            Err(e) if crate::api::is_status(&e, 410) => {
                let _ = app.db().execute("UPDATE videos SET state = 'expired' WHERE id = ?1", [&t.id]);
            }
            Err(e) => {
                eprintln!("video {}: {e:#}", t.id);
                let _ = app.db().execute(
                    "UPDATE videos SET attempts = attempts + 1,
                            state = CASE WHEN attempts + 1 >= ?2 THEN 'failed' ELSE 'pending' END WHERE id = ?1",
                    rusqlite::params![t.id, MAX_ATTEMPTS],
                );
            }
        }
        emit(app, &t.id, None, t.size);
    }
}

/// A deleted post's video: remove the files, and tell the relay this device
/// won't fetch them.
fn remove_deleted(app: &crate::state::App) -> Result<()> {
    let conn = app.db();
    let mut st = conn.prepare(
        "SELECT v.id, v.thumb_id, v.local_path, v.thumb_path, v.acked, v.thumb_acked FROM videos v
         JOIN posts p ON p.id = v.post_id WHERE p.deleted = 1",
    )?;
    type Row = (String, String, Option<String>, Option<String>, bool, bool);
    let rows: Vec<Row> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (vid, thumb_id, file, thumb, acked, thumb_acked) in rows {
        for f in [file, thumb].into_iter().flatten() {
            let _ = std::fs::remove_file(app.media_dir.join(f));
        }
        for (id, done) in [(&vid, acked), (&thumb_id, thumb_acked)] {
            if !done {
                conn.execute("INSERT OR IGNORE INTO media_acks_pending (id) VALUES (?1)", [id])?;
            }
        }
        conn.execute("DELETE FROM videos WHERE id = ?1", [&vid])?;
    }
    Ok(())
}

/// Ack the video files and poster frames this device is done with (fetched,
/// expired, or given up on). Runs after `feed::ack_media`, which already told
/// the relay this device acks files.
pub async fn ack(app: &crate::state::App, api: &crate::api::Api) {
    const BATCH: i64 = 200;
    loop {
        let (videos, thumbs): (Vec<String>, Vec<String>) = {
            let conn = app.db();
            let ids = |sql: &str| -> Vec<String> {
                conn.prepare(sql)
                    .and_then(|mut st| st.query_map(rusqlite::params![MAX_ATTEMPTS, BATCH], |r| r.get(0))?.collect())
                    .unwrap_or_default()
            };
            (
                ids("SELECT id FROM videos WHERE acked = 0 AND (state IN ('ready', 'expired', 'failed') OR attempts >= ?1) LIMIT ?2"),
                ids("SELECT thumb_id FROM videos WHERE thumb_acked = 0 AND (thumb_path IS NOT NULL OR thumb_attempts >= ?1) LIMIT ?2"),
            )
        };
        if videos.is_empty() && thumbs.is_empty() {
            return;
        }
        let ids: Vec<&String> = videos.iter().chain(&thumbs).collect();
        if let Err(e) = api.post::<_, serde_json::Value>("/media/acks", &serde_json::json!({ "ids": ids })).await {
            if !(crate::api::is_status(&e, 404) || crate::api::is_status(&e, 405)) {
                eprintln!("acking videos: {e:#}");
            }
            return;
        }
        let conn = app.db();
        for v in &videos {
            let _ = conn.execute("UPDATE videos SET acked = 1 WHERE id = ?1", [v]);
        }
        for t in &thumbs {
            let _ = conn.execute("UPDATE videos SET thumb_acked = 1 WHERE thumb_id = ?1", [t]);
        }
        if (videos.len() as i64) < BATCH && (thumbs.len() as i64) < BATCH {
            return;
        }
    }
}

// --- sending ---------------------------------------------------------------------

/// A staged video, still staged (it's removed only once it's sent).
pub fn staged(app: &crate::state::App, staged_id: &str) -> Result<Prepared> {
    app.staged_videos
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(staged_id)
        .cloned()
        .context("the video is no longer attached; add it again")
}

/// Encrypt and upload a prepared video and its poster frame, reporting the
/// upload as `upload-progress` events. Returns the reference to put in the post or message.
pub async fn upload(
    app: &crate::state::App,
    api: &crate::api::Api,
    v: &Prepared,
    encrypt: impl Fn(&[u8]) -> Vec<u8>,
) -> Result<VideoRef> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use tauri::Emitter;
    let plain = tokio::fs::read(&v.path).await.context("reading the prepared video")?;
    let (enc, enc_thumb) = (encrypt(&plain), encrypt(&v.thumb));
    let (d, td) = (sidetray_crypto::blob_digest(&enc), sidetray_crypto::blob_digest(&enc_thumb));
    let profile = app.profile_id.clone();
    let id = api
        .upload_media_as(enc, "video", move |sent, total| {
            if let Some(h) = crate::state::handle() {
                let _ = h.emit("upload-progress", serde_json::json!({ "profile": profile, "sent": sent, "total": total }));
            }
        })
        .await
        .map_err(|e| {
            if crate::api::is_status(&e, 507) {
                e.context("The server's video storage is full right now. Try again later.")
            } else if crate::api::is_status(&e, 429) {
                e.context("You've sent a lot of media in the last hour (the server allows about 50 MB). Try again later.")
            } else {
                e
            }
        })?;
    let thumb = api.upload_media_as(enc_thumb, "image", |_, _| {}).await?;
    if !crate::feed::safe_media_id(&id) || !crate::feed::safe_media_id(&thumb) {
        bail!("the server returned an unusable media id");
    }
    Ok(VideoRef {
        id,
        digest: B64.encode(d),
        thumb,
        thumb_digest: B64.encode(td),
        width: v.width,
        height: v.height,
        duration_ms: v.duration_ms,
        size: plain.len() as u64,
    })
}

/// After sending: keep the plaintext MP4 and poster frame as this device's
/// copy (for playback and re-sending), and let go of the staged video.
pub fn keep_sent(app: &crate::state::App, staged_id: &str, v: &Prepared, r: &VideoRef) -> Result<()> {
    let dest = app.media_dir.join(format!("{}.mp4", r.id));
    if std::fs::rename(&v.path, &dest).is_err() {
        std::fs::copy(&v.path, &dest).context("keeping the sent video")?;
        let _ = std::fs::remove_file(&v.path);
    }
    crate::feed::write_file(&app.media_dir.join(format!("{}.webp", r.thumb)), &v.thumb)?;
    app.staged_videos.lock().unwrap_or_else(|e| e.into_inner()).remove(staged_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHONE: &str = "Input #0, mov,mp4,m4a,3gp,3g2,mj2, from 'clip.mp4':
  Metadata:
    location        : +51.5074-000.1278/
  Duration: 00:01:10.03, start: 0.000000, bitrate: 17000 kb/s
  Stream #0:0[0x1](und): Video: hevc (Main) (hvc1 / 0x31637668), yuv420p(tv, bt709), 1920x1080, 16000 kb/s, 29.97 fps, 30 tbr, 600 tbn (default)
    Metadata:
      handler_name    : Core Media Video
    Side data:
      Display Matrix: rotation of -90.00 degrees
  Stream #0:1[0x2](und): Audio: aac (LC) (mp4a / 0x6134706D), 44100 Hz, mono, fltp, 96 kb/s (default)
  Stream #0:2[0x3](und): Data: none (mebx / 0x7862656D), 0 kb/s
At least one output file must be specified";

    #[test]
    fn probe_reads_duration_rotation_and_audio() {
        let p = parse_probe(PHONE).unwrap();
        assert_eq!(p, Probe { duration_ms: 70_030, width: 1080, height: 1920, audio_channels: Some(1) });
        let silent = "  Duration: 00:00:05.00, start: 0.0\n  Stream #0:0: Video: h264 (High), yuv420p, 640x480 [SAR 1:1 DAR 4:3], 30 fps";
        assert_eq!(parse_probe(silent).unwrap(), Probe { duration_ms: 5000, width: 640, height: 480, audio_channels: None });
        // An old-style rotation line, and a cover image that isn't the video.
        let old = "  Duration: 00:00:02.50\n  Stream #0:0: Video: mjpeg, 300x300 (attached pic)\n  Stream #0:1: Video: h264, 1280x720, 30 fps\n    Side data:\n      displaymatrix: rotation of 90.00 degrees\n  Stream #0:2: Audio: opus, 48000 Hz, stereo";
        assert_eq!(parse_probe(old).unwrap(), Probe { duration_ms: 2500, width: 720, height: 1280, audio_channels: Some(2) });
    }

    #[test]
    fn probe_refuses_non_videos() {
        assert!(parse_probe("clip.mp4: Invalid data found when processing input").is_err());
        assert!(parse_probe("  Duration: 00:03:00.00\n  Stream #0:0: Audio: mp3, 44100 Hz, stereo").is_err());
        assert!(parse_probe("  Duration: N/A\n  Stream #0:0: Video: h264, 640x480").is_err());
    }

    #[test]
    fn plan_follows_the_spec() {
        // Short clips: capped at 2,500 kb/s, 720p.
        assert_eq!(plan(10_000, true).unwrap(), Plan { video_kbps: 2500, max_side: 1280 });
        // 45 s still fits 720p; 60 s drops to 480p at about 1,170 kb/s.
        let p45 = plan(45_000, true).unwrap();
        assert_eq!(p45.max_side, 1280);
        assert!(p45.video_kbps >= 1500, "{p45:?}");
        assert_eq!(plan(60_000, true).unwrap(), Plan { video_kbps: 1170, max_side: 854 });
        // About 48 s is where 720p ends.
        assert_eq!(plan(47_000, true).unwrap().max_side, 1280);
        assert_eq!(plan(49_000, true).unwrap().max_side, 854);
        // No audio: the video gets its share.
        assert_eq!(plan(60_000, false).unwrap().video_kbps, 1266);
        // The guard (can't happen at 60 s).
        assert!(plan(200_000, true).is_err());
    }

    #[test]
    fn progress_lines() {
        assert_eq!(progress_us("out_time_us=1500000"), Some(1_500_000));
        assert_eq!(progress_us("out_time_ms=1500000"), Some(1_500_000));
        assert_eq!(progress_us("out_time_us=N/A"), None);
        assert_eq!(progress_us("frame=12"), None);
    }

    #[test]
    fn encode_args_strip_metadata_and_trim() {
        let info = Probe { duration_ms: 70_030, width: 1080, height: 1920, audio_channels: Some(1) };
        let a = encode_args(&info, 60_000, plan(60_000, true).unwrap()).join(" ");
        assert!(a.contains("-map_metadata -1"), "{a}");
        assert!(a.contains("-t 60.000"), "{a}");
        assert!(a.contains("min(854,iw)"), "{a}");
        assert!(a.contains("-b:v 1170k"), "{a}");
        assert!(a.contains("-ac 1"), "{a}");
        assert!(a.contains("+faststart"), "{a}");
    }

    /// An ffmpeg for the tests that run it: SIDETRAY_FFMPEG, which must also
    /// have the lavfi test sources (any full build does) to make the inputs.
    fn test_ffmpeg() -> Option<PathBuf> {
        std::env::var_os("SIDETRAY_FFMPEG").map(PathBuf::from)
    }

    async fn make_source(ffmpeg: &std::path::Path, out: &std::path::Path, secs: u32, size: &str) {
        let st = command(ffmpeg)
            .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i"])
            .arg(format!("testsrc2=size={size}:rate=60"))
            .args(["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000"])
            .args(["-t", &secs.to_string(), "-c:v", "mpeg4", "-q:v", "2", "-c:a", "aac"])
            .args(["-metadata", "location=+51.5074-000.1278/", "-metadata", "comment=GPS-SECRET-MARKER"])
            .arg(out)
            .status()
            .await
            .unwrap();
        assert!(st.success());
    }

    #[tokio::test]
    async fn prepares_a_clip_with_a_poster_and_no_metadata() {
        let Some(ff) = test_ffmpeg() else { return };
        let dir = std::env::temp_dir().join(format!("sidetray-video-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.mp4");
        make_source(&ff, &src, 4, "1920x1080").await;
        let out = dir.join("out.mp4");
        let seen = std::sync::Mutex::new(Vec::new());
        let p = prepare(&ff, &src, &out, &Cancel::default(), |f| seen.lock().unwrap().push(f)).await.unwrap();
        assert_eq!((p.width, p.height), (1280, 720));
        assert!((3900..=4200).contains(&p.duration_ms), "{}", p.duration_ms);
        assert!(p.size <= TARGET_BYTES && p.size > 10_000);
        let bytes = std::fs::read(&out).unwrap();
        for secret in [&b"51.5074"[..], b"GPS-SECRET-MARKER"] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret), "metadata survived");
        }
        let info = String::from_utf8_lossy(&command(&ff).arg("-hide_banner").arg("-i").arg(&out).output().await.unwrap().stderr).to_string();
        assert!(info.contains("h264") && info.contains("aac") && info.contains("30 fps"), "{info}");
        let thumb = image::load_from_memory_with_format(&p.thumb, image::ImageFormat::WebP).unwrap();
        assert_eq!((thumb.width(), thumb.height()), (400, 225));
        assert_eq!(*seen.lock().unwrap().last().unwrap(), 1.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn long_clips_are_cut_to_60_seconds_at_480p() {
        let Some(ff) = test_ffmpeg() else { return };
        let dir = std::env::temp_dir().join(format!("sidetray-video-long-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("long.mp4");
        make_source(&ff, &src, 65, "640x360").await;
        let p = prepare(&ff, &src, &dir.join("out.mp4"), &Cancel::default(), |_| {}).await.unwrap();
        assert!((59_500..=60_500).contains(&p.duration_ms), "{}", p.duration_ms);
        // 640x360 is under 480p's 854: kept, not upscaled.
        assert_eq!((p.width, p.height), (640, 360));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancel_stops_the_encoder() {
        let Some(ff) = test_ffmpeg() else { return };
        let dir = std::env::temp_dir().join(format!("sidetray-video-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.mp4");
        make_source(&ff, &src, 30, "1920x1080").await;
        let cancel = Cancel::default();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            c2.notify_one();
        });
        let e = prepare(&ff, &src, &dir.join("out.mp4"), &cancel, |_| {}).await.unwrap_err();
        assert_eq!(e.to_string(), CANCELLED);
        assert!(!dir.join("out.mp4").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_configured_ffmpeg_can_encode() {
        // Runs only where an ffmpeg is configured (SIDETRAY_FFMPEG).
        if std::env::var_os("SIDETRAY_FFMPEG").is_none() {
            return;
        }
        let s = support().await;
        assert!(s.can_send, "{:?}", s.reason);
    }
}
