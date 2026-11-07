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
