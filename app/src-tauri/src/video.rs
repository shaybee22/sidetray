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

#[cfg(test)]
mod tests {
    use super::*;

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
