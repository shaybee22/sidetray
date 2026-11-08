//! Settings for this device, whatever the group: `<data dir>/device-settings.json`.
//! Read when the profiles open, so the background sync (a push wake-up or the
//! periodic job, possibly without the window) follows them too.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

const FILE: &str = "device-settings.json";

#[derive(Serialize, Deserialize)]
struct DeviceSettings {
    /// SPEC Phase 9 "Mobile data": download videos while on a metered network.
    #[serde(default = "yes")]
    videos_on_mobile_data: bool,
}

fn yes() -> bool {
    true
}

static VIDEOS_ON_MOBILE_DATA: AtomicBool = AtomicBool::new(true);

pub fn load(root: &Path) {
    let s: Option<DeviceSettings> = std::fs::read(root.join(FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok());
    VIDEOS_ON_MOBILE_DATA.store(s.is_none_or(|s| s.videos_on_mobile_data), Ordering::SeqCst);
}

pub fn videos_on_mobile_data() -> bool {
    VIDEOS_ON_MOBILE_DATA.load(Ordering::SeqCst)
}

pub fn set_videos_on_mobile_data(root: &Path, on: bool) -> Result<()> {
    let s = DeviceSettings { videos_on_mobile_data: on };
    crate::feed::write_file(&root.join(FILE), &serde_json::to_vec_pretty(&s)?).context("saving the device settings")?;
    VIDEOS_ON_MOBILE_DATA.store(on, Ordering::SeqCst);
    Ok(())
}

/// Whether a video may download now without being asked for: always on a
/// computer; on a phone, unless the network is metered and the setting is off.
pub fn auto_download_videos() -> bool {
    videos_on_mobile_data() || !metered()
}

/// Android's "this network is metered" (mobile data, a hotspot, a Wi-Fi network
/// marked metered), asked at most every few seconds. Never on a computer.
fn metered() -> bool {
    #[cfg(target_os = "android")]
    {
        use std::sync::Mutex;
        use std::time::{Duration, Instant};
        static CACHE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);
        let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, m)) = *c {
            if at.elapsed() < Duration::from_secs(3) {
                return m;
            }
        }
        // If Android can't say, assume the careful answer.
        let m = crate::android::is_metered().unwrap_or(true);
        *c = Some((Instant::now(), m));
        m
    }
    #[cfg(not(target_os = "android"))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setting_is_saved_and_defaults_on() {
        let dir = std::env::temp_dir().join(format!("sidetray-device-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        load(&dir);
        assert!(videos_on_mobile_data());
        set_videos_on_mobile_data(&dir, false).unwrap();
        VIDEOS_ON_MOBILE_DATA.store(true, Ordering::SeqCst);
        load(&dir);
        assert!(!videos_on_mobile_data());
        // Computers are never metered.
        assert!(auto_download_videos());
        set_videos_on_mobile_data(&dir, true).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
