//! A phone doesn't update itself yet (SPEC.md "Android app", A4): the update
//! commands report `off`, like a desktop build run from a checkout.

use serde::Serialize;
use tauri::AppHandle;

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    Off,
}

#[derive(Serialize, Clone)]
pub struct View {
    pub current_version: String,
    #[serde(flatten)]
    pub status: Status,
}

#[derive(Default)]
pub struct Updates;

pub fn installed() -> bool {
    false
}

pub fn view(handle: &AppHandle) -> View {
    View { current_version: handle.package_info().version.to_string(), status: Status::Off }
}

pub async fn check(handle: &AppHandle) -> View {
    view(handle)
}

pub fn install(_handle: &AppHandle) -> anyhow::Result<()> {
    anyhow::bail!("updates on a phone come as a new APK")
}

pub fn spawn(_handle: AppHandle) {}
