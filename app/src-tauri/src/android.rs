//! The app's own Kotlin helper (`SideTrayAndroid` in
//! gen/android/app/src/main/java/org/sidetray/app/SideTrayAndroid.kt), called
//! over JNI: content shared to Side Tray from other apps, leaving the app on
//! the back button, deleting camera originals, and decoding photo formats only
//! Android can read (HEIC/HEIF, AVIF).

use crate::keystore::with_env;
use anyhow::{bail, Context, Result};
use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::JNIEnv;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

const HELPER: &str = "org.sidetray.app.SideTrayAndroid";

/// The app's classes aren't visible to `FindClass` from a native thread, so
/// load the helper through the activity's class loader.
fn helper<'a>(env: &mut JNIEnv<'a>) -> Result<JClass<'a>> {
    let ctx = ndk_context::android_context();
    // SAFETY: tao keeps a global reference to the activity in ndk-context for
    // the life of the process; this borrows it without taking ownership.
    let context = unsafe { JObject::from_raw(ctx.context().cast()) };
    let loader = env.call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
    let name = env.new_string(HELPER)?;
    let class = env
        .call_method(&loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[JValue::Object(&name)])?
        .l()?;
    Ok(JClass::from(class))
}

fn call_void(method: &str) -> Result<()> {
    with_env(|env| {
        let class = helper(env)?;
        env.call_static_method(&class, method, "()V", &[])?;
        Ok(())
    })
}

/// System bars and cutouts, in CSS pixels: [top, right, bottom, left].
pub fn insets() -> Result<Option<[f32; 4]>> {
    let s = with_env(|env| {
        let class = helper(env)?;
        let s = env.call_static_method(&class, "insets", "()Ljava/lang/String;", &[])?.l()?;
        if s.is_null() {
            return Ok(None);
        }
        Ok(Some(String::from(env.get_string(&JString::from(s))?)))
    })?;
    let Some(s) = s else { return Ok(None) };
    let v: Vec<f32> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    Ok(v.try_into().ok())
}

/// Back button with nothing left to close: background the app, like Home.
pub fn move_to_background() -> Result<()> {
    call_void("moveToBackground")
}

/// Delete the camera's full-size originals (they carry location data).
pub fn clean_captures() -> Result<()> {
    call_void("cleanCaptures")
}

/// Decode with Android's own decoder (HEIC/HEIF, AVIF), EXIF orientation
/// applied, longest side at most `max_side`. `None` if Android can't either.
pub fn decode_image(bytes: &[u8], max_side: u32) -> Result<Option<image::RgbaImage>> {
    let out = with_env(|env| {
        let class = helper(env)?;
        let input = env.byte_array_from_slice(bytes)?;
        let max = i32::try_from(max_side).unwrap_or(i32::MAX);
        let out = env.call_static_method(&class, "decodeImage", "([BI)[B", &[JValue::Object(&input), JValue::Int(max)])?.l()?;
        if out.is_null() {
            return Ok(None);
        }
        Ok(Some(env.convert_byte_array(JByteArray::from(out))?))
    })
    .context("decoding the photo with Android's decoder")?;
    let Some(out) = out else { return Ok(None) };
    if out.len() < 8 {
        bail!("Android's decoder returned nothing");
    }
    let w = u32::from_be_bytes(out[0..4].try_into().unwrap());
    let h = u32::from_be_bytes(out[4..8].try_into().unwrap());
    let img = image::RgbaImage::from_raw(w, h, out[8..].to_vec()).context("Android's decoder returned a damaged image")?;
    Ok(Some(img))
}

// --- Share → Side Tray ---------------------------------------------------------------

#[derive(Deserialize)]
struct SharedFile {
    path: PathBuf,
}

#[derive(Deserialize)]
struct Shared {
    text: String,
    subject: String,
    dir: PathBuf,
    files: Vec<SharedFile>,
    skipped: usize,
    errors: Vec<String>,
}

/// What another app shared, as the UI sees it. The pictures stay in the app's
/// cache until `take_shared_photo` reads them, by index.
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ShareView {
    /// Still copying the pictures out of the other app: ask again shortly.
    Copying,
    Ready {
        text: String,
        subject: String,
        photos: usize,
        /// Files that weren't pictures (or over the limit of 20).
        skipped: usize,
        errors: Vec<String>,
    },
}

/// The share being worked on: its folder and pictures (taken ones are `None`).
static CURRENT: Mutex<Option<(PathBuf, Vec<Option<PathBuf>>)>> = Mutex::new(None);

pub fn take_share() -> Result<Option<ShareView>> {
    let s = with_env(|env| {
        let class = helper(env)?;
        let s = env.call_static_method(&class, "takeShare", "()Ljava/lang/String;", &[])?.l()?;
        if s.is_null() {
            return Ok(None);
        }
        Ok(Some(String::from(env.get_string(&JString::from(s))?)))
    })?;
    let Some(s) = s else { return Ok(None) };
    if s == "copying" {
        return Ok(Some(ShareView::Copying));
    }
    let shared: Shared = serde_json::from_str(&s).context("reading what was shared")?;
    let photos = shared.files.len();
    end_share();
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((shared.dir, shared.files.into_iter().map(|f| Some(f.path)).collect()));
    Ok(Some(ShareView::Ready { text: shared.text, subject: shared.subject, photos, skipped: shared.skipped, errors: shared.errors }))
}

/// The shared picture number `index`, read once and deleted.
pub fn take_shared_photo(index: usize) -> Result<Vec<u8>> {
    let path = {
        let mut cur = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
        let Some((_, files)) = cur.as_mut() else { bail!("that share is over") };
        files.get_mut(index).and_then(Option::take).context("that shared picture was already used")?
    };
    let bytes = std::fs::read(&path).context("reading a shared picture");
    let _ = std::fs::remove_file(&path);
    bytes
}

/// Done with the current share: delete whatever's left of it.
pub fn end_share() {
    if let Some((dir, _)) = CURRENT.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = std::fs::remove_dir_all(dir);
    }
}
