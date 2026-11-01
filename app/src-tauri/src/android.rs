//! The app's own Kotlin helper (`SideTrayAndroid` in
//! gen/android/app/src/main/java/org/sidetray/app/SideTrayAndroid.kt), called
//! over JNI: content shared to Side Tray from other apps, leaving the app on
//! the back button, deleting camera originals, and decoding photo formats only
//! Android can read (HEIC/HEIF, AVIF); and for notifications (A3): showing
//! them, the notification permission, UnifiedPush registration and the
//! periodic sync. The other way, Kotlin calls the `Java_..._native*` functions
//! at the bottom: a push wake-up or the periodic job syncs through them,
//! possibly in a process where the window never started.

use crate::keystore::with_env;
use anyhow::{bail, Context, Result};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

const HELPER: &str = "org.sidetray.app.SideTrayAndroid";

/// The JavaVM and the application context, handed over by
/// `SideTrayAndroid.nativeInit`. A push wake-up or the periodic sync can start
/// the app's process without its window, so without tao and its ndk-context
/// (which can only be set once per process, by tao).
static JVM: OnceLock<(jni::JavaVM, GlobalRef)> = OnceLock::new();

/// The process's JavaVM pointer: ours if Kotlin set it, else tao's.
pub fn java_vm() -> Result<*mut jni::sys::JavaVM> {
    if let Some((vm, _)) = JVM.get() {
        return Ok(vm.get_java_vm_pointer());
    }
    if !ANDROID_CONTEXT_READY.load(Ordering::SeqCst) {
        bail!("Android isn't ready yet");
    }
    Ok(ndk_context::android_context().vm().cast())
}

/// Set once the Tauri window is up (tao has filled in ndk-context by then).
pub static ANDROID_CONTEXT_READY: AtomicBool = AtomicBool::new(false);

/// The app's classes aren't visible to `FindClass` from a native thread, so
/// load the helper through the app's class loader.
fn helper<'a>(env: &mut JNIEnv<'a>) -> Result<JClass<'a>> {
    let raw = match JVM.get() {
        Some((_, ctx)) => ctx.as_obj().as_raw(),
        // SAFETY: tao keeps a global reference to the application context in
        // ndk-context for the life of the process.
        None => ndk_context::android_context().context().cast(),
    };
    // Borrowed, not owned: both references live as long as the process.
    let context = unsafe { JObject::from_raw(raw) };
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

// --- notifications (A3) -----------------------------------------------------------

fn call_string(method: &str, args: &[&str]) -> Result<Option<String>> {
    with_env(|env| {
        let class = helper(env)?;
        let jargs: Vec<JObject> = args.iter().map(|a| env.new_string(a).map(JObject::from)).collect::<Result<_, _>>()?;
        let vals: Vec<JValue> = jargs.iter().map(JValue::Object).collect();
        let sig = format!("({})Ljava/lang/String;", "Ljava/lang/String;".repeat(args.len()));
        let s = env.call_static_method(&class, method, sig, &vals)?.l()?;
        if s.is_null() {
            return Ok(None);
        }
        Ok(Some(String::from(env.get_string(&JString::from(s))?)))
    })
}

/// One notification for `showNotifications` in Kotlin.
#[derive(Serialize)]
pub struct Note {
    /// The same id replaces an older notification (the same post, the same conversation).
    pub id: i32,
    pub channel: &'static str,
    pub title: String,
    pub body: String,
    /// JSON of `alerts::Target`; comes back through `take_open` when it's tapped.
    pub target: String,
}

pub fn notify(notes: &[Note]) -> Result<()> {
    if notes.is_empty() {
        return Ok(());
    }
    call_string("showNotifications", &[&serde_json::to_string(notes)?])?;
    Ok(())
}

/// What a tapped notification was about (JSON of `alerts::Target`), once.
pub fn take_open() -> Result<Option<String>> {
    call_string("takeOpen", &[])
}

/// "on" (allowed and switched on), "needs_permission" (Android 13+ hasn't been
/// granted it), or "off" (switched off in the system settings).
pub fn notification_state() -> Result<String> {
    Ok(call_string("notificationState", &[])?.unwrap_or_else(|| "off".into()))
}

/// Show Android's permission prompt. "asked", or "no_window" without an activity.
pub fn request_notification_permission() -> Result<String> {
    Ok(call_string("requestNotificationPermission", &[])?.unwrap_or_default())
}

pub fn open_notification_settings() -> Result<()> {
    call_string("openNotificationSettings", &[])?;
    Ok(())
}

/// The app is visible (set by Kotlin's process lifecycle observer, and by Tauri).
pub static FOREGROUND: AtomicBool = AtomicBool::new(false);

pub fn is_foreground() -> bool {
    FOREGROUND.load(Ordering::SeqCst)
}

// --- UnifiedPush and the periodic sync (A3) ---------------------------------------------

/// Register with the UnifiedPush distributor (picking one if none is chosen
/// yet). `fresh` unregisters first, so the distributor makes a new endpoint
/// (say, after its default server changed). The distributor's package, or
/// None if there's no distributor app on the phone.
pub fn push_register(fresh: bool) -> Result<Option<String>> {
    Ok(call_string("pushRegister", &[if fresh { "fresh" } else { "" }])?.filter(|d| !d.is_empty()))
}

pub fn push_unregister() -> Result<()> {
    call_string("pushUnregister", &[])?;
    Ok(())
}

/// Turn the periodic background sync (about every 15 minutes) on or off.
pub fn periodic_sync(on: bool) -> Result<()> {
    call_string("periodicSync", &[if on { "on" } else { "off" }])?;
    Ok(())
}

// --- called from Kotlin ------------------------------------------------------------------

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(String::from).unwrap_or_default()
}

fn ret(env: &mut JNIEnv, s: String) -> jstring {
    env.new_string(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Catch panics: unwinding into the JVM would take the whole process down.
fn guarded(what: &str, f: impl FnOnce() -> String + std::panic::UnwindSafe) -> String {
    std::panic::catch_unwind(f).unwrap_or_else(|_| format!("{what}: panicked"))
}

/// `SideTrayAndroid.nativeInit(context)`: remember the JavaVM and the application context.
#[no_mangle]
pub extern "system" fn Java_org_sidetray_app_SideTrayAndroid_nativeInit(env: JNIEnv, _class: JClass, context: JObject) {
    if JVM.get().is_some() {
        return;
    }
    let (Ok(vm), Ok(ctx)) = (env.get_java_vm(), env.new_global_ref(&context)) else { return };
    let _ = JVM.set((vm, ctx));
}

/// `SideTrayAndroid.nativeForeground(visible)`: the app came to the front or left it.
#[no_mangle]
pub extern "system" fn Java_org_sidetray_app_SideTrayAndroid_nativeForeground(_env: JNIEnv, _class: JClass, visible: jboolean) {
    let visible = visible != 0;
    FOREGROUND.store(visible, Ordering::SeqCst);
    crate::mobile_push::foreground_changed(visible);
}

/// `SideTrayAndroid.nativeSync(dataDir)`: a wake-up or the periodic job. Syncs
/// (which shows any notifications) and returns a line for the log.
#[no_mangle]
pub extern "system" fn Java_org_sidetray_app_SideTrayAndroid_nativeSync(mut env: JNIEnv, _class: JClass, dir: JString) -> jstring {
    let dir = PathBuf::from(jstr(&mut env, &dir));
    let out = guarded("sync", move || crate::mobile_push::background_sync(dir));
    ret(&mut env, out)
}

/// `SideTrayAndroid.nativePush(dataDir, kind, value)`: the distributor gave a
/// new endpoint ("endpoint", the URL), or registration ended ("unregistered",
/// "failed" with the reason).
#[no_mangle]
pub extern "system" fn Java_org_sidetray_app_SideTrayAndroid_nativePush(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    kind: JString,
    value: JString,
) -> jstring {
    let (dir, kind, value) = (PathBuf::from(jstr(&mut env, &dir)), jstr(&mut env, &kind), jstr(&mut env, &value));
    let out = guarded("push", move || crate::mobile_push::push_event(dir, &kind, &value));
    ret(&mut env, out)
}
