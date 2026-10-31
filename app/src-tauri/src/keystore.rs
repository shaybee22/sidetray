//! Android Keystore wrapping for this device's secrets (SPEC.md "Android app":
//! "Keys protected by the Android Keystore").
//!
//! The Keystore can't do X25519/Ed25519 on every phone, so it holds one
//! non-exportable AES-256-GCM key, and the app keeps its secrets blob (device
//! private keys, token, and the local key that wraps the group keys) encrypted
//! with it in app-private storage. The AES key never leaves the Keystore (the
//! TEE on most phones); clearing the app's data or uninstalling deletes it, and
//! the phone then has to join again as a new device.
//!
//! Called straight through JNI (the JavaVM from `ndk-context`), so it works
//! from any thread, including the main thread that runs sync commands.

use anyhow::{bail, Context, Result};
use jni::objects::{JByteArray, JObject, JValue};
use jni::JNIEnv;

const ALIAS: &str = "org.sidetray.app.device-secrets.v1";
/// Bound into every wrap: a blob from somewhere else doesn't unwrap here.
const AAD: &[u8] = b"sidetray/android-keystore/v1";
/// Wrapped blob: MAGIC || 12-byte IV || ciphertext with its GCM tag.
const MAGIC: &[u8] = b"STK1";
const IV_LEN: usize = 12;

const PURPOSE_ENCRYPT_DECRYPT: i32 = 1 | 2;
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;

pub fn wrap(plain: &[u8]) -> Result<Vec<u8>> {
    with_env(|env| {
        let key = key(env, true)?;
        let cipher = cipher(env)?;
        env.call_method(&cipher, "init", "(ILjava/security/Key;)V", &[JValue::Int(ENCRYPT_MODE), JValue::Object(&key)])?;
        update_aad(env, &cipher)?;
        let ct = do_final(env, &cipher, plain)?;
        let iv: JByteArray = env.call_method(&cipher, "getIV", "()[B", &[])?.l()?.into();
        let iv = env.convert_byte_array(iv)?;
        if iv.len() != IV_LEN {
            bail!("the Keystore picked a {}-byte IV", iv.len());
        }
        Ok([MAGIC, &iv, &ct].concat())
    })
    .context("protecting this device's keys with the Android Keystore")
}

pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>> {
    let Some(rest) = wrapped.strip_prefix(MAGIC).filter(|r| r.len() > IV_LEN) else {
        bail!("this device's stored keys are damaged");
    };
    let (iv, ct) = rest.split_at(IV_LEN);
    with_env(|env| {
        let Ok(key) = key(env, false) else {
            bail!("the Android Keystore no longer has this app's key (was the app's data restored from elsewhere?)");
        };
        let cipher = cipher(env)?;
        let iv = env.byte_array_from_slice(iv)?;
        let spec =
            env.new_object("javax/crypto/spec/GCMParameterSpec", "(I[B)V", &[JValue::Int(128), JValue::Object(&iv)])?;
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Int(DECRYPT_MODE), JValue::Object(&key), JValue::Object(&spec)],
        )?;
        update_aad(env, &cipher)?;
        do_final(env, &cipher, ct)
    })
    .context("unlocking this device's keys with the Android Keystore")
}

/// Attach this thread to the JVM, run `f` in a local reference frame, and turn
/// a pending Java exception into an error (cleared, so the thread stays usable).
fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T>) -> Result<T> {
    let ctx = ndk_context::android_context();
    // SAFETY: tao stores the process's JavaVM pointer in ndk-context at startup.
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;
    let out = env.with_local_frame(64, |env| -> Result<T> { f(env) });
    if env.exception_check().unwrap_or(false) {
        let thrown = env.exception_occurred().ok();
        let _ = env.exception_clear();
        let what = thrown.and_then(|t| describe(&mut env, &t)).unwrap_or_else(|| "a Java exception".into());
        bail!("{what}");
    }
    out
}

fn describe(env: &mut JNIEnv, t: &JObject) -> Option<String> {
    let s = env.call_method(t, "toString", "()Ljava/lang/String;", &[]).ok()?.l().ok()?;
    let s: String = env.get_string(&s.into()).ok()?.into();
    Some(s)
}

/// The app's AES key, created on first use when `create`.
fn key<'a>(env: &mut JNIEnv<'a>, create: bool) -> Result<JObject<'a>> {
    let provider = env.new_string("AndroidKeyStore")?;
    let ks = env
        .call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&provider)],
        )?
        .l()?;
    env.call_method(&ks, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", &[JValue::Object(&JObject::null())])?;
    let alias = env.new_string(ALIAS)?;
    let existing = env
        .call_method(&ks, "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;", &[JValue::Object(&alias), JValue::Object(&JObject::null())])?
        .l()?;
    if !existing.is_null() {
        return Ok(existing);
    }
    if !create {
        bail!("no key");
    }
    let aes = env.new_string("AES")?;
    let kg = env
        .call_static_method(
            "javax/crypto/KeyGenerator",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[JValue::Object(&aes), JValue::Object(&provider)],
        )?
        .l()?;
    let builder = env.new_object(
        "android/security/keystore/KeyGenParameterSpec$Builder",
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&alias), JValue::Int(PURPOSE_ENCRYPT_DECRYPT)],
    )?;
    let gcm = string_array(env, "GCM")?;
    let none = string_array(env, "NoPadding")?;
    const B: &str = "Landroid/security/keystore/KeyGenParameterSpec$Builder;";
    env.call_method(&builder, "setBlockModes", format!("([Ljava/lang/String;){B}"), &[JValue::Object(&gcm)])?;
    env.call_method(&builder, "setEncryptionPaddings", format!("([Ljava/lang/String;){B}"), &[JValue::Object(&none)])?;
    env.call_method(&builder, "setKeySize", format!("(I){B}"), &[JValue::Int(256)])?;
    // The Keystore picks the IV; never let a caller supply one.
    env.call_method(&builder, "setRandomizedEncryptionRequired", format!("(Z){B}"), &[JValue::Bool(1)])?;
    let spec = env.call_method(&builder, "build", "()Landroid/security/keystore/KeyGenParameterSpec;", &[])?.l()?;
    env.call_method(&kg, "init", "(Ljava/security/spec/AlgorithmParameterSpec;)V", &[JValue::Object(&spec)])?;
    Ok(env.call_method(&kg, "generateKey", "()Ljavax/crypto/SecretKey;", &[])?.l()?)
}

fn string_array<'a>(env: &mut JNIEnv<'a>, s: &str) -> Result<JObject<'a>> {
    let s = env.new_string(s)?;
    Ok(env.new_object_array(1, "java/lang/String", &s)?.into())
}

fn cipher<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
    let name = env.new_string("AES/GCM/NoPadding")?;
    Ok(env
        .call_static_method("javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", &[JValue::Object(&name)])?
        .l()?)
}

fn update_aad(env: &mut JNIEnv, cipher: &JObject) -> Result<()> {
    let aad = env.byte_array_from_slice(AAD)?;
    env.call_method(cipher, "updateAAD", "([B)V", &[JValue::Object(&aad)])?;
    Ok(())
}

fn do_final(env: &mut JNIEnv, cipher: &JObject, data: &[u8]) -> Result<Vec<u8>> {
    let input = env.byte_array_from_slice(data)?;
    let out: JByteArray = env.call_method(cipher, "doFinal", "([B)[B", &[JValue::Object(&input)])?.l()?.into();
    Ok(env.convert_byte_array(out)?)
}
