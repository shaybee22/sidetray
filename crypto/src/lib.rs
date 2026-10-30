//! Side Tray crypto core (SPEC.md, "Crypto and onboarding").
//!
//! Pure-Rust primitives whose wire formats match libsodium, so any libsodium
//! binding can read what this crate writes:
//!
//! | Operation            | Construction                    | libsodium equivalent                        |
//! | -------------------- | ------------------------------- | ------------------------------------------- |
//! | Group key delivery   | X25519 + XSalsa20-Poly1305 seal | `crypto_box_seal` / `crypto_box_seal_open`  |
//! | Content encryption   | XChaCha20-Poly1305 (IETF)       | `crypto_aead_xchacha20poly1305_ietf_*`      |
//! | Authorship           | Ed25519 detached signatures     | `crypto_sign_detached` / `_verify_detached` |
//! | Safety code hash     | BLAKE2b-256                     | `crypto_generichash` (32-byte output)       |
//!
//! Formats:
//!
//! - Sealed group key: `crypto_box_seal(key_version as u32 LE || key[32])`,
//!   84 bytes. The version is inside the seal so a relabelled blob is detected.
//! - Content blob: `nonce[24] || ciphertext || tag[16]`, with associated data
//!   `key_version as u32 LE || caller_ad`. Binding the version means a blob
//!   relabelled with a different `key_version` fails to decrypt.
//! - Safety code: see [`safety_code`].

use blake2::{digest::consts::U32, Blake2b, Digest};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod protocol;
mod wordlist;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const GROUP_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// `crypto_box_SEALBYTES`: ephemeral public key (32) + MAC (16).
pub const SEAL_OVERHEAD: usize = 48;
/// Length of a sealed group key blob.
pub const SEALED_GROUP_KEY_LEN: usize = SEAL_OVERHEAD + 4 + GROUP_KEY_LEN;

/// Domain separator for the safety-code hash. Bump the suffix if the
/// derivation or wordlist ever changes.
pub const SAFETY_CODE_DOMAIN: &[u8] = b"sidetray/safety-code/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A public key isn't a valid key for its algorithm.
    InvalidPublicKey,
    /// Unsealing or decryption failed: wrong key, wrong version or tampered data.
    Decrypt,
    /// The signature doesn't match the message and public key.
    BadSignature,
    /// Input has the wrong length or structure.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidPublicKey => "invalid public key",
            Error::Decrypt => "decryption failed",
            Error::BadSignature => "signature verification failed",
            Error::Malformed => "malformed input",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Device keys
// ---------------------------------------------------------------------------

/// A device's private keys: X25519 for receiving sealed group keys and
/// Ed25519 for signing. Never leaves the device. Zeroized on drop.
pub struct DeviceKeys {
    enc: crypto_box::SecretKey,
    sign: SigningKey,
}

/// The public half of a device's keys, as sent in a join request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePublicKeys {
    pub enc: [u8; PUBLIC_KEY_LEN],
    pub sign: [u8; PUBLIC_KEY_LEN],
}

impl DeviceKeys {
    /// Restore keys from their stored secret bytes.
    pub fn from_secret_bytes(enc: &[u8; SECRET_KEY_LEN], sign: &[u8; SECRET_KEY_LEN]) -> Self {
        DeviceKeys {
            enc: crypto_box::SecretKey::from(*enc),
            sign: SigningKey::from_bytes(sign),
        }
    }

    /// X25519 secret key bytes, for storage in the OS keychain.
    pub fn enc_secret_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        Zeroizing::new(self.enc.to_bytes())
    }

    /// Ed25519 secret key (seed) bytes, for storage in the OS keychain.
    pub fn sign_secret_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        Zeroizing::new(self.sign.to_bytes())
    }

    pub fn public(&self) -> DevicePublicKeys {
        DevicePublicKeys {
            enc: *self.enc.public_key().as_bytes(),
            sign: self.sign.verifying_key().to_bytes(),
        }
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeys")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// Generate a fresh device identity (X25519 + Ed25519) from the OS RNG.
pub fn generate_device_keys() -> DeviceKeys {
    DeviceKeys {
        enc: crypto_box::SecretKey::generate(&mut OsRng),
        sign: SigningKey::generate(&mut OsRng),
    }
}

// ---------------------------------------------------------------------------
// Group keys
// ---------------------------------------------------------------------------

/// A symmetric group key and its version. Zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct GroupKey {
    version: u32,
    key: [u8; GROUP_KEY_LEN],
}

impl GroupKey {
    pub fn from_bytes(version: u32, key: &[u8; GROUP_KEY_LEN]) -> Self {
        GroupKey { version, key: *key }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// Raw key bytes, for local storage.
    pub fn key_bytes(&self) -> Zeroizing<[u8; GROUP_KEY_LEN]> {
        Zeroizing::new(self.key)
    }
}

impl fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupKey")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Generate 32 random bytes as the group key for `version`.
pub fn generate_group_key(version: u32) -> GroupKey {
    let mut key = [0u8; GROUP_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let gk = GroupKey { version, key };
    key.zeroize();
    gk
}

/// Seal a group key to a device's X25519 public key (`crypto_box_seal`).
///
/// Sealed boxes are anonymous: the recipient can't tell who sealed it. If the
/// recipient needs to know a Key Master produced the blob, sign it too.
pub fn seal_group_key(group_key: &GroupKey, recipient_enc_pk: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut payload = Zeroizing::new([0u8; 4 + GROUP_KEY_LEN]);
    payload[..4].copy_from_slice(&group_key.version.to_le_bytes());
    payload[4..].copy_from_slice(&group_key.key);
    crypto_box::PublicKey::from(*recipient_enc_pk)
        .seal(&mut OsRng, &payload[..])
        .expect("sealing into a Vec cannot fail")
}

/// Open a sealed group key with this device's X25519 secret key.
pub fn unseal_group_key(device: &DeviceKeys, sealed: &[u8]) -> Result<GroupKey> {
    if sealed.len() != SEALED_GROUP_KEY_LEN {
        return Err(Error::Malformed);
    }
    let payload = Zeroizing::new(device.enc.unseal(sealed).map_err(|_| Error::Decrypt)?);
    let version = u32::from_le_bytes(payload[..4].try_into().expect("length checked"));
    let key: &[u8; GROUP_KEY_LEN] = payload[4..].try_into().map_err(|_| Error::Malformed)?;
    Ok(GroupKey::from_bytes(version, key))
}

// ---------------------------------------------------------------------------
// Content encryption
// ---------------------------------------------------------------------------

fn content_aad(key_version: u32, ad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + ad.len());
    aad.extend_from_slice(&key_version.to_le_bytes());
    aad.extend_from_slice(ad);
    aad
}

/// Encrypt post/comment/reaction/media bytes with the group key.
///
/// Returns `nonce || ciphertext || tag`. The key's version is bound as
/// associated data, followed by `ad` (pass `&[]` if there's nothing else to
/// bind). Store `group_key.version()` alongside the blob as `key_version`.
pub fn encrypt(group_key: &GroupKey, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new((&group_key.key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = content_aad(group_key.version, ad);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory input");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a blob from [`encrypt`] with the group key whose version matches
/// the blob's `key_version`. Fails on any tampering, wrong key, wrong version
/// or different `ad`.
pub fn decrypt(group_key: &GroupKey, blob: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Malformed);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new((&group_key.key).into());
    let aad = content_aad(group_key.version, ad);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| Error::Decrypt)
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// Sign `message` with the device's Ed25519 key (detached, 64 bytes).
pub fn sign(device: &DeviceKeys, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    device.sign.sign(message).to_bytes()
}

/// Verify a detached Ed25519 signature. Uses strict verification (rejects
/// small-order keys and non-canonical signatures), like libsodium.
pub fn verify(sign_pk: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(sign_pk).map_err(|_| Error::InvalidPublicKey)?;
    let sig: &[u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| Error::Malformed)?;
    vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| Error::BadSignature)
}

// ---------------------------------------------------------------------------
// Safety code
// ---------------------------------------------------------------------------

/// The code both screens show during a join, e.g. `TACO-RIVER-MAPLE-LANTERN-42`.
///
/// `h = BLAKE2b-256(SAFETY_CODE_DOMAIN || enc_pk || sign_pk)`. The first 40 bits
/// of `h` (big-endian) are split into four 10-bit indices into the 1024-word
/// list, and the number is `u16::from_be_bytes([h[5], h[6]]) % 100`,
/// zero-padded to two digits. About 46 bits in all.
///
/// Both public keys are covered, so swapping either one in transit changes
/// the code. Pure byte arithmetic on a fixed hash and a compiled-in list, so
/// the result is the same on every platform.
pub fn safety_code(device: &DevicePublicKeys) -> String {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(SAFETY_CODE_DOMAIN);
    hasher.update(device.enc);
    hasher.update(device.sign);
    let h = hasher.finalize();
    let bits = u64::from_be_bytes([0, 0, 0, h[0], h[1], h[2], h[3], h[4]]);
    let word = |i: u32| wordlist::WORDS[((bits >> (30 - 10 * i)) & 0x3ff) as usize];
    let n = u16::from_be_bytes([h[5], h[6]]) % 100;
    format!("{}-{}-{}-{}-{:02}", word(0), word(1), word(2), word(3), n)
}

#[cfg(test)]
mod tests;
