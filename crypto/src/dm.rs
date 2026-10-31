//! Direct messages (SPEC "Phase 5b: Direct messages").
//!
//! Each message gets a fresh 32-byte [`MessageKey`]. Its text and photos are
//! encrypted with that key (XChaCha20-Poly1305, as for posts, but with no key
//! version in the associated data), and the key is sealed (`crypto_box_seal`)
//! to every device the message is for: all of the recipient's devices and the
//! sender's other devices. The sender signs [`protocol::dm_message`], which
//! covers the recipient list and every sealed key, so the relay can't add,
//! drop or swap a recipient.

use crate::{protocol, sign, verify, DeviceKeys, Error, Result, NONCE_LEN, PUBLIC_KEY_LEN, SEAL_OVERHEAD, SIGNATURE_LEN, TAG_LEN};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use std::collections::BTreeSet;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MESSAGE_KEY_LEN: usize = 32;
/// Length of a message key sealed to one device.
pub const SEALED_MESSAGE_KEY_LEN: usize = SEAL_OVERHEAD + MESSAGE_KEY_LEN;

/// The key of one direct message. Zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey([u8; MESSAGE_KEY_LEN]);

impl MessageKey {
    pub fn generate() -> Self {
        let mut k = [0u8; MESSAGE_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        let key = MessageKey(k);
        k.zeroize();
        key
    }

    pub fn from_bytes(key: &[u8; MESSAGE_KEY_LEN]) -> Self {
        MessageKey(*key)
    }

    /// Raw key bytes, for local storage (wrapped) so photos can be fetched later.
    pub fn key_bytes(&self) -> Zeroizing<[u8; MESSAGE_KEY_LEN]> {
        Zeroizing::new(self.0)
    }

    /// Encrypt text or a photo: `nonce[24] || ciphertext || tag[16]`, bound to `ad`.
    pub fn encrypt(&self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad: ad })
            .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory input");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn decrypt(&self, blob: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Malformed);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        XChaCha20Poly1305::new((&self.0).into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
            .map_err(|_| Error::Decrypt)
    }

    /// Seal this key to one device's X25519 public key.
    pub fn seal_to(&self, recipient_enc_pk: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
        crypto_box::PublicKey::from(*recipient_enc_pk)
            .seal(&mut OsRng, &self.0[..])
            .expect("sealing into a Vec cannot fail")
    }
}

impl fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessageKey(..)")
    }
}

/// Open a message key sealed to this device.
pub fn unseal_message_key(device: &DeviceKeys, sealed: &[u8]) -> Result<MessageKey> {
    if sealed.len() != SEALED_MESSAGE_KEY_LEN {
        return Err(Error::Malformed);
    }
    let plain = Zeroizing::new(device.enc.unseal(sealed).map_err(|_| Error::Decrypt)?);
    let key: &[u8; MESSAGE_KEY_LEN] = plain[..].try_into().map_err(|_| Error::Malformed)?;
    Ok(MessageKey::from_bytes(key))
}

/// The id both members' apps compute for their conversation: 32 hex
/// characters of a hash of the group and the two member ids (in either order).
pub fn conversation_id(group_id: &str, member_a: &str, member_b: &str) -> String {
    crate::domain_hash(b"sidetray/conversation-id/v1", &protocol::conversation_fields(group_id, member_a, member_b))[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A direct message ready to upload.
pub struct SealedDm {
    pub ciphertext: Vec<u8>,
    /// (device id, the message key sealed to it), one per recipient device.
    pub sealed_keys: Vec<(String, Vec<u8>)>,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Encrypt `plaintext` with `key`, seal the key to every recipient device
/// (from the verified roster: `(device id, X25519 public key)`), and sign.
/// Encrypt the message's photos with the same key first (AD
/// [`protocol::dm_media_ad`]) and put their digests in `plaintext`.
pub fn seal_dm(
    sender: &DeviceKeys,
    group_id: &str,
    conversation_id: &str,
    sender_device_id: &str,
    key: &MessageKey,
    plaintext: &[u8],
    recipients: &[(String, [u8; PUBLIC_KEY_LEN])],
) -> Result<SealedDm> {
    let ids: BTreeSet<&str> = recipients.iter().map(|(d, _)| d.as_str()).collect();
    if recipients.is_empty() || ids.len() != recipients.len() || ids.contains(sender_device_id) {
        return Err(Error::Malformed);
    }
    let ciphertext = key.encrypt(plaintext, &protocol::dm_ad(group_id, conversation_id));
    let sealed_keys: Vec<(String, Vec<u8>)> = recipients.iter().map(|(d, pk)| (d.clone(), key.seal_to(pk))).collect();
    let signature = sign(sender, &protocol::dm_message(group_id, conversation_id, sender_device_id, &sealed_keys, &ciphertext));
    Ok(SealedDm { ciphertext, sealed_keys, signature })
}

/// The receiving side: check the sender's signature over the whole message
/// (all recipients included), that this device is one of the recipients and
/// appears once, then unseal the key and decrypt. The caller checks that
/// `sender_sign_pk` belongs to a verified member and that the conversation id
/// is the one for the two members involved.
#[allow(clippy::too_many_arguments)]
pub fn open_dm(
    me: &DeviceKeys,
    my_device_id: &str,
    group_id: &str,
    conversation_id: &str,
    sender_device_id: &str,
    sender_sign_pk: &[u8; PUBLIC_KEY_LEN],
    ciphertext: &[u8],
    sealed_keys: &[(String, Vec<u8>)],
    signature: &[u8],
) -> Result<(MessageKey, Vec<u8>)> {
    let ids: BTreeSet<&str> = sealed_keys.iter().map(|(d, _)| d.as_str()).collect();
    if ids.len() != sealed_keys.len() {
        return Err(Error::Malformed);
    }
    verify(sender_sign_pk, &protocol::dm_message(group_id, conversation_id, sender_device_id, sealed_keys, ciphertext), signature)?;
    let mine = sealed_keys.iter().find(|(d, _)| d == my_device_id).ok_or(Error::Malformed)?;
    let key = unseal_message_key(me, &mine.1)?;
    let plain = key.decrypt(ciphertext, &protocol::dm_ad(group_id, conversation_id))?;
    Ok((key, plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_device_keys;

    #[test]
    fn conversation_ids_are_symmetric_and_per_group() {
        let a = conversation_id("g", "m_ana", "m_bo");
        assert_eq!(a, conversation_id("g", "m_bo", "m_ana"));
        assert_eq!(a.len(), 32);
        assert_ne!(a, conversation_id("h", "m_ana", "m_bo"));
        assert_ne!(a, conversation_id("g", "m_ana", "m_cy"));
        // Python (the relay) computes the same: pinned so a change on either side is caught.
        assert_eq!(conversation_id("g_1", "m_a", "m_b"), "dbc7a9437fdca0816b5a0237c041d789");
    }

    #[test]
    fn every_recipient_opens_and_nobody_else() {
        let sender = generate_device_keys();
        let sender_other = generate_device_keys();
        let bo1 = generate_device_keys();
        let bo2 = generate_device_keys();
        let outsider = generate_device_keys();
        let key = MessageKey::generate();
        let recipients = vec![
            ("d_bo1".to_string(), bo1.public().enc),
            ("d_bo2".to_string(), bo2.public().enc),
            ("d_ana2".to_string(), sender_other.public().enc),
        ];
        let m = seal_dm(&sender, "g", "c", "d_ana1", &key, b"hello", &recipients).unwrap();
        let spk = sender.public().sign;
        for (dev, keys) in [("d_bo1", &bo1), ("d_bo2", &bo2), ("d_ana2", &sender_other)] {
            let (k, plain) = open_dm(keys, dev, "g", "c", "d_ana1", &spk, &m.ciphertext, &m.sealed_keys, &m.signature).unwrap();
            assert_eq!(plain, b"hello");
            assert!(k == key);
        }
        // Not on the list.
        assert!(open_dm(&outsider, "d_out", "g", "c", "d_ana1", &spk, &m.ciphertext, &m.sealed_keys, &m.signature).is_err());
        // Someone else's sealed key relabelled as mine: the signature breaks.
        let mut swapped = m.sealed_keys.clone();
        swapped[0].0 = "d_out".into();
        assert!(open_dm(&outsider, "d_out", "g", "c", "d_ana1", &spk, &m.ciphertext, &swapped, &m.signature).is_err());
        // Dropping a recipient, another conversation or group, or a forged sender: refused.
        let fewer = &m.sealed_keys[..2];
        assert_eq!(
            open_dm(&bo1, "d_bo1", "g", "c", "d_ana1", &spk, &m.ciphertext, fewer, &m.signature).unwrap_err(),
            Error::BadSignature
        );
        assert!(open_dm(&bo1, "d_bo1", "g", "c2", "d_ana1", &spk, &m.ciphertext, &m.sealed_keys, &m.signature).is_err());
        assert!(open_dm(&bo1, "d_bo1", "h", "c", "d_ana1", &spk, &m.ciphertext, &m.sealed_keys, &m.signature).is_err());
        let forger = generate_device_keys().public().sign;
        assert!(open_dm(&bo1, "d_bo1", "g", "c", "d_ana1", &forger, &m.ciphertext, &m.sealed_keys, &m.signature).is_err());
        // The relay reordering the list is fine.
        let mut reordered = m.sealed_keys.clone();
        reordered.reverse();
        assert!(open_dm(&bo2, "d_bo2", "g", "c", "d_ana1", &spk, &m.ciphertext, &reordered, &m.signature).is_ok());
        // Listing me twice is refused.
        let mut twice = m.sealed_keys.clone();
        twice.push(twice[0].clone());
        assert_eq!(open_dm(&bo1, "d_bo1", "g", "c", "d_ana1", &spk, &m.ciphertext, &twice, &m.signature).unwrap_err(), Error::Malformed);
    }

    #[test]
    fn photos_use_the_message_key_with_their_own_ad() {
        let key = MessageKey::generate();
        let blob = key.encrypt(b"webp bytes", &protocol::dm_media_ad("g", "c"));
        assert_eq!(key.decrypt(&blob, &protocol::dm_media_ad("g", "c")).unwrap(), b"webp bytes");
        assert!(key.decrypt(&blob, &protocol::dm_ad("g", "c")).is_err());
        assert!(MessageKey::generate().decrypt(&blob, &protocol::dm_media_ad("g", "c")).is_err());
        let sealed = key.seal_to(&generate_device_keys().public().enc);
        assert_eq!(sealed.len(), SEALED_MESSAGE_KEY_LEN);
    }

    #[test]
    fn bad_recipient_lists_are_refused_when_sealing() {
        let s = generate_device_keys();
        let pk = generate_device_keys().public().enc;
        let key = MessageKey::generate();
        assert!(seal_dm(&s, "g", "c", "d_me", &key, b"x", &[]).is_err());
        assert!(seal_dm(&s, "g", "c", "d_me", &key, b"x", &[("d_me".into(), pk)]).is_err());
        assert!(seal_dm(&s, "g", "c", "d_me", &key, b"x", &[("d_a".into(), pk), ("d_a".into(), pk)]).is_err());
    }
}
