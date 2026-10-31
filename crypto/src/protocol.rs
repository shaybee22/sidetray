//! Byte strings that Side Tray signs or binds as associated data.
//!
//! Each starts with a domain string and then length-prefixes every field
//! (`u32 LE length || bytes`), so no two different inputs give the same bytes
//! and a signature for one purpose can't be replayed as another.

fn framed(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + fields.iter().map(|f| 4 + f.len()).sum::<usize>());
    out.extend_from_slice(domain);
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// What the approving Key Master signs for each sealed group key. Binds the
/// blob to the group, the recipient device and its key, and the key version,
/// so the server can't move a grant to another device or relabel it.
pub fn key_grant_message(
    group_id: &str,
    recipient_device_id: &str,
    recipient_enc_pk: &[u8; 32],
    key_version: u32,
    sealed_blob: &[u8],
) -> Vec<u8> {
    framed(
        b"sidetray/key-grant/v1",
        &[
            group_id.as_bytes(),
            recipient_device_id.as_bytes(),
            recipient_enc_pk,
            &key_version.to_le_bytes(),
            sealed_blob,
        ],
    )
}

/// What an author signs for each event they post.
pub fn event_message(
    group_id: &str,
    author_device_id: &str,
    kind: &str,
    key_version: u32,
    ciphertext: &[u8],
) -> Vec<u8> {
    framed(
        b"sidetray/event/v1",
        &[
            group_id.as_bytes(),
            author_device_id.as_bytes(),
            kind.as_bytes(),
            &key_version.to_le_bytes(),
            ciphertext,
        ],
    )
}

/// Associated data for encrypting a media blob (photo or thumbnail). The post
/// that references a blob also records its [`crate::blob_digest`], so the
/// server can't swap one group member's encrypted photo for another's.
pub fn media_ad(group_id: &str) -> Vec<u8> {
    framed(b"sidetray/media-ad/v1", &[group_id.as_bytes()])
}

/// Associated data for an event's content encryption (the key version is
/// added by [`crate::encrypt`] itself).
pub fn event_ad(group_id: &str, kind: &str) -> Vec<u8> {
    framed(b"sidetray/event-ad/v1", &[group_id.as_bytes(), kind.as_bytes()])
}

/// What a Key Master signs to certify one device of a member: who it belongs to,
/// what the member is called, the device's two public keys and the member's role.
#[allow(clippy::too_many_arguments)]
pub fn member_cert_message(
    group_id: &str,
    member_id: &str,
    device_id: &str,
    display_name: &str,
    role: &str,
    enc_pk: &[u8; 32],
    sign_pk: &[u8; 32],
    issuer_device_id: &str,
) -> Vec<u8> {
    framed(
        b"sidetray/member-cert/v1",
        &[
            group_id.as_bytes(),
            member_id.as_bytes(),
            device_id.as_bytes(),
            display_name.as_bytes(),
            role.as_bytes(),
            enc_pk,
            sign_pk,
            issuer_device_id.as_bytes(),
        ],
    )
}

/// What an approving Key Master signs to hand a new device the Key Master
/// signing keys it already trusts (its own included), as `(device_id, sign_pk)`.
/// Order doesn't matter: the list is sorted before framing.
pub fn anchors_message(group_id: &str, recipient_device_id: &str, anchors: &[(String, [u8; 32])]) -> Vec<u8> {
    let mut sorted: Vec<&(String, [u8; 32])> = anchors.iter().collect();
    sorted.sort();
    let mut fields: Vec<&[u8]> = vec![group_id.as_bytes(), recipient_device_id.as_bytes()];
    for (id, pk) in &sorted {
        fields.push(id.as_bytes());
        fields.push(pk);
    }
    framed(b"sidetray/anchors/v1", &fields)
}

/// The fields of a conversation id (see [`crate::dm::conversation_id`]): the
/// group and the two member ids, smaller first, so both sides get the same bytes.
pub fn conversation_fields(group_id: &str, member_a: &str, member_b: &str) -> Vec<u8> {
    let (lo, hi) = if member_a <= member_b { (member_a, member_b) } else { (member_b, member_a) };
    framed(b"", &[group_id.as_bytes(), lo.as_bytes(), hi.as_bytes()])
}

/// What the sender of a direct message signs: the group, the conversation,
/// the sending device, every recipient device with the message key sealed to
/// it (sorted by device id, so the order the server relays them in doesn't
/// matter), and the ciphertext. The server can't add, drop or swap a
/// recipient, or move the message to another conversation.
pub fn dm_message(
    group_id: &str,
    conversation_id: &str,
    sender_device_id: &str,
    sealed_keys: &[(String, Vec<u8>)],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut sorted: Vec<&(String, Vec<u8>)> = sealed_keys.iter().collect();
    sorted.sort();
    let count = (sorted.len() as u32).to_le_bytes();
    let mut fields: Vec<&[u8]> = vec![group_id.as_bytes(), conversation_id.as_bytes(), sender_device_id.as_bytes(), &count];
    for (device, sealed) in &sorted {
        fields.push(device.as_bytes());
        fields.push(sealed);
    }
    fields.push(ciphertext);
    framed(b"sidetray/dm/v1", &fields)
}

/// Associated data for a direct message's text (encrypted with its message key).
pub fn dm_ad(group_id: &str, conversation_id: &str) -> Vec<u8> {
    framed(b"sidetray/dm-ad/v1", &[group_id.as_bytes(), conversation_id.as_bytes()])
}

/// Associated data for a direct message's photos and thumbnails.
pub fn dm_media_ad(group_id: &str, conversation_id: &str) -> Vec<u8> {
    framed(b"sidetray/dm-media-ad/v1", &[group_id.as_bytes(), conversation_id.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_fields_matter_but_key_order_does_not() {
        let k = |d: &str, b: u8| (d.to_string(), vec![b; 80]);
        let base = dm_message("g", "c", "d", &[k("a", 1), k("b", 2)], b"ct");
        assert_eq!(base, dm_message("g", "c", "d", &[k("b", 2), k("a", 1)], b"ct"));
        for other in [
            dm_message("h", "c", "d", &[k("a", 1), k("b", 2)], b"ct"),
            dm_message("g", "e", "d", &[k("a", 1), k("b", 2)], b"ct"),
            dm_message("g", "c", "x", &[k("a", 1), k("b", 2)], b"ct"),
            dm_message("g", "c", "d", &[k("a", 1)], b"ct"),
            dm_message("g", "c", "d", &[k("a", 1), k("b", 3)], b"ct"),
            dm_message("g", "c", "d", &[k("a", 1), k("c", 2)], b"ct"),
            dm_message("g", "c", "d", &[k("a", 1), k("b", 2)], b"cu"),
        ] {
            assert_ne!(base, other);
        }
        assert_eq!(conversation_fields("g", "m1", "m2"), conversation_fields("g", "m2", "m1"));
        assert_ne!(conversation_fields("g", "m1", "m2"), conversation_fields("h", "m1", "m2"));
        assert_ne!(dm_ad("g", "c"), dm_media_ad("g", "c"));
    }

    #[test]
    fn fields_cannot_run_together() {
        assert_ne!(event_ad("ab", "c"), event_ad("a", "bc"));
        assert_ne!(event_message("g", "dx", "post", 1, b""), event_message("gd", "x", "post", 1, b""));
    }

    #[test]
    fn every_grant_field_matters() {
        let base = key_grant_message("g", "d", &[1; 32], 1, b"blob");
        assert_ne!(base, key_grant_message("h", "d", &[1; 32], 1, b"blob"));
        assert_ne!(base, key_grant_message("g", "e", &[1; 32], 1, b"blob"));
        assert_ne!(base, key_grant_message("g", "d", &[2; 32], 1, b"blob"));
        assert_ne!(base, key_grant_message("g", "d", &[1; 32], 2, b"blob"));
        assert_ne!(base, key_grant_message("g", "d", &[1; 32], 1, b"blob!"));
    }

    #[test]
    fn every_event_field_matters() {
        let base = event_message("g", "d", "post", 1, b"ct");
        assert_ne!(base, event_message("h", "d", "post", 1, b"ct"));
        assert_ne!(base, event_message("g", "e", "post", 1, b"ct"));
        assert_ne!(base, event_message("g", "d", "comment", 1, b"ct"));
        assert_ne!(base, event_message("g", "d", "post", 2, b"ct"));
        assert_ne!(base, event_message("g", "d", "post", 1, b"cu"));
    }

    #[test]
    fn every_cert_field_matters() {
        let m = |g, mi, d, n, r, e: u8, s: u8, i| member_cert_message(g, mi, d, n, r, &[e; 32], &[s; 32], i);
        let base = m("g", "m", "d", "Ana", "member", 1, 2, "k");
        for other in [
            m("h", "m", "d", "Ana", "member", 1, 2, "k"),
            m("g", "n", "d", "Ana", "member", 1, 2, "k"),
            m("g", "m", "e", "Ana", "member", 1, 2, "k"),
            m("g", "m", "d", "Anna", "member", 1, 2, "k"),
            m("g", "m", "d", "Ana", "keymaster", 1, 2, "k"),
            m("g", "m", "d", "Ana", "member", 3, 2, "k"),
            m("g", "m", "d", "Ana", "member", 1, 3, "k"),
            m("g", "m", "d", "Ana", "member", 1, 2, "j"),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn anchors_are_order_independent_but_complete() {
        let a = ("d1".to_string(), [1; 32]);
        let b = ("d2".to_string(), [2; 32]);
        assert_eq!(anchors_message("g", "r", &[a.clone(), b.clone()]), anchors_message("g", "r", &[b.clone(), a.clone()]));
        assert_ne!(anchors_message("g", "r", &[a.clone(), b.clone()]), anchors_message("g", "r", &[a.clone()]));
        assert_ne!(anchors_message("g", "r", &[a.clone()]), anchors_message("g", "s", &[a]));
    }

    #[test]
    fn domains_are_distinct() {
        // A grant signature must never verify as an event signature.
        let grant = key_grant_message("g", "d", &[0; 32], 1, b"x");
        let event = event_message("g", "d", "post", 1, b"x");
        assert_ne!(grant[..21], event[..21]);
    }
}
