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

/// Associated data for an event's content encryption (the key version is
/// added by [`crate::encrypt`] itself).
pub fn event_ad(group_id: &str, kind: &str) -> Vec<u8> {
    framed(b"sidetray/event-ad/v1", &[group_id.as_bytes(), kind.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn domains_are_distinct() {
        // A grant signature must never verify as an event signature.
        let grant = key_grant_message("g", "d", &[0; 32], 1, b"x");
        let event = event_message("g", "d", "post", 1, b"x");
        assert_ne!(grant[..21], event[..21]);
    }
}
