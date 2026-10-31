use super::*;

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// Flip one bit in each byte position in turn and check `check` rejects every variant.
fn assert_every_flip_fails(data: &[u8], check: impl Fn(&[u8]) -> bool) {
    assert!(check(data), "untampered input must pass");
    for i in 0..data.len() {
        let mut t = data.to_vec();
        t[i] ^= 0x01;
        assert!(!check(&t), "flipping byte {i} was not detected");
    }
}

// Fixed identity shared with the libsodium vectors below (generated with
// PyNaCl 1.6.2 / libsodium): enc secret = 0x01..=0x20, sign seed = 0x21..=0x40.
fn fixed_device() -> DeviceKeys {
    let enc: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    let sign: [u8; 32] = core::array::from_fn(|i| i as u8 + 33);
    DeviceKeys::from_secret_bytes(&enc, &sign)
}

// --- device keys -----------------------------------------------------------

#[test]
fn device_keys_are_random() {
    let a = generate_device_keys().public();
    let b = generate_device_keys().public();
    assert_ne!(a.enc, b.enc);
    assert_ne!(a.sign, b.sign);
}

#[test]
fn device_keys_round_trip_through_bytes() {
    let d = generate_device_keys();
    let restored = DeviceKeys::from_secret_bytes(&d.enc_secret_bytes(), &d.sign_secret_bytes());
    assert_eq!(d.public(), restored.public());
}

#[test]
fn fixed_device_public_keys_match_libsodium() {
    let p = fixed_device().public();
    assert_eq!(hex::encode(p.enc), "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
    assert_eq!(hex::encode(p.sign), "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0");
}

#[test]
fn debug_output_hides_secrets() {
    let gk = GroupKey::from_bytes(1, &[0xAB; 32]);
    assert_eq!(format!("{gk:?}"), "GroupKey { version: 1, .. }");
    let d = fixed_device();
    assert_eq!(format!("{d:?}"), format!("DeviceKeys {{ public: {:?}, .. }}", d.public()));
}

// --- group keys and sealing --------------------------------------------------

#[test]
fn group_keys_are_random_and_keep_version() {
    let a = generate_group_key(1);
    let b = generate_group_key(2);
    assert_ne!(*a.key_bytes(), *b.key_bytes());
    assert_eq!(a.version(), 1);
    assert_eq!(b.version(), 2);
    assert_eq!(GroupKey::from_bytes(1, &a.key_bytes()), a);
}

#[test]
fn seal_unseal_round_trip() {
    let device = generate_device_keys();
    for version in [1, 2, u32::MAX] {
        let gk = generate_group_key(version);
        let sealed = seal_group_key(&gk, &device.public().enc);
        assert_eq!(sealed.len(), SEALED_GROUP_KEY_LEN);
        assert_eq!(unseal_group_key(&device, &sealed).unwrap(), gk);
    }
}

#[test]
fn seal_is_randomized() {
    let device = generate_device_keys();
    let gk = generate_group_key(1);
    let pk = device.public().enc;
    assert_ne!(seal_group_key(&gk, &pk), seal_group_key(&gk, &pk));
}

#[test]
fn unseal_with_wrong_device_fails() {
    let gk = generate_group_key(1);
    let sealed = seal_group_key(&gk, &generate_device_keys().public().enc);
    assert_eq!(unseal_group_key(&generate_device_keys(), &sealed), Err(Error::Decrypt));
}

#[test]
fn unseal_detects_every_flipped_byte() {
    let device = generate_device_keys();
    let sealed = seal_group_key(&generate_group_key(5), &device.public().enc);
    assert_every_flip_fails(&sealed, |s| unseal_group_key(&device, s).is_ok());
}

#[test]
fn unseal_rejects_wrong_length() {
    let device = generate_device_keys();
    let sealed = seal_group_key(&generate_group_key(1), &device.public().enc);
    assert_eq!(unseal_group_key(&device, &sealed[..sealed.len() - 1]), Err(Error::Malformed));
    assert_eq!(unseal_group_key(&device, &[sealed.clone(), vec![0]].concat()), Err(Error::Malformed));
    assert_eq!(unseal_group_key(&device, &[]), Err(Error::Malformed));
}

#[test]
fn unseal_libsodium_sealed_box() {
    // crypto_box_seal(u32le(7) || [0x42; 32], fixed enc pk) from libsodium.
    let sealed = hex::decode(
        "9a499e2a918fa85ae1161e7f195a25571c4e6a0866b1861c71465ccbefb0f367\
         b1409fba6a5ac1aa44aef984d1e8c6be0d6c607a61e2324b564f3f6cb48d4eb9\
         e2dad45cc3514e5480b0535f1f0207587dcd3039",
    )
    .unwrap();
    let gk = unseal_group_key(&fixed_device(), &sealed).unwrap();
    assert_eq!(gk, GroupKey::from_bytes(7, &[0x42; 32]));
}

// --- content encryption -----------------------------------------------------

#[test]
fn encrypt_decrypt_round_trip() {
    let gk = generate_group_key(3);
    for msg in [&b""[..], b"hello", &vec![0x5A; 1 << 20]] {
        let blob = encrypt(&gk, msg, b"post");
        assert_eq!(blob.len(), NONCE_LEN + msg.len() + TAG_LEN);
        assert_eq!(decrypt(&gk, &blob, b"post").unwrap(), msg);
    }
}

#[test]
fn encrypt_uses_fresh_nonces() {
    let gk = generate_group_key(1);
    let a = encrypt(&gk, b"same", &[]);
    let b = encrypt(&gk, b"same", &[]);
    assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
}

#[test]
fn decrypt_detects_every_flipped_byte() {
    let gk = generate_group_key(1);
    let blob = encrypt(&gk, b"a short post body", b"ad");
    assert_every_flip_fails(&blob, |b| decrypt(&gk, b, b"ad").is_ok());
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let blob = encrypt(&generate_group_key(1), b"secret", &[]);
    assert_eq!(decrypt(&generate_group_key(1), &blob, &[]), Err(Error::Decrypt));
}

#[test]
fn decrypt_with_wrong_key_version_fails() {
    // Same key bytes, different version label: the version is authenticated.
    let v1 = generate_group_key(1);
    let v2 = GroupKey::from_bytes(2, &v1.key_bytes());
    let blob = encrypt(&v1, b"secret", &[]);
    assert_eq!(decrypt(&v2, &blob, &[]), Err(Error::Decrypt));
}

#[test]
fn decrypt_with_wrong_ad_fails() {
    let gk = generate_group_key(1);
    let blob = encrypt(&gk, b"secret", b"post:1");
    assert_eq!(decrypt(&gk, &blob, b"post:2"), Err(Error::Decrypt));
    assert_eq!(decrypt(&gk, &blob, b""), Err(Error::Decrypt));
}

#[test]
fn decrypt_rejects_short_and_truncated_blobs() {
    let gk = generate_group_key(1);
    assert_eq!(decrypt(&gk, &[0; NONCE_LEN + TAG_LEN - 1], &[]), Err(Error::Malformed));
    let blob = encrypt(&gk, b"secret", &[]);
    assert_eq!(decrypt(&gk, &blob[..blob.len() - 1], &[]), Err(Error::Decrypt));
}

#[test]
fn decrypt_libsodium_xchacha20poly1305() {
    // crypto_aead_xchacha20poly1305_ietf_encrypt("hello side tray",
    //   ad = u32le(3) || "post:abc", nonce = 0x40..=0x57, key = 0x80..=0x9f), nonce prepended.
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let gk = GroupKey::from_bytes(3, &key);
    let blob = hex::decode(
        "404142434445464748494a4b4c4d4e4f5051525354555657\
         99691f9834d087339f7757a784cfe4e4f7c097f418fceca981200964971699",
    )
    .unwrap();
    assert_eq!(decrypt(&gk, &blob, b"post:abc").unwrap(), b"hello side tray");
}

// --- signatures --------------------------------------------------------------

#[test]
fn sign_verify_round_trip() {
    let d = generate_device_keys();
    for msg in [&b""[..], b"post body", &vec![7; 10_000]] {
        let sig = sign(&d, msg);
        assert_eq!(verify(&d.public().sign, msg, &sig), Ok(()));
    }
}

#[test]
fn verify_detects_flipped_message_byte() {
    let d = generate_device_keys();
    let pk = d.public().sign;
    let msg = b"I really wrote this";
    let sig = sign(&d, msg);
    assert_every_flip_fails(msg, |m| verify(&pk, m, &sig).is_ok());
}

#[test]
fn verify_detects_flipped_signature_byte() {
    let d = generate_device_keys();
    let pk = d.public().sign;
    let sig = sign(&d, b"msg");
    assert_every_flip_fails(&sig, |s| verify(&pk, b"msg", s).is_ok());
}

#[test]
fn verify_with_wrong_key_fails() {
    let sig = sign(&generate_device_keys(), b"msg");
    let other = generate_device_keys().public().sign;
    assert_eq!(verify(&other, b"msg", &sig), Err(Error::BadSignature));
}

#[test]
fn verify_rejects_bad_lengths_and_keys() {
    let d = generate_device_keys();
    let sig = sign(&d, b"msg");
    assert_eq!(verify(&d.public().sign, b"msg", &sig[..63]), Err(Error::Malformed));
    // y = 2 is not on the curve.
    let mut not_a_point = [0u8; 32];
    not_a_point[0] = 2;
    assert_eq!(verify(&not_a_point, b"msg", &sig), Err(Error::InvalidPublicKey));
}

#[test]
fn signature_matches_libsodium() {
    // Ed25519 is deterministic: crypto_sign_detached("signed by libsodium") with seed 0x21..=0x40.
    let d = fixed_device();
    let sig = sign(&d, b"signed by libsodium");
    assert_eq!(
        hex::encode(sig),
        "cd53bd987f40cba1be58291988c0f25a0542f949ecfbf2c895413313387c366d\
         6c208c21ee4192bd9a416e12a45d7668f8e4000ed4becb517a56457ffcb4bc0d"
    );
}

#[test]
fn rfc8032_test_vector_1() {
    let sk: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let d = DeviceKeys::from_secret_bytes(&[1; 32], &sk);
    assert_eq!(
        hex::encode(d.public().sign),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex::encode(sign(&d, b"")),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

// --- safety code -------------------------------------------------------------

#[test]
fn wordlist_is_frozen() {
    let words = wordlist::WORDS;
    let mut sorted = words.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 1024, "words must be unique");
    assert!(words.iter().all(|w| (4..=7).contains(&w.len()) && w.bytes().all(|c| c.is_ascii_uppercase())));
    let mut prefixes: Vec<&str> = words.iter().map(|w| &w[..4]).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    assert_eq!(prefixes.len(), 1024, "first four letters must be unique");
    // Any edit to the list changes this hash. Don't update it: make a new list and bump SAFETY_CODE_DOMAIN.
    let h = Blake2b::<U32>::digest(words.join("\n").as_bytes());
    assert_eq!(hex::encode(h), "892520d37817c694073fadfac321eb0ffbdab014ad1b5a917ef880f854f88773");
}

#[test]
fn safety_code_known_answer() {
    // Computed independently in Python with libsodium's BLAKE2b; must never change.
    assert_eq!(safety_code(&fixed_device().public()), "MISS-PARCEL-EARTH-PRICE-88");
    let zeros = DevicePublicKeys { enc: [0; 32], sign: [0; 32] };
    assert_eq!(safety_code(&zeros), "IMPACT-DEED-FRAGILE-YEAR-18");
}

#[test]
fn safety_code_is_deterministic_and_well_formed() {
    let p = generate_device_keys().public();
    let code = safety_code(&p);
    assert_eq!(code, safety_code(&p));
    let parts: Vec<&str> = code.split('-').collect();
    assert_eq!(parts.len(), 5, "{code}");
    for w in &parts[..4] {
        assert!(wordlist::WORDS.contains(w), "{code}");
    }
    assert_eq!(parts[4].len(), 2);
    assert!(parts[4].bytes().all(|c| c.is_ascii_digit()));
}

#[test]
fn safety_code_covers_both_public_keys() {
    let p = fixed_device().public();
    let base = safety_code(&p);
    let mut enc_changed = p;
    enc_changed.enc[31] ^= 1;
    let mut sign_changed = p;
    sign_changed.sign[0] ^= 1;
    assert_ne!(safety_code(&enc_changed), base);
    assert_ne!(safety_code(&sign_changed), base);
}

#[test]
fn blob_digest_is_stable_and_sensitive() {
    assert_eq!(blob_digest(b"abc"), blob_digest(b"abc"));
    assert_ne!(blob_digest(b"abc"), blob_digest(b"abd"));
    assert_ne!(blob_digest(b""), [0; 32]);
}

#[test]
fn event_id_is_short_hex_and_distinct_from_blob_digest() {
    let id = event_id(b"ciphertext");
    assert_eq!(id.len(), 32);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(id, event_id(b"ciphertext"));
    assert_ne!(id, event_id(b"ciphertexu"));
    let digest_prefix: String = blob_digest(b"ciphertext")[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(id, digest_prefix);
}

#[test]
fn key_grants_round_trip_and_bind_every_field() {
    let km = generate_device_keys();
    let me = generate_device_keys();
    let gk = generate_group_key(3);
    let (sealed, sig) = grant_group_key(&km, "g", "d_me", &me.public().enc, &gk);
    let km_pk = km.public().sign;
    assert!(open_key_grant(&me, "g", "d_me", 3, &sealed, &sig, &km_pk).unwrap() == gk);
    // Wrong signer, group, device, version label or tampered blob: refused.
    let other = generate_device_keys().public().sign;
    assert_eq!(open_key_grant(&me, "g", "d_me", 3, &sealed, &sig, &other).unwrap_err(), Error::BadSignature);
    assert!(open_key_grant(&me, "h", "d_me", 3, &sealed, &sig, &km_pk).is_err());
    assert!(open_key_grant(&me, "g", "d_you", 3, &sealed, &sig, &km_pk).is_err());
    assert!(open_key_grant(&me, "g", "d_me", 4, &sealed, &sig, &km_pk).is_err());
    assert_every_flip_fails(&sealed, |s| open_key_grant(&me, "g", "d_me", 3, s, &sig, &km_pk).is_ok());
    // A grant for someone else's key doesn't open, even with a valid signature.
    let (sealed2, sig2) = grant_group_key(&km, "g", "d_me", &generate_device_keys().public().enc, &gk);
    assert!(open_key_grant(&me, "g", "d_me", 3, &sealed2, &sig2, &km_pk).is_err());
    // A Key Master who signs a mislabelled grant still gets caught by the seal.
    let sealed3 = seal_group_key(&generate_group_key(2), &me.public().enc);
    let sig3 = sign(&km, &protocol::key_grant_message("g", "d_me", &me.public().enc, 3, &sealed3));
    assert_eq!(open_key_grant(&me, "g", "d_me", 3, &sealed3, &sig3, &km_pk).unwrap_err(), Error::Malformed);
}
