# The Side Tray — MVP Spec

Oct 30, 2026 · James Powell

## Overview

Side Tray is a private, invite-only feed for one group of friends and family: everyone sees every post, in time order, with comments and reactions. No ads, no algorithm, no suggestions, and the server can't read anything because posts are end-to-end encrypted.

**MVP goals**

- One group, one chronological feed: text posts, photos, comments, reactions
- Desktop app (Windows, Linux, macOS) that lives in the system tray and notifies on new posts
- Local SQLite archive on every device; the server is a thin relay that prunes old data
- End-to-end encryption with a human Key Master who approves new members
- Installable from GitHub releases with a first-run wizard: server address, group name, display name, email

**Not in the MVP**

- Multiple groups (schema carries `group_id` so this is a later feature, not a rewrite)
- Facebook cross-posting browser extension (phase 2)
- Native phone apps (PWA later), video, DMs, search beyond the local archive

## Architecture

A thin relay on a cloud VPS passes encrypted events between desktop apps; all reading, rendering and long-term storage happen on members' own machines.

```
[Member device: Tauri app]  <-- encrypted blobs (HTTPS + WebSocket) -->  [Cloud VPS: Caddy -> FastAPI relay -> SQLite + media folder]
[Key Master device]         <-- sealed keys -------------------------->        (ciphertext only, pruned at 90 days)
```

**Stack**

- **Server**: Python + FastAPI, SQLite, media on local disk, behind Caddy; one Docker Compose file on a $5–6/month VPS (1 vCPU, 1 GB RAM, 25 GB disk is plenty)
- **Client**: Tauri 2 (Rust backend, web frontend), which gives tray icon, notifications, auto-update and small installers (~10 MB)
- **Client UI**: plain HTML/JS or Svelte inside the Tauri webview; the same UI can be served on `localhost` so people can open it in a regular browser
- **Crypto**: libsodium via the `sodiumoxide`/`libsodium-sys` or `crypto_box` Rust crates on the client; the server never decrypts

## Crypto and onboarding

The group key never travels through email or the server in readable form. Each device has its own keypair; the Key Master's app hands the group key to a new device sealed to that device's public key. Library: libsodium (sealed boxes for key delivery, secretbox / XChaCha20-Poly1305 for content).

**Keys**

- **Device keypair** (X25519): generated on first run, private half stays on the device
- **Group key** (32 random bytes): encrypts every post, comment, reaction and photo; each has a `key_version`
- **Signing keypair** (Ed25519, per device): signs every post so members can see who really wrote it

**Join flow**

1. User installs the app and enters server address, group name, display name and email.
2. App generates its keypairs and sends a join request with the public keys.
3. Server holds the request as `pending` and pushes it to every Key Master online.
4. Both screens show the same safety code: 4 words from a 1024-word list + 2 digits, derived from a hash of the new device's public keys (encryption and signing), e.g. `TIGER-RIVER-MAPLE-LEMON-42`.
5. Key Master phones the new user and compares codes, or scans a QR code from their screen in person.
6. Key Master approves; their app seals the group key (all versions) to the new device's public key and uploads the sealed blobs.
7. New device downloads, unseals, and the feed unlocks.

**Key Master rules**

- The first person to set up the group is the Key Master; they can promote others to Key Master (recommend at least two)
- Any Key Master can approve joins and remove members
- Server enforces the role for approvals, but cannot read or forge the group key

**Removing a member**

1. Key Master removes the member; server revokes their device tokens immediately.
2. Key Master's app generates a new group key (`key_version + 1`) and seals it to every remaining device.
3. New content uses the new key. The removed member keeps what they already downloaded; nothing can un-send that.

**New or lost device**: the user re-runs the join flow under the same account; the Key Master approves the new device and can revoke the old one.

## Data model

The server stores routing metadata in the clear and every piece of content as an encrypted blob. Every table carries `group_id` so multiple groups later means adding a groups admin screen, not migrating data.

**Server (SQLite, one file)**

| Table | Key columns | Notes |
| --- | --- | --- |
| groups | id, name, created_at | One row for the MVP |
| members | id, group_id, display_name, email, role (member / keymaster), status (active / removed) | Email is an identifier only, no verification in MVP |
| devices | id, member_id, enc_pubkey, sign_pubkey, status (pending / active / revoked), token_hash, last_seen | One member, many devices |
| sealed_keys | device_id, key_version, sealed_blob | Group key sealed to each device |
| events | seq (autoincrement), group_id, kind (post / comment / reaction / edit / delete), author_device_id, key_version, ciphertext, media_ids, created_at | The feed, as an append-only log |
| media | id, group_id, size_bytes, path on disk, created_at | Encrypted image files |
| acks | device_id, last_seq | How far each device has synced |

**Client (local SQLite)**

| Table | Key columns | Notes |
| --- | --- | --- |
| identity | server_url, group_id, member_id, device keys, group keys by version | Private keys protected by the OS keychain where available |
| members | id, display_name, sign_pubkey, role | Cached roster |
| posts | id, seq, author_id, body, created_at, edited_at, deleted | Decrypted, plaintext on disk |
| comments | id, post_id, author_id, body, created_at | |
| reactions | post_id, author_id, emoji | One per person per post |
| media | id, post_id, local_path, thumb_path | Full image + thumbnail |
| sync_state | last_seq | |

Open question: encrypt the local SQLite at rest (SQLCipher) or rely on OS disk encryption. MVP default: rely on the OS.

## Sync and pruning

The feed is an append-only log with a sequence number; each device pulls everything after its last seq, acks it, and the server deletes what every active device has acked or what has passed the retention window.

**Sync loop**

1. On startup, and on every WebSocket `new_event` push, the client calls `GET /events?after=<last_seq>`.
2. Client decrypts, verifies the author signature, writes to local SQLite, downloads any referenced media.
3. Client calls `POST /ack` with the highest seq it stored.
4. Fallback poll every 15 minutes in case the socket drops.

**Edits and deletes** are new events (`kind: edit` / `delete`) pointing at the original post id, so the log never changes in place.

**Pruning (server cron, hourly)**

- Delete events and media where every active device's `last_seq` is at or past them
- Also delete anything older than the retention window (default 90 days), even if someone hasn't synced
- A device that hasn't checked in for longer than the retention window gets a "you missed some posts" notice on return
- Revoked devices don't count toward "everyone has it"

**New members** only get what's still on the server (up to 90 days). Optional later: an existing member's app can share its local archive with a newly approved device.

**Media**

- Client resizes before upload: longest side 2048 px, WebP quality ~80, EXIF stripped (GPS included)
- Client makes a 400 px thumbnail
- Both encrypted with the group key, uploaded to `POST /media`, referenced by id in the post event
- Rough size: ~300–500 KB per photo; at that size, 10 GB of disk holds 20,000+ photos before pruning matters

## API

All endpoints are HTTPS under `/api/v1`, authenticated with a per-device bearer token issued at join (stored hashed on the server). Bodies are JSON; content fields are base64 ciphertext.

| Method | Path | Who | Purpose |
| --- | --- | --- | --- |
| GET | /group | anyone | Group name and whether it exists (first-run wizard check) |
| POST | /join | anyone | Submit join request: display name, email, public keys → returns device id + pending token |
| GET | /join/status | pending device | Poll approval; returns sealed group keys once approved |
| GET | /joins/pending | Key Master | List pending devices with public keys |
| POST | /joins/{device_id}/approve | Key Master | Upload sealed group keys for that device |
| POST | /joins/{device_id}/deny | Key Master | Reject the request |
| GET | /members | member | Roster: names, roles, signing public keys |
| POST | /members/{id}/remove | Key Master | Remove member, revoke devices |
| POST | /members/{id}/role | Key Master | Promote or demote Key Master |
| POST | /keys/rotate | Key Master | Upload a new key version sealed to every active device |
| GET | /keys | member | Fetch sealed keys for this device (after a rotation) |
| GET | /events?after={seq} | member | Pull the log, paged (500 per page) |
| POST | /events | member | Append an event: kind, key_version, ciphertext, media_ids, signature |
| POST | /ack | member | Report highest stored seq |
| POST | /media | member | Upload encrypted image or thumbnail → media id |
| GET | /media/{id} | member | Download encrypted media |
| WS | /ws | member | Server pushes `new_event`, `join_request`, `key_rotated`, `removed` |

Rate limits for the MVP: 30 events/minute and 50 MB of media/hour per device.

## Build phases

Each phase ends with something you can run and poke at; hand them to CC one at a time.

1. **Server skeleton**: FastAPI + SQLite, the events/ack/media endpoints with a hardcoded test token, Docker Compose with Caddy for HTTPS. Done when `curl` can post and pull events.
2. **Crypto core**: a small shared module (Rust crate for the client; the server never decrypts) for keygen, sealing, encrypt/decrypt, sign/verify, safety-code words. Done when round-trip tests pass.
3. **Join and Key Master flow**: join, pending list, approve with sealed keys, device tokens, safety code on both screens. Done when a second device joins with a phone-call code check.
   - Sealed boxes are anonymous, so each sealed group-key blob must be signed with the approving Key Master's Ed25519 key. The new device verifies that signature against a Key Master's signing key before it trusts the unsealed group key.
4. **Desktop client feed**: Tauri app, first-run wizard, local SQLite, sync loop, post/comment/react, photo resize + upload. Done when two devices see each other's posts.
5. **Tray and notifications**: minimize to tray, unread badge, native notifications, start with OS (optional toggle).
6. **Pruning and removal**: hourly prune job, member removal, key rotation. Done when a removed device stops receiving and old events disappear from the server.
7. **Release**: GitHub Actions builds Windows (.msi), macOS (.dmg), Linux (.AppImage / .deb); install page with screenshots.

**Distribution**

- Unsigned Windows installers trigger the SmartScreen warning; options are a code-signing cert (~$100–300/yr) or a one-line "More info → Run anyway" instruction on the install page
- macOS needs an Apple Developer account ($99/yr) for notarization, or users right-click → Open
- Tauri has a built-in updater that reads signed release manifests from GitHub; turn it on in phase 7

**Later**

- Multiple groups with an admin screen to create them
- Facebook "Send to Side Tray too?" browser extension
- PWA for phones, then native apps if needed
- Archive sharing for new members, SQLCipher at rest, email verification via the M365 domain
