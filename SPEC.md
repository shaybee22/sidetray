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
- Native phone apps (an Android app is planned; see "Android app" below), video, search beyond the local archive
- Direct messages come right after the MVP feed (Phase 5b below)

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
4. Fallback poll every 30 seconds while the socket is down (it reconnects with backoff), and every 15 minutes as a safety net while it's up.

**Edits and deletes** are new events (`kind: edit` / `delete`) pointing at the original post id, so the log never changes in place.

**Pruning (server cron, hourly)**

- Delete events and media where every active device's `last_seq` is at or past them, once they're older than the history window (default 14 days, `SIDETRAY_HISTORY_DAYS`; 0 = right away), so new members still see the recent feed
- Also delete anything older than the retention window (default 90 days, `SIDETRAY_RETENTION_DAYS`), even if someone hasn't synced
- A device that hasn't checked in for longer than the retention window gets a "you missed some posts" notice on return
- Revoked devices don't count toward "everyone has it"

**New members** get what's still on the server: at least the last 14 days (the history window), up to 90 days of what someone hasn't fetched yet. Approval seals them every group key version those events use. Optional later: an existing member's app can share its local archive with a newly approved device.

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
| POST | /leave | member | Leave the group: revoke all my devices (Phase 8) |
| POST | /devices/{id}/revoke | Key Master | Revoke one device (lost or replaced); the member stays |
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
   - 5b. **Direct messages**: end-to-end encrypted one-to-one messages; see the next section.
6. **Pruning and removal**: hourly prune job, member removal, key rotation. Done when a removed device stops receiving and old events disappear from the server.
   - 6b. **Real servers, invites, avatars, more groups**: `install.sh`, public certificates, invite links, avatars, several groups per server; see below.
7. **Release**: GitHub Actions builds Windows (.msi), macOS (.dmg), Linux (.AppImage / .deb); install page with screenshots.
   - As built (0.1.0): a per-user NSIS installer (.exe, no admin) instead of .msi, which registers `sidetray://` and the notification AppUserModelID against the installed exe and has Start menu and optional desktop shortcuts; Linux .AppImage and .deb; no macOS yet. A `v*` tag builds them in GitHub Actions into a draft release with `latest.json`. Installed apps update themselves through the Tauri updater (minisign-signed bundles; endpoint configurable, see the README) after the person clicks *Restart to update*. Unsigned for now (SmartScreen "Run anyway"); the install page is the README's "For family members" section.

## Phase 5b: Direct messages

Private one-to-one conversations (text and photos) between two members, relayed by the same server. Not encrypted with the group key: only the two people's devices can read them, so other members, Key Masters and the server can't.

**Encryption**

- Each message gets a fresh 32-byte message key. The text and any photos are encrypted with it (XChaCha20-Poly1305, as for posts).
- The message key is sealed (`crypto_box_seal`) separately to every active device of the recipient **and** every other active device of the sender, so the sender's laptop sees what they sent from their desktop. Device public keys come from the verified roster only (member certificates chaining to a pinned Key Master), never from the server's word.
- The sender signs the message with their device's Ed25519 key, over: group, conversation id, sender device, the list of recipient device ids, the ciphertext and each sealed key. Recipients check the signature and that they're on the list before trusting it.
- A device that joins later (a new laptop) doesn't get earlier messages: they were sealed to the devices that existed then. Archive sharing between a person's own devices can come later.
- Removed members' devices are revoked and drop out of the roster, so nothing new is sealed to them.

**What the server sees**: who messages whom and when, message sizes, and which devices each message is for. Not the content.

**Server**

| Table | Key columns | Notes |
| --- | --- | --- |
| dm_messages | seq, group_id, conversation_id, sender_device_id, ciphertext, signature, media_ids, created_at | `conversation_id` is a hash of the two member ids, so both sides compute the same one |
| dm_keys | message_seq, device_id, sealed_key | One row per device the message is for |
| dm_acks | device_id, last_dm_seq | How far each device has synced its messages |

- `POST /dms` with `{conversation_id, recipient_member_id, ciphertext, signature, media_ids, sealed_keys: [{device_id, sealed_key}]}`. The server checks that the sealed keys cover exactly the active devices of both people (minus the sending device), so a sender can't quietly leave a device out or add an outsider.
- `GET /dms?after=<seq>` returns only messages that have a `dm_keys` row for the calling device, with that row's sealed key. `POST /dms/ack` moves the device's cursor.
- Photos use `POST /media` as today, but a message's media is readable only by the participants' devices (`GET /media/{id}` checks the message's device list).
- `/ws` pushes `{"type": "new_dm", "seq"}` to the recipient's devices and the sender's other devices only.
- **Pruning, participants only**: a message and its media are deleted once every device in its `dm_keys` has acked it, or when it passes the retention window. Other members' devices don't count, unlike the feed.
- Rate limits shared with posts (30 events/minute, 50 MB media/hour per device).

**Client**

- Local tables `conversations` (id, other member, last message, unread count) and `dm_messages` (seq, conversation, sender, body, created_at, photos), plaintext on disk like posts.
- **Messages tab**: the conversation list, newest first, with the other person's name, the last message and an unread dot. "New message" picks a member from the verified roster.
- **Chat screen**: messages as bubbles (mine on the right), photos inline with the same resize, EXIF stripping and lightbox as posts, a composer at the bottom (Ctrl+Enter sends).
- Notifications: "Ana sent you a message" with the first line, click opens the conversation. DM unread counts go into the tray badge.

**As built** (where it differs from or adds to the plan above):

- `GET /dms` returns every sealed key of a message, not just the caller's: the signature covers them all, so a recipient needs them to check it. They're ciphertext to other devices, so nothing leaks.
- Message numbers count per group (`seq`), like event numbers, and `/members` lists a former device's `revoked_dm_seq`, so a message a removed member sent just before the removal still verifies on a device that syncs later.
- The relay also requires a message's photos to be uploaded by the sending device and not already used by a post or another message, and a post can't reference a message's photo.
- A message pushes `new_dm` only to the devices it was sealed to.

**Done when** two members exchange text and a photo, the sender's second device shows the conversation too, a third member's device gets nothing from `GET /dms` and can't fetch the photo, and both messages disappear from the server once every participant device has acked them.

## Phase 6b: Real servers, invites, avatars, more groups

Everything so far runs against a test relay on a LAN IP with Caddy's private CA. This phase makes a server something a non-developer can stand up on a domain, makes joining one click from a link, gives people faces, and lets one server host several groups. Built in two steps: 6b-1 (server: installer, several groups, rate limits) and 6b-2 (app: certificates, invite links, avatars). Where the build differs from the first plan, the text below says what was built.

**`install.sh` server installer**

One script, run as root on a fresh Debian or Ubuntu VPS: `curl -fsSL <release url>/install.sh | sudo bash`, or download and run it.

1. Asks for the domain name (e.g. `tray.example.org`) and an email address for Let's Encrypt expiry notices. Checks the domain's A/AAAA record points at this machine and that ports 80 and 443 are free; explains what to fix if not.
2. Installs Docker Engine and the Compose plugin from Docker's apt repository if they're missing.
3. Creates `/opt/sidetray` with `compose.yaml`, a production `Caddyfile` (the domain as the site address, `email <address>`, no `tls internal`) and `.env` (`SIDETRAY_HOST`, `SIDETRAY_RETENTION_DAYS=90`). Files it would overwrite are kept as `.bak`.
4. Pulls the images and runs `docker compose up -d`, then waits until `https://<domain>/api/v1/health` answers over a publicly trusted certificate.
5. Runs `sidetray-admin new-group` (below) and prints the one-time setup token and an invite link for the first person, the future Key Master.

Re-running it is safe: it updates the stack, keeps the data volumes and `.env`, and only issues a new setup token if asked to.

**Production certificate mode**

- For a server on a domain, the app trusts the normal public certificate roots (webpki roots, as browsers do), so a Let's Encrypt certificate just works. No root certificate is compiled into the app any more.
- A **test server** is one the wizard reaches by a bare IP address, or one whose root certificate someone pastes under *Advanced*. In test mode Caddy serves its root certificate (never the key) at `/sidetray-root.crt`; the app downloads it, checks that the server's own certificate chains to it, and shows its SHA-256 fingerprint, which `install.sh` prints too. Only after the person confirms that the two match does the app pin that root for this server (stored with the identity) and trust it, and nothing else, from then on. The app labels such servers "test server" on *This device*.
- A test server presenting a certificate that doesn't chain to the pinned root is refused, with a warning that says the certificate changed and why that matters. *This device → Server certificate → Check it again* shows the server's current fingerprint next to the pinned one; replacing the pin takes a second, explicit confirmation ("the operator read me this fingerprint").
- The choice is stored per server. Verification is never turned off, and plain `http://` stays limited to `localhost`.

**Invite links**

- Format: `sidetray://join?server=https%3A%2F%2Ftray.example.org&group=Smith%20Family`. Both values are URL-encoded; nothing else is accepted.
- The `sidetray://` scheme is registered with `tauri-plugin-deep-link`. Until the Phase 7 installer does it, the app registers it for the current user (on Windows under `HKCU\Software\Classes\sidetray`) each time it starts. Opening a link starts the app, or hands the link to the running copy, and opens the wizard with the server and group name filled in and checked (including the fingerprint step for a test server). The person still types their name and email. An app that already belongs to a group says so instead.
- Links carry no secrets and grant nothing: the join is still `pending` until a Key Master compares safety codes on the phone. A link for a server that isn't `https://` is refused.
- Key Masters get an *Invite* button on the Key Master tab: the link, a *Copy* button and a QR code. (The installer doesn't print a link: before the first group exists there's no group name to put in it.)

**Avatars and display names**

- Optional. *This device → Profile* lets you pick a photo, then drag and zoom it inside a circle (like Discord) and save. The crop happens in the app: a 256×256 WebP, metadata stripped like post photos.
- The image is encrypted with the group key, uploaded with `POST /media`, and announced in a new signed event, `kind: profile`, payload `{"display_name"?, "avatar": {"id", "digest"} | null}`. The media id also goes in the event's clear `media_ids`. `null` removes the avatar.
- Every profile event states the whole profile (an absent `display_name` means the certified name), because the latest one wins outright and is all the relay keeps. So changing only the name sends the current photo again, re-encrypted under the current group key.
- Clients use the latest valid profile event per member. Initials on a coloured circle remain the fallback whenever there's no avatar, it hasn't downloaded yet, or it fails its digest check.
- A display name change rides the same event, but it's only a request: everyone keeps seeing the certified name (in posts, comments, the member list, messages and notifications) until a Key Master accepts the new one (one click, which re-signs that member's certificates: `POST /members/{id}/name`; the relay then pushes `roster` so every app updates at once). Until then Key Masters see a "name change pending" marker. That stops someone renaming themselves "Mom" to scam people. Avatars change straight away.
- The relay never prunes a member's latest profile event or its avatar, so devices that join later still see everyone's face; older profile events prune normally.

**Multiple groups per server**

- `docker compose exec api sidetray-admin new-group` prints a fresh one-time setup token (stored hashed, valid 7 days). The first device to join with it creates a new group and becomes its Key Master, exactly like the first group today. `SIDETRAY_SETUP_TOKEN` in `.env` keeps working for a server's first group.
- The server never lists its groups. `GET /group?name=<name>` only answers whether that exact name (case-insensitive) exists, and every authenticated call works within the group of the calling device's token. Group names are unique per server.
- Pruning, rate limits and the `/ws` hub are already per group; the tables already carry `group_id`.
- In the app, one install still joins one group. An in-app group switcher (several identities side by side) is Phase 8.

**Done when** `install.sh` brings up a fresh VPS on a real domain, the app joins it with no pasted certificate, an invite link opens the wizard pre-filled, a cropped avatar and a new name show up on another member's device, and a second group created with `sidetray-admin new-group` can't see or be found from the first.

## Android app

Side Tray runs on Windows and Linux, and from 0.2.0 on Android. This section is the plan for the phone app; all four phases are built (see "As built" under each).

**Decisions**

- **Tauri 2 on Android.** The same Rust backend and `sidetray-crypto` crate, and as much of `app/ui` as possible. The crypto crate is pure Rust (no libsodium to link), so it cross-compiles as is. The C parts of the app's dependencies (`ring` for rustls, bundled SQLite, libwebp) build with the NDK's clang. Desktop-only plugins (tray, autostart, single-instance, updater) sit behind `cfg(desktop)`; Android gets its own equivalents where needed.
- **The phone is its own device.** It generates its own X25519 and Ed25519 keypairs on first run and joins through the normal flow: join request, the same safety code on both screens, a Key Master approves. A person can approve their own phone from a Key Master desktop. Keys never move between devices: no export, no QR transfer, no backup of private keys. The phone gets the group key sealed to it like any new device, and direct messages are sealed to it from then on (earlier ones aren't, as for any new device).
- **Keys protected by the Android Keystore.** The Keystore can't run libsodium-style X25519/Ed25519 operations on every device, so the app keeps a non-exportable AES-256-GCM key in the Keystore and stores the device's private keys, token and group keys wrapped with it in app-private storage. Unwrapped keys live only in memory, as on desktop. Uninstalling the app or clearing its data means a new device and a new join.
- **Notifications through UnifiedPush and a self-hosted ntfy.** The server runs ntfy next to the relay; `install.sh` can set it up (optional, off unless the operator says yes). A push carries no content, only a wake-up: the app then syncs over the normal API, decrypts, and shows the notification itself, so neither ntfy nor any distributor sees names, text or who posted. No Google FCM. Users without a UnifiedPush distributor app get a periodic background sync instead (WorkManager, about every 15 minutes, Android's minimum).
- **Share target.** "Share → Side Tray" from any app (Facebook, Photos, the browser) opens the composer with the shared image(s) and/or text attached; the person chooses post or direct message and sends. Shared photos go through the same resize, EXIF strip and WebP encode as any photo.
- **Distribution.** A signed APK attached to GitHub releases first, sideloaded. The app checks `latest.json` (or an Android entry next to it) and shows "New version available" with a *Download* button that fetches the APK and hands it to the system installer. Play Store is a later decision.

**What changes on the server**

- Push registration: `POST /push` with `{endpoint}` (the UnifiedPush endpoint URL the distributor gives the app) and `DELETE /push`, stored per device. Revoking a device deletes its endpoint.
- Wherever the relay pushes on `/ws` today (`new_event`, `new_dm`, `join_request`, `key_rotated`, `removed`, `roster`), it also POSTs an empty wake-up to the endpoints of the affected devices that have no live `/ws` connection. Coalesced: at most one wake-up per device every few seconds.
- The relay only POSTs to endpoints on the configured ntfy host or that a distributor issued; it doesn't fetch arbitrary URLs for anyone.

**Phases**

**A1. Android build, join, feed, posting, comments, DMs (sync while open)**

- `tauri android init`; the app builds and runs on an emulator and a real phone.
- Keystore-wrapped key storage (above) in place of Credential Manager.
- First-run wizard and join flow, including invite links (`sidetray://` as an Android intent filter) and the test-server fingerprint step.
- Feed, posts with photos, comments, reactions, Messages tab and chat, Key Master tab (approve joins from the phone too). Sync and `/ws` run while the app is in the foreground; nothing in the background yet.
- The existing layout made usable on a phone screen; the real mobile polish is A2.
- **Done when** a phone joins a group, a Key Master desktop approves it after comparing codes, and the phone posts, comments and exchanges direct messages with a desktop.
- **As built:**
  - The app crate is now a library (`sidetray_app_lib::run()`, which the Android build loads) plus a thin desktop `main.rs`. Tray, updater, autostart and single-instance are `cfg(desktop)`; `tray_mobile.rs` and `update_mobile.rs` stand in on a phone.
  - Keystore wrapping is done in Rust over JNI (`keystore.rs`, using the JavaVM from `ndk-context`), not a Kotlin plugin, so it works from any thread, including the main thread that runs synchronous commands. The wrapped secrets blob goes in the database's `secrets` table; the group keys stay wrapped by the local key inside it, as on desktop.
  - Android's IPC carries only JSON, so photo bytes go to Rust as base64 there (`{b64}`); desktop still sends a raw body.
  - The page is edge to edge: safe-area padding, and on a phone the chat is sized from the visual viewport (Android doesn't shrink the page for the keyboard). A phone hides desktop-only settings (`html.mobile`).
  - Coming back to the foreground (`RunEvent::Resumed`) syncs at once and nudges the push loop.
  - Tested on a Motorola razr ultra 2025 (Android, arm64) against a relay on the build PC through `adb reverse`: join approved from a desktop Key Master, the phone approving a desktop's join, posts with a photo from the system photo picker, comments and reactions both ways, direct messages with photos both ways (and on the sender's other device), a `sidetray://` invite link to an HTTPS test server with the fingerprint step on a freshly cleared app, and a public-certificate HTTPS check.

What this Windows machine needs to build for Android:

- **Android Studio** (easiest way to get everything below, plus the emulator), or the standalone command-line tools.
- **Android SDK**: an SDK Platform (API 34 or newer), Platform-Tools (`adb`), Build-Tools, Command-line Tools, and the Android Emulator with a system image, all from the SDK Manager.
- **Android NDK** (side-by-side, r27 or the version Tauri's docs name), for the Rust and C code.
- **JDK 17**: Android Studio's bundled JBR works (`C:\Program Files\Android\Android Studio\jbr`).
- **Environment variables**: `JAVA_HOME` (the JDK), `ANDROID_HOME` (usually `%LOCALAPPDATA%\Android\Sdk`), `NDK_HOME` (`%ANDROID_HOME%\ndk\<version>`).
- **Rust targets**: `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android`.
- **Windows Developer Mode** on (Settings → System → For developers), because the Tauri Android build creates symlinks.
- A phone with USB debugging on, or an emulator image (x86_64).

**A2. Share target, camera and gallery, mobile layout**

- "Share → Side Tray" intent filters for `image/*` (one or several) and `text/plain`; the shared content opens in the composer.
- Photo picker with the camera and the system gallery (Android photo picker).
- Mobile layout polish: bottom tabs, full-width composer, larger touch targets, back button behaviour, safe areas, the photo lightbox with pinch zoom.
- **Done when** sharing a photo from another app lands in a Side Tray post on a desktop, and a photo taken with the camera posts the same way.
- **As built:**
  - Intent filters: `SEND` for `image/*` and `text/plain`, `SEND_MULTIPLE` for `image/*`. `MainActivity.kt` passes the intent to `SideTrayAndroid.kt`, which copies up to 20 pictures (64 MB each) into the app's cache on a worker thread; the page polls `take_share` (on start and on resume) and stages each picture through the usual pipeline by index (`stage_shared_photo`), which deletes it. The share dialog shows the staged thumbnails and the text (a browser's page title and address are joined), with *Post it to the feed* or a list of people to message; the choice puts everything into that composer to review and send. Not active (no group, waiting, removed): a notice says so and the share is dropped.
  - Camera: `<input capture="environment">` buttons (composer, comment, chat). The manifest declares a `<queries>` entry for `IMAGE_CAPTURE` (since Android 11 the WebView can't see a camera app otherwise); no CAMERA permission is needed. The WebView's capture file (full size, with location) is deleted after staging and at a cold start.
  - Gallery: the existing `multiple` inputs open the system photo picker with multi-select. A picked file that's briefly unreadable (`NotReadableError`, seen once on the emulator) is retried.
  - HEIC/HEIF and AVIF: when the image crate can't decode a photo, Android's `ImageDecoder` does (over JNI, `src/android.rs`), scaled to 2048 px with the EXIF orientation applied; the RGBA pixels then go through the same WebP encode, so no metadata survives. A computer refuses HEIC with a message. The profile cropper converts through `photo_preview`, since the WebView can't show HEIC.
  - Back: `MainActivity.kt` registers its own back callback that calls `window.__sidetrayBack()` in the page (Tauri's back-button listener belongs to the activity it was registered with and stops working once the activity is recreated). Order: photo viewer, dialog, emoji row, chat, another tab → feed; on the feed, if anything is unsent, "Leave without sending?"; then `moveTaskToBack` (the app keeps running).
  - Layout: bottom tab bar with icons, icon-only photo and camera buttons in comments and chat, a full-width composer, a pinch/drag/double-tap photo viewer, and safe areas from `system_insets` (Android's own insets) where the WebView reports none. Tested on the razr's outer screen (480×410 CSS px usable, density 2.25) and inner screen (408×997, density 3).
  - Flip phones: a density change recreates the activity and reloads the page; drafts (text, and IDs of photos still staged in the app process) and the open tab and chat are saved in `localStorage` and restored (`staged_photos`, `page_boot`). Keeping the activity across the change was tried: the WebView then kept drawing at the old scale.
  - `allowBackup="false"`, with data-extraction rules that exclude everything: a restored backup put an old identity back on a reinstalled phone (without its Keystore key), and backups would copy decrypted posts.
  - Tested on the emulator (Android 15, x86_64) and the razr ultra 2025 against a relay on the build PC: three pictures (JPEG, PNG, a rotated HEIC with GPS tags) shared from the Files app as a message, arriving on the desktop upright, scaled and without EXIF; a link shared to the feed; a cold-start share; sharing with no group joined; camera shots posted from the composer and a comment; multi-select from the photo picker (HEIC included on the phone); Back at every level; a draft carried from the inner to the outer screen and back.

**A3. Push through UnifiedPush and ntfy**

- Server: ntfy in `compose.yaml` behind Caddy (its own path or subdomain), the optional step in `install.sh`, the `/push` endpoints and wake-ups above.
- App: the UnifiedPush connector, registering the endpoint with the relay, syncing on a wake-up and showing local notifications (new post, comment on your post, direct message, join request for Key Masters). Tapping a notification opens the post or conversation.
- Fallback: WorkManager periodic sync (~15 minutes) when no distributor is installed, with a line in settings explaining how to get instant notifications (install ntfy).
- **Done when** a post from a desktop notifies a locked phone within seconds through ntfy, a phone without a distributor notifies within the sync interval, and a capture of the push traffic shows no content.
- **As built:**
  - Server: `push_endpoints` (one per device, unique endpoint) and `GET/POST/DELETE /push`. The relay accepts only topics on its own ntfy (`SIDETRAY_NTFY_URL`, single path segment, `?up=1` at most) or hosts the operator lists (`SIDETRAY_PUSH_HOSTS`, `ntfy.sh` by default so phones need no setup; empty allows only the own ntfy), and POSTs to its own ntfy over Docker's network (`SIDETRAY_NTFY_INTERNAL=http://ntfy`), never following redirects. The wake-up is an empty body with `TTL` and `Urgency` headers; ntfy fills in its own placeholder (`triggered`). Wakes go to devices with no `/ws` socket, for every push except `new_event` of reactions and profile changes; at most one per device every 5 s with a trailing one; 404/410 deletes the endpoint (507 from ntfy.sh, "no active subscriber", keeps it); revoked devices get a last wake and lose their endpoint.
  - The default is ntfy.sh, the ntfy app's own default server: zero configuration, and the wake-ups carry nothing. A self-hosted ntfy (v2.28.0) is optional: a Compose service under the `push` profile, private (`auth-default-access: deny-all`, `*:up*:rw`), web app off, 12-hour cache. On a domain it shares 443 and the Let's Encrypt certificate with the relay: Caddy sends `/api/*` to the relay and everything else to ntfy (ntfy can't live under a sub-path, but its paths don't clash with `/api`), so no port, DNS record or trust step. On a test server it gets its own port (8443): that port has a 10-year self-signed certificate from `install.sh`: the ntfy app pins a server's exact certificate, and Caddy's internal ones rotate every 12 hours. It names a dummy host (`push.sidetray.invalid`), because Caddy refuses a second TLS setup for the same IP and would otherwise serve it on 443 too; the ntfy app skips the name check for a pinned certificate. `install.sh` asks about push (default no; asked on a re-run of a server that hasn't decided; `--push`/`--no-push`).
  - App: the UnifiedPush connector 3.3.5 picks the saved distributor, else ntfy, else the first one; the person points ntfy's *Default server* at the relay's ntfy, and the app asks for a fresh endpoint whenever the relay refused the last one. Push events and wake-ups go through `SideTrayWorker` (WorkManager): expedited for a wake-up, periodic (15 min, network required) whenever wake-ups don't reach the phone. The worker calls into Rust over JNI (`nativeSync`, `nativePush`), loading the library itself if the window never started; Rust then uses its own JavaVM reference and the process's single `App`. The app closes `/ws` when it leaves the foreground (Kotlin's `ProcessLifecycleOwner`), so the relay starts waking it right away, and reconnects on return.
  - Notifications: built in Rust after any sync (also in the window's own sync loop while the app is in the background) and shown by Kotlin, on channels for posts, comments, messages, join requests and membership; the same post or conversation replaces its earlier notification; all are cleared when the app comes to the front. Join requests already notified are remembered in the database, since each wake-up may be a new process. A sync counts as a new device's backlog only before its first completed sync (it used to be "from event 0", which kept a new group's first post quiet).
  - Notification permission: a card on the feed after joining offers it, then Android's prompt; *Device → Settings* shows state and delivery (instant through ntfy, or about every 15 minutes and why) with *Turn on*, *Open notification settings* and *Check again*.
  - Battery: the app checks whether Side Tray and the distributor are exempt from battery optimization (and whether Side Tray is Restricted). If not, a card on the feed and *Device → Settings* explain and offer buttons: Android's own "let app always run in background?" dialog for Side Tray (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`), and the distributor's App info screen (Android doesn't let one app exempt another). The card goes away once both are Unrestricted, or after *Not now*.
  - Follow-up tests: on the razr (Android 16), both apps were battery-optimized; the card caught it, Side Tray's dialog and ntfy's App info → App battery usage → Allow background usage → Unrestricted fixed it, and the card went away. *Check again* moved the registration to ntfy.sh, and a post reached the locked phone with Side Tray closed in 2.7 s, with nothing configured in ntfy. The production layout (ntfy on 443 next to the relay) was validated with Caddy and its routing checked on the test server's Docker network.
  - Tested against the test server (10.1.1.188, ntfy on 8443) with a desktop Key Master: on a Motorola razr ultra 2025 (Android 16) and the emulator (Android 15), each joined, offered notifications after approval, and first fell back to the periodic sync with ntfy on its default ntfy.sh (relay refused the endpoint; the app explained the fix). With ntfy pointed at the test server and its certificate trusted, a desktop post reached the razr, app closed and phone locked and asleep, about 4 s later (1.2 s on a later run); ntfy received an empty message (`triggered`), and the smoke test's capture shows nothing else. Tapping notifications opened the app (cold and warm) at the post or the conversation. With ntfy disabled the app switched to the 15-minute sync, said so once, and a post arrived with the next periodic run. Backgrounding the app closed its socket at once. The smoke test checks ntfy's privacy rules, a live wake-up and no wake-up for a connected device.

**A4. Release pipeline**

- GitHub Actions builds a signed release APK on `v*` tags (alongside the desktop builds) and attaches it to the release, with its version in the update manifest.
- In-app update prompt: on start and daily, check the manifest; if newer, show "New version available" with *Download*, then hand the APK to the installer (the person allows "install unknown apps" for Side Tray once).
- The APK signing key stays out of the repo: a keystore in GitHub Actions secrets (base64 keystore, store and key passwords), with an offline backup kept by the maintainer. Losing it means users must uninstall and reinstall (a new device and a new join), so the backup matters.
- **Done when** a tag produces a release with the APK attached, and a phone running the previous version offers the update and installs it.
- **As built:**
  - Manifest: the release job writes `android.json` (`{version, url, sha256, size}`, the URL pointing at the versioned APK on that tag) instead of an entry in Tauri's `latest.json`, which the desktop jobs write and which carries minisign signatures the phone doesn't need. The app reads `releases/latest/download/android.json` (drafts are skipped, so a phone only sees a published release); a 404 counts as up to date. `SIDETRAY_ANDROID_UPDATE_URL` at build time points a test build elsewhere and is the only way plain `http://` is accepted. Debug builds (debug key) don't check unless built with it.
  - Signing: an RSA 4096 PKCS12 keystore (alias `sidetray`, 2054), kept with the release manager next to the updater key and in three Actions secrets (`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_PASSWORD`). Gradle signs the release build when the git-ignored `gen/android/keystore.properties` exists (CI writes it from the secrets). The job refuses an APK whose certificate isn't the expected SHA-256 or whose `versionName` isn't the tag's version. `proguard-rules.pro` keeps `org.sidetray.app.**`, since Rust calls those classes by name over JNI and R8 minifies the release build, and the constructors of Room databases (WorkManager creates `WorkDatabase_Impl` by reflection; without the rule the first release build crashed at launch).
  - APK: arm64 only (`--target aarch64`), attached as `Side.Tray_X.Y.Z_arm64.apk` and `SideTray.apk`. A universal APK would carry four copies of the Rust library for 32-bit and x86 devices hardly anyone in a family has.
  - App (`update_mobile.rs`): checks 15 s after start, then whenever a day has passed since the last successful check (ten minutes after a failed one: a check at start can fail while the phone dozes), looking at the wall clock every 15 minutes and on resume, since a sleeping phone stops tokio's timers. A newer version shows a card on the feed (*Download and install*, *Not now* per version, kept in `localStorage`) and a line and button in *Device → Settings → Updates*. Rust streams the APK to `cache/updates/SideTray-<version>.apk` with progress, checks the SHA-256 and size limit, and Kotlin (`installApk`) opens it with `ACTION_INSTALL_PACKAGE` (`ACTION_VIEW` as a fallback: with the APK type it also offers Termux, office apps and so on in an "Open with" chooser) through the existing FileProvider (`REQUEST_INSTALL_PACKAGES` in the manifest). Without "install unknown apps" for Side Tray, the card explains the switch ("Allow from this source"), opens `ACTION_MANAGE_UNKNOWN_APP_SOURCES`, and installs by itself when the page becomes visible again with it allowed. A downloaded APK that's still newer is reused (also after Android restarts the process); older ones are deleted at start.

## Backlog for 0.1.2 (done in 0.2.0)

- "Start Side Tray when I sign in" (*This device → Settings*) defaults to ON for new installs. Existing installs keep whatever they have.
  - As built: an installed copy (the NSIS install, an AppImage, or a Linux package under `/usr`) decides once per data folder, at its first start of 0.2.0 or later: no identity yet means a new install, so it turns autostart on; otherwise it leaves it. A marker file `autostart-default` in the data folder records that it decided. Copies run from a build or with `SIDETRAY_DATA_DIR` never register.

## Phase 8: Several groups in the app

One install can belong to several groups (on one server or several), switch between them from the header, and leave a group. The relay has hosted several groups since Phase 6b; this phase is the app side, plus one new endpoint for leaving. Built in three steps, in this order: 8a (profiles and the migration), 8b (switching, background groups, push), 8c (leaving).

**Profiles**

- Each group the app belongs to is a **profile**: its own folder `groups/<local_id>/` in the app's data folder, holding its own `sidetray.db` (identity, device keys' wrapped group keys, posts, messages, `kv`) and `media/`. Its private keys and token stay in the OS keychain entry `device-<local_id>` (Android: the profile database's `secrets` table, wrapped by the app's one Keystore key). So a profile is one device of one member in one group, with nothing shared with the others: separate keypairs, separate tokens, separate archives.
- The folder name is the identity's `local_id`, which already names the keychain entry. A new profile picks a fresh random `local_id` when it's created (before the wizard) and keeps it.
- The app opens every profile at start: each has its own `App` (database connection, secrets cache, sync loop, push socket, locks). One of them is **active**: the one the window shows and every UI command acts on. The commands take the active `App` instead of a single managed one; feed, DM, crypto and Key Master code is unchanged, it just receives whichever `App` is active.
- The active profile's `local_id` is saved in `active-group` in the data folder, so the app comes back to the group last looked at.
- Files that belong to the install, not a group, stay at the top of the data folder: `autostart-default`, `notification-icon.png`, `active-group`.

**Migration (8a)**

On the first start of this version, an existing `sidetray.db` at the top of the data folder becomes the first profile, without touching its contents:

1. Open it, checkpoint the WAL into the main file (`PRAGMA wal_checkpoint(TRUNCATE)`), and write a consistent backup copy next to it (`VACUUM INTO 'sidetray-before-groups.db'`), kept until a later release removes it.
2. Read the identity's `local_id` (an install that never joined gets a fresh one) and close the database.
3. Move `sidetray.db` (and any `-wal`/`-shm` left), and `media/`, into `groups/<local_id>.migrating/`, then rename that folder to `groups/<local_id>/`. Every step is a rename on the same disk, so nothing is copied and no photo is re-downloaded.
4. Make it the active profile.

If the app stops halfway, the next start sees the `.migrating` folder, moves in whatever is still at the top, and finishes the rename. The keychain entry doesn't move (it's named by `local_id`). On Android the push registration moves to the profile's own instance (below).

**Switching (8b)**

- The group name in the header becomes a menu button ("Powwow ▾"). The menu lists every profile by group name (with "waiting for approval" or "left / removed" where that applies), a dot on any group other than the active one with unread posts, messages or join requests, a tick on the active one, and *Join another group*.
- Picking a group switches the active profile (`switch_group`) and the page re-reads its state and redraws, as at start. Unsent text or photos in the composer or a chat: "Discard what you haven't sent?" first, since staged photos belong to the profile they were picked in.
- *Join another group* creates an empty profile, makes it active and runs the existing wizard (with a *Cancel* that deletes the empty profile and goes back). An invite link opened while the app is in a group does the same, pre-filled; the old "already belongs to a group" block is gone. A link for a group the app is already in (same server and group name) switches to it instead. `register` refuses a second profile for the same server and group.
- The waiting and removed screens get the same menu when there's more than one group, so a pending join doesn't trap the window.
- An empty profile (no identity) that isn't active is deleted at start, so an abandoned wizard leaves nothing behind.

**Groups in the background (8b)**

- Every profile keeps syncing on its own loop and socket, active or not. Events that redraw the page (`synced`, `push-status`, `removed`) are only sent for the active profile; any profile's sync also sends `groups-changed`, which redraws the menu's dots.
- Notifications fire for every profile. With more than one group, their titles name it ("Ana posted in Powwow"). Clicking one (a Windows toast, an Android notification) switches to that group first, then opens the post or conversation: the target carries the profile's `local_id`. The "don't notify, they're looking at it" rule only applies to the active profile.
- The tray badge and tooltip add up every profile's unread posts, messages and join requests.

**Android push per profile (8b)**

- Each profile registers its own UnifiedPush instance, named by its `local_id`, so it gets its own endpoint (the relay keeps one endpoint per device, and each profile is a separate device). Push state (`push_endpoint`, `push_registered` and so on) stays in each profile's `kv`.
- Kotlin passes the instance through: `nativePush(dir, kind, value, instance)` and `nativeSync(dir, instance)` (a wake-up syncs that profile; the periodic job, with an empty instance, syncs them all). Events for an instance no profile owns are ignored, and the old single instance (`default`) is unregistered once.
- The periodic 15-minute sync is on while any active profile has no working instant push. The battery and notification-permission cards are about the phone, not a group, so they stay where they are.

**Leaving a group (8c)**

Server: `POST /leave`, by any active device, for its own member.

- Revokes every device of the calling member in that group (active and pending), records `revoked_seq`/`revoked_dm_seq` as a removal does (their earlier posts and messages still verify), marks the member as gone (the member row says `removed`, the devices' reason says `left`), and sets `rotation_pending` if any other active member remains, so a Key Master's app rotates the group key as after a removal. Pushes `removed` (scope `left`) to the member's devices and `roster` to the group.
- The last active Key Master can't leave while anyone else is still in the group: 409, "promote someone to Key Master first". If they're the only member left, they can.
- `GET /join/status` then says `left` for those devices. Another device of the same member records `left` (read-only archive, like `removed`, with its own wording: "You left Powwow").
- Tests in `server/tests/test_leave.py`, alongside `test_groups.py`: leaving revokes all the member's devices and sets rotation_pending; a Key Master with a co-Key Master can leave; the last Key Master with other members can't; the last member can; other groups are untouched; a left device's token stops working; a left member's earlier events stay in `/members` former devices.

App: *Leave this group* at the bottom of *Device* (and *Delete these saved posts* on the removed screen, *Cancel this request* while waiting, which become the same action for a profile that's no longer active on the relay).

- A confirm dialog says what happens: everyone keeps what you posted, this device deletes everything it saved from that group, and coming back means asking to join again.
- For an active profile the app calls `POST /leave` first and stops if it fails (offline, or the last Key Master: the dialog shows the reason). Then: stop the profile's loops, unregister its push instance, close its database, delete its keychain entry and its folder.
- The app switches to another profile (the most recently used one left), or to the wizard in a new empty profile if none remain.

**Done when** the live Powwow install updates and comes up in Powwow with every post, photo and message still there; it joins a second group from an invite link and switches between the two; a post in the inactive group notifies (desktop toast and Android push) and puts a dot in the menu, and clicking the notification opens it in that group; the app restarts in the group last used; and leaving the second group revokes its devices on the relay, deletes its folder and keychain entry, and lands back in Powwow.

**As built (not yet released):**

- `profiles.rs` holds the profiles; every UI command takes the active one through a small `Active` command argument, so the feed, DM, crypto and Key Master modules didn't change. The window's Tauri handle moved from each `App` into one process-wide static (it's one per process anyway, and it keeps tests that build an `App` from loading window code).
- A profile is deleted by showing the next one first (the one used before, another joined group, or a new empty one), then closing its database and deleting its keychain entry and folder, so the active profile is never a deleted one.
- The relay's `members.status` only allows `active`/`removed`, so a member who left is `removed` there and their devices carry `revoked_reason = 'left'`; `GET /join/status` says `left`.
- The old *Start over* (`reset`) is gone: cancelling a join, starting over after a denial and *Delete these saved posts* after a removal all delete the profile the same way as leaving (without the relay call).
- Tested with a local relay and two desktop copies: an install with its data at the top of the folder (and most of it still in the WAL after an unclean exit) moved into `groups/<local_id>/` with its posts and keys working; a second group founded from *Join another group*; a post in the hidden group gave a toast "Rosa posted in Alpha" and a dot on the menu, and its notification target switched groups; a restart came back in the last group; the only Key Master was refused (409); a member leaving landed in the wizard with folder and keychain entry gone, and the Key Master's app rotated the key. Android compiles (`aarch64-linux-android`) but the per-group push instances haven't been tried on a phone yet.

## Phase 9: Short videos (in progress)

Short video clips in feed posts and direct messages. A video is transcoded on the sender's device, encrypted like a photo and uploaded through the same `POST /media`. The relay holds the video file only briefly: until every device it's for has downloaded it, two weeks at most, and within a 2 GB cap per group and 5 GB per server. The post text and the poster frame (an ordinary encrypted thumbnail) follow normal post retention. Once the video file is gone, people see the poster frame, the text, "Video expired" and a *Request* button.

Built in three stages, each tested before the next: **9a** the relay (video retention, per-file acks, also for feed photos) and the app's photo acks; **9b** desktop transcoding, sending and playback; **9c** Android.

**Limits**

- At most **one video per post or message**. It can't be mixed with photos (keeps the composer, the UI and the retention rules simple). Not in comments: a video-only comment would be an empty comment to apps before this phase, and they refuse those (`feed.rs` `RefBody` check).
- At most **60 s**. For a longer clip the app asks "Use the first 60 seconds?"; *Yes* trims it while transcoding (ffmpeg `-t 60`; on Android a Media3 `ClippingConfiguration` ending at 60 s), *No* drops it.
- The encrypted file is at most **10 MB** (`SIDETRAY_MAX_MEDIA_BYTES`, already the limit; Caddy allows 12 MB). The encoder aims for a 9.5 MB MP4 so the nonce, tag and container overhead always fit.

**Transcoding (before encryption, on the sender's device)**

- Output: MP4 (H.264 High or Main, AAC-LC 96 kb/s stereo, or mono if the source is mono), `+faststart`, 30 fps at most, metadata stripped (`-map_metadata -1`: no GPS or device model, like photos).
- Bitrate: `video_kbps = (9.5 MB × 8 / duration_s) − 96`, capped at 2,500 kb/s, with `duration_s` the duration after trimming. **720p** (longest side 1280) when that gives at least 1,500 kb/s, otherwise **480p** (longest side 854). With a 9.5 MB budget, 720p holds up to about 48 s and longer clips drop to 480p (at 60 s about 1,170 kb/s, which is watchable at 480p). Below 400 kb/s the clip is refused; that can't happen at 60 s, it's only a guard.
- One pass with a capped rate (`-b:v`, `-maxrate` 1.5×, `-bufsize` 2×). If the file still comes out over 9.5 MB, encode again at 85% of the bitrate, once. Hardware encoders don't do two-pass, so verify and retry rather than rely on two-pass.
- **Poster frame**: the frame at 1 s (or the first frame for shorter clips). It goes through the existing photo steps (`photo::fit` to 400 px, `encode_webp`), so it's an ordinary WebP thumbnail. Width, height and duration come from the transcode.
- **Desktop: bundled ffmpeg sidecar** (Tauri `bundle.externalBin`, one binary per target triple, run through `tauri-plugin-shell`). Progress comes from `-progress pipe:1` (`out_time_ms` / duration).
  - *Licensing:* the app is MIT/Apache, so ship an **LGPL** ffmpeg build with no GPL parts, which means no libx264. The H.264 encoder is the operating system's: `h264_mf` (Media Foundation) on Windows and `h264_videotoolbox` on macOS. On Linux it's `libopenh264` (BSD; Cisco's patent cover only applies to their binary downloaded at runtime, so decide on that before shipping Linux). AAC is ffmpeg's built-in `aac`. Windows "N" editions lack Media Foundation until the Media Feature Pack is installed: detect that and say so.
  - *Size:* a trimmed build (only the demuxers and decoders needed for common phone and camera formats, the encoders above, and the mp4 muxer) is roughly 15–25 MB per platform. The installer and each updater download grow by that much.
- **Android: Media3 Transformer** (`androidx.media3:media3-transformer`, `-effect`, `-common`) on the platform's hardware `MediaCodec` encoder. It adds about 1–2 MB to the APK versus about 20–30 MB per ABI for ffmpeg (ffmpeg-kit, the usual Android build, was retired in 2025). `Presentation.createForHeight(720 or 480)` scales, `VideoEncoderSettings.setBitrate` sets the bitrate, and the same verify-and-retry rule applies, because hardware bitrate control is loose. The poster frame comes from `MediaMetadataRetriever.getFrameAtTime` and goes into the existing `android::decode_image` path. Called from Rust through new `SideTrayAndroid` JNI functions, like `decode_image` today. Media3 works from API 21 and the app's `minSdk` is 24.
- Both platforms take the source file by path, never the whole file through IPC. On Android the file comes from the picker or share intent (`content://` URI), copied to the cache folder.

**Format on the wire**

- Feed `post` body gains `"video"?: {"id", "digest", "thumb", "thumb_digest", "width", "height", "duration_ms", "size"}`. The DM body gains the same field. `digest` covers the encrypted file, as for photos, so the relay can't swap it.
- The video and poster frame are encrypted exactly like photos (feed: group key with `media_ad`; DM: the message key with `dm_media_ad`, one `crypto::encrypt` over the whole file). That's fine at 10 MB, and playback waits for the whole download anyway.
- `POST /media?kind=video` marks the upload as a video file. The relay can't check that (it's encrypted), but mislabelling a video as a photo only gets it photo retention under the same 10 MB limit, which is possible today anyway.
- Apps before this phase ignore the unknown `video` field (no `deny_unknown_fields`). They show the text alone, or an empty post for a video with no text. Acceptable; the release notes tell people to update.

**Per-file acks (relay, 9a)**

- Tables: `media` gains `kind` (`image` / `video`); `devices` gains `media_acks` (1 once the device has used the endpoint below); new `media_acks (media_id, device_id, acked_at)`; new `media_gone (id, group_id, kind, reason, gone_at)`, the tombstones behind 410.
- `POST /media/acks` with `{"ids": [...]}` (at most 500), sent after the device has downloaded the files, checked their digests and decrypted them. It may be empty: an app sends it once to say it acks files (`devices.media_acks = 1`). Ids this device may not `GET`, or that are gone, are skipped. `POST /media/{id}/ack` does the same for one file. Repeated acks are harmless.
- **Who has to have a file**: the active devices of active members that ack files (`media_acks = 1`), that existed when it was uploaded (`requested_at ≤ media.created_at`), other than the uploader. For a DM file, only those of them in its message's `dm_keys`. A device approved later doesn't hold a file back, but can still fetch it while it's there. Apps from before this phase never ack files, so they don't count: for photos the old rule (their event cursor) still covers them, and they can't play videos anyway.
- **Feed photos** (closes the `SIDETRAY_HISTORY_DAYS=0` gap): an event acked by everyone and past the history window is pruned only once every file of it has been acked by everyone above. The retention window still deletes it regardless.
- **DM photos** keep the 0.3.1 rule (the DM cursor waits for photos).

**Video retention (relay, 9a)**

- **Deleted when any of these is true** (hourly in `prune()`, and the caps also at upload time):
  1. it's referenced by a post or message and everyone above has acked it (`reason = 'delivered'`);
  2. it's older than `SIDETRAY_VIDEO_TTL_DAYS` (default 14), whatever the acks (`'ttl'`);
  3. its group's video files together exceed `SIDETRAY_VIDEO_GROUP_CAP_GB` (default 2), or all video files on the server exceed `SIDETRAY_VIDEO_CAP_GB` (default 5): oldest first until under both (`'cap'`). At upload time the relay evicts first, then accepts. Files uploaded in the last hour that no post or message refers to yet are never evicted. If the new file still doesn't fit, the upload gets `507` "video storage is full, try again later".
  4. its post is deleted or passes retention, as for photos (`'retention'`).
- A DM message stays on the relay while its video file is there (so `GET /media/{id}` keeps limiting it to the message's devices), and goes as usual once the file is gone.
- The file and its `media` row go; a `media_gone` row stays for the TTL plus a week. `GET /media/{id}` then answers **410 Gone** with `{"detail", "reason"}` instead of 404, so apps can tell "expired" from "broken".
- The poster frame is an ordinary photo and follows the post's normal retention.
- Settings in `.env` / `compose.yaml`: `SIDETRAY_VIDEO_TTL_DAYS`, `SIDETRAY_VIDEO_CAP_GB`, `SIDETRAY_VIDEO_GROUP_CAP_GB`.

**App: sending (9b, 9c)**

- The composer (post and DM) gets a video button and takes videos from share intents. It runs: pick → probe (over 60 s asks "Use the first 60 seconds?") → transcode with a progress bar ("Preparing video… 42%", with Cancel) → stage it (poster frame shown like a staged photo, with the duration).
- When you send, upload progress comes from a streamed request body (`reqwest::Body::wrap_stream`, counting bytes), and the post appears after the upload. The 300 s upload timeout stays; 10 MB over a slow phone link fits.
- The sender's plaintext MP4 stays in the profile's `media/` (`<id>.mp4`), like the sender's photos today (`feed.rs` "keep the plaintext photos locally", `dm.rs` "Keep our own copy"). That's the copy for re-sending.

**App: receiving and playback (9b, 9c)**

- Sync records the video reference with a state: `pending → downloading → ready | expired | failed`.
- Download is automatic in the background after the poster frame, newest first, one at a time, so a device acks soon and the file can leave the server. After the digest check and decryption, it saves `<id>.mp4` and acks it with `POST /media/acks`. A 410 sets `expired`; other errors count toward the existing attempts limit.
- **Mobile data:** a setting *Auto-download videos on mobile data* (Device → Settings, default on). When it's off and Android says the network is metered (`ConnectivityManager.isActiveNetworkMetered`), videos stay `pending` until the next sync on an unmetered network, or until tapped. Computers always download.
- **Playback:** on a computer the app reads the decrypted file through a command and plays it from a `blob:` URL in a `<video controls>` element (CSP `media-src blob:`). On Android that can't work (Tauri's Android IPC sends a large binary reply as script text; 8 MB never arrived in checkpoint 2), so `serve_media` serves `<id>.mp4` from the media folder with `Range` (206, at most 2 MB per response) and the video view carries that URL as `src` (CSP `media-src http://media.localhost media:`).
- The feed or chat shows the poster frame with a play badge and the duration. While downloading it shows "Downloading video… 3.1 / 8.7 MB"; once `ready`, tapping plays it inline or in the lightbox.
- **Expired:** the poster frame (greyed), the post text, "Video expired" and a **Request** button. Request opens the DM with the poster and pre-fills "Could you send me your video from <date>?", plus a structured `"video_request": {"post_id", "video_id"}` in the DM body. Request is hidden on your own posts and greyed out with the reason when the poster has left or either side has no verified device (`dm::recipients` rules).
- **Re-send:** on the poster's devices that have the local file, an incoming `video_request` shows a **Send it** button in the chat. Your own video in the feed also has *Send in a message…*. Both re-upload the local MP4 as a new DM video (new `media_id` and message key; nothing reused). A request for a video this device doesn't have shows "This video isn't on this device".

**Conflicts with the code before this phase, and how they're resolved**

1. **Acks were event cursors, not delivery receipts.** `POST /ack` and `POST /dms/ack` move a per-device sequence number, and the feed ack goes out at sync (`feed.rs` ~201) before `download_media` runs. *Resolved (9a)* by the per-file acks above; the cursors stay as they are.
2. **Same cause, photos.** DM photos: fixed in 0.3.1 (`dm::sync` acks only up to the first message with photos still to fetch). Feed photos with `SIDETRAY_HISTORY_DAYS=0`: *resolved (9a)* by the per-file rule for feed photos.
3. **A DM file can't outlive its message's access check.** `GET /media/{id}` limits DM media to the message's devices only while a `dm_media` row exists. *Resolved (9a)*: the message stays while its video file does.
4. **Media lifetime followed the event.** Video adds an earlier, independent deletion; the existing rules still apply on top. `media.kind` tells the two apart.
5. **The server cap is shared by every group.** *Resolved (9a)* by the per-group cap (2 GB) under the server cap (5 GB).
6. **History for new members.** Feed events stay 14 days for people who join later, but a video file usually leaves as soon as existing devices have it. New members mostly see "Video expired"; the Request flow is the answer.
7. **404 vs expired.** The app treats any download failure the same and gives up silently after `MAX_MEDIA_ATTEMPTS` (5). Video needs the 410 handling and visible states above (9b).
8. **Local media serving is photo-only** (`serve_media`, `<id>.webp`, no `Range`). Not needed with blob playback (9b); see Playback.
9. **Photo-only names in the model.** `PhotoRef`, `snippet()` ("shared a photo") and notifications assume photos. Add the "shared a video" wording (9b).
10. **Upload is one in-memory request with no progress.** `Api::upload_media(Vec<u8>)` / `download_media` return when done. Both need streamed versions that report progress (9b).
11. **Rate limit:** 50 MB/hour of media per device allows about five videos an hour. Probably fine; say so in the composer's error when it's hit.

**Files to touch**

- 9a, relay: `server/app/main.py` (columns and tables, `kind=video` on upload, cap eviction and 507, `POST /media/acks` and `/media/{id}/ack`, 410 tombstones, `prune()` rules), `compose.yaml` (the three settings), new `server/tests/test_video.py`.
- 9a, app: `feed.rs` (ack downloaded feed photos with `POST /media/acks`; an older relay without it is fine), `db.rs` (a `server_acked` column on `media`).
- 9b: new `app/src-tauri/src/video.rs` (probe, bitrate maths, ffmpeg sidecar, poster frame, progress events); `feed.rs` and `dm.rs` (`video` field, states, download + ack, re-send, `video_request`); `db.rs` (video columns); `api.rs` (streamed upload/download with progress, 410); `lib.rs` (commands `stage_video`, `cancel_transcode`, `read_video`, `resend_video`); `photo.rs` (poster frame); `alerts.rs` (wording); `tauri.conf.json` (`externalBin`, CSP `media-src blob:`); `Cargo.toml` (`tauri-plugin-shell`); `capabilities/*` (sidecar permission); `binaries/` and a fetch script for the LGPL ffmpeg builds; `.github/workflows/release.yml` (sidecar before `tauri build`); `app/ui/app.js`, `index.html`, `style.css`; `README.md` (ffmpeg licence notice and source).
- 9c: `android.rs` (JNI for probe, transcode, poster frame, picker, metered check), `video.rs` (an Android encoder next to the ffmpeg one; `plan()`, staging, upload and the UI stay shared), `gen/android/app/build.gradle.kts` (Media3), `SideTrayAndroid.kt` and `MainActivity.kt` (picker launcher, Transformer, metered network, WebView playback settings), `AndroidManifest.xml` (`ACCESS_NETWORK_STATE`; `video/*` in the share filters), `lib.rs` (Android `pick_video`, `download_video`, the mobile-data setting), `app/ui/app.js`, `index.html`, `style.css` (phone Video button, "Waiting for Wi-Fi", video lightbox).

**9c plan: Android** (decided before building; checkpoints below)

*Encoder: the platform's MediaCodec through Media3 Transformer, not a bundled ffmpeg.*

| | Media3 Transformer (MediaCodec) | Bundled LGPL ffmpeg for arm64 |
|---|---|---|
| H.264 encoder | the phone's hardware encoder (every Android phone has one; the CDD requires it) | the same hardware encoder through ffmpeg's `h264_mediacodec`, so no quality gain |
| Decoding | hardware, frames stay on the GPU (decode → OpenGL → encode); expect faster than real time | software decoding unless `hevc_mediacodec` is added; a 4K HEVC phone clip could take minutes and drain the battery |
| HDR phone clips (10-bit HLG/HDR10) | tone-mapped to SDR (`HDR_MODE_TONE_MAP_HDR_TO_SDR_USING_OPEN_GL`, Android 10+) | needs `zscale`/`tonemap` (more libraries) or comes out washed out |
| Running it | an ordinary library call from Kotlin | Android 10+ won't run a program from app storage, so it would have to ship as a fake `lib*.so` in `jniLibs`, or be linked into the Rust library over FFI |
| `content://` input | reads the picker or share URI directly | needs a copy to the cache folder or `/proc/self/fd` tricks |
| APK size (release, arm64, 13.8 MB today) | about +1–3 MB after R8 (Transformer pulls in ExoPlayer's decoding parts) | about +5 MB compressed (the Windows build is 12 MB uncompressed), plus a second cross-build script and CI job (NDK) |
| Code shared with desktop | `plan()`, size check and retry, staging, upload, UI; probe and encode differ | the probe parser and `encode_args` too |

So Media3, as the SPEC already planned. The bundled ffmpeg would only win on sharing more code, and it costs speed, battery, HDR handling and a second toolchain. Checkpoint 1 measures the APK growth and encode time; if Media3 can't keep files under 9.5 MB within the one retry, or leaves location data in, stop and reconsider.

*How it works on Android*

- **Probe** (`probeVideo(uri)` in Kotlin): `MediaMetadataRetriever` for duration, width, height, rotation and whether there's audio; `MediaExtractor` for the audio channel count and the colour transfer (to detect HDR). Returned as JSON into the same `video::Probe`, so `plan()` (720p/480p, bitrate, the 400 kb/s guard) is shared with desktop.
- **Transcode** (`transcodeVideo(...)`): a Transformer started on the main looper (it needs a Looper thread, and the main looper outlives the razr's activity re-creation when it switches screens). `Presentation.createForHeight(720 or 480)` (rotation is applied, so portrait stays portrait); `FrameDropEffect` to cap at 30 fps; `VideoEncoderSettings` with the planned bitrate (CBR: the razr's VBR overshot by 27% in checkpoint 1), H.264 High where the encoder offers it, otherwise Main; AAC at 96 kb/s, mono stays mono; `ClippingConfiguration` ending at 60 s for the trim; HDR tone-mapped to SDR, and below Android 10 an HDR clip is refused with a clear message. Rust polls `transcodeState()` every 250 ms for progress (`Transformer.getProgress`), the same polling style as `takeShare`, and sends the same `video-progress` events. Cancel calls `Transformer.cancel()` and deletes the half-made file. Over 9.5 MB: encode once more at 85%, as on desktop (hardware bitrate control is loose).
- **Metadata**: Transformer writes a new MP4 but can carry the source's location over. After every encode, Rust checks the MP4's boxes and renames any `udta`/`meta`/`©xyz` box to `free` in place. That keeps the file valid, removes GPS and the device model, and works whatever Media3 does. A test checks a clip recorded with location on.
- **Poster frame**: `MediaMetadataRetriever.getFrameAtTime(1 s)` on the output, compressed to JPEG and passed to the existing `photo::poster`.
- **Support check** (`video_support`): Android 7+ (the app's `minSdk` 24) with an `video/avc` and an `audio/mp4a-latm` encoder in `MediaCodecList`; otherwise the reason is shown, as for Windows N.
- **While it runs**: no foreground service; an encode takes seconds. If Android kills the app meanwhile, the staging folder is cleared on the next start (already the case).

*Video picker and "Use the first 60 seconds?"*

- The phone composers (post and DM) get the Video button (now `desktop-only`). It calls the same `pick_video` command. On Android that calls a `PickVisualMedia(VideoOnly)` launcher registered in `MainActivity.onCreate` (the Photo Picker: no storage permission; the Google Photos one on the razr). Rust waits for the result by polling `takePickedVideo()` (waiting / cancelled / a `content://` URI). The picker URI stays readable until the app's process ends, so Media3 reads it directly with no copy. A cloud-only video is downloaded by the picker first, so the composer shows "Getting the video…" until the probe returns.
- Photos stay on the WebView's `<input type=file>` as now. Videos never use it, because that would push the whole file through the page.
- `stage_video` takes the URI where desktop takes a path. A clip over 60 s returns `needs_trim` exactly as on desktop, and the UI asks the same "Use the first 60 seconds?" question (`askConfirm`). *Yes* stages again with `trim: true`, which becomes the `ClippingConfiguration`. *No* drops it. No UI changes beyond showing the button.
- **Share → Side Tray**: `video/*` joins the `SEND` and `SEND_MULTIPLE` filters. A share with a video passes the video's URI, not a copy, to the composer, which stages it through the same flow and question. A share with several videos, or videos and photos together, takes the first video and says "One video at a time, and not with photos: using the first video." The share's URI permission lasts while the activity does, so the URI is staged right away.
- Not in 9c: recording a video from the composer (a `capture` button). Pick from the gallery, or share from the camera app.

*Metered network and "Auto-download videos on mobile data"*

- The setting (default on) is device-wide, in `<data dir>/device-settings.json`, because the background sync (push wake-up, periodic job) reads it in a process where the page may never have started. It's in Settings on the phone only.
- `isMetered()` in Kotlin: `ConnectivityManager.isActiveNetworkMetered()` (needs `ACCESS_NETWORK_STATE`, a normal permission granted at install). Rust checks it before each video file in `fetch_videos`, not once per sync, since the phone can leave Wi-Fi mid-sync. A download already running is finished.
- Setting off and metered: the video stays `pending`, marked held. The poster shows "Waiting for Wi-Fi · tap to download (8.7 MB)". A tap calls `download_video(id)`, which fetches that one now. Poster frames and photos always download; sending isn't affected.
- A phone tethered to another phone's hotspot usually reports metered, which is the right answer. On a computer the check is always "not metered", so computers always download.
- A held video still counts for the relay's ack rule, so it holds the file on the relay (up to the 14 days) until the phone is back on Wi-Fi. If that never happens, it expires, and Request covers it.

*Blob playback in Android WebView: risks and what to do*

1. **Fullscreen doesn't work.** Tauri's generated `RustWebChromeClient.onShowCustomView` hides the fullscreen view as soon as it opens, and `gen/.../generated/` is rewritten on every build. So: `controlsList="nofullscreen"` and `disablePictureInPicture` on Android, and a full-screen button that moves the playing `<video>` into the app's own lightbox (fixed overlay, `object-fit: contain`; it plays on, nothing reloads). Turning the phone sideways then fills the screen.
2. **Playing after the IPC await.** WebView defaults to `mediaPlaybackRequiresUserGesture = true`, and the tap's gesture may have expired by the time `read_video` returns. The UI already ignores a refused `play()`, leaving the native controls. If it is refused on the razr, `MainActivity` turns the setting off on the WebView it already finds for the back button (the app only plays its own videos).
3. **Memory.** The 10 MB file exists as a Rust `Vec`, a Java `byte[]`, an `ArrayBuffer` and a `Blob` for a moment (about 40 MB at peak). Fine on the razr, a risk on a 2 GB phone. On Android keep one video in memory, not three, and revoke the rest. Checkpoint 2 measures time to first frame (aim: under 1 s for 10 MB) and memory (`dumpsys meminfo`).
4. **Seeking.** Chromium serves a blob from memory and seeks within it, and the MP4's `moov` position doesn't matter. Expected fine; tested.
5. **Leaving the app.** WebView may keep playing audio in the background. Pause every video on `visibilitychange` when the page is hidden.
6. **Activity re-creation** (razr screen switch). If the page reloads, the blob and the `playing` map go and the poster comes back. Acceptable; check that nothing errors.
7. **Fallback** if blob playback fails on the razr (memory, seeking): `serve_media` serves `<id>.mp4` with `Range`/206 through the custom protocol (the SPEC's existing fallback). Only if needed.

*Desktop gap found while planning (not 9c):* HDR phone clips sent from a computer come out washed out, because the desktop path converts to 8-bit with no tone-mapping. Phones share HDR clips to computers rarely; note it in the README and fix later.

*Testing on the razr*

- The razr runs release-signed builds, and a debug build can't install over one without wiping data, so it has no WebView DevTools. Drive it with `ui.py` (uiautomator, taps, screenshots). Option, only with the user's OK: a local-only `SIDETRAY_WEBVIEW_DEBUG` build flag that calls `WebView.setWebContentsDebuggingEnabled(true)`, never set in CI.
- Test clips (made on the PC, pushed to `/sdcard/Movies/SideTrayTest/` and media-scanned, deleted afterwards): 45 s 1080p, 90 s, portrait (rotation 90), 4K60 HEVC, 10-bit HLG HDR, mono, no audio, plus one real razr recording with location on. The picker shows the real gallery: open the test album, take a screenshot before every tap, and never tap Done blind.
- The phone ("James Phone Test" in Campfire Club) gets the branch build with `adb install -r`, which keeps its data. Alex's and Bea's copies are the desktop side. tst-svr only.

*Checkpoints* (each one builds, passes the tests and is committed to `phase-9-video`; the progress note says which are done)

1. **Media3 spike.** Add the Media3 dependencies, then add `probeVideo`, `transcodeVideo`, `transcodeState`, `cancelTranscode` and `videoFrame` with their JNI wrappers. Drive one encode of a pushed clip from a hidden debug command. Measure: APK size before and after (release, arm64), encode time for 60 s, output size against the 9.5 MB target, profile, the metadata boxes, and HDR tone-mapping. **Stop and report**: this is the encoder decision gate.
2. **Receiving and playback on the razr** (no sending yet). The branch build on the phone downloads and acks desktop videos and plays and seeks them. Lightbox full screen, the gesture check, pause on hidden, one video in memory. Measure time to play and memory.
3. **Metered check and the setting.** `isMetered`, `device-settings.json`, the Settings switch, the held state, and tap to download. Test on the razr: Wi-Fi off, mobile data on, setting off, video stays held; tap it, it downloads; back on Wi-Fi, held ones download.
4. **Sending from the phone.** The Android encoder in `video.rs` (probe → `plan()` → transcode → size check and retry → metadata strip → poster), the phone Video button, the picker, the 60-second question, progress and cancel. Test: 45 s → 720p, 90 s → first 60 s at 480p, portrait, HDR, a cancel, a DM; Alex and Bea play them.
5. **Share → Side Tray** with videos (single, several, mixed with photos).
6. **The full "Done when" on the razr and desktop**, then a release (R8) build check, since Media3 ships its own keep rules but R8 broke WorkManager before. Update CHANGELOG and README (permissions, licences).

**Done when** a 45 s phone clip posts at 720p and a 60 s one at 480p, each under 10 MB with a working poster frame and no metadata, and a 90 s clip posts as its first 60 s after the question. Every device of the group plays it after download, and the relay deletes the file once the last device acks (the post and poster frame stay). A video nobody fetched is gone after 14 days; with the caps set low, the oldest go first and an upload that can't fit gets a clear error. A DM video works the same for just the two people's devices, and a third member gets 404. With *Auto-download videos on mobile data* off, the razr on mobile data leaves a video pending until it's back on Wi-Fi. A member whose copy expired taps Request, and the poster taps Send it and the requester plays it. Desktop (Windows) and the razr both transcode, show progress and seek during playback. With `SIDETRAY_HISTORY_DAYS=0`, a feed photo stays on the relay until every device has downloaded it.

**Progress** (branch `phase-9-video`; update after each step)

- 9a done (relay retention and per-file acks, app feed-photo acks), tested live on tst-svr / Campfire Club.
- 9b step 1 done: `scripts/build-ffmpeg.sh` (trimmed LGPL ffmpeg 9.0.2, cross-compiled with mingw-w64), `tauri.ffmpeg.conf.json` overlay (`externalBin`, used by the release workflow's Windows build so plain builds and tests don't need the binary), release job `ffmpeg`, `video.rs` (finds `ffmpeg.exe` next to the app or `SIDETRAY_FFMPEG`; `video_support` command checks for `h264_mf`, `aac` and Media Foundation). The binary itself hasn't been built yet: the build needs the user's go-ahead (auto mode refuses to compile downloaded source). Dev testing uses the winget ffmpeg via `SIDETRAY_FFMPEG`.
- 9b step 2 done: `video.rs` probe (parses `ffmpeg -i`: duration, display size after rotation, audio channels), `plan()` (SPEC bitrate maths: 720p to about 48 s, then 480p; 60 s = 1,170 kb/s), `prepare()` (one encode with `h264_mf` High profile, peak-constrained VBR, `-t` trim, `-fpsmax 30`, metadata stripped, faststart; re-encode at 85% if over 9.5 MB; poster frame at 1 s through `photo::poster`; progress from `-progress pipe:1`; cancel kills ffmpeg first). Commands `pick_video` (native dialog via tauri-plugin-dialog, Rust-side only), `stage_video {path, trim}` (returns `needs_trim` for clips over 60 s until asked again with `trim: true`), `cancel_transcode`, `unstage_video`, `staged_video`; events `video-progress {profile, fraction}`. Prepared MP4s wait in `<profile>/staging/` (cleared at start). Tests run real encodes when `SIDETRAY_FFMPEG` is set.
- 9b step 3 done: `videos` table (state, poster, ack flags, `mine`); `video` field in posts (`feed.rs` `PostBody`) and DMs (`dm.rs` `DmBody`; a video-only message is allowed); `video::upload` (streamed `POST /media?kind=video` with `upload-progress` events; 507 and 429 explained), poster uploaded as an image; the sender keeps `<id>.mp4`. Sync: `video::fetch_thumbs` (also before the DM ack, which now waits for poster frames but not video files), then `fetch_videos` (newest first, one at a time, `video-state` progress events, 410 -> `expired`, 5 attempts -> `failed`), then `video::ack`. Deleted posts queue their video acks. UI: Video button in the post and DM composers (desktop), progress bar with Cancel, "Use the first 60 seconds?", staged poster with length, upload progress, poster with state in feed and chat. Tested on Alex's and Bea's copies (SIDETRAY_FFMPEG): 45 s -> 720p 8.2 MB, 90 s -> first 60 s at 480p 9.4 MB, both downloaded and acked; the DM video was pruned as delivered.
- 9b step 4 done: playback from a `blob:` URL (`read_video` returns the decrypted MP4 as raw bytes; CSP `media-src 'self' blob:`; the `<video>` survives feed and chat redraws; seeking works, no Range needed on desktop). Expired: greyed poster, "Video expired", **Request** (hidden on your own, disabled when the author can't get messages) opens the DM pre-filled with "Could you send me your video from <date>?" and a `video_request {post_id, video_id}` (`dm_messages.video_request`). An incoming request shows **Send it** where this device has the file and it's this member's video, otherwise "This video isn't on this device". Your own ready video has **Send in a message…** (picker, then a staged copy). `stage_local_video` copies the local MP4 into staging, so a re-send is a new file and key. Tested on Alex and Bea: play and seek, expired via 410, Request, Send it, play the re-sent copy, Send in a message, Cancel mid-encode.
- **9b is done.** The bundled ffmpeg is built (`scripts/build-ffmpeg.sh` in WSL, which needs `--enable-d3d11va` for `h264_mf`; 12 MB, LGPL), and the video tests pass with it (`SIDETRAY_FFMPEG` = the bundled build, `SIDETRAY_TEST_SOURCE_FFMPEG` = a full ffmpeg to make the lavfi test clips). `cargo tauri build --config tauri.ffmpeg.conf.json` puts `ffmpeg.exe` next to the app. Open: macOS/Linux encoders (no sidecar there yet: those apps play videos but can't send); dropping a video file on the composer (only the Video button for now).
- 9c planned (see "9c plan: Android" above): Media3 Transformer, not a bundled ffmpeg. Nothing built yet.
- 9c step 0 done: `SIDETRAY_WEBVIEW_DEBUG=1` (local builds only) turns on WebView DevTools in a release build and adds `assets/webview-debug`; Gradle refuses it when `CI` is set, and the release workflow fails on an APK with that file.
- **9c checkpoint 1 done (Media3 spike), waiting for the user's decision.** `SideTrayVideo.kt` (probe, Transformer 1.11.1, progress, cancel, poster frame), JNI in `android.rs`, `video::out_size`, and a temporary `video_spike` command. Results on the razr (release build, arm64):
  - APK: 14,090,473 → 14,707,548 bytes (+617 KB, +4.4%; Media3 is +547 KB of dex, the Rust code +50 KB).
  - Speed: 45 s 1080p → 720p in 4.5–4.8 s; 90 s → first 60 s at 480p in 5.7–7.4 s; 15 s 4K60 HEVC → 720p30 in 2.8 s.
  - Output: H.264 High (level 3.1), 30 fps, AAC 96 kb/s, stereo or mono as the source; portrait keeps its rotation (720×1280 as displayed, poster 225×400 upright); trim gives 60.02 s; the `moov` is at the front (streamable).
  - Size: the hardware encoder's VBR overshoots by about 27% (45 s: 12.1 MB, then 10.4 MB after the 85% retry, over the 10 MB limit). CBR hits the requested rate; what's left over is the muxer's fixed ~400 KB reserve for the `moov` (CBR first try 9.86 MB; CBR plus a retry rescaled by the measured overshoot: 9.09 MB). **So: CBR, plan the bitrate against 9.5 MB minus that 400 KB, and make the retry rescale by the measured overshoot instead of a flat 85%.**
  - Metadata: the source's location (`©xyz` in `udta`) is copied into the output; other tags (comment) aren't. The planned in-place strip is needed.
  - HDR: an HLG-tagged clip is detected and comes out as 8-bit BT.709, but the test clip is a synthetic pattern, so whether the colours look right needs a real HDR recording from the razr (checkpoint 4).
  - Not tried yet: cancel on the phone (wired, tested in checkpoint 4).
- Decided after checkpoint 1: Media3 with CBR; the Android plan budgets 9.5 MB minus the ~400 KB `moov` reserve; the retry rescales the bitrate by the measured overshoot (×0.95 margin) instead of a flat 85%. Built in checkpoint 4.
- **9c checkpoint 2 done (receiving and playback on the razr), waiting for the go-ahead.** Results:
  - Blob playback is impossible on Android: `read_video` of an 8 MB file never returned. Tauri 2.12 on Android can't use its custom-protocol IPC (`canUseCustomProtocol = osName !== 'android'`), so a large raw reply goes back as a JS array literal. Replaced by the planned fallback: `serve_media` serves the decrypted `.mp4` with `Range`; `VideoView.src` on Android; desktop keeps the blob.
  - On the razr (screen on): metadata in 5 ms, a seek to 30 s in 38 ms (the player asks `Range: bytes=131072-` and gets 206); a real tap plays with sound, so `mediaPlaybackRequiresUserGesture` stays as it is; the scrubber seeks.
  - Full screen: Android's own button is greyed out (`controlslist=nofullscreen`); the app's ⛶ button moves the playing `<video>` into `#video-viewer` (it plays on), × or Back puts it back in the post, still playing.
  - Leaving the app (Home) pauses it; it stays paused on return.
  - One video in memory on a phone: playing the DM video put the feed video back to its poster. App process +6 MB while playing (PSS 196 → 202 MB); the WebView renderer 113 MB PSS.
  - A feed post (720p, 45 s) and a DM (480p, 60 s) from Alex downloaded and played on the phone. Posts the phone received while on the old app stay text-only (it never recorded their video), as expected.
  - Desktop re-checked on Alex's copy: blob playback and seeking unchanged, no ⛶ button.
  - Not tested: the razr switching screens (activity re-creation) mid-playback.
- Next: 9c checkpoint 3 (metered check and the mobile-data setting).

## Distribution and later

**Distribution**

- Unsigned Windows installers trigger the SmartScreen warning; options are a code-signing cert (~$100–300/yr) or a one-line "More info → Run anyway" instruction on the install page
- macOS needs an Apple Developer account ($99/yr) for notarization, or users right-click → Open
- Tauri has a built-in updater that reads signed release manifests from GitHub; turn it on in phase 7

**Later**

- Facebook "Send to Side Tray too?" browser extension
- Android app: see "Android app" above; iPhone later
- Archive sharing for new members, SQLCipher at rest, email verification via the M365 domain
- iPhone photos: accept HEIC/HEIF in the photo picker (decode, then the same resize, EXIF strip and WebP encode)
- Linux: keep the device's private keys and token in the system keyring (Secret Service / libsecret) instead of the local database
