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

- Delete events and media where every active device's `last_seq` is at or past them
- Also delete anything older than the retention window (default 90 days, `SIDETRAY_RETENTION_DAYS`), even if someone hasn't synced
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
- In the app, one install still joins one group. An in-app group switcher (several identities side by side) is a later phase.

**Done when** `install.sh` brings up a fresh VPS on a real domain, the app joins it with no pasted certificate, an invite link opens the wizard pre-filled, a cropped avatar and a new name show up on another member's device, and a second group created with `sidetray-admin new-group` can't see or be found from the first.

## Android app

Side Tray 0.1.1 runs on Windows and Linux. This section plans a phone app for Android. A1 and A2 are built (see "As built" under each); A3 and A4 are not.

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

**A4. Release pipeline**

- GitHub Actions builds a signed release APK on `v*` tags (alongside the desktop builds) and attaches it to the release, with its version in the update manifest.
- In-app update prompt: on start and daily, check the manifest; if newer, show "New version available" with *Download*, then hand the APK to the installer (the person allows "install unknown apps" for Side Tray once).
- The APK signing key stays out of the repo: a keystore in GitHub Actions secrets (base64 keystore, store and key passwords), with an offline backup kept by the maintainer. Losing it means users must uninstall and reinstall (a new device and a new join), so the backup matters.
- **Done when** a tag produces a release with the APK attached, and a phone running the previous version offers the update and installs it.

## Backlog for 0.1.2

- "Start Side Tray when I sign in" (*This device → Settings*) defaults to ON for new installs. Existing installs keep whatever they have.

## Distribution and later

**Distribution**

- Unsigned Windows installers trigger the SmartScreen warning; options are a code-signing cert (~$100–300/yr) or a one-line "More info → Run anyway" instruction on the install page
- macOS needs an Apple Developer account ($99/yr) for notarization, or users right-click → Open
- Tauri has a built-in updater that reads signed release manifests from GitHub; turn it on in phase 7

**Later**

- In-app group switcher (one install in several groups); the server side is Phase 6b
- Facebook "Send to Side Tray too?" browser extension
- Android app: see "Android app" above; iPhone later
- Archive sharing for new members, SQLCipher at rest, email verification via the M365 domain
- iPhone photos: accept HEIC/HEIF in the photo picker (decode, then the same resize, EXIF strip and WebP encode)
- Linux: keep the device's private keys and token in the system keyring (Secret Service / libsecret) instead of the local database
