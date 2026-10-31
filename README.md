# Side Tray

Private, end-to-end encrypted feed for one group. See [SPEC.md](SPEC.md).

**Status: Phase 5 (tray, notifications, real-time push).** A Tauri 2 desktop app
(`app/`) has a first-run wizard (join, or found the group with the setup token),
the safety-code join flow, a Key Master screen, and a feed with posts, photos,
comments and reactions. It keeps a local SQLite archive and syncs the moment the
relay pushes a change over a WebSocket (polling every 30 seconds only while the
socket is down). It lives in the system tray with an unread badge and shows
native notifications. Devices join with their public keys, compare safety codes
with a Key Master by phone, and receive the group key sealed to them and signed by
the approving Key Master. The dev CLI (`cli/`) speaks the same formats. Pruning,
removal, key rotation and rate limits come in Phase 6; direct messages are
specified as Phase 5b in SPEC.md.

## Layout

```
compose.yaml          api (FastAPI + SQLite) behind caddy (HTTPS)
Caddyfile             TLS via Caddy's internal CA (no domain yet)
server/app/main.py    the relay
scripts/smoke-test.sh live TLS checks + full API run on a throwaway container
scripts/ws_probe.py   stdlib-only WebSocket client the smoke test uses for /ws
crypto/               Rust crate: keys, sealing, encryption, signatures, safety codes
cli/                  Rust dev CLI (`sidetray`): init-group, join, approve, post, pull
app/src-tauri/        desktop app backend (Rust, Tauri 2)
app/ui/               desktop app frontend (plain HTML/CSS/JS, no build step)
```

## Run

Needs Docker Engine with the Compose plugin.

```sh
cp .env.example .env     # set SIDETRAY_HOST and SIDETRAY_SETUP_TOKEN
docker compose up -d --build
./scripts/smoke-test.sh  # never touches the real group
```

Data lives in the `api_data` volume (`/data/sidetray.db` and `/data/media/`).
Caddy's CA and certs live in `caddy_data`; keep that volume or clients will need the new root.

## Trusting the test certificate

There's no domain yet, so Caddy signs a cert for the IP with its own local CA.
Export the root and point curl at it:

```sh
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > sidetray-root.crt
curl --cacert sidetray-root.crt https://10.1.1.188/api/v1/health
```

When a domain exists, set `SIDETRAY_HOST` to it and remove `tls internal`
from the Caddyfile to get a Let's Encrypt cert.

## API

All under `/api/v1`. Authenticated calls send `Authorization: Bearer <device token>`;
the token comes back from `POST /join` and is stored hashed. Binary fields are
base64. The server never decrypts.

| Method | Path | Who | Body / params | Returns |
| --- | --- | --- | --- | --- |
| GET | /health | anyone | | `{ok}` |
| GET | /group | anyone | | `{exists, id?, name?}` |
| POST | /join | anyone | `{group_name, display_name, email, enc_pubkey, sign_pubkey, setup_token?}` | `{group_id, group_name, member_id, device_id, token, status, role}` |
| GET | /join/status | any device token | | `{status: pending\|active\|denied, role?, sealed_keys[]?}` |
| GET | /keys | member | | `{sealed_keys[]}` |
| GET | /joins/pending | Key Master | | `{pending[]}` with each device's public keys |
| POST | /joins/{device_id}/approve | Key Master | `{sealed_keys: [{key_version, sealed_blob, signature}], cert, anchors[], anchors_signature}` | `{status: active}` |
| POST | /joins/{device_id}/deny | Key Master | | `{status: denied}` |
| GET | /members | member | | `{members: [{id, display_name, role, devices: [{id, enc_pubkey, sign_pubkey, certs[]}]}]}` |
| POST | /certs | Key Master | `{certs: [{device_id, role, display_name, signature}]}` | `{stored}` |
| POST | /members/{id}/role | Key Master | `{role: "keymaster", certs[]}`, one per active device | `{role}` |
| POST | /events | member | `{kind, key_version, ciphertext, signature, media_ids[]}` | `{seq}` |
| GET | /events | member | `?after=<seq>&limit=<1..500>` | `{events[], last_seq, has_more}` |
| POST | /ack | member | `{seq}` (only moves forward) | `{last_seq}` |
| POST | /media | member | raw bytes, max 10 MB | `{id, size_bytes}` |
| GET | /media/{id} | member | | the bytes |
| WS | /ws | member | `Authorization: Bearer` on the upgrade request | push messages, below |

- **Creating the group:** on a server with no group, `POST /join` with the
  operator's `SIDETRAY_SETUP_TOKEN` creates it, and that device becomes the active
  Key Master. Without the right token it's refused, so nobody else can claim an
  empty server. Once the group exists the setup token does nothing.
- **Joining:** anyone else's join is `pending`. A pending token works only for
  `/join/status`. Joining with the email of an existing member adds a device to
  that member (the pending list flags it).
- **Approving:** a Key Master uploads the group key (every version) sealed to the
  new device. Each sealed blob carries the Key Master's Ed25519 signature over
  `protocol::key_grant_message` (group, recipient device, recipient key, version,
  blob). `/join/status` returns it with the signer's public keys.
- **Certificates:** every device in the roster carries member certificates:
  a Key Master's signature over `protocol::member_cert_message` (group, member,
  device, display name, role, both public keys, issuer). The server only checks
  that a certificate's role and name match its records; clients verify the
  signatures. Approving uploads the new device's certificate, plus the Key
  Master keys the approver trusts (`anchors`), signed over
  `protocol::anchors_message`. Promotion needs a `keymaster` certificate from the
  calling Key Master for each of the member's devices. Demotion waits for
  revocation (Phase 6).

## Push channel (Phase 5)

`/api/v1/ws` is a WebSocket for "something changed" hints; content still only
comes from `GET /events`. A missing, unknown, pending or revoked token gets HTTP
403 instead of a socket. Messages are JSON text frames:

| Message | Sent to | Meaning |
| --- | --- | --- |
| `{"type":"hello","device_id"}` | the new socket | connected |
| `{"type":"new_event","seq","kind"}` | every active device except the author's | an event was appended: sync |
| `{"type":"join_request","device_id","display_name","existing_member"}` | Key Masters' devices | someone is waiting for approval |
| `{"type":"key_rotated","key_version"}` | every active device | fetch `GET /keys` (sent by key rotation, Phase 6) |
| `{"type":"removed"}` | the revoked device; then the socket closes | sent by member removal (Phase 6), and by the socket itself if it notices the device is no longer active |
| `{"type":"pong"}` | the pinging socket | reply to `{"type":"ping"}` |

Clients send `{"type":"ping"}` every 25 seconds; a socket silent for 75 seconds
(`SIDETRAY_WS_IDLE_SECONDS`) is closed. Up to 4 sockets per device. The hub is in
memory, so the relay runs as a single uvicorn worker (it already did). Caddy
proxies the upgrade with no extra configuration.

## Roster trust

The server relays the roster, but clients don't take its word for it
(`crypto::roster::verify_roster`):

- Each device pins **anchors**: the Key Master signing keys it trusts.
  - The founder pins itself.
  - A joining device pins the approving Key Master, but only after the user types
    that Key Master's code (`status --km-code`). It also pins the Key Masters the
    approver vouched for in the signed anchors list.
- A certificate counts only if it's signed by an anchor or by a device that
  itself has a valid `keymaster` certificate. A promotion therefore needs an
  existing Key Master's signature. A member can't certify anyone, including
  promoting itself.
- Devices without a valid certificate are listed as `UNVERIFIED`, and `pull`
  refuses their posts. Names and roles shown come from certificates, never from
  the server's fields.

## Desktop app (Phase 4)

Build on Windows: the Rust MSVC toolchain, Visual Studio C++ Build Tools and
the WebView2 runtime (preinstalled on Windows 11). No Node or npm is needed:
the UI is plain files in `app/ui/`, embedded at build time.

```sh
cd app/src-tauri
cargo build --release          # target/release/sidetray-app(.exe)
cargo test                     # photo stripping, event checks, notices, key storage, badge
```

Installers (`.msi` etc.) come with Phase 7 via `cargo install tauri-cli` and
`cargo tauri build`.

- **First run.** The wizard asks for the server address and checks `GET /group`.
  If the group exists, it asks for the group name, your display name and email,
  then sends the join request. It shows the safety code big, and polls until a
  Key Master approves. You then type the code that Key Master reads back to you,
  the same check as the CLI's `status --km-code`. Nothing is stored or trusted
  until it matches. On a server with no group, the wizard offers to create one
  with the operator's setup token, and you become its Key Master.
- **Key Master screen.** Lists pending joins without their codes: you type the
  code you heard, and the app approves only if it matches the keys the server
  relayed. It then shows your own code to read back. You can also deny.
- **Feed.** Newest first: posts, photos, comments, one reaction per person per
  post, and delete for your own posts. It syncs after every action and whenever
  the push socket says something changed. While the socket is down it polls
  every 30 seconds and reconnects with backoff (1 s doubling to 60 s, with
  jitter); while it's up, a 15-minute poll is only a safety net. The header shows
  **Live** while connected. Sync applies the same rules as
  `pull`: an event counts only if its author has a member certificate chaining
  to a pinned Key Master, the signature verifies and it decrypts. Anything else
  is skipped and counted under *This device*.
- **Tray.** Closing the window hides it; the app keeps running in the system
  tray. Left-click the icon (or its *Open Side Tray* menu item) to bring it back;
  *Quit* is the only way to exit. Launching the app again focuses the running
  copy. The icon gets a red badge with the number of new posts and comments by
  others (plus waiting join requests for Key Masters), "9+" past nine, and the
  tooltip spells it out. The count clears when the feed is on screen in a
  focused window. A new device's first sync (the backlog) doesn't count.
- **Notifications.** Native toasts for posts by others, comments by others on
  your posts, and, for Key Masters, new join requests. More than three at once
  become one summary. Nothing pops up while the window is in front. Clicking a
  toast opens the app scrolled to that post (or to the Key Master tab). On
  Windows the app registers its AppUserModelID (`org.sidetray.app`) under
  `HKCU\Software\Classes\AppUserModelId` at startup, since toasts need one and
  there's no installer yet. Clicks are handled while the app is running and the
  toast is on screen; clicking an old toast in the notification centre isn't
  wired up yet (needs the installer's COM activator, Phase 7). On macOS and
  Linux toasts go through `tauri-plugin-notification`, which can't report
  clicks.
- **Start with Windows.** *This device → Settings* has a toggle, off by default.
  When on, the app starts at sign-in hidden in the tray (`--minimized`), via
  `tauri-plugin-autostart` (a `HKCU\...\Run` entry on Windows, a launch agent
  on macOS, an autostart entry on Linux).
- **Photos.** Resized so the longest side is 2048 px and saved as WebP at
  quality 80, plus a 400 px thumbnail. The EXIF orientation is applied, then all
  metadata (GPS included) is dropped, because the output is encoded from raw
  pixels. Both files are encrypted with the group key
  (AD `protocol::media_ad(group)`) and uploaded to `POST /media`. The post
  records each blob's `blob_digest`, so the server can't swap photos; it's
  checked before decrypting.
- **HTTPS.** `app/src-tauri/pinned-roots.pem` (Caddy's internal root for the
  test relay) is compiled in. When it's non-empty, the app trusts exactly those
  roots and no others, for both HTTPS calls and the `wss://` push socket. The wizard's *Advanced* box can pin a different root PEM
  for a server. If the file is emptied, the public web roots are used, for when
  the server gets a real domain. Verification is never off. Plain `http://` is
  accepted only for `127.0.0.1`/`localhost`, for a relay in development.
- **Local data** lives in the app data dir (`%APPDATA%\org.sidetray.app` on
  Windows; `SIDETRAY_DATA_DIR` overrides it, and lets test copies run side by
  side without the single-instance check). `sidetray.db` holds the spec's
  client tables plus `anchors` and `member_devices`, and `media/` holds the
  decrypted photos. Posts are plaintext on disk (SPEC: rely on OS disk
  encryption). The device's private keys, its token and a local wrapping key
  are kept in one Windows Credential Manager / macOS Keychain entry. Group keys
  sit in SQLite, encrypted under that wrapping key. Linux has no keychain
  backend yet, so there those secrets live in the database.

## Event payloads

Event content is JSON, encrypted with AD `protocol::event_ad(group, kind)` and
signed over `protocol::event_message`. Comments, reactions, edits and deletes
point at a post by its **event id**, `crypto::event_id(ciphertext)` (32 hex
characters). Every client computes it the same way, and the server can't change
it without breaking the signature.

| kind | payload |
| --- | --- |
| post | `{"text", "photos"?: [{"full", "full_digest", "thumb", "thumb_digest", "width", "height"}]}`, with media ids, and digests as base64 `blob_digest` of each encrypted blob |
| comment | `{"post": event_id, "text"}` |
| reaction | `{"post": event_id, "emoji"}`. The latest one per member wins; `""` removes it |
| edit | `{"post": event_id, "text"}`. Only the post's author |
| delete | `{"post": event_id}`. Only the post's author |

A post's photo media ids also go in the event's clear `media_ids` field, so the
server can prune them with the event.

## CLI (Phase 3)

```sh
cd cli && cargo build --release      # binary: target/release/sidetray
```

Each device keeps its keys and state in `--state <dir>` (default `.sidetray`),
so several can run side by side. Pass `--ca-cert sidetray-root.crt` while there's
no real domain.

| Command | Who | What it does |
| --- | --- | --- |
| `init-group --server --group --name --email --setup-token` | first device | Creates the group, makes you Key Master, generates group key v1 |
| `join --server --group --name --email` | new device | Sends public keys, prints the safety code to read out |
| `pending` | Key Master | Lists join requests with codes computed from the relayed keys |
| `approve <device> --code <code>` | Key Master | Refuses unless the code you heard matches; seals and signs every key version; prints your Key Master code |
| `deny <device>` | Key Master | Rejects a request |
| `status [--km-code <code>]` | anyone | After approval: verifies the grants and anchors, then stores keys and pins the approver once you type their code. Later: picks up a promotion |
| `certify [<device> --code <code>] [--keymaster]` | Key Master | Self-certify, or certify a device approved before certificates existed |
| `promote <member_id>` | Key Master | Signs Key Master certificates for a verified member's devices |
| `members`, `post <text>`, `pull` | members | Verified roster (flags unverified devices); encrypt + sign a post; verify author certificate + signature, decrypt, ack. `pull` shows each post's id, photo count, comments and reactions |
| `comment <post_id> <text>`, `react <post_id> <emoji>` | members | Comment on or react to a post by its id (`react <id> ""` removes your reaction) |

Posts are encrypted with associated data `protocol::event_ad(group, kind)`.
Authors sign `protocol::event_message(group, author device, kind, version, ciphertext)`.
The state file holds private keys and is created with mode 0600. The desktop app
will use the OS keychain instead.

## Crypto core (Phase 2)

`crypto/` is a pure-Rust library (no system libsodium) whose formats match libsodium:

| Function | Construction | Format |
| --- | --- | --- |
| `generate_device_keys` | X25519 + Ed25519 | 32-byte public keys each |
| `generate_group_key(version)` | 32 random bytes | |
| `seal_group_key` / `unseal_group_key` | `crypto_box_seal` | seals `u32le(version) ‖ key`, 84 bytes |
| `encrypt` / `decrypt` | XChaCha20-Poly1305 IETF | `nonce[24] ‖ ct ‖ tag[16]`, AD = `u32le(key_version) ‖ ad` |
| `sign` / `verify` | Ed25519 detached, strict verify | 64 bytes |
| `safety_code` | BLAKE2b-256 over both public keys, 1024-word list | `MISS-PARCEL-EARTH-PRICE-88` |
| `blob_digest` | BLAKE2b-256, domain-separated | 32 bytes; pins an encrypted photo to its post |
| `event_id` | BLAKE2b-256 of an event's ciphertext, domain-separated | 32 hex characters |

```sh
cd crypto && cargo test
```

The tests include vectors produced by libsodium (via PyNaCl) and RFC 8032, and they
check that flipping any single byte is caught. The wordlist in `crypto/src/wordlist.rs`
is frozen: a test pins its hash, because editing it would change every safety code.
It comes from the public-domain [12dicts](http://wordlist.aspell.net/12dicts/) lists;
`crypto/tools/wordlist/` has the script and blocklist that picked it.

## Notes

- Every table carries `group_id`; the MVP has one group per server.
- Tokens are stored as SHA-256 hashes.
- Every startup removes the Phase 1 seed (group `g_test`). The cleanup is a no-op
  once the seed is gone, and touches only rows with `group_id = 'g_test'`; real ids
  are `g_` plus 16 random characters. `server/tests/test_legacy_cleanup.py` checks this
  (`cd server && python -m unittest discover tests`).
- Footprint on the test VM: ~35 MB (api) + ~70 MB (caddy), with 256 MB / 128 MB caps.
