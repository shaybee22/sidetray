# Side Tray

Private, end-to-end encrypted feed for one group. See [SPEC.md](SPEC.md).

**Status: Phase 5b (direct messages), after 6b.** A Tauri 2 desktop app
(`app/`) has a first-run wizard (join, or found the group with the setup token),
the safety-code join flow, a Key Master screen, and a feed with posts, photos,
comments and reactions. It keeps a local SQLite archive and syncs the moment the
relay pushes a change over a WebSocket (polling every 30 seconds only while the
socket is down). It lives in the system tray with an unread badge and shows
native notifications. Devices join with their public keys, compare safety codes
with a Key Master by phone, and receive the group key sealed to them and signed by
the approving Key Master. Key Masters manage members from the app: promote,
remove, or revoke a lost device, after which their app rotates the group key
for everyone left. The relay prunes what every device has fetched, and anything
past 90 days. The dev CLI (`cli/`) speaks the same formats. A server can host
several groups that can't see or find each other, `install.sh` sets one up on
a fresh Debian or Ubuntu machine, and the relay enforces rate limits (see
[Run your own server](#run-your-own-server)). The app trusts a server on a
domain through the public certificate roots, and a test server only after its
person confirmed the root certificate's fingerprint. Key Masters invite people
with a `sidetray://` link or QR code, and everyone can set a photo and ask
for a new name, which shows once a Key Master accepts it. Members send each
other end-to-end encrypted direct messages (text and photos) that only the
two people's devices can read. Still to come: release builds (7), specified
in SPEC.md.

## Layout

```
install.sh            server installer: Docker, /opt/sidetray, HTTPS, first setup token
compose.yaml          api (FastAPI + SQLite) behind caddy (HTTPS)
Caddyfile             TLS via Caddy's internal CA, for a dev checkout on a LAN IP
server/app/main.py    the relay
server/app/admin.py   operator commands (`sidetray-admin new-group | list-groups | prune`)
scripts/smoke-test.sh live TLS checks + full API run on a throwaway container
scripts/ws_probe.py   stdlib-only WebSocket client the smoke test uses for /ws
crypto/               Rust crate: keys, sealing, encryption, signatures, safety codes
cli/                  Rust dev CLI (`sidetray`): init-group, join, approve, post, pull
app/src-tauri/        desktop app backend (Rust, Tauri 2)
app/ui/               desktop app frontend (plain HTML/CSS/JS, no build step)
```

## Run your own server

You need a small Debian or Ubuntu machine (1 vCPU, 1 GB RAM and 25 GB of disk
is plenty; tested on Ubuntu 26.04) with ports 80 and 443 free. For real use,
also get a domain name with an A (and/or AAAA) record pointing at the server.
From a checkout or release folder, as root:

```sh
sudo ./install.sh
```

It asks:

1. **How people reach the server.** Either a **domain name** plus an email
   address for Let's Encrypt (production: a publicly trusted certificate,
   renewed automatically), or a **LAN IP address** (test mode: Caddy signs
   with its own CA; the app shows that CA's fingerprint when someone first
   connects, and they compare it with what the installer printed). For a
   domain, it checks that the name resolves to this machine before going on.
2. **Retention**: how many days the relay keeps posts and photos that not
   every device has fetched yet (default 90).

Then it installs Docker Engine and the Compose plugin from Docker's apt
repository (if missing), writes `/opt/sidetray` (`compose.yaml`, `Caddyfile`,
`.env`, `server/`), builds and starts the stack, waits until
`https://<address>/api/v1/health` answers, and prints a **setup token**. Give
the token to whoever will run the group: in the app's wizard they enter the
server address and a name for the group, then their name and email and the
token, and they become the group's first Key Master. In test mode it also
saves the root certificate as `/opt/sidetray/sidetray-root.crt` and prints its
SHA-256 fingerprint: tell it to everyone who connects, by a channel you trust
(the app shows the same fingerprint and asks them to compare). If the
Caddyfile changed, re-running the installer restarts Caddy so it takes effect.

For unattended runs, every question has a flag:
`--domain tray.example.org --email you@example.org` or `--ip 10.1.1.191`,
`--retention 90`, `--yes` (keep existing settings), and `--new-group` (also print a
token for another group). Piped from a release, `curl -fsSL <url>/install.sh |
sudo SIDETRAY_SOURCE_URL=<release tarball> bash` works the same way.

**Re-running it is safe.** It updates the code and restarts the stack. The data
volumes (`sidetray_api_data`, `sidetray_caddy_data`) and `.env` are kept;
only the settings you change are rewritten, and the old file is saved as
`.env.bak`. Other files it replaces are saved as `.bak` too. It issues a new
setup token only when the server has no group and no unused token, or with
`--new-group`. Tokens are stored hashed, so a lost one can't be shown again;
issue a new one instead.

### Updating a server

Updating is the same command as installing: get the new code, then run the
installer again. From the checkout you installed from:

```sh
cd ~/sidetray          # wherever your checkout is
git pull
sudo ./install.sh --yes
```

From a release instead: `curl -fsSL <release url>/install.sh | sudo
SIDETRAY_SOURCE_URL=<release tarball> bash -s -- --yes`.

`--yes` keeps every setting as it is (domain or IP, retention). The installer
copies the new `compose.yaml`, `server/` and `install.sh` into `/opt/sidetray`
(keeping a `.bak` of anything it replaces), rebuilds the api image and
restarts the stack. The data volumes and `.env` are kept, and the relay
upgrades its database by itself when it starts (new tables and columns are
added in place; nothing is deleted). Clients don't need updating at the same
time: an older app just doesn't use what's new. To check afterwards:

```sh
sudo sidetray-admin list-groups                       # every group still there, with counts
cd /opt/sidetray && sudo docker compose logs api --tail 20
```

If you installed from a plain copy of the files rather than a git checkout,
switch to a checkout once (`git clone <repository> ~/sidetray`) and run the
installer from there; it only needs `compose.yaml`, `server/` and
`install.sh` next to each other.

### More groups, and other admin commands

One server can host several groups. They're separate: a device's token only
works inside its own group, event numbers count per group, and the API never
lists groups. `GET /group?name=` only says whether a group of that exact name
exists. Group names are unique per server (case doesn't matter).

```sh
sudo sidetray-admin new-group      # one-time setup token, valid 7 days (--days N)
sudo sidetray-admin list-groups    # groups with member/device/event counts, unused tokens
sudo sidetray-admin prune          # run the hourly prune job now
```

`sidetray-admin` on the host runs the same command inside the api container
(`docker compose exec api sidetray-admin ...`, which also works in a dev
checkout). `list-groups` is for the operator only; group names and counts
never go out over the API.

### Rate limits

| What | Limit | Key | Setting in `.env` |
| --- | --- | --- | --- |
| `POST /events` and `POST /dms` together | 30 per minute | device | `SIDETRAY_EVENTS_PER_MINUTE` |
| `POST /media` (posts, avatars and message photos) | 50 MB per hour | device | `SIDETRAY_MEDIA_MB_PER_HOUR` |
| `POST /join` | 10 attempts per hour | client IP | `SIDETRAY_JOINS_PER_HOUR` |
| `GET /group?name=` | 60 per hour | client IP | `SIDETRAY_LOOKUPS_PER_HOUR` |

Over the limit, the relay answers `429` with a `Retry-After` header. Attempts
count whether or not they succeed, so wrong group names and setup tokens use up
the join budget too. That stops one address from flooding Key Masters with
join requests or guessing group names. Each group also holds at most 20 pending
requests. The client IP comes from Caddy's `X-Forwarded-For`, which Caddy sets
itself and doesn't take from the client, so a forged header doesn't get
around the limit. The counters live in memory (the relay is one process), so a
restart resets them.

### Files and data

Data lives in the `api_data` volume (`/data/sidetray.db` and `/data/media/`).
The prune job runs hourly. Caddy's CA and certificates live in `caddy_data`;
keep that volume, or test-mode clients will need the new root.

## Run from a checkout (development)

Needs Docker Engine with the Compose plugin.

```sh
cp .env.example .env     # set SIDETRAY_HOST and SIDETRAY_SETUP_TOKEN
docker compose up -d --build
./scripts/smoke-test.sh  # never touches the real groups
```

`SIDETRAY_SETUP_TOKEN` creates the server's first group; later ones need
`docker compose exec api sidetray-admin new-group`. The smoke test sources
`./.env` and runs `docker compose`, so on a server set up with `install.sh`, run
it from a checkout with `.env` linked to `/opt/sidetray/.env` (the Compose
project is named `sidetray` either way).

## Trusting the test certificate

In test mode (a LAN IP, no domain), Caddy signs a cert for the IP with its own
local CA, and serves that CA's root certificate (not its key) at
`https://<ip>/sidetray-root.crt`. The app fetches it there, shows its SHA-256
fingerprint and pins it once the person confirms it matches what `install.sh`
printed. `install.sh` also saves the root as `/opt/sidetray/sidetray-root.crt`;
in a dev checkout, export it and point curl at it:

```sh
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > sidetray-root.crt
curl --cacert sidetray-root.crt https://10.1.1.191/api/v1/health
```

For a Let's Encrypt cert, run `install.sh` with a domain (production mode).

## API

All under `/api/v1`. Authenticated calls send `Authorization: Bearer <device token>`;
the token comes back from `POST /join` and is stored hashed. Binary fields are
base64. The server never decrypts.

| Method | Path | Who | Body / params | Returns |
| --- | --- | --- | --- | --- |
| GET | /health | anyone | | `{ok}` |
| GET | /sidetray-root.crt | anyone | served by Caddy, test mode only (not under /api/v1) | Caddy's root certificate (PEM) |
| GET | /group | anyone | `?name=<group name>` (required; 400 without) | `{exists, name?}` |
| POST | /join | anyone | `{group_name, display_name, email, enc_pubkey, sign_pubkey, setup_token?}` | `{group_id, group_name, member_id, device_id, token, status, role}` |
| GET | /join/status | any device token | | `{status: pending\|active\|denied\|removed\|revoked, role?, sealed_keys[]?}` |
| GET | /keys | member | | `{sealed_keys[], key_version, rotation_pending}` |
| POST | /keys/rotate | Key Master | `{key_version, sealed_keys: [{device_id, sealed_blob, signature}]}` | `{key_version, devices}` |
| GET | /joins/pending | Key Master | | `{pending[]}` with each device's public keys |
| POST | /joins/{device_id}/approve | Key Master | `{sealed_keys: [{key_version, sealed_blob, signature}], cert, anchors[], anchors_signature}` | `{status: active}` |
| POST | /joins/{device_id}/deny | Key Master | | `{status: denied}` |
| GET | /members | member | | `{members: [{id, display_name, role, devices: [{id, enc_pubkey, sign_pubkey, certs[], last_seen?, joined_at?}]}], former: [...]}` (former devices also carry `revoked_seq` and `revoked_dm_seq`) |
| POST | /certs | Key Master | `{certs: [{device_id, role, display_name, signature}]}` | `{stored}` |
| POST | /members/{id}/role | Key Master | `{role: "keymaster", certs[]}`, one per active device | `{role}` |
| POST | /members/{id}/name | Key Master | `{display_name, certs[]}`, one per active device, carrying the new name | `{member_id, display_name}` |
| POST | /members/{id}/remove | Key Master | | `{revoked_devices[], rotation_pending}` |
| POST | /devices/{id}/revoke | Key Master | | `{status: revoked, rotation_pending}` |
| POST | /events | member | `{kind, key_version, ciphertext, signature, media_ids[]}` | `{seq}` |
| GET | /events | member | `?after=<seq>&limit=<1..500>` | `{events[], last_seq, has_more, pruned_through, retention_days, key_version}` |
| POST | /ack | member | `{seq}` (only moves forward) | `{last_seq}` |
| POST | /media | member | raw bytes, max 10 MB | `{id, size_bytes}` |
| GET | /media/{id} | member | | the bytes. A direct message's photo only for the devices it was sealed to and the sender's (`404` for anyone else) |
| POST | /dms | member | `{conversation_id, recipient_member_id, ciphertext, signature, media_ids[], sealed_keys: [{device_id, sealed_key}]}` | `{seq}` |
| GET | /dms | member | `?after=<seq>&limit=<1..500>` | `{messages: [{seq, conversation_id, sender_device_id, sender_member_id, recipient_member_id, ciphertext, signature, media_ids[], created_at, sealed_keys[]}], last_seq, has_more}`, only messages sealed to the calling device |
| POST | /dms/ack | member | `{seq}` (only moves forward) | `{last_seq}` |
| WS | /ws | member | `Authorization: Bearer` on the upgrade request | push messages, below |

- **Creating a group:** `POST /join` with a valid `setup_token` creates a group
  named `group_name`, and that device becomes its active Key Master. Valid
  tokens are one-time tokens from `sidetray-admin new-group` (unused, under 7
  days old) and, while the server has no group yet, the operator's
  `SIDETRAY_SETUP_TOKEN`. A wrong, used or expired token gets `403`, and a
  name that's already taken (ignoring case) gets `409`.
- **Joining:** without a setup token, `POST /join` goes to the group of that
  name, or gets `404` if there's none. The join is `pending`. A pending token works only for
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
  calling Key Master for each of the member's devices. There's no demotion; remove
  the member instead.

## Push channel (Phase 5)

`/api/v1/ws` is a WebSocket for "something changed" hints; content still only
comes from `GET /events`. A missing, unknown, pending or revoked token gets HTTP
403 instead of a socket. Messages are JSON text frames:

| Message | Sent to | Meaning |
| --- | --- | --- |
| `{"type":"hello","device_id"}` | the new socket | connected |
| `{"type":"new_event","seq","kind"}` | every active device except the author's | an event was appended: sync |
| `{"type":"new_dm","seq"}` | the devices a direct message was sealed to (the recipient's, and the sender's other devices) | sync direct messages |
| `{"type":"roster"}` | every active device | a Key Master accepted a new name: sync, so it shows everywhere |
| `{"type":"join_request","device_id","display_name","existing_member"}` | Key Masters' devices | someone is waiting for approval |
| `{"type":"key_rotated","key_version"}` | every active device | a Key Master rotated the group key: fetch `GET /keys` |
| `{"type":"removed","scope"}` | the revoked device; then the socket closes | `scope` is `member` (the member was removed) or `device` (just this device was revoked). Also sent by the socket itself if it notices the device is no longer active |
| `{"type":"pong"}` | the pinging socket | reply to `{"type":"ping"}` |

Clients send `{"type":"ping"}` every 25 seconds; a socket silent for 75 seconds
(`SIDETRAY_WS_IDLE_SECONDS`) is closed. Up to 4 sockets per device. The hub is in
memory, so the relay runs as a single uvicorn worker (it already did). Caddy
proxies the upgrade with no extra configuration.

## Removal, key rotation and pruning (Phase 6)

- **Removing a member** (`POST /members/{id}/remove`) revokes every device of
  theirs at once: their tokens stop working (`401`), open sockets get
  `removed` and close, and `/join/status` says `removed`. A Key Master can't
  remove themselves. **Revoking a device** (`POST /devices/{id}/revoke`) does
  the same for one device, say a lost laptop; the member stays and its
  `/join/status` says `revoked`.
- **Key rotation.** Either one sets `rotation_pending` (`GET /keys`). The Key
  Master's app then makes key version N+1 with `crypto::grant_group_key`:
  sealed to each remaining device's key *from its verified roster* and signed,
  exactly like a join grant. `POST /keys/rotate` accepts only version N+1 and
  only if it's sealed to exactly the active devices, and pushes `key_rotated`.
  Every app's sync then fetches the new key and accepts it only if a Key Master
  in its own verified roster signed it (`crypto::open_key_grant`). Old versions
  stay, so old posts keep decrypting. If the rotating app is interrupted, the
  pending flag makes the next Key Master sync finish the job.
- **Stale keys are refused.** After a rotation, `POST /events` with an older
  `key_version` gets `409`; the app and CLI fetch the new key and retry once.
  Approvals must include the current version.
- **Removed people's earlier posts.** `GET /members` lists revoked devices under
  `former`, with `revoked_seq`, the last event seq before they were cut off.
  Clients verify their certificates as usual and accept their events only up
  to that seq, so a device that syncs after a removal still shows the posts
  made before it. A device leaves `former` once its events are pruned.
- **Removing a Key Master** could leave members certified only by them
  unverified for some devices, so the removing Key Master's app first re-signs
  certificates for devices it verified just before.
- **Pruning** runs hourly in the relay: it deletes events (and their media)
  that every active device has acked, and anything older than
  `SIDETRAY_RETENTION_DAYS`. Revoked devices and removed members don't hold
  anything back; a device that has never acked holds everything back.
  Uploads no event or message refers to go after a day. Direct messages
  count only their own devices: one goes (with its photos) once every
  still-active device it was sealed to has acked it (`POST /dms/ack`), or
  past the retention window. Each active member's latest
  `profile` event and its avatar are never pruned, so devices that join later
  still see names and faces. The relay records the highest seq
  it pruned; `GET /events` returns it as `pruned_through`, and a returning
  device whose cursor is below it shows "You missed some posts".
- Known limits: a key version granted by a Key Master who has since been
  removed can't be verified by a device that comes back after that, so its
  events are rejected there. Removed Key Masters stay pinned as anchors on
  devices that pinned them at join.

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
cargo test                     # photos, events, notices, keys, badge, invites, fingerprints, profiles, messages
```

Installers (`.msi` etc.) come with Phase 7 via `cargo install tauri-cli` and
`cargo tauri build`.

- **First run.** The wizard asks for the server address and the group's name
  (servers don't list their groups). For a test server it first shows the root
  certificate's fingerprint to confirm (see HTTPS below). Then it checks
  `GET /group?name=`: if the group exists, you type your display name and email
  and it sends the join request. It shows the safety code big, and polls until a
  Key Master approves. You then type the code that Key Master reads back to you,
  the same check as the CLI's `status --km-code`. Nothing is stored or trusted
  until it matches. If there's no group of that name, the wizard offers to
  create it with a setup token, and you become its Key Master.
- **Invite links.** The Key Master tab has an *Invite* button: a
  `sidetray://join?server=...&group=...` link with *Copy*, and the same link as
  a QR code. The app registers `sidetray://` for the current user at every
  start (`tauri-plugin-deep-link`; on Windows `HKCU\Software\Classes\sidetray`),
  until the Phase 7 installer does it. Opening a link starts the app, or hands
  it to the running copy, and fills in and checks server and group, so the new
  member types only their name and email. Links carry no secret; anything but
  an `https://` server and a group name is refused, and an app that's already
  in a group says so.
- **Profile.** *This device → Profile*: pick a photo, drag and zoom it inside a
  circle, save. The app crops it to 256x256 in a canvas, re-encodes it as WebP
  (no metadata), encrypts it with the group key, uploads it and publishes a
  signed `profile` event; the name the group sees changes the same way.
  Others' apps check the photo against the digest in the event before showing
  it; until then, or without one, the initial on a coloured circle stays.
  Photos show in the feed, on comments and in the member list.
- **Key Master screen.** Lists pending joins without their codes: you type the
  code you heard, and the app approves only if it matches the keys the server
  relayed. It then shows your own code to read back. You can also deny.
- **Members.** Everyone sees the member list: photo, name, Key Master tag and
  certificate status (verified, partly verified, unverified) for each member,
  and each device with who certified it. Key Masters also see when each device
  was last seen and get *Make Key Master*, *Remove* and, per device, *Revoke*.
  Each asks for confirmation in a dialog (Cancel has the focus). Remove and
  Revoke then rotate the group key and say how many devices got it.
- **Names.** A new name chosen under *Profile* is only a request. Everyone,
  everywhere (feed, comments, members, messages, notifications), keeps
  seeing the certified name until a Key Master clicks *Accept new name* on
  the Members tab, which re-signs that member's certificates with it
  (`POST /members/{id}/name`); the relay then pushes `roster` so every app
  shows the new name at once. Until then Key Masters, and only they, see a
  "name change pending" marker on the member and on their posts. This stops
  someone renaming themselves "Mom" to fool people. A photo change shows
  straight away.
- **Removed.** When the relay says this device was removed or revoked (a
  `removed` push, or a `401` confirmed by `/join/status`), the app stops
  syncing, shows a notification and a "You've been removed from this group"
  screen (or "This device was disconnected"). The archive stays: *Look through
  saved posts* opens the feed read-only, with a switch to the saved messages. *Delete them and join a group again*
  wipes the local data and restarts the wizard.
- **Missed posts.** A device that comes back after the relay pruned events it
  never got shows a dismissible notice at the top of the feed.
- **Feed.** Newest first: posts, photos, comments, one reaction per person per
  post, and delete for your own posts. It syncs after every action and whenever
  the push socket says something changed. While the socket is down it polls
  every 30 seconds and reconnects with backoff (1 s doubling to 60 s, with
  jitter); while it's up, a 15-minute poll is only a safety net. The header shows
  **Live** while connected. Sync applies the same rules as
  `pull`: an event counts only if its author has a member certificate chaining
  to a pinned Key Master, the signature verifies and it decrypts. Anything else
  is skipped and counted under *This device*.
- **Messages.** The *Messages* tab lists conversations, newest first, with
  the other person's photo and name, the last message and an unread count.
  *New message* picks someone from the verified roster, and *Message* next to
  a member on the Members tab opens the conversation with them. The chat
  shows bubbles (yours on the right), photos inline (same resize, EXIF
  stripping and lightbox as posts), and a composer (Ctrl+Enter sends). Each
  message has its own random key, sealed to every device of the other person
  and your own other devices (from the verified roster) and signed by this
  device; see [Direct messages](#direct-messages-phase-5b). Someone who was
  removed can't be messaged, and a removed device can't send; conversations
  already on a device stay readable there.
- **Tray.** Closing the window hides it; the app keeps running in the system
  tray. Left-click the icon (or its *Open Side Tray* menu item) to bring it back;
  *Quit* is the only way to exit. Launching the app again focuses the running
  copy. The icon gets a red badge with the number of new posts and comments by
  others, unread direct messages (plus waiting join requests for Key
  Masters), "9+" past nine, and the tooltip spells it out. The feed count
  clears when the feed is on screen in a focused window, a conversation's when
  it's open in a focused window. A new device's first sync (the backlog) doesn't count.
- **Notifications.** Native toasts for posts by others, comments by others on
  your posts, direct messages ("Ana sent you a message" and its first line;
  a click opens the conversation), and, for Key Masters, new join requests. More than three at once
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
- **HTTPS.** Trust is per server, for both HTTPS calls and the `wss://` push
  socket. A server on a domain is checked against the public web roots
  (`webpki-roots`), as a browser would, so Let's Encrypt just works. A **test
  server** (a bare IP address, or a root pasted under *Advanced*) has its own
  CA: the wizard downloads its root from `/sidetray-root.crt`, checks the
  server's certificate chains to it, and shows its SHA-256 fingerprint (as
  `openssl x509 -fingerprint -sha256` and `install.sh` print it). Once you
  confirm it matches, that root is pinned in the identity and is the only one
  trusted for that server. If the server later presents a certificate that
  doesn't chain to it, every request is refused and a red banner says the
  certificate changed and what that can mean. *This device → Server
  certificate* shows the pinned fingerprint; *Check it again* compares it with
  the server's current one, and replacing the pin needs a second explicit
  confirmation. No root is compiled in. Verification is never off (except to
  download a test server's root for that comparison). Plain `http://` is
  accepted only for `127.0.0.1`/`localhost`, for a relay in development.
- **Local data** lives in the app data dir (`%APPDATA%\org.sidetray.app` on
  Windows; `SIDETRAY_DATA_DIR` overrides it, and lets test copies run side by
  side without the single-instance check). `sidetray.db` holds the spec's
  client tables plus `anchors`, `member_devices`, `conversations`,
  `dm_messages` and `dm_photos`, and `media/` holds the decrypted photos.
  Each message's key is kept wrapped like the group keys, so its photos can
  be fetched later. Posts are plaintext on disk (SPEC: rely on OS disk
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
| profile | `{"display_name"?, "avatar": {"id", "digest"} \| null}`: the author's whole profile; the latest one wins. No `display_name` means the certified name. The avatar is a 256x256 WebP encrypted like a photo, `digest` its `blob_digest` |

A post's photo media ids (and a profile's avatar id) also go in the event's
clear `media_ids` field, so the server can prune them with the event.

## Direct messages (Phase 5b)

Only the two people's devices can read a conversation: not other members,
not Key Masters, not the relay.

- **Sending.** A fresh 32-byte message key encrypts the payload
  `{"text", "photos"?: [...]}` (photo references as in posts) with AD
  `protocol::dm_ad(group, conversation)`, and each photo and thumbnail with AD
  `protocol::dm_media_ad(group, conversation)`. The key is sealed
  (`crypto_box_seal`) to every device of the recipient and every other device
  of the sender, with public keys from the verified roster only; the app
  refuses to send if one of those devices has no valid certificate. The
  sending device signs `protocol::dm_message`: group, conversation, sending
  device, every `(device id, sealed key)` sorted by device id, and the
  ciphertext (`crypto::dm::seal_dm`).
- **The conversation id** is `crypto::dm::conversation_id(group, a, b)`, 32
  hex characters of a hash of the group and both member ids (either order),
  so both sides, and the relay, compute the same one.
- **The relay** only accepts a message to an active member of the same group,
  with the conversation id for the two members, and with sealed keys for
  exactly the active devices of both members other than the sending one.
  Photos must be uploaded by the sending device and not belong to anything
  else. It stores the device list (`dm_keys`), returns a message only to
  those devices, with every sealed key so they can check the signature, and
  serves its photos only to them and the sender. Message numbers count per
  group, like event numbers.
- **Receiving** (`crypto::dm::open_dm`): the sender device must be verified
  (or a former device, for messages up to its `revoked_dm_seq`), the relay's
  sender and recipient must match the device and the signed conversation id,
  the signature over the whole recipient list must verify, and this device
  must be on it. Anything else is rejected and counted under *This device*.
- **A new device** of yours only gets messages sent after it joined, and
  someone removed stops receiving at once (their devices are revoked, so the
  next message isn't sealed to them).
- **What the relay sees:** who writes to whom and when, sizes, and which
  devices each message is for. Not the text or photos. Members can also tell
  roughly how many messages their group exchanges, from gaps in the message
  numbers.

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
| `status [--km-code <code>]` | anyone | After approval: verifies the grants and anchors, then stores keys and pins the approver once you type their code. Later: picks up a promotion, or reports that the device was removed or revoked |
| `certify [<device> --code <code>] [--keymaster]` | Key Master | Self-certify, or certify a device approved before certificates existed |
| `promote <member_id>` | Key Master | Signs Key Master certificates for a verified member's devices |
| `members`, `post <text>`, `pull` | members | Verified roster (flags unverified devices); encrypt + sign a post; verify author certificate + signature, decrypt, ack. `pull` first fetches any rotated group key (checking a verified Key Master signed it), and shows each post's id, photo count, comments and reactions. `post` retries once with the new key if the relay says its key is out of date |
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
| `grant_group_key` / `open_key_grant` | seal + Ed25519 over `protocol::key_grant_message` | used for join approvals and key rotation |
| `event_id` | BLAKE2b-256 of an event's ciphertext, domain-separated | 32 hex characters |
| `dm::MessageKey` | 32 random bytes; XChaCha20-Poly1305 | `nonce[24] ‖ ct ‖ tag[16]`, AD as given (no key version) |
| `dm::seal_dm` / `dm::open_dm` | `crypto_box_seal` of the message key per device + Ed25519 over `protocol::dm_message` | sealed key 80 bytes |
| `dm::conversation_id` | BLAKE2b-256 of the group and both member ids, domain-separated | 32 hex characters |

```sh
cd crypto && cargo test
```

The tests include vectors produced by libsodium (via PyNaCl) and RFC 8032, and they
check that flipping any single byte is caught. The wordlist in `crypto/src/wordlist.rs`
is frozen: a test pins its hash, because editing it would change every safety code.
It comes from the public-domain [12dicts](http://wordlist.aspell.net/12dicts/) lists;
`crypto/tools/wordlist/` has the script and blocklist that picked it.

## Notes

- Every table carries `group_id`, and every authenticated call works inside the
  calling device's group; another group's devices, members and media look like
  they don't exist (`404`). Event `seq` numbers count per group (the
  `events.gseq` column): a server from before 6b keeps its existing numbers,
  and each group's counter continues from the old server-wide one.
- Tokens are stored as SHA-256 hashes.
- Every startup removes the Phase 1 seed (group `g_test`). The cleanup is a no-op
  once the seed is gone, and touches only rows with `group_id = 'g_test'`; real ids
  are `g_` plus 16 random characters. `server/tests/test_legacy_cleanup.py` checks this,
  `server/tests/test_prune.py` covers the prune job and the removed/revoked
  statuses, and `server/tests/test_groups.py` covers several groups, setup
  tokens, isolation, the per-group numbering migration and the rate limits,
  and `server/tests/test_profiles.py` covers profile events (and the events
  table rebuild that allows them), keeping each member's latest profile and
  avatar through pruning, and accepting a new name, and
  `server/tests/test_dms.py` covers direct messages: who can send to whom,
  the device list, who can fetch messages and photos, acks and pruning
  (`cd server && python -m unittest discover tests`; needs `httpx` for the
  last three).
- Footprint on the test VM: ~35 MB (api) + ~70 MB (caddy), with 256 MB / 128 MB caps.
