# Side Tray

Private, end-to-end encrypted feed for one group. See [SPEC.md](SPEC.md).

**Status: 0.2.0** ([CHANGELOG.md](CHANGELOG.md)). A Tauri 2 app for
Windows, Linux and Android (`app/`) has a first-run wizard (join, or found the group with the setup token),
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
two people's devices can read. Windows gets a per-user installer and Linux an
AppImage and a .deb, Android phones a signed APK, all built by GitHub Actions
on a version tag; installed copies update themselves from signed releases
(see [Releases](#releases)).

## For family members

Someone in your family runs Side Tray for the group (the *Key Master*). This
is how you get it onto your Windows computer. For a phone, see
[Install on an Android phone](#install-on-an-android-phone) below.

1. **Download the installer** from
   <https://github.com/shaybee22/sidetray/releases/latest/download/SideTray-Setup.exe>
   (your Key Master may send you this link too). It always gets the newest
   version, a file called `SideTray-Setup.exe`.
2. **Open it.** Double-click the file (or click it in your browser's
   downloads list). You don't need an administrator password.
3. **Windows will probably warn you.** A blue box appears that says
   **"Windows protected your PC"** and *"Microsoft Defender SmartScreen
   prevented an unrecognized app from starting."* There's only a
   **Don't run** button at first. That's expected: Side Tray is new and
   isn't signed with a paid certificate yet, so Windows doesn't recognise
   it (see [Code signing](#code-signing) for what that would change).
   - Click the small underlined **More info** link under the message.
   - The box now also shows *App: SideTray-Setup.exe* and
     *Publisher: Unknown publisher*, and a second button appears:
     **Run anyway**. Click it.

   It looks like this (a dark blue box, in the middle of the screen):

   ```
   First:                                   After "More info":
   ┌──────────────────────────────────┐     ┌──────────────────────────────────┐
   │ Windows protected your PC        │     │ Windows protected your PC        │
   │                                  │     │                                  │
   │ Microsoft Defender SmartScreen   │     │ Microsoft Defender SmartScreen   │
   │ prevented an unrecognized app    │     │ prevented an unrecognized app    │
   │ from starting. Running this app  │     │ from starting. Running this app  │
   │ might put your PC at risk.       │     │ might put your PC at risk.       │
   │ More info   <── click this       │     │                                  │
   │                                  │     │ App:       SideTray-Setup.exe    │
   │                                  │     │ Publisher: Unknown publisher     │
   │                                  │     │                                  │
   │                    [ Don't run ] │     │ [ Run anyway ]   [ Don't run ]   │
   └──────────────────────────────────┘     └──────────────────────────────────┘
                                                  ^── then this
   ```

   Only do this for `SideTray-Setup.exe` from the link above (or a file your
   Key Master sent you). If the name looks different, ask them first. (Some browsers also ask "keep this file?"
   when you download it; choose *Keep*.)
4. **Click through the installer.** Click *Next* until you see *Install*,
   then *Install*. On the last page, leave **Create desktop shortcut**
   ticked if you'd like an icon on your desktop, and click *Finish*. Side
   Tray opens.
5. **Join the group.** The easiest way: click the invite link your Key
   Master sent you (it starts with `sidetray://`). Side Tray fills in the
   server and the group for you. Otherwise type the server address and the
   group name exactly as they were given to you. Then type your name and
   email address and click *Ask to join*.
6. **Phone your Key Master.** Side Tray shows a code of four words and two
   numbers. Read it to your Key Master on the phone; they check it matches
   on their screen and let you in. They then read you *their* code: type it
   in, and you're done. (This phone call is what keeps strangers out, so
   please don't skip it or do it by email.)

**Afterwards.** Side Tray lives next to the clock (in the system tray; you
may need to click the little **^** arrow to see it). Closing the window
doesn't stop it, so it can tell you about new posts. Updates download by
themselves; when one is ready, Side Tray shows **Restart to update** at the
top of the window (and in the tray icon's menu). Click it whenever it suits
you: the app closes for a few seconds and comes back with the new version.

**Removing it.** *Settings → Apps → Installed apps → Side Tray →
Uninstall.* Your posts, messages and keys stay on the computer unless you
tick *Delete the application data*, so reinstalling picks up where you left
off.

### Install on an Android phone

Side Tray isn't in the Play Store; you download it from our release page
instead. A phone is a device of its own: it joins the group the same way a
computer does (with the phone call), even if Side Tray is already on your
computer.

1. **Download it.** On the phone, open this link in Chrome (your Key Master
   may send it to you too):
   <https://github.com/shaybee22/sidetray/releases/latest/download/SideTray.apk>.
   It's a file called `SideTray.apk`. If Chrome asks whether to keep or
   download it anyway, choose **Download anyway**.
2. **Open it.** Tap **Open** in Chrome's message at the bottom of the
   screen (or open the *Files* app, then *Downloads*, and tap
   `SideTray.apk`).
3. **Allow the install, once.** Android says something like *"For your
   security, your phone currently isn't allowed to install unknown apps from
   this source."* Tap **Settings**, turn on **Allow from this source**, then
   press Back. Android now asks *"Do you want to install this app?"*: tap
   **Install**.
   - **Google Play Protect** then probably says *"App scan recommended:
     Play Protect hasn't seen this app before"*, because Side Tray doesn't
     come from the Play Store. Either tap **Scan app** (Google checks it,
     then installs it), or tap **More details**, then **Install without
     scanning**, and confirm. Only do this for `SideTray.apk` from the link
     above.
4. **Open Side Tray** (the *Open* button, or its icon on your home screen).
5. **Join the group.** Easiest: tap the invite link your Key Master sent
   you (it starts with `sidetray://`); Side Tray fills in the server and the
   group. Otherwise type them exactly as they were given to you. Then type
   your name and email address and tap *Ask to join*.
6. **Phone your Key Master** and compare codes, exactly as on a computer
   (step 6 above).
7. **Turn on notifications.** After you're in, Side Tray asks *"Get notified
   about new posts?"*: tap **Turn on**, then **Allow**.

**Instant notifications with ntfy.** Without anything else, Side Tray checks
for news about every 15 minutes. For notifications within seconds, install
the free **ntfy** app from Google Play (search for *ntfy*, by Philipp
Heckel; it's also on F-Droid). There's nothing to set up in it: install it,
then open Side Tray again. If a card *Let notifications through* appears on
the feed, tap its buttons and choose **Allow** or **Unrestricted** as it
explains: Android otherwise holds the apps back to save battery, and
notifications come late.

**Updates.** Side Tray looks for a new version once a day. When there is
one, a card on the feed says *New version: Side Tray …*: tap **Download and
install**. The first time, Android has to allow Side Tray to install apps:
the card says *One more step*; tap **Open setting**, turn on **Allow from
this source**, and press Back. Android then asks *"Do you want to update
this app?"*: tap **Update**. Play Protect may ask about it again, as in
step 3. Your posts and messages stay.

**Removing it.** Long-press the Side Tray icon, then *App info* →
*Uninstall*. Unlike on a computer, this deletes the phone's keys with it:
installing it again means joining again (another phone call).

## Layout

```
CHANGELOG.md          what changed in each release
.github/workflows/    release.yml: installers and the updater manifest on a v* tag
install.sh            server installer: Docker, /opt/sidetray, HTTPS, first setup token, optional own push server
compose.yaml          api (FastAPI + SQLite) behind caddy (HTTPS); optional ntfy for Android push (profile "push")
Caddyfile             TLS via Caddy's internal CA, for a dev checkout on a LAN IP
server/app/main.py    the relay
server/app/admin.py   operator commands (`sidetray-admin new-group | list-groups | prune`)
scripts/smoke-test.sh live TLS checks + full API run on a throwaway container
scripts/ws_probe.py   stdlib-only WebSocket client the smoke test uses for /ws
crypto/               Rust crate: keys, sealing, encryption, signatures, safety codes
cli/                  Rust dev CLI (`sidetray`): init-group, join, approve, post, pull
app/src-tauri/        app backend (Rust, Tauri 2) for desktop and Android; windows/installer-hooks.nsh for the installer
app/src-tauri/gen/android/  the Android Studio project (generated by `cargo tauri android init`)
app/ui/               app frontend (plain HTML/CSS/JS, no build step)
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
3. **Your own push server** (default no). Android phones get notifications
   within seconds through the public ntfy.sh with no setup (the wake-ups are
   empty); answer yes to run your own ntfy instead. See *Notifications on
   Android phones* below.

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
`--domain tray.example.org --email you@example.org` or `--ip 10.1.1.188`,
`--retention 90`, `--push` or `--no-push`, `--yes` (keep existing settings), and
`--new-group` (also print a token for another group). Piped from a release, `curl -fsSL <url>/install.sh |
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

`--yes` keeps every setting as it is (domain or IP, retention, own push
server). A server that has never been asked about its own push server
(installed before the question existed) gets it when you run the installer
without `--yes`; with `--yes` it stays off (phones use ntfy.sh) until you add
`--push`. The installer
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

### Notifications on Android phones

**Nothing to set up.** Phones with the free **ntfy** app (from F-Droid or
Google Play) get notifications within seconds through ntfy's public server,
ntfy.sh, which is the ntfy app's default: install ntfy, open Side Tray, done.
Without ntfy, Side Tray checks for news about every 15 minutes.

When something happens (a post, a comment, a direct message, a join request
for Key Masters) and a phone has no connection open, the relay POSTs an
**empty** request to that phone's ntfy topic, at most once every 5 seconds
per phone. ntfy turns that into a wake-up for the Side Tray app (which sees
only ntfy's placeholder text `triggered`), and the app fetches and decrypts
the news over the normal API. ntfy.sh learns that some random topic should
wake up now, and your server's IP address; not names, text, the group or who
posted. The relay only sends to `ntfy.sh` and to your own ntfy (below), so it
can't be made to call other addresses; `SIDETRAY_PUSH_HOSTS` in `.env`
changes the list (comma-separated host names; set it empty to allow only
your own ntfy). ntfy.sh counts wake-ups against each phone's own allowance,
not the server's.

**Your own push server (optional).** If you'd rather not use ntfy.sh at all,
answer yes to the installer's push question (or pass `--push`). It adds an
`ntfy` container (Compose profile `push`, set in `.env` as
`COMPOSE_PROFILES=push`). ntfy is private: it refuses every topic except the
random UnifiedPush ones (`up…`) that phones read and the relay writes, and it
keeps nothing longer than 12 hours. The relay reaches it over Docker's
internal network.

- **On a domain**, ntfy shares the relay's address and Let's Encrypt
  certificate on port 443: Caddy sends `/api/*` to the relay and everything
  else to ntfy. No extra port, DNS record or certificate step. Each phone's
  ntfy app then needs *Settings → Default server* → `https://<your domain>`
  (then open Side Tray and tap *Device → Settings → Check again*). Phones
  still on ntfy.sh keep working.
- **On a test server** (an IP address) ntfy gets its own port, **8443**
  (`SIDETRAY_NTFY_PORT`), with a self-signed certificate that `install.sh`
  makes once and that lasts 10 years (`/opt/sidetray/ntfy-tls/`): the ntfy
  app pins a server's exact certificate, and Caddy's own test certificates
  change every 12 hours. It deliberately names no host, so Caddy keeps using
  its own CA on 443. On each phone, set ntfy's default server to
  `https://<ip>:8443`; ntfy then says the certificate isn't trusted:
  subscribe once to any topic starting with `up` (say `upcheck`), compare the
  fingerprint ntfy shows with the "its certificate" line `install.sh`
  printed, tap *Trust*, and unsubscribe again.

**Battery settings.** Android may hold back Side Tray or ntfy to save
battery, and then notifications arrive late or not at all. Side Tray checks
both and, if needed, shows a card on the feed ("Let notifications through")
with buttons: one opens Android's own "let app always run in background?"
dialog for Side Tray, the other opens ntfy's App info, where the person taps
*App battery usage* (on newer phones then *Allow background usage*) and
chooses *Unrestricted*. *Device → Settings* shows the same.

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
curl --cacert sidetray-root.crt https://10.1.1.188/api/v1/health
```

For a Let's Encrypt cert, run `install.sh` with a domain (production mode).

## API

All under `/api/v1`. Authenticated calls send `Authorization: Bearer <device token>`;
the token comes back from `POST /join` and is stored hashed. Binary fields are
base64. The server never decrypts.

| Method | Path | Who | Body / params | Returns |
| --- | --- | --- | --- | --- |
| GET | /health | anyone | | `{ok, version}` |
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
| GET | /push | member | | `{offered, ntfy, hosts[], endpoint}`: whether the server sends wake-ups, its own ntfy, other allowed push hosts, and this device's endpoint |
| POST | /push | member | `{endpoint}`, a UnifiedPush endpoint on the server's ntfy (or an allowed host) | `{endpoint}`; `400` for any other address, `404` if the server sends no wake-ups |
| DELETE | /push | member | | `{deleted}` |
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

**Wake-ups (Android A3).** Each time the relay sends one of these messages
(except `new_event` for reactions and profile changes), a device that is
meant to get it but has **no socket open** and has registered an endpoint
(`POST /push`) gets an empty `POST` to that endpoint instead (no body, only
`TTL` and `Urgency` headers): at most one per device every 5 seconds
(`SIDETRAY_WAKE_EVERY_SECONDS`), with a later one sent when the interval is
up so the last change is never missed. Push servers that answer `404` or
`410` lose the endpoint. A revoked device gets one last wake-up (so it finds
out), and its endpoint is deleted.

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

Installers need the Tauri CLI (`cargo install tauri-cli --version "^2"`);
see [Releases](#releases).

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
  start (`tauri-plugin-deep-link`; on Windows `HKCU\Software\Classes\sidetray`)
  when it runs from a build; the installer registers it for the installed copy. Opening a link starts the app, or hands
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
  Windows toasts need an AppUserModelID (`org.sidetray.app`): the installer
  puts it on its Start menu and desktop shortcuts and registers its name and
  icon under `HKCU\Software\Classes\AppUserModelId`; a copy run from a build
  registers that key itself at startup. Clicks are handled while the app is
  running and the toast is on screen; clicking an old toast in the
  notification centre doesn't open the post yet (that needs a COM activator). On macOS and
  Linux toasts go through `tauri-plugin-notification`, which can't report
  clicks.
- **Updates.** An installed copy (the Windows installer, or the AppImage)
  checks for a new version 20 seconds after it starts and every 6 hours
  after that, downloads it in the background and checks its signature, then
  shows **Restart to update** at the top of the window and in the tray menu
  (and a notification if the window isn't in front). Nothing installs until
  someone clicks it. *This device → Updates* shows the version and has
  *Check for updates*. A copy run from a build never updates itself. See
  [Releases](#releases).
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
  checked before decrypting. Animated GIF, WebP and PNG keep only their first
  frame, and the app says so (a *Still* tag on the preview).
- **Adding photos.** In the post composer, a post's comment box and a chat,
  photos come from the picker button, from **paste** (Ctrl+V or right-click
  *Paste*: a copied picture or screenshot, or picture files copied in
  Explorer), or from **drag and drop** (files from Explorer, or a picture
  dragged out of a browser). Each goes through the pipeline above and shows as
  a preview with a remove (×) button until it's sent: up to 10 per post or
  message and 4 per comment. When the clipboard also holds text (Word and Excel
  put a picture of the text next to it), the text is pasted instead. A picture
  dragged from a web page that arrives as only its address is downloaded by the
  app (`stage_photo_url`: http or https, at most 64 MB); a `data:` address is
  read directly. Tauri's own file-drop handling is off (`dragDropEnabled`), so
  the page gets every drop and nothing dropped can navigate the window away.
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

## Android app (A1-A4)

The same app builds for Android (SPEC.md "Android app", phases A1 to A4):
join with the safety-code check (or from a `sidetray://` invite link), the
feed, posts with photos, comments, reactions, direct messages and the Key
Master tab; *Share → Side Tray* from other apps, the camera, multi-select from
the photo picker, HEIC photos, a phone layout with bottom tabs, and
notifications while it's closed (instant through the ntfy app, or about
every 15 minutes without it), and updates from the signed APK on each
release. Family members install it as in
[Install on an Android phone](#install-on-an-android-phone); to build one
yourself, see below.

**Build setup on Windows** (all per user, no admin except Developer Mode):

- JDK 17 and the Android SDK: Android Studio, or the command-line tools.
  With the command-line tools: Temurin JDK 17 unzipped to
  `%LOCALAPPDATA%\Android\jdk-17`, the [command-line tools](https://developer.android.com/studio#command-line-tools-only)
  in `%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest`, then
  `sdkmanager --licenses` (from Git Bash: `yes | sdkmanager.bat --licenses`) and
  `sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0" "ndk;27.3.13750724" "emulator" "system-images;android-35;google_apis;x86_64"`.
- User environment variables: `JAVA_HOME` (the JDK), `ANDROID_HOME`
  (`%LOCALAPPDATA%\Android\Sdk`), `NDK_HOME` (`%ANDROID_HOME%\ndk\27.3.13750724`),
  and `platform-tools` on `PATH` for `adb`.
- `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android`
- Windows Developer Mode on (Settings → System → For developers): the build
  symlinks the Rust library into the Android project.

```sh
cd app/src-tauri
cargo tauri android build --debug --apk --target aarch64   # a phone; x86_64 for the emulator
adb install -r gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

**A signed release build** (what CI makes on a tag) needs the release
keystore. `app/src-tauri/gen/android/keystore.properties`, which git ignores,
points at it:

```properties
storeFile=C:/Users/<you>/.tauri/sidetray-android.jks
storePassword=...
keyAlias=sidetray
keyPassword=...
```

Then `cargo tauri android build --apk --target aarch64` (no `--debug`)
writes `gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk`.
Without that file the release APK comes out unsigned. A debug build and a
release build are signed with different keys, so one can't replace the
other: `adb uninstall org.sidetray.app` first (which deletes the phone's
keys: it joins again). The release build is minified by R8;
`proguard-rules.pro` keeps the app's own classes, which Rust calls over JNI
by name, and the Room database constructors WorkManager needs (without them
a release build crashes at launch).

**Trying the update card** without publishing a release: build with
`SIDETRAY_ANDROID_UPDATE_URL=http://<host>/android.json` in the environment
(plain `http://` is accepted only for such a test build), and to make the
installed copy look old, also `--config '{"version":"0.1.9"}'`. On the test
server, put a newer signed APK and an `android.json` next to each other in a
folder served by `python3 -m http.server 8088`; `url` may be relative:

```json
{"version": "0.2.0", "url": "SideTray.apk", "sha256": "<sha256sum of the APK>", "size": 12345678}
```

The Android Studio project in `app/src-tauri/gen/android` is generated by
`cargo tauri android init` and committed (its own `.gitignore` keeps build
output out). Its launcher icons come from `icons/app-icon.png`
(`cargo tauri icon icons/app-icon.png -o <tmp>`, then copy `<tmp>/android/*`
into `gen/android/app/src/main/res`; running it in place would overwrite the
hand-made small desktop icons).

**Where it differs from the desktop app:**

- **Keys.** The phone is its own device: its own keypairs and its own join.
  Its secrets (private keys, token and the local key that wraps the group
  keys) are stored in the app's database encrypted with a non-exportable
  AES-256-GCM key in the Android Keystore (`src/keystore.rs`, over JNI).
  Clearing the app's data or uninstalling deletes that key: the phone then
  joins again as a new device.
- **No tray or autostart** (`cfg(desktop)` in `src/lib.rs`; `tray_mobile.rs`
  stands in). Coming back to the foreground syncs at once.
- **Updates** (`src/update_mobile.rs`). At every start and then once a day
  (also checked on coming back to the foreground) the app reads
  `android.json` from the newest published release
  (`releases/latest/download/android.json`: version, APK address, SHA-256
  and size). If it's newer, a card on the feed and *Device → Settings*
  offer it. *Download and install* downloads the APK into the app's cache
  (`cache/updates`), checks the SHA-256, and hands it to Android's installer
  through the FileProvider (`SideTrayAndroid.installApk`: `ACTION_INSTALL_PACKAGE`,
  so apps that also open APK files don't get offered in a chooser; with the
  `REQUEST_INSTALL_PACKAGES` permission). The first time, the person has to
  turn on *Install unknown apps → Allow from this source* for Side Tray: the
  card explains it and opens that screen, and installs as soon as they come
  back with it allowed. Android only replaces the app with an APK signed
  with the same key, so the checksum is only there to catch a damaged
  download. Old downloads are deleted at the next start. A debug build
  doesn't look for updates (it's signed with the debug key, so a release
  APK couldn't replace it), unless it's built with
  `SIDETRAY_ANDROID_UPDATE_URL` (below).
- **Photos** go to Rust as base64 in JSON (Android's IPC can't carry a raw
  body). *Photos* opens Android's photo picker (several at once); *Camera*
  (composer, comments, chat) opens the camera app, and the full-size shot it
  leaves in the app's folder is deleted once the photo is staged. HEIC/HEIF
  (and AVIF) photos are decoded by Android itself (Android 9 and newer), then
  go through the same resize, EXIF strip and WebP encode; a computer refuses
  them with a message saying so.
- **Share → Side Tray.** Intent filters for one or several images and for
  text and links. `MainActivity.kt` hands the intent to `SideTrayAndroid.kt`,
  which copies the pictures into the app's cache; the page asks for them
  (`take_share`, `src/android.rs`), stages them, and lets the person post them
  or send them as a message. Not in a group yet (or still waiting for
  approval): it says so.
- **Back button.** `MainActivity.kt` passes Back to the page: it closes the
  photo viewer, a dialog or a chat, then goes back to the feed, and only then
  puts the app in the background, asking first if a post, comment or message
  is half-written.
- **Layout.** The page runs edge to edge. The CSS pads for the status and
  gesture bars with `--sat`, `--sab` and so on: the larger of
  `env(safe-area-inset-*)` and the insets Android reports (older WebViews
  leave out the gesture bar). Tabs are at the bottom; the chat is sized from
  the visual viewport so the composer stays above the keyboard. Photos in the
  viewer pinch-zoom.
- **Flip phones.** Moving between a razr's inner and outer screens changes
  the density, which recreates the activity and reloads the page (the WebView
  can't change scale in place). Drafts (text, and the IDs of photos still
  staged in the app) and the open tab and chat are kept in `localStorage` and
  put back. Motorola asks once whether Side Tray may run on the outer screen.
- **No backups.** `allowBackup` is off: the local archive holds decrypted
  posts and photos, and a restored copy couldn't unlock its keys anyway.
- `sidetray://join?...` links open the app through an intent filter
  (`plugins.deep-link.mobile` in `tauri.conf.json`).
- **Notifications while closed** (`src/mobile_push.rs`). If a UnifiedPush
  distributor is installed (the ntfy app), Side Tray registers with it
  (`SideTrayAndroid.pushRegister`, the `org.unifiedpush.android:connector`
  library) and gives the relay the endpoint ntfy hands back
  (`SideTrayPushService` → `SideTrayWorker` → `POST /push`). A wake-up
  starts an expedited WorkManager job, which may use the network even while
  the phone dozes; it loads the Rust library if the app wasn't running,
  syncs as usual and shows the notifications (`alerts.rs`, through Kotlin's
  `showNotifications`). Without a distributor, or when the relay refuses the
  endpoint (ntfy pointed at another server), a periodic job syncs about every
  15 minutes instead, and the app says once how to get instant ones;
  *Device → Settings* always shows which it is, and *Check again* asks ntfy
  for a fresh endpoint (after its server changed). The app closes its push
  socket whenever it leaves the screen, so the relay starts sending wake-ups
  at once.
- **Battery restrictions.** `SideTrayAndroid.batteryState` checks whether
  Side Tray and the push app are exempt from battery optimization
  (`PowerManager.isIgnoringBatteryOptimizations`) and whether Side Tray is
  set to Restricted (`ActivityManager.isBackgroundRestricted`). If not, a
  card on the feed and *Device → Settings* explain and offer buttons:
  Android's `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` dialog for Side Tray (or
  its App info when it's Restricted), and ntfy's App info screen.
- **Notification permission** (Android 13+): asked only after joining, from
  a card on the feed ("Get notified about new posts?"), never at first
  launch. Tapping a notification opens the post, the conversation, or the
  Key Master tab (`take_open`). Channels: new posts, comments on your posts,
  direct messages, join requests, your membership.
- **One app state per process.** A wake-up can start the app's process
  without its window. Rust then gets the JavaVM from
  `SideTrayAndroid.nativeInit` instead of tao's ndk-context (which tao can set
  only once per process), and a window opened later reuses the same `App`
  (`state::shared`), so there's one database connection and one sync lock.

**Testing against a relay on this PC.** Plain `http://` is only allowed to
localhost, and `adb reverse` makes the PC's localhost the phone's:
`adb reverse tcp:8765 tcp:8765`, then use `http://127.0.0.1:8765` in the
wizard. A debug build's WebView can be driven over DevTools:
`adb forward tcp:9401 localabstract:webview_devtools_remote_$(adb shell pidof org.sidetray.app)`.
To try notifications on the emulator, install the ntfy APK from its
GitHub releases (the `fdroid` build) and point it at the test server as in
*Notifications on Android phones* (ntfy.sh needs no setup).
`adb shell am kill org.sidetray.app` closes the
app the way Android does (unlike `force-stop`, which also blocks wake-ups).
To try sharing without another app:
`adb shell am start -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT https://example.org`.

## Releases

One version number for everything: `app/src-tauri/Cargo.toml` (the app),
`app/src-tauri/tauri.conf.json` (`version`: the installers and the Android
APK's `versionName` and `versionCode` come from it), `crypto/Cargo.toml`,
`cli/Cargo.toml` and `server/app/__init__.py` (the relay reports it on
`/api/v1/health`). To release:

1. Bump the five versions (the release job refuses a tag they don't match), add a section to [CHANGELOG.md](CHANGELOG.md)
   (`## [x.y.z] - date`; it becomes the release notes), commit.
2. `git tag vX.Y.Z && git push origin main vX.Y.Z`.
3. [`.github/workflows/release.yml`](.github/workflows/release.yml) creates a
   **draft** release for the tag with `install.sh` attached, then builds on
   Windows (`nsis`: `Side Tray_X.Y.Z_x64-setup.exe`) and Ubuntu 22.04
   (`.deb` and `.AppImage`) with `tauri-apps/tauri-action`. Each build signs
   its update bundle and adds it, its `.sig` and its entry in `latest.json`
   to the release. The Windows job also attaches a copy named
   `SideTray-Setup.exe`, so `releases/latest/download/SideTray-Setup.exe`
   (the link in [For family members](#for-family-members)) is always the
   newest published installer. A third job builds the Android APK (arm64,
   signed with the release keystore; it fails unless the APK's certificate
   is the expected one and its version matches the tag) and attaches it as
   `Side.Tray_X.Y.Z_arm64.apk` and as `SideTray.apk`, plus `android.json`
   for the phones' update check. macOS isn't built yet.
4. Check the draft, then publish it. Installed apps only see a release once
   it's published (`releases/latest` skips drafts).

**Building an installer locally.** `cargo install tauri-cli --version "^2"`,
then in `app/src-tauri`: `cargo tauri build --bundles nsis` (Windows; NSIS is
downloaded on first use) or `--bundles deb,appimage` (Linux). The installer
lands in `target/release/bundle/`. Without the signing key in the
environment the build still makes the installer but fails at the updater
signature; set `TAURI_SIGNING_PRIVATE_KEY` (the key's contents or path) and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

**The Windows installer** (Tauri's NSIS template plus
`app/src-tauri/windows/installer-hooks.nsh`) installs per user into
`%LOCALAPPDATA%\Side Tray`, so it needs no administrator rights. It adds a
Start menu shortcut and, ticked by default on the last page, a desktop
shortcut, both carrying the AppUserModelID `org.sidetray.app` that
notifications use; registers `sidetray://` links
(`HKCU\Software\Classes\sidetray`) and the notification name and icon
(`HKCU\Software\Classes\AppUserModelId\org.sidetray.app`) against the
installed exe. The installed app then skips registering those itself.
Uninstalling (Settings → Apps, or `uninstall.exe`) removes the shortcuts, both
registry keys (the link handler only if it still points at this install),
the "start at sign-in" entry and the program folder. It keeps
`%APPDATA%\org.sidetray.app` (posts, photos, keys in Credential Manager)
unless the person ticks *Delete the application data*. `/S` installs or
uninstalls silently.

**The updater signing key** is a minisign keypair made with
`cargo tauri signer generate`. The public key is in `tauri.conf.json`
(`plugins.updater.pubkey`), so an app only installs updates signed with the
matching private key, wherever the manifest came from. The private key is
**not** in the repository: it lives with the release manager (for 0.1.0:
`%USERPROFILE%\.tauri\sidetray-updater.key`, password in
`sidetray-updater.key.password` next to it) and in two GitHub Actions
secrets, `TAURI_SIGNING_PRIVATE_KEY` (the file's contents) and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Keep a backup: losing it means
installed apps can't be updated any more (people would have to reinstall a
build with a new public key).

**Where apps look for updates.** By default
`https://github.com/shaybee22/sidetray/releases/latest/download/latest.json`
(`plugins.updater.endpoints`). That only works once the repository (or at
least its releases) is public, because the app can't sign in to GitHub. To
point apps elsewhere, any of:

- at build time, `SIDETRAY_UPDATE_URL=https://.../latest.json` in the
  environment (in CI: the repository variable `SIDETRAY_UPDATE_URL`);
- at run time, `SIDETRAY_UPDATE_URL` in the app's environment (wins over the
  build-time one);
- a config overlay: `cargo tauri build --config other.json` with
  `{"plugins": {"updater": {"endpoints": ["..."]}}}`.

The endpoint must be `https://` with a publicly trusted certificate. Any
static web server works: upload the new installer and its `latest.json`:

```json
{
  "version": "0.1.1",
  "notes": "What changed",
  "pub_date": "2026-11-01T12:00:00Z",
  "platforms": {
    "windows-x86_64": { "signature": "<contents of the .exe.sig>", "url": "https://.../Side Tray_0.1.1_x64-setup.exe" }
  }
}
```

(`linux-x86_64` takes the AppImage and its `.sig` the same way.) For a test
on a LAN with plain `http://`, build the test copies with an overlay that
also sets `"dangerousInsecureTransportProtocol": true`; never ship that in a
release. The 0.1.0 updater was tested that way: a 0.1.0 installed from the
installer found 0.1.1 on a static folder on the test server, downloaded and
verified it, and after *Restart to update* came back as 0.1.1 by itself.

**The Android signing key** is a keystore made with `keytool` (RSA 4096,
alias `sidetray`, valid until 2054). Android only installs an update over an
installed app if both are signed with the same key: **if the keystore is
lost, no phone can be updated any more**; everyone would have to uninstall
Side Tray and join again with an APK signed with a new key. So keep a backup
somewhere other than this computer (a password manager takes both the file
and its password). For 0.2.0 it lives with the release manager in
`%USERPROFILE%\.tauri\`: `sidetray-android.jks`, its password (store and
key password are the same) in `sidetray-android.jks.password`, and the
keystore as one line of base64 in `sidetray-android.jks.base64`. CI has it in
three GitHub Actions secrets: `ANDROID_KEYSTORE_BASE64` (that base64),
`ANDROID_KEYSTORE_PASSWORD` and `ANDROID_KEY_PASSWORD`. The certificate's
SHA-256 is
`C2:C4:FC:D1:70:16:29:57:03:C4:D9:F8:E8:01:30:C0:B4:FF:5B:CB:74:95:E1:26:2B:66:75:AD:EC:BB:88:DC`
(`CERT_SHA256` in the workflow; `apksigner verify --print-certs` shows it
for any APK).

### Code signing

The installer and app aren't Authenticode-signed yet. That's why Windows
shows "Windows protected your PC" with *Unknown publisher* (the steps are in
[For family members](#for-family-members)), and some antivirus programs are
warier of unsigned downloads. The update signature above is separate: it
stops anyone but us from pushing an update to installed apps, but Windows
doesn't know about it.

Signing with a code-signing certificate (an OV certificate, roughly
$100–300 a year, or Azure Trusted Signing at about $10 a month) would make
the installer and the dialogs show **Side Tray's publisher name** instead of
*Unknown publisher*, and let SmartScreen build a reputation for that
publisher, so after enough downloads the warning stops appearing at all (an
EV certificate skips that waiting period). Tauri can sign during the build
(`bundle.windows.certificateThumbprint`, or `signCommand` for a cloud
signing service), so it would be a configuration change in
`tauri.conf.json` and two more secrets in the workflow. macOS would need an
Apple Developer account ($99 a year) for signing and notarisation.

## Event payloads

Event content is JSON, encrypted with AD `protocol::event_ad(group, kind)` and
signed over `protocol::event_message`. Comments, reactions, edits and deletes
point at a post by its **event id**, `crypto::event_id(ciphertext)` (32 hex
characters). Every client computes it the same way, and the server can't change
it without breaking the signature.

| kind | payload |
| --- | --- |
| post | `{"text", "photos"?: [{"full", "full_digest", "thumb", "thumb_digest", "width", "height"}]}`, with media ids, and digests as base64 `blob_digest` of each encrypted blob |
| comment | `{"post": event_id, "text", "photos"?: [...]}`. Photo references as in posts (0.1.1, at most 4); with photos the text may be empty |
| reaction | `{"post": event_id, "emoji"}`. The latest one per member wins; `""` removes it |
| edit | `{"post": event_id, "text"}`. Only the post's author |
| delete | `{"post": event_id}`. Only the post's author |
| profile | `{"display_name"?, "avatar": {"id", "digest"} \| null}`: the author's whole profile; the latest one wins. No `display_name` means the certified name. The avatar is a 256x256 WebP encrypted like a photo, `digest` its `blob_digest` |

A post's or comment's photo media ids (and a profile's avatar id) also go in the event's
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
