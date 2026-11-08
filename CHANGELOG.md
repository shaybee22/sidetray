# Changelog

All notable changes to Side Tray. Versions follow [Semantic Versioning](https://semver.org/);
the app, the Rust crates and the relay share one version number.

## [Unreleased]

### App

- **Short videos in posts and direct messages**, sent from Windows and
  Android and played everywhere. The Video button prepares a clip on your
  device: at most a minute (a longer one can go as its first 60 seconds),
  720p or 480p, under 10 MB, with location, device model and recording time
  removed. Videos download in the background and play in the feed or chat.
  Once a video has left the server you see "Video expired" and can ask the
  person to send it again in a message; they can send it with one tap.
  (macOS and Linux can watch videos but not send them yet.)
- **On Android:** pick a video with the Video button or share one to Side Tray
  from another app; a full-screen button while it plays; and a setting,
  *Download videos on mobile data* (on by default), that makes videos wait
  for Wi-Fi when it's off (tap one to download it anyway).
- The app tells the relay which photos and videos it has downloaded, so the
  relay can let them go.
- Android: the post box's Photos, Camera and Video buttons are icons, so Post
  stays on the same line. Sharing to Side Tray shows its notes again (they
  were cleared as the pictures loaded) and no longer adds blank lines to a
  draft when nothing but pictures was shared.
- Over the relay's hourly upload limit, the error is one sentence that says
  how long to wait ("Try again in about 23 minutes."). "You asked for a
  video." is readable in your own message bubble.

### Relay

- **Video files are kept only briefly:** until every device has downloaded
  them, 14 days at most, and within 2 GB per group and 5 GB per server
  (`SIDETRAY_VIDEO_TTL_DAYS`, `SIDETRAY_VIDEO_GROUP_CAP_GB`,
  `SIDETRAY_VIDEO_CAP_GB`). A deleted video answers 410 with the reason.
- Feed photos stay until every updated device has downloaded them, also with
  `SIDETRAY_HISTORY_DAYS=0`.
- **The upload limit is now 150 MB per hour per device** (it was 50, about
  five videos), so a family can share a handful of clips at an event.
  `install.sh` writes `SIDETRAY_MEDIA_MB_PER_HOUR=150` into `.env` unless
  you've set your own value.

## [0.3.1] - 2026-11-07

A relay change for people who join later, and a fix for missing photos in
direct messages.

### Relay

- **People who join later see the recent feed.** The relay used to delete a
  post as soon as every device had fetched it, so a new member started with
  an empty feed. Posts and their photos now stay for at least 14 days
  (`SIDETRAY_HISTORY_DAYS`, `install.sh --history DAYS`; 0 restores the old
  behaviour); anything past the retention window (90 days) still goes.
  Direct messages are unchanged.
- Approving a join now has to include every group key version the kept posts
  use (the apps already send all the keys they hold), so a new device can
  read that history after a key rotation.
- Update with `git pull && sudo ./install.sh`; it adds the setting to `.env`.

### App

- **Photos in direct messages no longer go missing.** The app told the relay
  it had a message before it had downloaded the message's photos, so the
  relay could delete a photo first (for example when the download was
  interrupted) and it never arrived. The app now confirms a message only
  once its photos are saved, or after it has given up on them (5 tries).

## [0.3.0] - 2026-11-04

One app, several groups. Highlights:

### Several groups in one app

- **Be in more than one group.** The group name at the top is now a menu:
  switch between your groups, see a dot on any with something new, and
  *Join another group* (invite links work too, even when you're already in a
  group). Every group keeps syncing and notifying in the background; with more
  than one, notifications say which group ("Ana posted in Powwow"); on
  Windows, banners about a group you aren't looking at stay up longer.
- **Leave a group** from *This device*. Everyone keeps what you posted; this
  device deletes what it saved from that group. The only Key Master of a group
  has to promote someone first ("You’re the only Key Master. Promote someone
  else before leaving."). Leaving no longer pops up a "You left" notification
  (sometimes without the group's name) on the device you left from.
- Updating keeps your current group as it is: its posts, photos and messages
  move into a folder of their own the first time the new version starts (a
  backup copy, `sidetray-before-groups.db`, is kept next to it).
- Relay: `POST /api/v1/leave`.

## [0.2.0] - 2026-11-01

Side Tray comes to Android phones. Highlights:

- **An Android app** (`SideTray.apk` on the release; see *Install on an
  Android phone* in the README): the feed, photos, comments, reactions,
  direct messages and the Key Master tab, as on a computer. A phone joins as
  its own device, with the usual phone call to compare codes.
- **Notifications on phones**, also while Side Tray is closed: within seconds
  with the free ntfy app, nothing to set up; about every 15 minutes without it.
  The wake-ups carry no names and no content.
- **Pictures the easy way**: *Share → Side Tray* from any app on a phone, and
  the camera button. On a computer, paste (Ctrl+V) and drag and drop work as
  in 0.1.1.
- **Side Tray starts when you sign in** on new computer installs.

Upgrading: computers update themselves as before. Phones running a test
build of the app have to uninstall it and join again with the release APK
(it's signed with a different key).

### Android app

- Side Tray for Android phones (Android 7 and newer, 64-bit ARM: every
  phone from the last several years). A phone joins as its own device with
  the usual safety-code check, and has the feed, posts with photos,
  comments, reactions, direct messages and the Key Master tab (approve joins
  from the phone too).
- The phone's private keys and token are encrypted with a key held in the
  Android Keystore. The app is left out of Android backups (they would copy
  decrypted posts).
- `sidetray://` invite links open the app on a phone too.
- **Share → Side Tray** from any app: pictures (one or several), text and
  links. Side Tray shows what came in and asks where it goes: the feed, or a
  message to someone. If the app isn't in a group yet, it says so.
- **Camera** buttons on the composer, comments and chat. The full-size shot
  is deleted from the phone once it's been resized and stripped.
- Choose **several photos at once** from the photo picker.
- **HEIC/HEIF photos** (and AVIF) work on Android 9 and newer.
- **Back button**: closes the photo viewer, dialogs and chats, goes back to
  the feed, and asks before leaving with something unsent.
- **Phone layout**: tabs at the bottom, icon buttons, pinch-zoom in the photo
  viewer, and it fits the razr's small outer screen. Drafts survive moving
  between the inner and outer screens.
- **Notifications while the app is closed**: new posts, comments on your
  posts, direct messages and (for Key Masters) join requests. Tapping one
  opens that post, conversation or the Key Master tab.
- With the free **ntfy** app installed they arrive within seconds, with
  nothing to set up (UnifiedPush through ntfy.sh, ntfy's default; the
  wake-ups carry no content). Without it, Side Tray checks about every 15
  minutes and says once how to get instant ones.
- If Android holds back Side Tray or ntfy to save battery, a card explains it
  and has buttons that open the right settings to make both Unrestricted.
- Android 13 and newer: Side Tray offers to turn notifications on after you
  join, not at first launch. *Device → Settings* shows whether they're on and
  how they arrive.
- **Updates**: Side Tray looks for a new version when it starts and once a
  day. When there is one, a card on the feed offers *Download and install*;
  the first time, Android asks you to allow Side Tray to install apps
  ("Allow from this source"), and the card says how. Android then asks to
  confirm the update. Only an APK signed with Side Tray's own key can
  replace the app.

### Desktop app

- **Start Side Tray when I sign in** is now on for new installs (it opens
  quietly in the tray). Computers updating from 0.1.x keep their setting.
- A new group's very first post now notifies (it used to count as the
  backlog of a new device).
- A HEIC/HEIF photo is refused with a clear message instead of "isn't a
  photo this app can read".
- Internally the app is now a library plus a small executable, so the same
  code builds for Android.

### Relay

- Android wake-ups go through ntfy.sh by default (`SIDETRAY_PUSH_HOSTS`).
- Optional own push server: `install.sh` asks whether to run **ntfy** next to
  the relay (off unless you say yes; `--push` / `--no-push`). On a domain it
  shares port 443 and the Let's Encrypt certificate; a test server uses port
  8443 with a self-signed certificate. An existing server is asked on its
  next update.
- `GET/POST/DELETE /api/v1/push`: a phone registers its UnifiedPush endpoint.
  When a phone has no connection open, the relay sends it an **empty**
  wake-up; nothing about the group, the people or the content goes into it.
- Update the relay too (`git pull && sudo ./install.sh`) so phones get
  notifications; 0.1.x apps work with it unchanged.

### Releases

- Each release now also carries the signed Android APK
  (`Side.Tray_<version>_arm64.apk`, and the same file as `SideTray.apk`) and
  `android.json`, which phones read to find updates.

### Known limits

- The APK is for 64-bit ARM phones only (no 32-bit phones, no x86 Chromebooks
  or emulators).
- Android's Play Protect may ask about an app from outside the Play Store the
  first time; the README says what to tap.

## [0.1.1] - 2026-10-31

Adding pictures is now as easy as on Facebook. App only: the relay is
unchanged (its version number moves with the app's).

### Desktop app

- **Paste pictures**: Ctrl+V or right-click *Paste* in the post composer, a
  comment box or a chat attaches a copied picture or screenshot, or picture
  files copied in Explorer. Pasting text still pastes text, also when the
  clipboard holds a picture of it too (as Word and Excel do).
- **Drag and drop pictures** from Explorer or a browser window onto the
  composer, a post (for a comment) or a chat. A picture that comes from a web
  page as only its address is downloaded by the app.
- **Photos on comments**, up to 4 per comment, from the new *Photo* button,
  paste or drop. A comment can be just a photo.
- Every way in goes through the same pipeline as before (resized, EXIF and GPS
  stripped, thumbnailed, encrypted) and shows a preview with a remove (×)
  button before sending. Up to 10 photos per post or message, as before.
- Animated GIFs (and animated WebP and PNG) are sent as a still image of their
  first frame; the preview is tagged *Still* and the app says so.
- BMP files are accepted too.

### Known limits

- Someone still on 0.1.0 sees a comment's text but not its photos, and skips
  a photo-only comment. Updating doesn't bring those back, so update everyone
  (installed copies do it by themselves within a few hours).

## [0.1.0] - 2026-10-31

The first release: everything in [SPEC.md](SPEC.md) through Phase 7.

### Desktop app (Windows, Linux)

- First-run wizard: join a group with a server address and group name, or
  found one with a setup token. Invite links (`sidetray://join?...`) and QR
  codes fill it in.
- Safety-code join flow: a Key Master phones the new member and compares
  codes before approving; the group key is sealed to the new device and
  signed by the Key Master.
- Feed: text posts, photos (resized, EXIF and GPS stripped), comments,
  reactions, delete. End-to-end encrypted and signed; the relay never sees
  the content.
- Direct messages between two members, text and photos, readable only on
  their own devices.
- Members: verified roster with Key Master certificates; promote, remove,
  revoke a lost device, with automatic key rotation. New names wait for a
  Key Master to accept them. Profile photos.
- System tray with an unread badge, native notifications, optional start at
  sign-in.
- Test servers on a LAN IP: the app pins the server's root certificate only
  after you confirm its fingerprint.
- Windows installer (per-user, no admin rights needed): Start menu and
  optional desktop shortcut, `sidetray://` links and notifications
  registered against the installed app. Uninstalling removes those and
  keeps your posts and keys.
- Self-update: installed copies check for a signed update every few hours,
  download it in the background and offer *Restart to update*.

### Relay server

- FastAPI + SQLite relay behind Caddy, one Docker Compose stack.
- `install.sh` for a fresh Debian or Ubuntu server: Let's Encrypt on a
  domain, or a test mode on a LAN IP.
- Several groups per server, invisible to each other
  (`sidetray-admin new-group`).
- Hourly pruning (everything every device has fetched, and anything past
  90 days), rate limits, WebSocket push.
- `/api/v1/health` reports the relay's version.

### Known limits

- The Windows installer isn't code-signed yet, so Windows shows a
  SmartScreen warning the first time (see the README).
- No macOS build yet.
- Clicking an old notification in the Windows notification centre doesn't
  open the post it was about (one still on screen does).

[0.3.1]: https://github.com/shaybee22/sidetray/releases/tag/v0.3.1
[0.3.0]: https://github.com/shaybee22/sidetray/releases/tag/v0.3.0
[0.2.0]: https://github.com/shaybee22/sidetray/releases/tag/v0.2.0
[0.1.1]: https://github.com/shaybee22/sidetray/releases/tag/v0.1.1
[0.1.0]: https://github.com/shaybee22/sidetray/releases/tag/v0.1.0
