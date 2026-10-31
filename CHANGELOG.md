# Changelog

All notable changes to Side Tray. Versions follow [Semantic Versioning](https://semver.org/);
the app, the Rust crates and the relay share one version number.

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

[0.1.1]: https://github.com/shaybee22/sidetray/releases/tag/v0.1.1
[0.1.0]: https://github.com/shaybee22/sidetray/releases/tag/v0.1.0
