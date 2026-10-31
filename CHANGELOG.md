# Changelog

All notable changes to Side Tray. Versions follow [Semantic Versioning](https://semver.org/);
the app, the Rust crates and the relay share one version number.

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

[0.1.0]: https://github.com/shaybee22/sidetray/releases/tag/v0.1.0
