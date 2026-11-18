# Moving a Side Tray server to a new host

This moves a relay (its groups, members, Key Masters, post history, photos,
videos and settings) to a new machine with a few minutes of downtime. The apps
don't change anything: they keep the same address, the same device tokens and
the same keys, and reconnect on their own once the address points at the new
host.

What moves, and what doesn't:

| | In the backup |
| --- | --- |
| Database: groups, members, devices, Key Master certificates, sealed group keys, posts and comments still on the relay, direct messages, acks, setup tokens, push registrations | yes, a consistent copy taken while the relay runs |
| Photos and avatars | yes |
| Videos | yes, or leave them out with `--no-videos` (they're temporary anyway; the apps show them as expired) |
| Settings (`/opt/sidetray/.env`) | yes |
| Let's Encrypt certificates | **no**: the new host gets its own once DNS points at it |
| Test mode (a LAN IP): Caddy's own certificate authority, and the push server's certificate | yes: the apps pinned them, so the new host has to keep them |

The backup is encrypted with a passphrase you choose when you make it. The
passphrase isn't stored anywhere, so keep it somewhere safe until the move is
done. Without it the backup can't be restored. The group contents in it are
end-to-end encrypted anyway, but the file also holds the settings and the
records of who's in which group.

## The day before: lower the DNS TTL

At your DNS provider, set the TTL of the server's A record (and AAAA, if
there is one) to 5 minutes (300 seconds). Do this **at least a day ahead**: phones and
resolvers keep the old answer for as long as the *old* TTL said, so the drop
only takes effect after the old TTL has run out once. Then, on moving day,
everyone follows the new address within minutes.

Also create the new server (same or newer Debian/Ubuntu) and make sure you can
`ssh` to it. Give it a release of Side Tray **at least as new** as the old
server's: a restore refuses a backup from a newer release.

## 1. Stop new posts on the old server, and back it up

On the **old** server:

```sh
sudo sidetray-admin backup --final
```

`--final` first turns on maintenance mode: the relay keeps serving reads (the
feed, photos), but refuses new posts, comments, messages, uploads, joins and
Key Master actions with "This server is moving to a new host; try again in a
few minutes". That way nothing is posted to the old server after the backup and
lost in the move. Then it takes the backup. It asks for the passphrase twice
and prints where the file is, like:

```
Backup: /var/backups/sidetray/sidetray-backup-tray.example.org-20261118-210000Z.tar.gz.gpg (84M)
        copy for alice: /home/alice/sidetray-backup-tray.example.org-20261118-210000Z.tar.gz.gpg (delete it once you have it)

To copy it to your computer, run this there (Windows PowerShell, macOS or Linux):

    scp alice@tray.example.org:/home/alice/sidetray-backup-tray.example.org-20261118-210000Z.tar.gz.gpg .
```

The backup in `/var/backups/sidetray` is readable by root only (mode 600).
When you run the command with `sudo`, it also puts a copy in your own home
folder, owned by you and still mode 600, so you can `scp` it as yourself.
The printed command names that exact file. Run as root without `sudo`, it
prints a `root@` command for the copy in `/var/backups/sidetray`.

Options: `--no-videos` (smaller and faster), `--no-encrypt` (a plain
`.tar.gz`; avoid it unless the file never leaves machines you control),
`--out DIR`. Without `--final`, the backup is fine as a routine backup, but
anything posted after it is not in it.

Maintenance mode on its own: `sudo sidetray-admin maintenance on|off|status`.

## 2. Copy the backup to your computer

Run the `scp` line it printed **on your computer**: Windows PowerShell has
`scp` built in. Once you have the file, delete the copy in your home folder on
the server (`rm ~/sidetray-backup-*.tar.gz.gpg`). The root-only copy in
`/var/backups/sidetray` stays until you delete it.

## 3. Copy it to the new server and restore

From your computer:

```powershell
scp .\sidetray-backup-tray.example.org-20261118-210000Z.tar.gz.gpg alice@NEW-SERVER-IP:
```

On the **new** server, from a Side Tray release or checkout:

```sh
sudo ./install.sh --restore ~/sidetray-backup-tray.example.org-20261118-210000Z.tar.gz.gpg
```

(Or run `sudo ./install.sh` and answer **2) Restore** to "Fresh install or
restore from backup?".) The installer:

1. asks for the passphrase, decrypts the backup and checks every file's
   checksum;
2. checks the versions: a backup from an older release is updated after the
   restore, and one from a *newer* release is refused (install that release
   instead);
3. shows the address from the backup (`https://tray.example.org`) and asks you
   to confirm it;
4. installs Docker if needed, restores the settings and data;
5. **waits for DNS to point at this server** before it starts Caddy for a
   certificate (see step 4); it checks every 30 seconds for up to an hour;
6. starts the relay, waits for HTTPS and lists the restored groups.

The installer doesn't ask about mode, retention, history or the push server:
they come from the backup.

If anything fails partway, fix what it says and **run the same command again**.
A restore can be repeated safely. It refuses to overwrite a server that
already has groups of its own; pass `--force-restore` if you mean to.

Non-interactive: `sudo SIDETRAY_BACKUP_PASSPHRASE='...' ./install.sh --restore FILE --yes`.

## 4. Point DNS at the new server

While the installer waits, change the A (and AAAA) record of the domain to the
new server's public address. As soon as it resolves there, the installer gets
a Let's Encrypt certificate and finishes. If you'd rather not wait, answer `n`
to "Wait here until it points at this server?". Caddy then keeps retrying
for a certificate by itself.

**Test mode (a LAN IP instead of a domain):** there's no DNS to change. The
new server has to **take over the old one's IP address**: shut the old one
down (or give it another address) and give the new one that address before
you restore. The backup carries the test certificate authority, so the apps
keep trusting the server.

## 5. Check

On the new server:

```sh
sudo sidetray-admin list-groups     # every group, with member, device and event counts
```

Then open the app on a phone and a computer: the feed is there, and a new post
goes through. Devices reconnect within a minute or so of the name resolving to
the new server (phones may take longer if they're asleep: opening the app
syncs right away).

## 6. Keep the old server until everyone has moved

**Don't delete the old server yet.** Leave it running in maintenance mode until
every member's devices have shown up on the new one (`list-groups`, and the
people themselves). A device with a stale DNS answer still reaches the old
server: it can read, and its posts are refused with "this server is moving"
rather than lost. A few days is plenty. Then shut the old server down (and
destroy it, along with its backups, if it was a cloud VM).

Afterwards, raise the DNS TTL again if you like.

## Calling off a move

On the old server, `sudo sidetray-admin maintenance off` and it accepts posts
again. If DNS already pointed at the new server, point it back first; anything
posted on the new server in between stays there.

## Routine backups

`sudo sidetray-admin backup` (without `--final`) works any time while the relay
runs, and restores the same way. It asks for a passphrase on a terminal, so for
an unattended backup use `--no-encrypt` and protect the file yourself.
