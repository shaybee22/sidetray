"""Operator commands. Inside the api container they're `sidetray-admin`:

    docker compose exec api sidetray-admin new-group

On a server set up with install.sh, plain `sudo sidetray-admin ...` on the
host does the same.

new-group [--days N]  Print a fresh one-time setup token (valid 7 days, or N).
                      The first device that joins with it creates a new group
                      and becomes its Key Master. Only its hash is stored.
list-groups           Groups on this server with member, device, event and DM
                      counts, and the setup tokens not used yet. Operator
                      only: the API never lists groups.
setup-status          One line for scripts: groups=N tokens=N env_token=yes|no
prune                 Run the prune job now (it also runs every hour): delete
                      events and media every device has acked once past
                      SIDETRAY_HISTORY_DAYS, direct messages every device
                      they're for has acked, and anything older than
                      SIDETRAY_RETENTION_DAYS. Prints what it deleted as JSON.
maintenance on|off|status
                      While on, every write (posts, messages, uploads, joins,
                      Key Master actions) answers 503 "this server is moving",
                      so nothing lands here after the last backup. Reads and
                      acks still work.

Used by the host's `sidetray-admin backup` and by install.sh --restore:

snapshot DIR [--no-videos]
                      A consistent copy of the database (SQLite's online
                      backup API, safe while the relay runs) and its media
                      files (hard links) in DIR inside the data folder. Prints
                      JSON: app and schema version, counts.
snapshot-clean DIR    Remove a snapshot folder.
restore-data SRC --id ID [--force]
                      Replace this server's data with a snapshot in SRC, then
                      run the migrations. Refuses a server that already has
                      groups unless it's a re-run of the same restore (ID) or
                      --force. Safe to re-run if it fails partway.
"""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from . import main


def when(t: int | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "-"


def open_tokens(conn) -> list:
    return conn.execute(
        "SELECT created_at, expires_at FROM setup_tokens WHERE used_at IS NULL AND expires_at > ?"
        " ORDER BY created_at", (main.now(),)
    ).fetchall()


def env_token_usable(conn) -> bool:
    """SIDETRAY_SETUP_TOKEN only works while the server has no group."""
    return bool(main.SETUP_TOKEN) and conn.execute("SELECT 1 FROM groups LIMIT 1").fetchone() is None


def new_group(days: float) -> int:
    token, expires = main.issue_setup_token(days)
    print(f"Setup token for a new group (one use, valid until {when(expires)}):\n")
    print(f"    {token}\n")
    print("Give it to the person who will be the group's first Key Master. In the app")
    print("they enter this server's address, the group name they want, and this token.")
    return 0


def list_groups() -> int:
    with main.db() as conn:
        rows = conn.execute(
            "SELECT g.id, g.name, g.created_at, g.key_version,"
            " (SELECT COUNT(*) FROM members m WHERE m.group_id = g.id AND m.status = 'active') AS members,"
            " (SELECT COUNT(*) FROM devices d WHERE d.group_id = g.id AND d.status = 'active') AS devices,"
            " (SELECT COUNT(*) FROM devices d WHERE d.group_id = g.id AND d.status = 'pending') AS pending,"
            " (SELECT COUNT(*) FROM events e WHERE e.group_id = g.id) AS events,"
            " (SELECT MAX(created_at) FROM events e WHERE e.group_id = g.id) AS last_event,"
            " (SELECT COUNT(*) FROM dm_messages x WHERE x.group_id = g.id) AS dms"
            " FROM groups g ORDER BY g.created_at"
        ).fetchall()
        tokens = open_tokens(conn)
        env = env_token_usable(conn)
    if not rows:
        print("No groups yet.")
    else:
        head = ("id", "name", "created", "members", "devices", "pending", "events", "last post", "dms", "key")
        table = [head] + [
            (r["id"], r["name"], when(r["created_at"]), str(r["members"]), str(r["devices"]),
             str(r["pending"]), str(r["events"]), when(r["last_event"]), str(r["dms"]), f"v{r['key_version']}")
            for r in rows
        ]
        widths = [max(len(row[i]) for row in table) for i in range(len(head))]
        for row in table:
            print("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    print()
    if tokens:
        print(f"Unused setup tokens: {len(tokens)}")
        for t in tokens:
            print(f"  issued {when(t['created_at'])}, expires {when(t['expires_at'])}")
    else:
        print("Unused setup tokens: none")
    if env:
        print("SIDETRAY_SETUP_TOKEN in .env can still create the first group.")
    return 0


def setup_status() -> int:
    with main.db() as conn:
        groups = conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        tokens = len(open_tokens(conn))
        env = env_token_usable(conn)
    print(f"groups={groups} tokens={tokens} env_token={'yes' if env else 'no'}")
    return 0


def maintenance(action: str) -> int:
    flag = main.MAINTENANCE_FLAG
    if action == "on":
        flag.write_text(f"since {when(main.now())}\n")
        print("Maintenance mode is ON: posts, messages, uploads, joins and Key Master")
        print('actions are refused with "this server is moving". Reads and acks still work.')
    elif action == "off":
        flag.unlink(missing_ok=True)
        print("Maintenance mode is off: the relay accepts posts again.")
    else:
        print(f"maintenance={'on' if flag.exists() else 'off'}")
    return 0


def inside_data(path: str) -> Path:
    """A folder for snapshots: inside the data folder (so media can be
    hard-linked), and not the data or media folder itself."""
    p = Path(path).resolve()
    data = main.DATA_DIR.resolve()
    media = main.MEDIA_DIR.resolve()
    if data not in p.parents or p == media or media in p.parents:
        raise SystemExit(f"{path}: must be a folder inside {data}, outside media/")
    return p


def snapshot(path: str, videos: bool) -> int:
    out = inside_data(path)
    shutil.rmtree(out, ignore_errors=True)
    (out / "media").mkdir(parents=True)
    db_out = out / "sidetray.db"
    src = sqlite3.connect(main.DB_PATH, timeout=30)
    dst = sqlite3.connect(db_out)
    try:
        # One consistent read of the live database, whatever the relay is writing.
        src.backup(dst)
        # A self-contained file: no -wal next to it.
        dst.execute("PRAGMA journal_mode = DELETE")
        dst.row_factory = sqlite3.Row
        version = main.schema_version(dst)
        rows = dst.execute("SELECT id, path, kind FROM media").fetchall()
        groups = dst.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        events = dst.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        dst.close()
        src.close()
    copied = skipped_videos = missing = size = 0
    for r in rows:
        if r["kind"] == "video" and not videos:
            skipped_videos += 1
            continue
        f = main.MEDIA_DIR / r["path"]
        if not f.is_file():
            missing += 1  # pruned since the snapshot; the restore marks it gone
            continue
        target = out / "media" / r["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(f, target)
        except OSError:
            shutil.copy2(f, target)
        copied += 1
        size += f.stat().st_size
    print(json.dumps({
        "app_version": main.__version__, "schema_version": version, "groups": groups, "events": events,
        "media_files": copied, "media_bytes": size, "videos_left_out": skipped_videos, "media_missing": missing,
    }))
    return 0


def snapshot_clean(path: str) -> int:
    shutil.rmtree(inside_data(path), ignore_errors=True)
    return 0


RESTORE_MARKER = ".restored-from"


def restore_data(src: str, restore_id: str, force: bool) -> int:
    srcp = Path(src)
    if not (srcp / "sidetray.db").is_file():
        raise SystemExit(f"{src}: no sidetray.db in the snapshot")
    data = main.DATA_DIR
    data.mkdir(parents=True, exist_ok=True)
    marker = data / RESTORE_MARKER
    same_restore = marker.is_file() and marker.read_text().strip() == restore_id
    if main.DB_PATH.is_file() and not force and not same_restore:
        conn = sqlite3.connect(main.DB_PATH)
        try:
            groups = conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        except sqlite3.DatabaseError:
            groups = 0
        finally:
            conn.close()
        if groups:
            print(f"This server already has {groups} group(s). Restoring would replace them;"
                  " pass --force-restore to install.sh if that's what you want.", file=sys.stderr)
            return 3
    # Check the snapshot before touching anything.
    conn = sqlite3.connect(f"file:{(srcp / 'sidetray.db').resolve()}?mode=ro", uri=True)
    try:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
        version = main.schema_version(conn)
    finally:
        conn.close()
    if ok != "ok":
        raise SystemExit(f"the backup's database is damaged: {ok}")
    if version > main.SCHEMA_VERSION:
        print(f"The backup has schema version {version}; this relay ({main.__version__}) knows up to"
              f" {main.SCHEMA_VERSION}. Install the release the backup came from, or newer.", file=sys.stderr)
        return 4
    # From here a failed run is simply repeated: the marker says which restore
    # this data belongs to, and the copy goes to a staging folder first.
    marker.write_text(restore_id + "\n")
    stage = data / ".restore-tmp"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir()
    shutil.copy2(srcp / "sidetray.db", stage / "sidetray.db")
    if (srcp / "media").is_dir():
        shutil.copytree(srcp / "media", stage / "media")
    else:
        (stage / "media").mkdir()
    for name in ("sidetray.db-wal", "sidetray.db-shm", "sidetray.db"):
        (data / name).unlink(missing_ok=True)
    shutil.rmtree(main.MEDIA_DIR, ignore_errors=True)
    main.MAINTENANCE_FLAG.unlink(missing_ok=True)
    os.replace(stage / "sidetray.db", main.DB_PATH)
    os.replace(stage / "media", main.MEDIA_DIR)
    stage.rmdir()
    # The normal migrations, as on any start.
    main.init_db()
    t = main.now()
    with main.db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute("SELECT id, group_id, path FROM media").fetchall()
        missing = [r for r in rows if not (main.MEDIA_DIR / r["path"]).is_file()]
        # Videos left out of the backup show as expired in the apps, not as errors.
        main.drop_media(conn, missing, "migrated", t)
        groups = conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        now_version = main.schema_version(conn)
    print(json.dumps({"groups": groups, "events": events, "media_files": len(rows) - len(missing),
                      "media_marked_gone": len(missing), "schema_version_before": version,
                      "schema_version": now_version}))
    return 0


def run(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="sidetray-admin", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")
    ng = sub.add_parser("new-group", help="print a one-time setup token for a new group")
    ng.add_argument("--days", type=float, default=main.SETUP_TOKEN_DAYS, help="days the token is valid (default 7)")
    sub.add_parser("list-groups", help="list this server's groups (operator only)")
    sub.add_parser("setup-status", help="counts for scripts")
    sub.add_parser("prune", help="run the prune job now")
    mt = sub.add_parser("maintenance", help="refuse writes while the server moves (on|off|status)")
    mt.add_argument("action", choices=["on", "off", "status"])
    sn = sub.add_parser("snapshot", help="consistent copy of the data, for backups")
    sn.add_argument("dir")
    sn.add_argument("--no-videos", action="store_true")
    sc = sub.add_parser("snapshot-clean", help="remove a snapshot folder")
    sc.add_argument("dir")
    rd = sub.add_parser("restore-data", help="replace this server's data with a snapshot")
    rd.add_argument("src")
    rd.add_argument("--id", required=True)
    rd.add_argument("--force", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "restore-data":
        return restore_data(a.src, a.id, a.force)
    if a.cmd == "snapshot-clean":
        return snapshot_clean(a.dir)
    if a.cmd == "snapshot":
        # Only reads: the running relay has already migrated the database.
        if not main.DB_PATH.is_file():
            raise SystemExit(f"no database at {main.DB_PATH}")
        return snapshot(a.dir, not a.no_videos)
    try:
        main.init_db()
    except main.NewerSchemaError as e:
        print(e, file=sys.stderr)
        return 4
    if a.cmd == "maintenance":
        return maintenance(a.action)
    if a.cmd == "new-group":
        if not 0 < a.days <= 365:
            p.error("--days must be between 0 and 365")
        return new_group(a.days)
    if a.cmd == "list-groups":
        return list_groups()
    if a.cmd == "setup-status":
        return setup_status()
    print(json.dumps(main.prune()))
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
