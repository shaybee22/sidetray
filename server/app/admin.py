"""Operator commands. Inside the api container they're `sidetray-admin`:

    docker compose exec api sidetray-admin new-group

On a server set up with install.sh, plain `sudo sidetray-admin ...` on the
host does the same.

new-group [--days N]  Print a fresh one-time setup token (valid 7 days, or N).
                      The first device that joins with it creates a new group
                      and becomes its Key Master. Only its hash is stored.
list-groups           Groups on this server with member, device and event
                      counts, and the setup tokens not used yet. Operator
                      only: the API never lists groups.
setup-status          One line for scripts: groups=N tokens=N env_token=yes|no
prune                 Run the prune job now (it also runs every hour): delete
                      events and media every active device has acked, and
                      anything older than SIDETRAY_RETENTION_DAYS. Prints
                      what it deleted as JSON.
"""

import argparse
import json
import sys
import time

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
            " (SELECT MAX(created_at) FROM events e WHERE e.group_id = g.id) AS last_event"
            " FROM groups g ORDER BY g.created_at"
        ).fetchall()
        tokens = open_tokens(conn)
        env = env_token_usable(conn)
    if not rows:
        print("No groups yet.")
    else:
        head = ("id", "name", "created", "members", "devices", "pending", "events", "last post", "key")
        table = [head] + [
            (r["id"], r["name"], when(r["created_at"]), str(r["members"]), str(r["devices"]),
             str(r["pending"]), str(r["events"]), when(r["last_event"]), f"v{r['key_version']}")
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


def run(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="sidetray-admin", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")
    ng = sub.add_parser("new-group", help="print a one-time setup token for a new group")
    ng.add_argument("--days", type=float, default=main.SETUP_TOKEN_DAYS, help="days the token is valid (default 7)")
    sub.add_parser("list-groups", help="list this server's groups (operator only)")
    sub.add_parser("setup-status", help="counts for scripts")
    sub.add_parser("prune", help="run the prune job now")
    a = p.parse_args(argv)
    main.init_db()
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
