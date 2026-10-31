"""Side Tray relay.

Thin relay: stores ciphertext and routing metadata, never decrypts.
Every device has its own bearer token, issued at join and stored hashed.
The first device creates the group with the operator's setup token and
becomes its Key Master; later devices wait as `pending` until a Key Master
approves them and uploads the group key sealed (and signed) to them.

Connected devices get small push messages over /ws (see Hub) telling them
to sync; the content itself is only ever fetched with GET /events.

Phase 6: an hourly prune job deletes what every active device has acked and
anything past the retention window; Key Masters remove members, revoke lost
devices and rotate the group key (sealed and signed by their app, as at join).

Phase 6b: several groups per server. Each is created with a one-time setup
token (`sidetray-admin new-group`), the server never lists them, and every
authenticated call stays inside the calling device's group, down to event
numbers, which count per group. Rate limits per device and per client IP.
"""

import asyncio
import base64
import binascii
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from collections import deque
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from starlette.websockets import WebSocketDisconnect
from pydantic import BaseModel, Field, field_validator

DATA_DIR = Path(os.environ.get("SIDETRAY_DATA", "./data"))
DB_PATH = DATA_DIR / "sidetray.db"
MEDIA_DIR = DATA_DIR / "media"
# Operator secret that creates a server's first group (later ones need a
# one-time token from `sidetray-admin new-group`). Unset means disabled.
SETUP_TOKEN = os.environ.get("SIDETRAY_SETUP_TOKEN", "")
SETUP_TOKEN_DAYS = 7
MAX_MEDIA_BYTES = int(os.environ.get("SIDETRAY_MAX_MEDIA_BYTES", 10 * 1024 * 1024))
PAGE_SIZE = 500
MAX_PENDING = 20
KEY_LEN = 32
# /ws: sockets per device, and how long a socket may stay silent. Clients send
# {"type": "ping"} every 25 seconds; anything quieter than this is dropped.
MAX_SOCKETS_PER_DEVICE = 4
WS_IDLE_SECONDS = float(os.environ.get("SIDETRAY_WS_IDLE_SECONDS", 75))
WS_QUEUE = 256
# Pruning: events and media go once every active device has acked them, or
# after the retention window whatever the acks say.
RETENTION_DAYS = float(os.environ.get("SIDETRAY_RETENTION_DAYS") or 90)
PRUNE_EVERY_SECONDS = float(os.environ.get("SIDETRAY_PRUNE_EVERY_SECONDS") or 3600)
# Uploaded media that no event refers to (an upload whose post never came) is
# dropped after this long.
ORPHAN_MEDIA_SECONDS = 24 * 3600


def env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    return int(v) if v else default


# Rate limits (SPEC): per device, and per client IP for the unauthenticated
# calls, so nobody can flood Key Masters with join requests or guess group names.
EVENTS_PER_MINUTE = env_int("SIDETRAY_EVENTS_PER_MINUTE", 30)
MEDIA_BYTES_PER_HOUR = env_int("SIDETRAY_MEDIA_MB_PER_HOUR", 50) * 1024 * 1024
JOINS_PER_HOUR = env_int("SIDETRAY_JOINS_PER_HOUR", 10)
LOOKUPS_PER_HOUR = env_int("SIDETRAY_LOOKUPS_PER_HOUR", 60)

# Seeded by the Phase 1 skeleton for its hardcoded test token; removed on startup.
LEGACY_TEST_GROUP_ID = "g_test"

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    id            TEXT PRIMARY KEY,
    group_id      TEXT NOT NULL REFERENCES groups(id),
    display_name  TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('member', 'keymaster')),
    status        TEXT NOT NULL CHECK (status IN ('active', 'removed')),
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id           TEXT PRIMARY KEY,
    group_id     TEXT NOT NULL REFERENCES groups(id),
    member_id    TEXT NOT NULL REFERENCES members(id),
    enc_pubkey   BLOB,
    sign_pubkey  BLOB,
    status       TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    token_hash   TEXT UNIQUE,
    last_seen    INTEGER
);
CREATE TABLE IF NOT EXISTS sealed_keys (
    group_id     TEXT NOT NULL REFERENCES groups(id),
    device_id    TEXT NOT NULL REFERENCES devices(id),
    key_version  INTEGER NOT NULL,
    sealed_blob  BLOB NOT NULL,
    PRIMARY KEY (device_id, key_version)
);
CREATE TABLE IF NOT EXISTS events (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id          TEXT NOT NULL REFERENCES groups(id),
    kind              TEXT NOT NULL CHECK (kind IN ('post', 'comment', 'reaction', 'edit', 'delete')),
    author_device_id  TEXT NOT NULL REFERENCES devices(id),
    key_version       INTEGER NOT NULL,
    ciphertext        BLOB NOT NULL,
    signature         BLOB NOT NULL,
    media_ids         TEXT NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_group_seq ON events (group_id, seq);
CREATE TABLE IF NOT EXISTS media (
    id          TEXT PRIMARY KEY,
    group_id    TEXT NOT NULL REFERENCES groups(id),
    uploader_device_id TEXT NOT NULL REFERENCES devices(id),
    size_bytes  INTEGER NOT NULL,
    path        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
-- A Key Master's signed statement about one device (see crypto::roster).
-- The server checks the fields match its records but can't verify or forge
-- the signature's meaning; clients verify the chain themselves.
CREATE TABLE IF NOT EXISTS member_certs (
    group_id          TEXT NOT NULL REFERENCES groups(id),
    device_id         TEXT NOT NULL REFERENCES devices(id),
    issuer_device_id  TEXT NOT NULL REFERENCES devices(id),
    role              TEXT NOT NULL CHECK (role IN ('member', 'keymaster')),
    display_name      TEXT NOT NULL,
    signature         BLOB NOT NULL,
    created_at        INTEGER NOT NULL,
    PRIMARY KEY (device_id, issuer_device_id, role)
);
CREATE TABLE IF NOT EXISTS acks (
    group_id   TEXT NOT NULL REFERENCES groups(id),
    device_id  TEXT PRIMARY KEY REFERENCES devices(id),
    last_seq   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
-- One-time tokens from `sidetray-admin new-group`; whoever joins with one
-- creates a new group and becomes its Key Master.
CREATE TABLE IF NOT EXISTS setup_tokens (
    token_hash  TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    group_id    TEXT REFERENCES groups(id)
);
"""


def now() -> int:
    return int(time.time())


def name_key(name: str) -> str:
    """Group names are unique per server, ignoring case and repeated spaces."""
    return " ".join(name.split()).casefold()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def b64decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field} must be valid base64")


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def add_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def drop_legacy_test_group(conn: sqlite3.Connection) -> None:
    """Remove the Phase 1 seed (group g_test and everything in it).

    Runs on every startup and is a no-op once g_test is gone. Every statement
    is filtered on group_id = 'g_test', and real group ids are `g_` plus 16
    random characters (new_id), so no real group can match.
    """
    if not conn.execute("SELECT 1 FROM groups WHERE id = ?", (LEGACY_TEST_GROUP_ID,)).fetchone():
        return
    for row in conn.execute("SELECT path FROM media WHERE group_id = ?", (LEGACY_TEST_GROUP_ID,)):
        (MEDIA_DIR / row["path"]).unlink(missing_ok=True)
    for table in ("acks", "events", "media", "member_certs", "sealed_keys", "devices", "members"):
        conn.execute(f"DELETE FROM {table} WHERE group_id = ?", (LEGACY_TEST_GROUP_ID,))
    conn.execute("DELETE FROM groups WHERE id = ?", (LEGACY_TEST_GROUP_ID,))
    legacy_dir = MEDIA_DIR / LEGACY_TEST_GROUP_ID
    if legacy_dir.is_dir() and not any(legacy_dir.iterdir()):
        legacy_dir.rmdir()


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        # Phase 3 columns, added in place so existing databases keep working.
        add_column(conn, "devices", "requested_at", "INTEGER")
        add_column(conn, "devices", "approved_by", "TEXT REFERENCES devices(id)")
        add_column(conn, "sealed_keys", "signature", "BLOB")
        add_column(conn, "sealed_keys", "signer_device_id", "TEXT REFERENCES devices(id)")
        add_column(conn, "devices", "anchors", "TEXT")  # JSON [{device_id, sign_pubkey}]
        add_column(conn, "devices", "anchors_signature", "BLOB")
        # Phase 6: key rotation, pruning, removal.
        add_column(conn, "groups", "key_version", "INTEGER NOT NULL DEFAULT 1")
        add_column(conn, "groups", "pruned_through", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "groups", "rotation_pending", "INTEGER NOT NULL DEFAULT 0")
        add_column(conn, "devices", "revoked_reason", "TEXT")  # denied / removed / revoked
        add_column(conn, "devices", "revoked_at", "INTEGER")
        add_column(conn, "devices", "revoked_seq", "INTEGER")  # last event seq when it was cut off
        drop_legacy_test_group(conn)  # before group names become unique
        # Phase 6b: several groups. Event numbers (`gseq`, what the API calls
        # seq) count per group, so one group can't read another's activity in
        # the gaps. Existing events keep their number (gseq = seq) and each
        # group's counter starts from the old server-wide one, so cursors and
        # acks already on devices stay valid.
        add_column(conn, "groups", "name_key", "TEXT")
        for g in conn.execute("SELECT id, name FROM groups WHERE name_key IS NULL").fetchall():
            conn.execute("UPDATE groups SET name_key = ? WHERE id = ?", (name_key(g["name"]), g["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS groups_name_key ON groups (name_key)")
        if "gseq" not in {r["name"] for r in conn.execute("PRAGMA table_info(events)")}:
            conn.execute("ALTER TABLE events ADD COLUMN gseq INTEGER")
            add_column(conn, "groups", "event_seq", "INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE events SET gseq = seq")
            hw = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'events'").fetchone()
            conn.execute("UPDATE groups SET event_seq = ?", (hw[0] if hw else 0,))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS events_group_gseq ON events (group_id, gseq)")
        # Numbers each new event within its group, inside the inserting transaction.
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS events_number AFTER INSERT ON events WHEN NEW.gseq IS NULL BEGIN"
            " UPDATE groups SET event_seq = event_seq + 1 WHERE id = NEW.group_id;"
            " UPDATE events SET gseq = (SELECT event_seq FROM groups WHERE id = NEW.group_id)"
            " WHERE seq = NEW.seq; END"
        )
        conn.execute(
            "UPDATE groups SET key_version = MAX(key_version,"
            " (SELECT COALESCE(MAX(key_version), 1) FROM sealed_keys WHERE group_id = groups.id),"
            " (SELECT COALESCE(MAX(key_version), 1) FROM events WHERE group_id = groups.id))"
        )


def prune(t: int | None = None) -> dict:
    """Delete events (and their media) that every active device has acked, and
    events and media older than the retention window. Revoked devices and
    removed members don't count. Records the highest seq deleted per group
    (`pruned_through`), so a device that comes back with an older cursor
    knows it missed something."""
    t = now() if t is None else t
    cutoff = t - int(RETENTION_DAYS * 86400)
    out = {"events": 0, "media": 0}
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        doomed_media: set[str] = set()
        for g in conn.execute("SELECT id FROM groups").fetchall():
            gid = g["id"]
            # A device with no ack yet has nothing: it holds everything back.
            row = conn.execute(
                "SELECT COUNT(*) AS n, MIN(COALESCE(a.last_seq, 0)) AS low FROM devices d"
                " JOIN members m ON m.id = d.member_id LEFT JOIN acks a ON a.device_id = d.id"
                " WHERE d.group_id = ? AND d.status = 'active' AND m.status = 'active'",
                (gid,),
            ).fetchone()
            acked = row["low"] if row["n"] else 0
            where = "group_id = ? AND (gseq <= ? OR created_at < ?)"
            args = (gid, acked, cutoff)
            top = conn.execute(f"SELECT MAX(gseq) FROM events WHERE {where}", args).fetchone()[0]
            if top is None:
                continue
            for r in conn.execute(f"SELECT media_ids FROM events WHERE {where} AND media_ids != ''", args):
                doomed_media.update(m for m in r["media_ids"].split(",") if m)
            out["events"] += conn.execute(f"DELETE FROM events WHERE {where}", args).rowcount
            conn.execute("UPDATE groups SET pruned_through = MAX(pruned_through, ?) WHERE id = ?", (top, gid))
        # Media: referenced by a deleted event, past retention, or never referenced.
        live: set[str] = set()
        for r in conn.execute("SELECT media_ids FROM events WHERE media_ids != ''"):
            live.update(m for m in r["media_ids"].split(",") if m)
        doomed = [
            r for r in conn.execute("SELECT id, path, created_at FROM media").fetchall()
            if r["id"] in doomed_media or r["created_at"] < cutoff
            or (r["id"] not in live and r["created_at"] < t - ORPHAN_MEDIA_SECONDS)
        ]
        for r in doomed:
            conn.execute("DELETE FROM media WHERE id = ?", (r["id"],))
        out["media"] = len(doomed)
    # Files after the commit: a crash in between leaves a stray file, never a dangling row.
    for r in doomed:
        (MEDIA_DIR / r["path"]).unlink(missing_ok=True)
    return out


async def prune_loop() -> None:
    while True:
        try:
            n = await run_in_threadpool(prune)
            if n["events"] or n["media"]:
                print(f"prune: deleted {n['events']} events, {n['media']} media", flush=True)
        except Exception as e:  # keep the job alive; it retries next time
            print(f"prune failed: {e!r}", flush=True)
        await asyncio.sleep(PRUNE_EVERY_SECONDS)


class Hub:
    """Open /ws sockets by device, for push messages.

    In memory, so the relay must run as a single process (it does: one
    uvicorn worker). Request handlers run in a thread pool, so `send` hands
    messages to the event loop thread-safely; each socket drains its own
    queue. Messages only say "something changed"; clients then sync.
    """

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.sockets: dict[str, set[asyncio.Queue]] = {}

    def count(self, device_id: str) -> int:
        return len(self.sockets.get(device_id, ()))

    def attach(self, device_id: str, q: asyncio.Queue) -> None:
        self.sockets.setdefault(device_id, set()).add(q)

    def detach(self, device_id: str, q: asyncio.Queue) -> None:
        qs = self.sockets.get(device_id)
        if qs is not None:
            qs.discard(q)
            if not qs:
                del self.sockets[device_id]

    def send(self, device_ids, msg: dict, close: bool = False) -> None:
        """Queue `msg` for every open socket of these devices; callable from any thread.
        With close=True each socket is closed after the message."""
        if self.loop is None or self.loop.is_closed():
            return
        data = json.dumps(msg, separators=(",", ":"))
        self.loop.call_soon_threadsafe(self._deliver, list(device_ids), data, close)

    def _deliver(self, device_ids: list[str], data: str, close: bool) -> None:
        for d in device_ids:
            for q in list(self.sockets.get(d, ())):
                try:
                    q.put_nowait(data)
                    if close:
                        q.put_nowait(None)
                except asyncio.QueueFull:
                    # A socket that can't keep up is closed; the client reconnects and syncs.
                    while not q.empty():
                        q.get_nowait()
                    q.put_nowait(None)


hub = Hub()


class Limiter:
    """Sliding-window limit per key (a device id or a client IP). In memory,
    like the Hub, so it relies on the single process. `take` records `amount`
    and returns None if it fits, otherwise the seconds until it would."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = {}
        self.lock = threading.Lock()

    def _used(self, key: str, t: float) -> tuple[deque, int]:
        q = self.hits.setdefault(key, deque())
        while q and q[0][0] <= t - self.window:
            q.popleft()
        return q, sum(a for _, a in q)

    def room(self, key: str) -> int:
        with self.lock:
            return self.limit - self._used(key, time.monotonic())[1]

    def take(self, key: str, amount: int = 1) -> int | None:
        t = time.monotonic()
        with self.lock:
            if len(self.hits) > 10_000:  # forget idle keys now and then
                for k in [k for k, q in self.hits.items() if not q or q[-1][0] <= t - self.window]:
                    del self.hits[k]
            q, used = self._used(key, t)
            if used + amount <= self.limit:
                q.append((t, amount))
                return None
            # Wait until enough of the oldest hits age out.
            need, freed = used + amount - self.limit, 0
            for ts, a in q:
                freed += a
                if freed >= need:
                    return max(1, int(ts + self.window - t) + 1)
            return int(self.window)  # bigger than the whole limit


event_limit = Limiter(EVENTS_PER_MINUTE, 60)
media_limit = Limiter(MEDIA_BYTES_PER_HOUR, 3600)
join_limit = Limiter(JOINS_PER_HOUR, 3600)
lookup_limit = Limiter(LOOKUPS_PER_HOUR, 3600)


def limit(limiter: Limiter, key: str, what: str, amount: int = 1) -> None:
    wait = limiter.take(key, amount)
    if wait is not None:
        raise HTTPException(429, f"too many {what}; try again in {wait} seconds",
                            headers={"Retry-After": str(wait)})


def client_ip(request: Request) -> str:
    """The caller's address. Behind Caddy, uvicorn takes it from
    X-Forwarded-For, which Caddy sets itself (it ignores the client's own)."""
    return request.client.host if request.client else "unknown"


def active_device_ids(conn: sqlite3.Connection, group_id: str, keymasters_only: bool = False) -> list[str]:
    sql = ("SELECT d.id FROM devices d JOIN members m ON m.id = d.member_id"
           " WHERE d.group_id = ? AND d.status = 'active' AND m.status = 'active'")
    if keymasters_only:
        sql += " AND m.role = 'keymaster'"
    return [r["id"] for r in conn.execute(sql, (group_id,))]


def push_new_event(group_id: str, author_device_id: str, seq: int, kind: str) -> None:
    """Every active device except the one that posted (it already knows)."""
    with db() as conn:
        to = [d for d in active_device_ids(conn, group_id) if d != author_device_id]
    hub.send(to, {"type": "new_event", "seq": seq, "kind": kind})


def push_join_request(group_id: str, device_id: str, display_name: str, existing_member: bool) -> None:
    """Key Masters only: someone is waiting for approval."""
    with db() as conn:
        to = active_device_ids(conn, group_id, keymasters_only=True)
    hub.send(to, {"type": "join_request", "device_id": device_id,
                  "display_name": display_name, "existing_member": existing_member})


def push_key_rotated(group_id: str, key_version: int) -> None:
    """A new group key was sealed to every active device: fetch it with GET /keys.
    Sent by key rotation (Phase 6)."""
    with db() as conn:
        to = active_device_ids(conn, group_id)
    hub.send(to, {"type": "key_rotated", "key_version": key_version})


def push_removed(device_ids: list[str], scope: str) -> None:
    """These devices were revoked: tell them, then close their sockets. `scope`
    is "member" (the member was removed) or "device" (just this device).
    Sent by removal and revocation, and by /ws itself when it notices."""
    hub.send(device_ids, {"type": "removed", "scope": scope}, close=True)


def group_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute("SELECT id, name FROM groups WHERE name_key = ?", (name_key(name),)).fetchone()


def check_setup_token(conn: sqlite3.Connection, token: str) -> str | None:
    """Whether `token` may create a group: "env" for the operator's
    SIDETRAY_SETUP_TOKEN (only while the server has no group yet), the
    token's hash for an unused, unexpired one from `sidetray-admin new-group`,
    otherwise None."""
    if SETUP_TOKEN and secrets.compare_digest(token.encode(), SETUP_TOKEN.encode()):
        return None if conn.execute("SELECT 1 FROM groups LIMIT 1").fetchone() else "env"
    h = hash_token(token)
    row = conn.execute(
        "SELECT 1 FROM setup_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?", (h, now())
    ).fetchone()
    return h if row else None


def issue_setup_token(days: float = SETUP_TOKEN_DAYS) -> tuple[str, int]:
    """A fresh one-time token for a new group, stored hashed. Returns (token, expires_at)."""
    token = "st_" + secrets.token_urlsafe(24)
    t = now()
    with db() as conn:
        conn.execute("INSERT INTO setup_tokens (token_hash, created_at, expires_at) VALUES (?, ?, ?)",
                     (hash_token(token), t, t + int(days * 86400)))
    return token, t + int(days * 86400)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


class Device(BaseModel):
    id: str
    group_id: str
    member_id: str
    status: str
    role: str


def bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    return authorization[7:].strip()


def device_for_token(authorization: str | None) -> Device:
    """Any device holding a token, whatever its status (for /join/status)."""
    with db() as conn:
        row = conn.execute(
            "SELECT d.id, d.group_id, d.member_id, d.status, m.role FROM devices d"
            " JOIN members m ON m.id = d.member_id WHERE d.token_hash = ?",
            (hash_token(bearer(authorization)),),
        ).fetchone()
        if row is None:
            raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
        conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now(), row["id"]))
    return Device(**dict(row))


def any_device(authorization: str | None = Header(default=None)) -> Device:
    return device_for_token(authorization)


def current_device(authorization: str | None = Header(default=None)) -> Device:
    """An active device of an active member."""
    dev = device_for_token(authorization)
    if dev.status != "active":
        raise HTTPException(401, f"device is {dev.status}", headers={"WWW-Authenticate": "Bearer"})
    return dev


def keymaster_device(dev: Device = Depends(current_device)) -> Device:
    if dev.role != "keymaster":
        raise HTTPException(403, "Key Master only")
    return dev


def pubkey(value: str, field: str) -> bytes:
    raw = b64decode(value, field)
    if len(raw) != KEY_LEN:
        raise ValueError(f"{field} must be {KEY_LEN} bytes")
    return raw


class JoinIn(BaseModel):
    group_name: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    enc_pubkey: str  # base64, X25519
    sign_pubkey: str  # base64, Ed25519
    setup_token: str | None = None  # only to create the group

    @field_validator("enc_pubkey", "sign_pubkey")
    @classmethod
    def check_key(cls, v: str, info):
        pubkey(v, info.field_name)
        return v

    @field_validator("group_name", "display_name", "email")
    @classmethod
    def strip(cls, v: str):
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v


class SealedKeyIn(BaseModel):
    key_version: int = Field(ge=1)
    sealed_blob: str  # base64, crypto_box_seal output
    signature: str  # base64, approving Key Master's Ed25519 signature over the grant

    @field_validator("sealed_blob", "signature")
    @classmethod
    def check_b64(cls, v: str, info):
        b64decode(v, info.field_name)
        return v


class CertIn(BaseModel):
    """A member certificate. member_id and the public keys are the device's own
    (from the server's records); the issuer is the calling Key Master device."""

    device_id: str
    role: Literal["member", "keymaster"]
    display_name: str = Field(min_length=1, max_length=100)
    signature: str  # base64, Ed25519 over crypto::protocol::member_cert_message

    @field_validator("signature")
    @classmethod
    def check_sig(cls, v: str):
        if len(b64decode(v, "signature")) != 64:
            raise ValueError("signature must be 64 bytes")
        return v


class AnchorIn(BaseModel):
    device_id: str
    sign_pubkey: str  # base64

    @field_validator("sign_pubkey")
    @classmethod
    def check_key(cls, v: str):
        pubkey(v, "sign_pubkey")
        return v


class ApproveIn(BaseModel):
    sealed_keys: list[SealedKeyIn] = Field(min_length=1, max_length=1000)
    cert: CertIn
    # Key Master signing keys the approver trusts, handed to the new device,
    # signed over crypto::protocol::anchors_message.
    anchors: list[AnchorIn] = Field(min_length=1, max_length=100)
    anchors_signature: str

    @field_validator("anchors_signature")
    @classmethod
    def check_sig(cls, v: str):
        if len(b64decode(v, "anchors_signature")) != 64:
            raise ValueError("anchors_signature must be 64 bytes")
        return v


class CertsIn(BaseModel):
    certs: list[CertIn] = Field(min_length=1, max_length=100)


class GrantIn(BaseModel):
    """The new group key sealed to one device, signed by the rotating Key Master
    over crypto::protocol::key_grant_message."""

    device_id: str
    sealed_blob: str
    signature: str

    @field_validator("sealed_blob", "signature")
    @classmethod
    def check_b64(cls, v: str, info):
        b64decode(v, info.field_name)
        return v


class RotateIn(BaseModel):
    key_version: int = Field(ge=2)
    sealed_keys: list[GrantIn] = Field(min_length=1, max_length=1000)


class RoleIn(BaseModel):
    role: Literal["keymaster"]  # demotion waits for revocation (Phase 6)
    certs: list[CertIn] = Field(min_length=1, max_length=100)


class EventIn(BaseModel):
    kind: Literal["post", "comment", "reaction", "edit", "delete"]
    key_version: int = Field(ge=1)
    ciphertext: str  # base64
    signature: str  # base64
    media_ids: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("ciphertext", "signature")
    @classmethod
    def check_b64(cls, v: str, info):
        b64decode(v, info.field_name)
        return v


class AckIn(BaseModel):
    seq: int = Field(ge=0)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    hub.loop = asyncio.get_running_loop()
    pruner = asyncio.create_task(prune_loop())
    yield
    pruner.cancel()


app = FastAPI(title="Side Tray relay", version="0.6.1", docs_url=None, redoc_url=None, lifespan=lifespan)
api = APIRouter(prefix="/api/v1")


@api.get("/health")
def health():
    return {"ok": True}


@api.get("/group")
def get_group(request: Request, name: str | None = Query(default=None, max_length=100)):
    """Whether a group of exactly this name (ignoring case) exists here. The
    server never lists its groups, so without a name there's no answer."""
    if not name or not name.strip():
        raise HTTPException(400, "pass ?name=<group name>; this server doesn't list its groups")
    limit(lookup_limit, client_ip(request), "group lookups from your address")
    with db() as conn:
        g = group_by_name(conn, name)
    return {"exists": True, "name": g["name"]} if g else {"exists": False}


@api.post("/join", status_code=201)
def join(body: JoinIn, request: Request):
    # Every attempt counts, wrong names and tokens included.
    limit(join_limit, client_ip(request), "join requests from your address")
    enc_pk = pubkey(body.enc_pubkey, "enc_pubkey")
    sign_pk = pubkey(body.sign_pubkey, "sign_pubkey")
    token = secrets.token_urlsafe(32)
    t = now()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        g = group_by_name(conn, body.group_name)
        if body.setup_token is not None:
            # Creating a group: a valid setup token makes this device its Key Master.
            used = check_setup_token(conn, body.setup_token)
            if used is None:
                raise HTTPException(403, "that setup token isn't valid here (wrong, already used or expired)")
            if g is not None:
                raise HTTPException(409, "a group with that name already exists on this server; pick another")
            group_id, member_id, device_id = new_id("g"), new_id("m"), new_id("d")
            conn.execute(
                "INSERT INTO groups (id, name, name_key, created_at) VALUES (?, ?, ?, ?)",
                (group_id, body.group_name, name_key(body.group_name), t),
            )
            if used != "env":
                conn.execute("UPDATE setup_tokens SET used_at = ?, group_id = ? WHERE token_hash = ?",
                             (t, group_id, used))
            conn.execute(
                "INSERT INTO members (id, group_id, display_name, email, role, status, created_at)"
                " VALUES (?, ?, ?, ?, 'keymaster', 'active', ?)",
                (member_id, group_id, body.display_name, body.email, t),
            )
            conn.execute(
                "INSERT INTO devices (id, group_id, member_id, enc_pubkey, sign_pubkey, status,"
                " token_hash, last_seen, requested_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                (device_id, group_id, member_id, enc_pk, sign_pk, hash_token(token), t, t),
            )
            return {"group_id": group_id, "group_name": body.group_name, "member_id": member_id,
                    "device_id": device_id, "token": token, "status": "active", "role": "keymaster"}

        if g is None:
            raise HTTPException(404, "no group with that name on this server")
        pending = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE group_id = ? AND status = 'pending'", (g["id"],)
        ).fetchone()[0]
        if pending >= MAX_PENDING:
            raise HTTPException(429, "too many pending join requests")
        # A new device for an existing account joins under the same member;
        # the Key Master sees that in the pending list.
        member = conn.execute(
            "SELECT id, role FROM members WHERE group_id = ? AND lower(email) = lower(?) AND status = 'active'",
            (g["id"], body.email),
        ).fetchone()
        existing_member = member is not None
        if member:
            member_id, role = member["id"], member["role"]
        else:
            member_id, role = new_id("m"), "member"
            conn.execute(
                "INSERT INTO members (id, group_id, display_name, email, role, status, created_at)"
                " VALUES (?, ?, ?, ?, 'member', 'active', ?)",
                (member_id, g["id"], body.display_name, body.email, t),
            )
        device_id = new_id("d")
        conn.execute(
            "INSERT INTO devices (id, group_id, member_id, enc_pubkey, sign_pubkey, status,"
            " token_hash, last_seen, requested_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
            (device_id, g["id"], member_id, enc_pk, sign_pk, hash_token(token), t, t),
        )
    push_join_request(g["id"], device_id, body.display_name, existing_member)
    return {"group_id": g["id"], "group_name": g["name"], "member_id": member_id,
            "device_id": device_id, "token": token, "status": "pending", "role": role}


@api.get("/join/status")
def join_status(dev: Device = Depends(any_device)):
    if dev.status == "pending":
        return {"status": "pending", "device_id": dev.id}
    if dev.status != "active":
        return {"status": revoked_status(dev.id), "device_id": dev.id}
    with db() as conn:
        row = conn.execute(
            "SELECT approved_by, anchors, anchors_signature FROM devices WHERE id = ?", (dev.id,)
        ).fetchone()
    return {"status": "active", "device_id": dev.id, "member_id": dev.member_id,
            "role": dev.role, "sealed_keys": sealed_keys_for(dev.id),
            "approved_by": row["approved_by"],
            "anchors": json.loads(row["anchors"]) if row["anchors"] else [],
            "anchors_signature": b64encode(row["anchors_signature"] or b"")}


def revoked_status(device_id: str) -> str:
    """Where a device stands: "active", "denied" (its join was turned down),
    "removed" (its member was removed) or "revoked" (just this device)."""
    with db() as conn:
        r = conn.execute(
            "SELECT d.status, d.revoked_reason, d.approved_by, m.status AS member_status"
            " FROM devices d JOIN members m ON m.id = d.member_id WHERE d.id = ?",
            (device_id,),
        ).fetchone()
    if r is None:
        return "revoked"
    if r["status"] == "active" and r["member_status"] == "active":
        return "active"
    if r["revoked_reason"] == "denied" or (r["revoked_reason"] is None and r["approved_by"] is None):
        return "denied"
    if r["member_status"] == "removed" or r["revoked_reason"] == "removed":
        return "removed"
    return "revoked"


def last_seq(conn: sqlite3.Connection, group_id: str) -> int:
    """The highest event seq issued in this group (pruning doesn't lower it)."""
    return conn.execute("SELECT event_seq FROM groups WHERE id = ?", (group_id,)).fetchone()[0]


def group_row(conn: sqlite3.Connection, group_id: str) -> sqlite3.Row:
    return conn.execute(
        "SELECT key_version, pruned_through, rotation_pending FROM groups WHERE id = ?", (group_id,)
    ).fetchone()


def sealed_keys_for(device_id: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT k.key_version, k.sealed_blob, k.signature, k.signer_device_id,"
            " s.sign_pubkey AS signer_sign_pubkey, s.enc_pubkey AS signer_enc_pubkey,"
            " m.display_name AS signer_name"
            " FROM sealed_keys k LEFT JOIN devices s ON s.id = k.signer_device_id"
            " LEFT JOIN members m ON m.id = s.member_id"
            " WHERE k.device_id = ? ORDER BY k.key_version",
            (device_id,),
        ).fetchall()
    return [
        {
            "key_version": r["key_version"],
            "sealed_blob": b64encode(r["sealed_blob"]),
            "signature": b64encode(r["signature"] or b""),
            "signer_device_id": r["signer_device_id"],
            "signer_sign_pubkey": b64encode(r["signer_sign_pubkey"] or b""),
            "signer_enc_pubkey": b64encode(r["signer_enc_pubkey"] or b""),
            "signer_name": r["signer_name"],
        }
        for r in rows
    ]


@api.get("/keys")
def get_keys(dev: Device = Depends(current_device)):
    """This device's sealed group keys (every version), the group's current key
    version, and whether a removal is still waiting for a Key Master to rotate."""
    with db() as conn:
        g = group_row(conn, dev.group_id)
    return {"sealed_keys": sealed_keys_for(dev.id), "key_version": g["key_version"],
            "rotation_pending": bool(g["rotation_pending"])}


@api.post("/keys/rotate")
def rotate_keys(body: RotateIn, km: Device = Depends(keymaster_device)):
    """A Key Master uploads a new group key version, sealed to every active
    device (its own included) and signed per device. The server checks the
    version is the next one and that the set of devices is exactly the active
    ones, so nobody is quietly left out or added."""
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = group_row(conn, km.group_id)["key_version"]
        if body.key_version != cur + 1:
            raise HTTPException(409, f"the group key is at version {cur}; the next one is {cur + 1}")
        want = set(active_device_ids(conn, km.group_id))
        got = [k.device_id for k in body.sealed_keys]
        if len(set(got)) != len(got):
            raise HTTPException(422, "more than one key for the same device")
        if set(got) != want:
            missing, extra = sorted(want - set(got)), sorted(set(got) - want)
            raise HTTPException(422, {"error": "the new key must be sealed to exactly the active devices",
                                      "missing": missing, "not_active": extra})
        for k in body.sealed_keys:
            conn.execute(
                "INSERT INTO sealed_keys (group_id, device_id, key_version, sealed_blob, signature, signer_device_id)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (km.group_id, k.device_id, body.key_version, b64decode(k.sealed_blob, "sealed_blob"),
                 b64decode(k.signature, "signature"), km.id),
            )
        conn.execute("UPDATE groups SET key_version = ?, rotation_pending = 0 WHERE id = ?",
                     (body.key_version, km.group_id))
    push_key_rotated(km.group_id, body.key_version)
    return {"key_version": body.key_version, "devices": len(got)}


@api.get("/joins/pending")
def pending_joins(km: Device = Depends(keymaster_device)):
    with db() as conn:
        rows = conn.execute(
            "SELECT d.id, d.member_id, d.enc_pubkey, d.sign_pubkey, d.requested_at,"
            " m.display_name, m.email, m.role,"
            " (SELECT COUNT(*) FROM devices o WHERE o.member_id = d.member_id AND o.status = 'active')"
            "   AS active_devices"
            " FROM devices d JOIN members m ON m.id = d.member_id"
            " WHERE d.group_id = ? AND d.status = 'pending' ORDER BY d.requested_at",
            (km.group_id,),
        ).fetchall()
    return {
        "pending": [
            {
                "device_id": r["id"],
                "member_id": r["member_id"],
                "display_name": r["display_name"],
                "email": r["email"],
                "role": r["role"],
                "existing_member": r["active_devices"] > 0,
                "enc_pubkey": b64encode(r["enc_pubkey"]),
                "sign_pubkey": b64encode(r["sign_pubkey"]),
                "requested_at": r["requested_at"],
            }
            for r in rows
        ]
    }


def store_cert(conn: sqlite3.Connection, km: Device, cert: CertIn, role: str,
               allowed_status: tuple[str, ...] = ("active",)) -> None:
    """Check a certificate describes the device as the server knows it, then keep it."""
    row = conn.execute(
        "SELECT d.status, m.display_name FROM devices d JOIN members m ON m.id = d.member_id"
        " WHERE d.id = ? AND d.group_id = ?",
        (cert.device_id, km.group_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"no such device: {cert.device_id}")
    if row["status"] not in allowed_status:
        raise HTTPException(409, f"device {cert.device_id} is {row['status']}")
    if cert.role != role:
        raise HTTPException(422, f"certificate role {cert.role} doesn't match the member's role {role}")
    if cert.display_name != row["display_name"]:
        raise HTTPException(422, "certificate display_name doesn't match the member")
    conn.execute(
        "INSERT OR REPLACE INTO member_certs"
        " (group_id, device_id, issuer_device_id, role, display_name, signature, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (km.group_id, cert.device_id, km.id, cert.role, cert.display_name,
         b64decode(cert.signature, "signature"), now()),
    )


def member_role_of(conn: sqlite3.Connection, device_id: str) -> str:
    row = conn.execute(
        "SELECT m.role FROM devices d JOIN members m ON m.id = d.member_id WHERE d.id = ?", (device_id,)
    ).fetchone()
    return row["role"] if row else ""


def pending_device(conn: sqlite3.Connection, device_id: str, group_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT id, member_id, status FROM devices WHERE id = ? AND group_id = ?",
        (device_id, group_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "no such device")
    if row["status"] != "pending":
        raise HTTPException(409, f"device is {row['status']}, not pending")
    return row


@api.post("/joins/{device_id}/approve")
def approve_join(device_id: str, body: ApproveIn, km: Device = Depends(keymaster_device)):
    versions = [k.key_version for k in body.sealed_keys]
    if len(set(versions)) != len(versions):
        raise HTTPException(422, "duplicate key_version")
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        pending_device(conn, device_id, km.group_id)
        cur = group_row(conn, km.group_id)["key_version"]
        if cur not in versions:
            raise HTTPException(409, f"include the current group key (version {cur}); fetch GET /keys first")
        if body.cert.device_id != device_id:
            raise HTTPException(422, "certificate is for a different device")
        store_cert(conn, km, body.cert, member_role_of(conn, device_id), allowed_status=("pending",))
        conn.execute(
            "UPDATE devices SET anchors = ?, anchors_signature = ? WHERE id = ?",
            (json.dumps([a.model_dump() for a in body.anchors]),
             b64decode(body.anchors_signature, "anchors_signature"), device_id),
        )
        for k in body.sealed_keys:
            conn.execute(
                "INSERT OR REPLACE INTO sealed_keys"
                " (group_id, device_id, key_version, sealed_blob, signature, signer_device_id)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (km.group_id, device_id, k.key_version, b64decode(k.sealed_blob, "sealed_blob"),
                 b64decode(k.signature, "signature"), km.id),
            )
        conn.execute(
            "UPDATE devices SET status = 'active', approved_by = ? WHERE id = ?", (km.id, device_id)
        )
    return {"device_id": device_id, "status": "active", "key_versions": sorted(versions)}


@api.post("/joins/{device_id}/deny")
def deny_join(device_id: str, km: Device = Depends(keymaster_device)):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = pending_device(conn, device_id, km.group_id)
        # The token stays on file only so /join/status can report the denial;
        # every other endpoint requires an active device.
        conn.execute("UPDATE devices SET status = 'revoked', revoked_reason = 'denied', revoked_at = ?"
                     " WHERE id = ?", (now(), device_id))
        others = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE member_id = ? AND status != 'revoked'",
            (row["member_id"],),
        ).fetchone()[0]
        if others == 0:
            conn.execute("UPDATE members SET status = 'removed' WHERE id = ?", (row["member_id"],))
    return {"device_id": device_id, "status": "denied"}


@api.get("/members")
def members(dev: Device = Depends(current_device)):
    """The roster as the server sees it. Clients must verify each device's
    certificates (crypto::roster) and ignore anything that doesn't verify."""
    with db() as conn:
        rows = conn.execute(
            "SELECT m.id AS member_id, m.display_name, m.role, d.id AS device_id, d.enc_pubkey, d.sign_pubkey,"
            " d.last_seen, d.requested_at"
            " FROM members m JOIN devices d ON d.member_id = m.id"
            " WHERE m.group_id = ? AND m.status = 'active' AND d.status = 'active'"
            " ORDER BY m.created_at, d.requested_at",
            (dev.group_id,),
        ).fetchall()
        certs: dict[str, list[dict]] = {}
        for c in conn.execute(
            "SELECT device_id, issuer_device_id, role, display_name, signature FROM member_certs"
            " WHERE group_id = ? ORDER BY created_at",
            (dev.group_id,),
        ):
            certs.setdefault(c["device_id"], []).append({
                "issuer_device_id": c["issuer_device_id"], "role": c["role"],
                "display_name": c["display_name"], "signature": b64encode(c["signature"]),
            })
    out: dict[str, dict] = {}
    for r in rows:
        m = out.setdefault(r["member_id"], {"id": r["member_id"], "display_name": r["display_name"],
                                            "role": r["role"], "devices": []})
        d = {"id": r["device_id"], "enc_pubkey": b64encode(r["enc_pubkey"]),
             "sign_pubkey": b64encode(r["sign_pubkey"]), "certs": certs.get(r["device_id"], [])}
        if dev.role == "keymaster":
            # Activity is only shown to the people who manage devices.
            d["last_seen"], d["joined_at"] = r["last_seen"], r["requested_at"]
        m["devices"].append(d)
    # Devices revoked (or whose member was removed) while some of their events
    # may still be on the server: clients accept those events up to revoked_seq,
    # so a device that syncs late doesn't drop posts made before the removal.
    with db() as conn:
        former_rows = conn.execute(
            "SELECT m.id AS member_id, m.display_name, d.id AS device_id, d.enc_pubkey, d.sign_pubkey, d.revoked_seq"
            " FROM devices d JOIN members m ON m.id = d.member_id JOIN groups g ON g.id = d.group_id"
            " WHERE d.group_id = ? AND d.status = 'revoked' AND d.revoked_seq > g.pruned_through"
            " ORDER BY d.revoked_at",
            (dev.group_id,),
        ).fetchall()
    former: dict[str, dict] = {}
    for r in former_rows:
        m = former.setdefault(r["member_id"], {"id": r["member_id"], "display_name": r["display_name"], "devices": []})
        m["devices"].append({"id": r["device_id"], "enc_pubkey": b64encode(r["enc_pubkey"]),
                             "sign_pubkey": b64encode(r["sign_pubkey"]), "certs": certs.get(r["device_id"], []),
                             "revoked_seq": r["revoked_seq"]})
    return {"members": list(out.values()), "former": list(former.values())}


@api.post("/certs")
def add_certs(body: CertsIn, km: Device = Depends(keymaster_device)):
    """A Key Master certifies active devices at their current role (its own,
    after creating the group, or devices approved before certificates existed)."""
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        for c in body.certs:
            store_cert(conn, km, c, member_role_of(conn, c.device_id))
    return {"stored": len(body.certs)}


@api.post("/members/{member_id}/role")
def set_role(member_id: str, body: RoleIn, km: Device = Depends(keymaster_device)):
    """Promote a member to Key Master. Needs a keymaster certificate, signed by
    the calling Key Master, for every active device of that member."""
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        m = conn.execute(
            "SELECT role FROM members WHERE id = ? AND group_id = ? AND status = 'active'",
            (member_id, km.group_id),
        ).fetchone()
        if m is None:
            raise HTTPException(404, "no such member")
        if m["role"] == body.role:
            raise HTTPException(409, f"already {body.role}")
        devices = {r["id"] for r in conn.execute(
            "SELECT id FROM devices WHERE member_id = ? AND status = 'active'", (member_id,))}
        if {c.device_id for c in body.certs} != devices:
            raise HTTPException(422, "need exactly one certificate per active device of the member")
        for c in body.certs:
            store_cert(conn, km, c, body.role)
        conn.execute("UPDATE members SET role = ? WHERE id = ?", (body.role, member_id))
    return {"member_id": member_id, "role": body.role}


@api.post("/members/{member_id}/remove")
def remove_member(member_id: str, km: Device = Depends(keymaster_device)):
    """Remove a member: every one of their devices is revoked at once (tokens
    stop working, sockets get `removed`). The group key still has to be rotated
    by a Key Master's app; until then GET /keys says rotation_pending."""
    t = now()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        m = conn.execute(
            "SELECT status FROM members WHERE id = ? AND group_id = ?", (member_id, km.group_id)
        ).fetchone()
        if m is None:
            raise HTTPException(404, "no such member")
        if m["status"] != "active":
            raise HTTPException(409, "already removed")
        if member_id == km.member_id:
            raise HTTPException(409, "you can't remove yourself; ask another Key Master")
        devices = [r["id"] for r in conn.execute(
            "SELECT id FROM devices WHERE member_id = ? AND status IN ('active', 'pending')", (member_id,))]
        had_active = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE member_id = ? AND status = 'active'", (member_id,)
        ).fetchone()[0]
        conn.execute("UPDATE members SET status = 'removed' WHERE id = ?", (member_id,))
        conn.execute(
            "UPDATE devices SET revoked_seq = ? WHERE member_id = ? AND status = 'active'",
            (last_seq(conn, km.group_id), member_id),
        )
        conn.execute(
            "UPDATE devices SET status = 'revoked', revoked_reason = 'removed', revoked_at = ?"
            " WHERE member_id = ? AND status IN ('active', 'pending')",
            (t, member_id),
        )
        if had_active:
            conn.execute("UPDATE groups SET rotation_pending = 1 WHERE id = ?", (km.group_id,))
    push_removed(devices, "member")
    return {"member_id": member_id, "status": "removed", "revoked_devices": devices,
            "rotation_pending": bool(had_active)}


@api.post("/devices/{device_id}/revoke")
def revoke_device(device_id: str, km: Device = Depends(keymaster_device)):
    """Revoke one device (say, a lost laptop). Its member stays in the group.
    Like a removal, the group key then needs rotating."""
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        d = conn.execute(
            "SELECT status FROM devices WHERE id = ? AND group_id = ?", (device_id, km.group_id)
        ).fetchone()
        if d is None:
            raise HTTPException(404, "no such device")
        if d["status"] == "pending":
            raise HTTPException(409, "that device is still waiting to join; deny it instead")
        if d["status"] != "active":
            raise HTTPException(409, "already revoked")
        if device_id == km.id:
            raise HTTPException(409, "you can't revoke the device you're using")
        conn.execute("UPDATE devices SET status = 'revoked', revoked_reason = 'revoked', revoked_at = ?,"
                     " revoked_seq = ? WHERE id = ?", (now(), last_seq(conn, km.group_id), device_id))
        conn.execute("UPDATE groups SET rotation_pending = 1 WHERE id = ?", (km.group_id,))
    push_removed([device_id], "device")
    return {"device_id": device_id, "status": "revoked", "rotation_pending": True}


@api.post("/events", status_code=201)
def post_event(ev: EventIn, dev: Device = Depends(current_device)):
    limit(event_limit, dev.id, "events from this device")
    with db() as conn:
        cur = group_row(conn, dev.group_id)["key_version"]
        if ev.key_version < cur:
            # After a rotation, nothing new may use a key a removed member holds.
            raise HTTPException(409, f"key_version {ev.key_version} is out of date; the group key is at"
                                     f" version {cur} (fetch GET /keys)")
        if ev.key_version > cur:
            raise HTTPException(422, f"no group key version {ev.key_version} yet")
        for mid in ev.media_ids:
            if not conn.execute(
                "SELECT 1 FROM media WHERE id = ? AND group_id = ?", (mid, dev.group_id)
            ).fetchone():
                raise HTTPException(422, f"unknown media id: {mid}")
        cur = conn.execute(
            "INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext, signature, media_ids, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dev.group_id,
                ev.kind,
                dev.id,
                ev.key_version,
                b64decode(ev.ciphertext, "ciphertext"),
                b64decode(ev.signature, "signature"),
                ",".join(ev.media_ids),
                now(),
            ),
        )
        seq = conn.execute("SELECT gseq FROM events WHERE seq = ?", (cur.lastrowid,)).fetchone()[0]
    # After the commit, so a device that syncs on this push finds the event.
    push_new_event(dev.group_id, dev.id, seq, ev.kind)
    return {"seq": seq}


@api.get("/events")
def get_events(
    after: int = Query(0, ge=0),
    limit: int = Query(PAGE_SIZE, ge=1, le=PAGE_SIZE),
    dev: Device = Depends(current_device),
):
    with db() as conn:
        rows = conn.execute(
            "SELECT gseq AS seq, kind, author_device_id, key_version, ciphertext, signature, media_ids, created_at"
            " FROM events WHERE group_id = ? AND gseq > ? ORDER BY gseq LIMIT ?",
            (dev.group_id, after, limit + 1),
        ).fetchall()
        g = group_row(conn, dev.group_id)
    more = len(rows) > limit
    rows = rows[:limit]
    events = [
        {
            "seq": r["seq"],
            "kind": r["kind"],
            "author_device_id": r["author_device_id"],
            "key_version": r["key_version"],
            "ciphertext": b64encode(r["ciphertext"]),
            "signature": b64encode(r["signature"]),
            "media_ids": [m for m in r["media_ids"].split(",") if m],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return {
        "events": events,
        "last_seq": events[-1]["seq"] if events else after,
        "has_more": more,
        # A cursor below pruned_through means events this device never got were deleted.
        "pruned_through": g["pruned_through"],
        "retention_days": RETENTION_DAYS,
        "key_version": g["key_version"],
    }


@api.post("/ack")
def ack(body: AckIn, dev: Device = Depends(current_device)):
    with db() as conn:
        ceiling = last_seq(conn, dev.group_id)
        if body.seq > ceiling:
            raise HTTPException(422, f"seq {body.seq} is beyond the latest event ({ceiling})")
        # Acks only move forward.
        conn.execute(
            "INSERT INTO acks (group_id, device_id, last_seq, updated_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(device_id) DO UPDATE SET"
            " last_seq = MAX(acks.last_seq, excluded.last_seq), updated_at = excluded.updated_at",
            (dev.group_id, dev.id, body.seq, now()),
        )
        last = conn.execute("SELECT last_seq FROM acks WHERE device_id = ?", (dev.id,)).fetchone()[0]
    return {"last_seq": last}


@api.post("/media", status_code=201)
async def upload_media(request: Request, dev: Device = Depends(current_device)):
    declared = request.headers.get("content-length")
    if declared and int(declared) > MAX_MEDIA_BYTES:
        raise HTTPException(413, f"media larger than {MAX_MEDIA_BYTES} bytes")
    hourly = f"uploads from this device (limit {MEDIA_BYTES_PER_HOUR // (1024 * 1024)} MB per hour)"
    if media_limit.room(dev.id) < max(int(declared or 0), 1):
        limit(media_limit, dev.id, hourly, max(int(declared or 0), 1))  # raises 429 with Retry-After
    media_id = secrets.token_urlsafe(16)
    group_dir = MEDIA_DIR / dev.group_id
    group_dir.mkdir(parents=True, exist_ok=True)
    final = group_dir / media_id
    tmp = group_dir / f".{media_id}.part"
    size = 0
    try:
        with tmp.open("wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_MEDIA_BYTES:
                    raise HTTPException(413, f"media larger than {MAX_MEDIA_BYTES} bytes")
                f.write(chunk)
        if size == 0:
            raise HTTPException(422, "empty body")
        limit(media_limit, dev.id, hourly, size)
        tmp.rename(final)
    finally:
        tmp.unlink(missing_ok=True)
    with db() as conn:
        conn.execute(
            "INSERT INTO media (id, group_id, uploader_device_id, size_bytes, path, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (media_id, dev.group_id, dev.id, size, str(final.relative_to(MEDIA_DIR)), now()),
        )
    return {"id": media_id, "size_bytes": size}


@api.get("/media/{media_id}")
def download_media(media_id: str, dev: Device = Depends(current_device)):
    with db() as conn:
        row = conn.execute(
            "SELECT path FROM media WHERE id = ? AND group_id = ?", (media_id, dev.group_id)
        ).fetchone()
    if row is None:
        raise HTTPException(404, "media not found")
    return FileResponse(MEDIA_DIR / row["path"], media_type="application/octet-stream")


@api.websocket("/ws")
async def ws(websocket: WebSocket):
    """Push channel. Authenticated like every other call, with
    `Authorization: Bearer <device token>` on the upgrade request; an unknown
    or non-active token gets HTTP 403 instead of a socket.

    Server -> client, JSON text frames:
      {"type": "hello", "device_id"}            once, on connect
      {"type": "new_event", "seq", "kind"}      someone else appended an event
      {"type": "join_request", "device_id", "display_name", "existing_member"}  Key Masters only
      {"type": "key_rotated", "key_version"}    fetch GET /keys
      {"type": "removed", "scope"}              this device was revoked ("device") or its
                                                member removed ("member"); the socket closes
      {"type": "pong"}                          reply to a ping
    Client -> server: {"type": "ping"} at least every WS_IDLE_SECONDS.
    """
    try:
        dev = await run_in_threadpool(device_for_token, websocket.headers.get("authorization"))
    except HTTPException:
        await websocket.close(code=1008)
        return
    if dev.status != "active" or hub.count(dev.id) >= MAX_SOCKETS_PER_DEVICE:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=WS_QUEUE)
    hub.attach(dev.id, q)

    async def reader():
        while True:
            try:
                text = await asyncio.wait_for(websocket.receive_text(), WS_IDLE_SECONDS)
            except (asyncio.TimeoutError, WebSocketDisconnect, RuntimeError, KeyError):
                return
            try:
                kind = json.loads(text).get("type")
            except (ValueError, AttributeError):
                continue
            if kind == "ping":
                # Notice revocation even if nobody calls push_removed.
                st = await run_in_threadpool(revoked_status, dev.id)
                if st != "active":
                    push_removed([dev.id], "member" if st == "removed" else "device")
                    continue
                try:
                    q.put_nowait('{"type":"pong"}')
                except asyncio.QueueFull:
                    return

    async def writer():
        while True:
            data = await q.get()
            if data is None:
                return
            await websocket.send_text(data)

    try:
        await websocket.send_text(json.dumps({"type": "hello", "device_id": dev.id}))
        tasks = {asyncio.create_task(reader()), asyncio.create_task(writer())}
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for t in done:
            t.exception()  # retrieve, so a dropped connection isn't logged as unhandled
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.detach(dev.id, q)
        try:
            await websocket.close()
        except (RuntimeError, WebSocketDisconnect):
            pass  # already closed


app.include_router(api)
