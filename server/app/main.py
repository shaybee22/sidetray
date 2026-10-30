"""Side Tray relay — Phase 1 skeleton.

Thin relay: stores ciphertext and routing metadata, never decrypts.
Phase 1 auth is a single hardcoded test token bound to a seeded test device.
"""

import base64
import binascii
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

DATA_DIR = Path(os.environ.get("SIDETRAY_DATA", "./data"))
DB_PATH = DATA_DIR / "sidetray.db"
MEDIA_DIR = DATA_DIR / "media"
TEST_TOKEN = os.environ.get("SIDETRAY_TEST_TOKEN", "sidetray-test-token")
MAX_MEDIA_BYTES = int(os.environ.get("SIDETRAY_MAX_MEDIA_BYTES", 10 * 1024 * 1024))
PAGE_SIZE = 500

# Fixed ids for the seeded Phase 1 group/member/device.
TEST_GROUP_ID = "g_test"
TEST_MEMBER_ID = "m_test"
TEST_DEVICE_ID = "d_test"

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
CREATE TABLE IF NOT EXISTS acks (
    group_id   TEXT NOT NULL REFERENCES groups(id),
    device_id  TEXT PRIMARY KEY REFERENCES devices(id),
    last_seq   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


def now() -> int:
    return int(time.time())


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


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        # Phase 1 seed: one group, one member, one active device holding the test token.
        t = now()
        conn.execute(
            "INSERT OR IGNORE INTO groups (id, name, created_at) VALUES (?, ?, ?)",
            (TEST_GROUP_ID, "Test Group", t),
        )
        conn.execute(
            "INSERT OR IGNORE INTO members (id, group_id, display_name, email, role, status, created_at)"
            " VALUES (?, ?, 'Test Device', 'test@example.invalid', 'keymaster', 'active', ?)",
            (TEST_MEMBER_ID, TEST_GROUP_ID, t),
        )
        conn.execute(
            "INSERT OR IGNORE INTO devices (id, group_id, member_id, status, token_hash, last_seen)"
            " VALUES (?, ?, ?, 'active', ?, NULL)",
            (TEST_DEVICE_ID, TEST_GROUP_ID, TEST_MEMBER_ID, hash_token(TEST_TOKEN)),
        )
        # Keep the seeded device's token in sync with the configured test token.
        conn.execute(
            "UPDATE devices SET token_hash = ? WHERE id = ?",
            (hash_token(TEST_TOKEN), TEST_DEVICE_ID),
        )


class Device(BaseModel):
    id: str
    group_id: str
    member_id: str


def current_device(authorization: str | None = Header(default=None)) -> Device:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:].strip()
    with db() as conn:
        row = conn.execute(
            "SELECT id, group_id, member_id FROM devices WHERE token_hash = ? AND status = 'active'",
            (hash_token(token),),
        ).fetchone()
        if row is None:
            raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
        conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now(), row["id"]))
    return Device(**dict(row))


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
    yield


app = FastAPI(title="Side Tray relay", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)
api = APIRouter(prefix="/api/v1")


@api.get("/health")
def health():
    return {"ok": True}


@api.post("/events", status_code=201)
def post_event(ev: EventIn, dev: Device = Depends(current_device)):
    with db() as conn:
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
        return {"seq": cur.lastrowid}


@api.get("/events")
def get_events(
    after: int = Query(0, ge=0),
    limit: int = Query(PAGE_SIZE, ge=1, le=PAGE_SIZE),
    dev: Device = Depends(current_device),
):
    with db() as conn:
        rows = conn.execute(
            "SELECT seq, kind, author_device_id, key_version, ciphertext, signature, media_ids, created_at"
            " FROM events WHERE group_id = ? AND seq > ? ORDER BY seq LIMIT ?",
            (dev.group_id, after, limit + 1),
        ).fetchall()
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
    }


@api.post("/ack")
def ack(body: AckIn, dev: Device = Depends(current_device)):
    with db() as conn:
        # sqlite_sequence holds the highest seq ever issued, even after pruning.
        hw = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'events'").fetchone()
        ceiling = hw[0] if hw else 0
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


app.include_router(api)
