"""Side Tray relay.

Thin relay: stores ciphertext and routing metadata, never decrypts.
Every device has its own bearer token, issued at join and stored hashed.
The first device creates the group with the operator's setup token and
becomes its Key Master; later devices wait as `pending` until a Key Master
approves them and uploads the group key sealed (and signed) to them.
"""

import base64
import binascii
import hashlib
import json
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
# Operator secret that allows creating the group; unset means no group can be created.
SETUP_TOKEN = os.environ.get("SIDETRAY_SETUP_TOKEN", "")
MAX_MEDIA_BYTES = int(os.environ.get("SIDETRAY_MAX_MEDIA_BYTES", 10 * 1024 * 1024))
PAGE_SIZE = 500
MAX_PENDING = 20
KEY_LEN = 32

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
        drop_legacy_test_group(conn)


def the_group(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """The MVP has one group per server."""
    return conn.execute("SELECT id, name FROM groups ORDER BY created_at LIMIT 1").fetchone()


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
    yield


app = FastAPI(title="Side Tray relay", version="0.3.0", docs_url=None, redoc_url=None, lifespan=lifespan)
api = APIRouter(prefix="/api/v1")


@api.get("/health")
def health():
    return {"ok": True}


@api.get("/group")
def get_group():
    with db() as conn:
        g = the_group(conn)
    return {"exists": True, "id": g["id"], "name": g["name"]} if g else {"exists": False}


@api.post("/join", status_code=201)
def join(body: JoinIn):
    enc_pk = pubkey(body.enc_pubkey, "enc_pubkey")
    sign_pk = pubkey(body.sign_pubkey, "sign_pubkey")
    token = secrets.token_urlsafe(32)
    t = now()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        g = the_group(conn)
        if g is None:
            # Creating the group: the operator's setup token makes this device its Key Master.
            if not SETUP_TOKEN or not body.setup_token or not secrets.compare_digest(
                body.setup_token, SETUP_TOKEN
            ):
                raise HTTPException(403, "no group yet; creating one needs the server's setup token")
            group_id, member_id, device_id = new_id("g"), new_id("m"), new_id("d")
            conn.execute(
                "INSERT INTO groups (id, name, created_at) VALUES (?, ?, ?)",
                (group_id, body.group_name, t),
            )
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

        if body.setup_token is not None:
            raise HTTPException(409, "the group already exists; join it instead")
        if body.group_name.casefold() != g["name"].casefold():
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
    # TODO(Phase 4): push join_request to online Key Masters over /ws.
    return {"group_id": g["id"], "group_name": g["name"], "member_id": member_id,
            "device_id": device_id, "token": token, "status": "pending", "role": role}


@api.get("/join/status")
def join_status(dev: Device = Depends(any_device)):
    if dev.status == "pending":
        return {"status": "pending", "device_id": dev.id}
    if dev.status != "active":
        return {"status": "denied", "device_id": dev.id}
    with db() as conn:
        row = conn.execute(
            "SELECT approved_by, anchors, anchors_signature FROM devices WHERE id = ?", (dev.id,)
        ).fetchone()
    return {"status": "active", "device_id": dev.id, "member_id": dev.member_id,
            "role": dev.role, "sealed_keys": sealed_keys_for(dev.id),
            "approved_by": row["approved_by"],
            "anchors": json.loads(row["anchors"]) if row["anchors"] else [],
            "anchors_signature": b64encode(row["anchors_signature"] or b"")}


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
    return {"sealed_keys": sealed_keys_for(dev.id)}


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
        conn.execute("UPDATE devices SET status = 'revoked' WHERE id = ?", (device_id,))
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
            "SELECT m.id AS member_id, m.display_name, m.role, d.id AS device_id, d.enc_pubkey, d.sign_pubkey"
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
        m["devices"].append({"id": r["device_id"], "enc_pubkey": b64encode(r["enc_pubkey"]),
                             "sign_pubkey": b64encode(r["sign_pubkey"]),
                             "certs": certs.get(r["device_id"], [])})
    return {"members": list(out.values())}


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
