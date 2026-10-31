"""Phase 6b server side: several groups per server, setup tokens, isolation,
per-group event numbers (and the migration to them), and rate limits.

Run from server/:  python -m unittest discover tests   (needs httpx for TestClient)
"""

import base64
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware  # noqa: E402


def key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


class Base(unittest.TestCase):
    env: dict = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        self._saved = {k: os.environ.get(k) for k in ["SIDETRAY_SETUP_TOKEN", *self.env]}
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        os.environ.update(self.env)
        import app.main as main
        self.m = importlib.reload(main)
        self.m.init_db()
        # As uvicorn runs it behind Caddy (--proxy-headers --forwarded-allow-ips "*").
        self.c = TestClient(ProxyHeadersMiddleware(self.m.app, trusted_hosts="*"))

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def join(self, group, name, setup_token=None, ip="10.0.0.1"):
        body = {"group_name": group, "display_name": name, "email": f"{name}@x.test",
                "enc_pubkey": key(), "sign_pubkey": key()}
        if setup_token is not None:
            body["setup_token"] = setup_token
        return self.c.post("/api/v1/join", json=body, headers={"X-Forwarded-For": ip})

    def found(self, group, token):
        r = self.join(group, f"km-{group}", token)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def auth(self, tok):
        return {"Authorization": f"Bearer {tok}"}

    def post(self, tok):
        return self.c.post("/api/v1/events", headers=self.auth(tok),
                           json={"kind": "post", "key_version": 1, "ciphertext": "eA==", "signature": "eA=="})


class GroupsTest(Base):
    def test_env_token_only_for_the_first_group(self):
        self.assertEqual(self.join("A", "x", "wrong").status_code, 403)
        self.found("Alpha", "env-token")
        self.assertEqual(self.join("Beta", "y", "env-token").status_code, 403)

    def test_one_time_tokens(self):
        self.found("Alpha", "env-token")
        tok, _ = self.m.issue_setup_token()
        self.assertTrue(tok.startswith("st_"))
        self.assertEqual(self.join("alpha", "y", tok).status_code, 409)  # names unique, any case
        self.assertEqual(self.join("ALPHA ", "y", tok).status_code, 409)
        b = self.found("Beta", tok)
        self.assertEqual(b["role"], "keymaster")
        self.assertEqual(self.join("Gamma", "z", tok).status_code, 403)  # used
        old, _ = self.m.issue_setup_token(days=-1)
        self.assertEqual(self.join("Gamma", "z", old).status_code, 403)  # expired
        with self.m.db() as conn:
            row = conn.execute("SELECT group_id, used_at FROM setup_tokens WHERE group_id IS NOT NULL").fetchone()
        self.assertEqual(row["group_id"], b["group_id"])

    def test_group_lookup_needs_a_name(self):
        self.found("Smith Family", "env-token")
        self.assertEqual(self.c.get("/api/v1/group").status_code, 400)
        self.assertEqual(self.c.get("/api/v1/group?name=").status_code, 400)
        self.assertEqual(self.c.get("/api/v1/group", params={"name": "smith  family"}).json(),
                         {"exists": True, "name": "Smith Family"})
        self.assertEqual(self.c.get("/api/v1/group", params={"name": "Jones"}).json(), {"exists": False})

    def test_groups_are_isolated(self):
        a = self.found("Alpha", "env-token")
        b = self.found("Beta", self.m.issue_setup_token()[0])
        ta, tb = a["token"], b["token"]
        # Joining by name lands in that group only.
        pa = self.join("Alpha", "pal").json()
        self.assertEqual(pa["group_id"], a["group_id"])
        self.assertEqual(self.c.get("/api/v1/joins/pending", headers=self.auth(tb)).json(), {"pending": []})
        r = self.c.post(f"/api/v1/joins/{pa['device_id']}/deny", headers=self.auth(tb))
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.c.post(f"/api/v1/members/{a['member_id']}/remove", headers=self.auth(tb)).status_code, 404)
        self.assertEqual(self.c.post(f"/api/v1/devices/{a['device_id']}/revoke", headers=self.auth(tb)).status_code, 404)
        # Events: numbered per group, and each sees only its own.
        self.assertEqual([self.post(ta).json()["seq"] for _ in range(3)], [1, 2, 3])
        self.assertEqual(self.post(tb).json()["seq"], 1)
        eb = self.c.get("/api/v1/events", headers=self.auth(tb)).json()
        self.assertEqual([e["seq"] for e in eb["events"]], [1])
        self.assertEqual(self.c.post("/api/v1/ack", headers=self.auth(tb), json={"seq": 3}).status_code, 422)
        # Media
        mid = self.c.post("/api/v1/media", headers=self.auth(ta), content=b"blob").json()["id"]
        self.assertEqual(self.c.get(f"/api/v1/media/{mid}", headers=self.auth(tb)).status_code, 404)
        r = self.c.post("/api/v1/events", headers=self.auth(tb), json={
            "kind": "post", "key_version": 1, "ciphertext": "eA==", "signature": "eA==", "media_ids": [mid]})
        self.assertEqual(r.status_code, 422)
        # Roster
        names = [m["display_name"] for m in self.c.get("/api/v1/members", headers=self.auth(tb)).json()["members"]]
        self.assertEqual(names, ["km-Beta"])

    def test_prune_per_group(self):
        a = self.found("Alpha", "env-token")
        b = self.found("Beta", self.m.issue_setup_token()[0])
        for _ in range(2):
            self.post(a["token"])
        self.post(b["token"])
        self.c.post("/api/v1/ack", headers=self.auth(a["token"]), json={"seq": 2})
        self.assertEqual(self.m.prune()["events"], 2)
        self.assertEqual(len(self.c.get("/api/v1/events", headers=self.auth(b["token"])).json()["events"]), 1)
        self.assertEqual(self.post(a["token"]).json()["seq"], 3)  # numbers never go back


class MigrationTest(unittest.TestCase):
    def test_existing_events_keep_their_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["SIDETRAY_DATA"] = d
            # A Phase 6 database: one group, global seq, the first two events pruned.
            conn = sqlite3.connect(Path(d) / "sidetray.db")
            conn.executescript("""
                CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
                CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL,
                    kind TEXT NOT NULL, author_device_id TEXT NOT NULL, key_version INTEGER NOT NULL,
                    ciphertext BLOB NOT NULL, signature BLOB NOT NULL, media_ids TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL);
                INSERT INTO groups VALUES ('g_1', 'Family', 1);
            """)
            for _ in range(5):
                conn.execute("INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext,"
                             " signature, created_at) VALUES ('g_1', 'post', 'd', 1, x'00', x'00', 1)")
            conn.execute("DELETE FROM events WHERE seq > 3")  # pruned: high-water mark stays 5
            conn.commit()
            conn.close()
            import app.main as main
            m = importlib.reload(main)
            m.init_db()
            m.init_db()  # idempotent
            with m.db() as c:
                self.assertEqual([r[0] for r in c.execute("SELECT gseq FROM events ORDER BY seq")], [1, 2, 3])
                self.assertEqual(m.last_seq(c, "g_1"), 5)
                c.execute("INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext,"
                          " signature, created_at) VALUES ('g_1', 'post', 'd', 1, x'00', x'00', 1)")
                self.assertEqual(c.execute("SELECT MAX(gseq) FROM events").fetchone()[0], 6)
                self.assertEqual(c.execute("SELECT name_key FROM groups").fetchone()[0], "family")


class LimitsTest(Base):
    env = {"SIDETRAY_MEDIA_MB_PER_HOUR": "1", "SIDETRAY_JOINS_PER_HOUR": "3", "SIDETRAY_LOOKUPS_PER_HOUR": "2"}

    def test_limiter(self):
        lim = self.m.Limiter(10, 60)
        self.assertIsNone(lim.take("k", 6))
        self.assertEqual(lim.room("k"), 4)
        self.assertIsNotNone(lim.take("k", 5))
        self.assertIsNone(lim.take("k", 4))
        self.assertEqual(lim.take("k", 11), 60)
        self.assertIsNone(lim.take("other", 10))

    def test_events_per_device(self):
        a = self.found("Alpha", "env-token")
        codes = [self.post(a["token"]).status_code for _ in range(31)]
        self.assertEqual(codes, [201] * 30 + [429])
        r = self.post(a["token"])
        self.assertTrue(1 <= int(r.headers["Retry-After"]) <= 60)

    def test_media_per_device(self):
        a = self.found("Alpha", "env-token")
        h = self.auth(a["token"])
        half = b"x" * (512 * 1024)
        self.assertEqual([self.c.post("/api/v1/media", headers=h, content=half).status_code for _ in range(3)],
                         [201, 201, 429])
        self.assertEqual(len(list((self.m.MEDIA_DIR / a["group_id"]).iterdir())), 2)  # nothing half-stored

    def test_joins_per_ip(self):
        self.found("Alpha", "env-token")  # 10.0.0.1: 1
        self.assertEqual(self.join("Alpha", "a").status_code, 201)
        self.assertEqual(self.join("Nope", "b").status_code, 404)  # wrong names count too
        self.assertEqual(self.join("Alpha", "c").status_code, 429)
        self.assertEqual(self.join("Alpha", "d", ip="10.0.0.2").status_code, 201)

    def test_lookups_per_ip(self):
        g = lambda: self.c.get("/api/v1/group", params={"name": "x"}).status_code  # noqa: E731
        self.assertEqual([g(), g(), g()], [200, 200, 429])


if __name__ == "__main__":
    unittest.main()
