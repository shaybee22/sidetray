"""Phase 6b-2 server side: `profile` events (and the table rebuild that allows
them on older databases), pruning that keeps each member's latest profile and
its avatar, and a Key Master accepting a member's new name.

Run from server/:  python -m unittest discover tests   (needs httpx for TestClient)
"""

import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DAY = 86400



class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def load(self):
        import app.main as main
        self.m = importlib.reload(main)
        self.m.init_db()


class MigrationTest(Base):
    def test_old_events_table_is_rebuilt_keeping_rows_and_counter(self):
        path = Path(self.tmp.name) / "sidetray.db"
        import app.main as main
        conn = sqlite3.connect(path)
        # The schema as it was before profile events.
        conn.executescript(main.SCHEMA.replace(", 'profile'", ""))
        conn.execute("INSERT INTO groups (id, name, created_at) VALUES ('g_1', 'G', 1)")
        conn.execute("INSERT INTO members VALUES ('m_a', 'g_1', 'A', 'a@x', 'member', 'active', 1)")
        conn.execute("INSERT INTO devices (id, group_id, member_id, status) VALUES ('a', 'g_1', 'm_a', 'active')")
        for _ in range(5):
            conn.execute("INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext, signature,"
                         " created_at) VALUES ('g_1', 'post', 'a', 1, x'01', x'02', 7)")
        conn.execute("DELETE FROM events WHERE seq > 3")  # pruned: the counter stays at 5
        conn.commit()
        conn.close()
        self.load()
        with self.m.db() as c:
            self.assertIn("'profile'", c.execute("SELECT sql FROM sqlite_master WHERE name = 'events'").fetchone()[0])
            self.assertEqual([tuple(r) for r in c.execute("SELECT seq, gseq FROM events ORDER BY seq")],
                             [(1, 1), (2, 2), (3, 3)])
            c.execute("INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext, signature,"
                      " created_at) VALUES ('g_1', 'profile', 'a', 1, x'01', x'02', 8)")
            row = c.execute("SELECT seq, gseq FROM events WHERE kind = 'profile'").fetchone()
            # Numbering continues from before the rebuild, through the recreated trigger.
            self.assertEqual(tuple(row), (6, 6))
        # A second start is a no-op.
        self.load()
        with self.m.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 4)


class PruneProfilesTest(Base):
    def setUp(self):
        super().setUp()
        self.load()
        self.t = 1_000 * DAY
        with self.m.db() as c:
            c.execute("INSERT INTO groups (id, name, created_at) VALUES ('g_1', 'G', 1)")
            for d, mstatus in [("a", "active"), ("b", "active"), ("out", "removed")]:
                c.execute("INSERT INTO members (id, group_id, display_name, email, role, status, created_at)"
                          " VALUES (?, 'g_1', ?, ?, 'member', ?, 1)", (f"m_{d}", d, f"{d}@x", mstatus))
                c.execute("INSERT INTO devices (id, group_id, member_id, status, token_hash)"
                          " VALUES (?, 'g_1', ?, ?, ?)", (d, f"m_{d}", "active" if mstatus == "active" else "revoked", d))

    def event(self, kind, author, age_days=0, media=()):
        with self.m.db() as c:
            for mid in media:
                (self.m.MEDIA_DIR / "g_1").mkdir(parents=True, exist_ok=True)
                (self.m.MEDIA_DIR / "g_1" / mid).write_bytes(b"x")
                c.execute("INSERT INTO media (id, group_id, uploader_device_id, size_bytes, path, created_at)"
                          " VALUES (?, 'g_1', ?, 1, ?, ?)", (mid, author, f"g_1/{mid}", self.t - age_days * DAY))
            return c.execute(
                "INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext, signature, media_ids,"
                " created_at) VALUES ('g_1', ?, ?, 1, x'00', x'00', ?, ?)",
                (kind, author, ",".join(media), self.t - age_days * DAY),
            ).lastrowid

    def test_latest_profile_and_avatar_survive_acks_and_retention(self):
        old_a = self.event("profile", "a", 200, ["av_old"])
        new_a = self.event("profile", "a", 120, ["av_new"])
        prof_b = self.event("profile", "b", 1)
        gone = self.event("profile", "out", 120, ["av_out"])
        post = self.event("post", "b", 100, ["photo"])
        with self.m.db() as c:
            for d in ("a", "b"):
                c.execute("INSERT INTO acks VALUES ('g_1', ?, ?, 1)", (d, post))
        self.m.prune(self.t)
        with self.m.db() as c:
            left = sorted(r[0] for r in c.execute("SELECT seq FROM events"))
            media = sorted(r[0] for r in c.execute("SELECT id FROM media"))
        # A removed member's profile goes like anything else.
        self.assertEqual(left, [new_a, prof_b])
        self.assertNotIn(old_a, left)
        self.assertNotIn(gone, left)
        self.assertEqual(media, ["av_new"])
        self.assertTrue((self.m.MEDIA_DIR / "g_1" / "av_new").exists())
        self.assertFalse((self.m.MEDIA_DIR / "g_1" / "av_old").exists())


class NameTest(Base):
    def setUp(self):
        super().setUp()
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        self.load()
        from fastapi.testclient import TestClient
        self.c = TestClient(self.m.app)

    def tearDown(self):
        os.environ.pop("SIDETRAY_SETUP_TOKEN", None)
        super().tearDown()

    def test_keymaster_accepts_a_new_name(self):
        import base64
        key = lambda: base64.b64encode(os.urandom(32)).decode()  # noqa: E731
        sig = base64.b64encode(b"s" * 64).decode()
        km = self.c.post("/api/v1/join", json={"group_name": "G", "display_name": "Km", "email": "k@x",
                                               "enc_pubkey": key(), "sign_pubkey": key(),
                                               "setup_token": "env-token"}).json()
        auth = {"Authorization": f"Bearer {km['token']}"}
        ana = self.c.post("/api/v1/join", json={"group_name": "G", "display_name": "Ana", "email": "a@x",
                                                "enc_pubkey": key(), "sign_pubkey": key()}).json()
        with self.m.db() as c:
            c.execute("UPDATE devices SET status = 'active' WHERE id = ?", (ana["device_id"],))
            c.execute("INSERT INTO member_certs VALUES (?, ?, ?, 'member', 'Ana', x'00', 1)",
                      (km["group_id"], ana["device_id"], km["device_id"]))
        cert = lambda name: {"device_id": ana["device_id"], "role": "member", "display_name": name,  # noqa: E731
                             "signature": sig}
        url = f"/api/v1/members/{ana['member_id']}/name"
        # The certificate must carry the new name, for every active device.
        self.assertEqual(self.c.post(url, headers=auth, json={"display_name": "Ana B", "certs": [cert("Ana")]})
                         .status_code, 422)
        r = self.c.post(url, headers=auth, json={"display_name": " Ana B ", "certs": [cert("Ana B")]})
        self.assertEqual(r.status_code, 200, r.text)
        roster = self.c.get("/api/v1/members", headers=auth).json()["members"]
        them = next(m for m in roster if m["id"] == ana["member_id"])
        self.assertEqual(them["display_name"], "Ana B")
        self.assertEqual([c["display_name"] for c in them["devices"][0]["certs"]], ["Ana B"])
        # Members can't.
        ana_auth = {"Authorization": f"Bearer {ana['token']}"}
        self.assertEqual(self.c.post(url, headers=ana_auth, json={"display_name": "X", "certs": [cert("X")]})
                         .status_code, 403)
        # And profile events are accepted.
        r = self.c.post("/api/v1/events", headers=ana_auth,
                        json={"kind": "profile", "key_version": 1, "ciphertext": "eA==", "signature": "eA=="})
        self.assertEqual(r.status_code, 201, r.text)


if __name__ == "__main__":
    unittest.main()
