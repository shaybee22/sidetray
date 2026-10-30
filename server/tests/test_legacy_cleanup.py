"""The Phase 1 seed cleanup runs on every startup: check it removes only g_test.

Run from server/:  python -m unittest discover tests
"""

import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class LegacyCleanupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        import app.main as main
        self.main = importlib.reload(main)  # pick up SIDETRAY_DATA

    def tearDown(self):
        self.tmp.cleanup()

    def seed(self, conn, group_id, device_id, media_id):
        m = self.main
        conn.execute("INSERT INTO groups VALUES (?, 'G', 1)", (group_id,))
        conn.execute("INSERT INTO members VALUES (?, ?, 'N', 'e@x', 'keymaster', 'active', 1)",
                     (f"m_{device_id}", group_id))
        conn.execute("INSERT INTO devices (id, group_id, member_id, status, token_hash) VALUES (?, ?, ?, 'active', ?)",
                     (device_id, group_id, f"m_{device_id}", f"hash-{device_id}"))
        conn.execute("INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext, signature, created_at)"
                     " VALUES (?, 'post', ?, 1, x'00', x'00', 1)", (group_id, device_id))
        conn.execute("INSERT INTO acks VALUES (?, ?, 1, 1)", (group_id, device_id))
        conn.execute("INSERT INTO sealed_keys (group_id, device_id, key_version, sealed_blob) VALUES (?, ?, 1, x'00')",
                     (group_id, device_id))
        conn.execute("INSERT INTO member_certs VALUES (?, ?, ?, 'keymaster', 'N', x'00', 1)",
                     (group_id, device_id, device_id))
        (m.MEDIA_DIR / group_id).mkdir(parents=True, exist_ok=True)
        (m.MEDIA_DIR / group_id / media_id).write_bytes(b"blob")
        conn.execute("INSERT INTO media VALUES (?, ?, ?, 4, ?, 1)",
                     (media_id, group_id, device_id, f"{group_id}/{media_id}"))

    def counts(self, group_id):
        conn = sqlite3.connect(self.main.DB_PATH)
        out = {t: conn.execute(f"SELECT COUNT(*) FROM {t} WHERE group_id = ?", (group_id,)).fetchone()[0]
               for t in ("members", "devices", "events", "acks", "sealed_keys", "member_certs", "media")}
        out["groups"] = conn.execute("SELECT COUNT(*) FROM groups WHERE id = ?", (group_id,)).fetchone()[0]
        conn.close()
        return out

    def test_removes_only_g_test_and_is_idempotent(self):
        m = self.main
        m.init_db()  # create schema on an empty database
        real = m.new_id("g")
        with m.db() as conn:
            self.seed(conn, "g_test", "d_test", "legacy-media")
            self.seed(conn, real, m.new_id("d"), "real-media")
        self.assertEqual(self.counts("g_test")["events"], 1)

        for _ in range(3):  # every startup
            m.init_db()
            self.assertEqual(set(self.counts("g_test").values()), {0})
            self.assertEqual(set(self.counts(real).values()), {1})
        self.assertFalse((m.MEDIA_DIR / "g_test").exists())
        self.assertEqual((m.MEDIA_DIR / real / "real-media").read_bytes(), b"blob")

    def test_real_group_ids_cannot_collide_with_g_test(self):
        for _ in range(1000):
            gid = self.main.new_id("g")
            self.assertNotEqual(gid, "g_test")
            self.assertEqual(len(gid), 18)


if __name__ == "__main__":
    unittest.main()
