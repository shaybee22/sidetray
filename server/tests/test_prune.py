"""The prune job (Phase 6): acked-by-everyone and past-retention deletion.

Run from server/:  python -m unittest discover tests
"""

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DAY = 86400


class PruneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        import app.main as main
        self.m = importlib.reload(main)  # pick up SIDETRAY_DATA
        self.m.init_db()
        self.t = 1_000 * DAY
        with self.m.db() as c:
            c.execute("INSERT INTO groups (id, name, created_at) VALUES ('g_1', 'G', 1)")
            for d, status, member_status in [("a", "active", "active"), ("b", "active", "active"),
                                             ("gone", "revoked", "active"), ("out", "active", "removed")]:
                c.execute("INSERT INTO members (id, group_id, display_name, email, role, status, created_at)"
                          " VALUES (?, 'g_1', ?, ?, 'member', ?, 1)", (f"m_{d}", d, f"{d}@x", member_status))
                c.execute("INSERT INTO devices (id, group_id, member_id, status, token_hash) VALUES (?, 'g_1', ?, ?, ?)",
                          (d, f"m_{d}", status, f"h_{d}"))

    def tearDown(self):
        self.tmp.cleanup()

    def event(self, age_days=0, media=()):
        with self.m.db() as c:
            for mid in media:
                path = Path("g_1") / mid
                (self.m.MEDIA_DIR / "g_1").mkdir(parents=True, exist_ok=True)
                (self.m.MEDIA_DIR / path).write_bytes(b"x")
                c.execute("INSERT INTO media (id, group_id, uploader_device_id, size_bytes, path, created_at)"
                          " VALUES (?, 'g_1', 'a', 1, ?, ?)", (mid, str(path), self.t - age_days * DAY))
            return c.execute(
                "INSERT INTO events (group_id, kind, author_device_id, key_version, ciphertext, signature, media_ids,"
                " created_at) VALUES ('g_1', 'post', 'a', 1, x'00', x'00', ?, ?)",
                (",".join(media), self.t - age_days * DAY),
            ).lastrowid

    def ack(self, device, seq):
        with self.m.db() as c:
            c.execute("INSERT OR REPLACE INTO acks VALUES ('g_1', ?, ?, 1)", (device, seq))

    def seqs(self):
        with self.m.db() as c:
            return [r[0] for r in c.execute("SELECT seq FROM events ORDER BY seq")]

    def pruned_through(self):
        with self.m.db() as c:
            return c.execute("SELECT pruned_through FROM groups").fetchone()[0]

    def test_waits_for_every_active_device(self):
        s1, s2, s3 = self.event(media=["p1"]), self.event(), self.event()
        self.ack("a", s3)
        # b has no ack at all: nothing goes, whatever revoked/removed devices did.
        self.ack("gone", 0)
        self.assertEqual(self.m.prune(self.t), {"events": 0, "media": 0, "dms": 0})
        self.ack("b", s2)
        self.assertEqual(self.m.prune(self.t), {"events": 2, "media": 1, "dms": 0})
        self.assertEqual(self.seqs(), [s3])
        self.assertEqual(self.pruned_through(), s2)
        self.assertFalse((self.m.MEDIA_DIR / "g_1" / "p1").exists())

    def test_revoked_and_removed_devices_dont_hold_things_back(self):
        s1 = self.event()
        self.ack("a", s1)
        self.ack("b", s1)
        # "gone" (revoked) and "out" (removed member) never acked.
        self.assertEqual(self.m.prune(self.t)["events"], 1)

    def test_retention_window_wins_over_acks(self):
        old = self.event(age_days=91, media=["old"])
        new = self.event(age_days=89)
        self.assertEqual(self.m.prune(self.t), {"events": 1, "media": 1, "dms": 0})
        self.assertEqual(self.seqs(), [new])
        # Devices whose cursor is below this missed something.
        self.assertEqual(self.pruned_through(), old)

    def test_orphan_media_after_a_day(self):
        with self.m.db() as c:
            for mid, age in [("fresh", 0.5), ("stale", 2)]:
                c.execute("INSERT INTO media (id, group_id, uploader_device_id, size_bytes, path, created_at)"
                          " VALUES (?, 'g_1', 'a', 1, ?, ?)", (mid, f"g_1/{mid}", self.t - int(age * DAY)))
        self.event(media=["kept"])
        self.assertEqual(self.m.prune(self.t)["media"], 1)
        with self.m.db() as c:
            self.assertEqual(sorted(r[0] for r in c.execute("SELECT id FROM media")), ["fresh", "kept"])

    def test_revoked_status(self):
        with self.m.db() as c:
            c.execute("INSERT INTO devices (id, group_id, member_id, status, token_hash, revoked_reason)"
                      " VALUES ('den', 'g_1', 'm_a', 'revoked', 'h_den', 'denied')")
            c.execute("INSERT INTO devices (id, group_id, member_id, status, token_hash, approved_by)"
                      " VALUES ('lost', 'g_1', 'm_a', 'revoked', 'h_lost', 'a')")
            c.execute("UPDATE devices SET approved_by = 'a' WHERE id = 'out'")
        st = self.m.revoked_status
        self.assertEqual([st("a"), st("den"), st("lost"), st("out"), st("nope")],
                         ["active", "denied", "revoked", "removed", "revoked"])


if __name__ == "__main__":
    unittest.main()
