"""The prune job (Phase 6): acked-by-everyone (once past the history window)
and past-retention deletion, and the key versions a new device must get.

Run from server/:  python -m unittest discover tests   (needs httpx for TestClient)
"""

import base64
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

DAY = 86400
OLD = 15  # days: past the default 14-day history window, inside the 90-day retention


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
        s1, s2, s3 = self.event(OLD, media=["p1"]), self.event(OLD), self.event(OLD)
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
        s1 = self.event(OLD)
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

    def test_history_window_keeps_recent_acked_events(self):
        recent = self.event(13, media=["recent"])
        self.event(OLD, media=["old"])
        newest = self.event(0)
        for d in ("a", "b"):
            self.ack(d, newest)
        # Everyone has all three, but only the one past 14 days goes (with its photo).
        self.assertEqual(self.m.prune(self.t), {"events": 1, "media": 1, "dms": 0})
        self.assertEqual(self.seqs(), [recent, newest])
        self.assertTrue((self.m.MEDIA_DIR / "g_1" / "recent").exists())
        self.assertFalse((self.m.MEDIA_DIR / "g_1" / "old").exists())
        # Two days later the 13-day-old one has aged out too.
        self.assertEqual(self.m.prune(self.t + 2 * DAY), {"events": 1, "media": 1, "dms": 0})
        self.assertEqual(self.seqs(), [newest])

    def test_history_window_needs_the_acks_too(self):
        s1 = self.event(OLD)
        self.ack("a", s1)  # b hasn't fetched it: it stays until retention
        self.assertEqual(self.m.prune(self.t)["events"], 0)
        self.assertEqual(self.m.prune(self.t + 76 * DAY)["events"], 1)

    def test_retention_wins_over_a_longer_history_window(self):
        self.m.HISTORY_DAYS = 365
        self.event(91)
        s2 = self.event(30)
        for d in ("a", "b"):
            self.ack(d, s2)
        self.assertEqual(self.m.prune(self.t)["events"], 1)
        self.assertEqual(self.seqs(), [s2])

    def test_history_days_setting(self):
        for value, kept in [(None, True), ("", True), ("0", False), ("3", False), ("30", True)]:
            with self.subTest(SIDETRAY_HISTORY_DAYS=value):
                if value is not None:
                    os.environ["SIDETRAY_HISTORY_DAYS"] = value
                try:
                    import app.main as main
                    self.m = importlib.reload(main)
                finally:
                    os.environ.pop("SIDETRAY_HISTORY_DAYS", None)
                with self.m.db() as c:
                    c.execute("DELETE FROM events")
                s1 = self.event(5)
                for d in ("a", "b"):
                    self.ack(d, s1)
                self.m.prune(self.t)
                self.assertEqual(self.seqs(), [s1] if kept else [])

    def test_direct_messages_ignore_the_history_window(self):
        with self.m.db() as c:
            mid = c.execute(
                "INSERT INTO dm_messages (group_id, seq, conversation_id, sender_device_id, sender_member_id,"
                " recipient_member_id, ciphertext, signature, created_at)"
                " VALUES ('g_1', 1, 'c', 'a', 'm_a', 'm_b', x'00', x'00', ?)", (self.t,)).lastrowid
            c.execute("INSERT INTO dm_keys VALUES (?, 'b', x'00')", (mid,))
            c.execute("INSERT INTO dm_acks VALUES ('g_1', 'b', 1, 1)")
        # Sent today and fetched by its only device: it goes now.
        self.assertEqual(self.m.prune(self.t), {"events": 0, "media": 0, "dms": 1})

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


def b64(n=32) -> str:
    return base64.b64encode(os.urandom(n)).decode()


class ApproveKeysTest(unittest.TestCase):
    """A newly approved device must get every group key the kept history uses."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        import app.main as main
        self.m = importlib.reload(main)
        self.m.init_db()
        self.c = TestClient(self.m.app)
        self.km = self.join("km", "env-token")

    def tearDown(self):
        os.environ.pop("SIDETRAY_SETUP_TOKEN", None)
        self.tmp.cleanup()

    def join(self, name, setup_token=None):
        body = {"group_name": "G", "display_name": name, "email": f"{name}@x.test",
                "enc_pubkey": b64(), "sign_pubkey": b64()}
        if setup_token:
            body["setup_token"] = setup_token
        r = self.c.post("/api/v1/join", json=body)
        self.assertIn(r.status_code, (200, 201), r.text)
        return r.json() | {"name": name}

    def h(self, who):
        return {"Authorization": f"Bearer {who['token']}"}

    def post(self, version):
        r = self.c.post("/api/v1/events", headers=self.h(self.km),
                        json={"kind": "post", "key_version": version, "ciphertext": "eA==", "signature": "eA=="})
        self.assertEqual(r.status_code, 201, r.text)

    def rotate(self, version):
        r = self.c.post("/api/v1/keys/rotate", headers=self.h(self.km), json={
            "key_version": version,
            "sealed_keys": [{"device_id": self.km["device_id"], "sealed_blob": b64(80), "signature": b64(64)}]})
        self.assertEqual(r.status_code, 200, r.text)

    def approve(self, who, versions):
        return self.c.post(f"/api/v1/joins/{who['device_id']}/approve", headers=self.h(self.km), json={
            "sealed_keys": [{"key_version": v, "sealed_blob": b64(80), "signature": b64(64)} for v in versions],
            "cert": {"device_id": who["device_id"], "role": "member", "display_name": who["name"],
                     "signature": b64(64)},
            "anchors": [{"device_id": self.km["device_id"], "sign_pubkey": b64()}],
            "anchors_signature": b64(64)})

    def test_approval_must_include_the_keys_of_kept_posts(self):
        self.post(1)
        self.rotate(2)
        self.post(2)
        new = self.join("new")
        r = self.approve(new, [2])
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn("missing version 1", r.json()["detail"])
        r = self.approve(new, [1, 2])
        self.assertEqual(r.status_code, 200, r.text)
        keys = self.c.get("/api/v1/keys", headers=self.h(new)).json()["sealed_keys"]
        self.assertEqual([k["key_version"] for k in keys], [1, 2])

    def test_pruned_versions_arent_needed(self):
        self.post(1)
        self.rotate(2)
        self.post(2)
        with self.m.db() as c:
            c.execute("DELETE FROM events WHERE key_version = 1")
        self.assertEqual(self.approve(self.join("new"), [2]).status_code, 200)

    def test_versions_the_key_master_never_had_arent_needed(self):
        # A Key Master approved after version 1 was retired holds only version 2.
        self.post(1)
        self.rotate(2)
        with self.m.db() as c:
            c.execute("UPDATE devices SET approved_by = id WHERE id = ?", (self.km["device_id"],))
        self.assertEqual(self.approve(self.join("new"), [2]).status_code, 200)


if __name__ == "__main__":
    unittest.main()
