"""Phase 9a server side: per-file acks (videos and feed photos), video
retention (delivered, TTL, per-group and server caps), 410 tombstones, and
direct-message videos.

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

DAY = 86400


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def key() -> str:
    return b64(os.urandom(32))


class Base(unittest.TestCase):
    history_days = "14"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        os.environ["SIDETRAY_HISTORY_DAYS"] = self.history_days
        import app.main as main
        self.m = importlib.reload(main)
        self.m.init_db()
        from fastapi.testclient import TestClient
        self.c = TestClient(self.m.app)
        self.km = self.join("Km", "k@x", setup="env-token")
        self.ana = self.join("Ana", "a@x")
        self.bo = self.join("Bo", "b@x")
        self.group = self.km["group_id"]

    def tearDown(self):
        for k in ("SIDETRAY_SETUP_TOKEN", "SIDETRAY_HISTORY_DAYS"):
            os.environ.pop(k, None)
        self.tmp.cleanup()

    def join(self, name, email, setup=None, group="G"):
        body = {"group_name": group, "display_name": name, "email": email, "enc_pubkey": key(), "sign_pubkey": key()}
        if setup:
            body["setup_token"] = setup
        r = self.c.post("/api/v1/join", json=body)
        self.assertEqual(r.status_code, 201, r.text)
        dev = r.json()
        with self.m.db() as c:
            c.execute("UPDATE devices SET status = 'active' WHERE id = ?", (dev["device_id"],))
        dev["auth"] = {"Authorization": f"Bearer {dev['token']}"}
        return dev

    # --- helpers -----------------------------------------------------------------

    def upload(self, dev, kind="video", size=100):
        r = self.c.post(f"/api/v1/media?kind={kind}", headers=dev["auth"], content=os.urandom(size))
        return r

    def uploaded(self, dev, kind="video", size=100):
        r = self.upload(dev, kind, size)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["id"]

    def post(self, dev, media):
        r = self.c.post("/api/v1/events", headers=dev["auth"], json={
            "kind": "post", "key_version": 1, "ciphertext": b64(b"ct"), "signature": b64(b"s" * 64),
            "media_ids": list(media)})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["seq"]

    def ack_files(self, dev, ids):
        r = self.c.post("/api/v1/media/acks", headers=dev["auth"], json={"ids": list(ids)})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["acked"]

    def ack_events(self, dev, seq):
        self.assertEqual(self.c.post("/api/v1/ack", headers=dev["auth"], json={"seq": seq}).status_code, 200)

    def get(self, dev, mid):
        return self.c.get(f"/api/v1/media/{mid}", headers=dev["auth"])

    def age(self, mid, days):
        with self.m.db() as c:
            c.execute("UPDATE media SET created_at = created_at - ? WHERE id = ?", (int(days * DAY), mid))

    def prune(self, days_later=0):
        return self.m.prune(self.m.now() + int(days_later * DAY))

    def exists(self, mid):
        with self.m.db() as c:
            row = c.execute("SELECT path FROM media WHERE id = ?", (mid,)).fetchone()
        return row is not None and (self.m.MEDIA_DIR / row["path"]).exists()

    def events(self):
        with self.m.db() as c:
            return [r[0] for r in c.execute("SELECT gseq FROM events ORDER BY gseq")]

class VideoTest(Base):
    # --- uploads -----------------------------------------------------------------

    def test_upload_kind(self):
        v, p = self.uploaded(self.ana, "video"), self.uploaded(self.ana, "image")
        default = self.c.post("/api/v1/media", headers=self.ana["auth"], content=b"x").json()["id"]
        with self.m.db() as c:
            kinds = {r["id"]: r["kind"] for r in c.execute("SELECT id, kind FROM media")}
        self.assertEqual(kinds, {v: "video", p: "image", default: "image"})
        self.assertEqual(self.upload(self.ana, "gif").status_code, 422)

    # --- delivered ---------------------------------------------------------------

    def test_a_video_goes_once_every_device_has_acked_it(self):
        v = self.uploaded(self.ana)
        seq = self.post(self.ana, [v])
        self.prune()
        self.assertTrue(self.exists(v))  # nobody has it yet
        # Every device, including ones whose app doesn't ack files yet, must have it.
        self.assertEqual(self.ack_files(self.bo, [v]), 1)
        self.prune()
        self.assertTrue(self.exists(v))  # the Key Master still hasn't
        self.assertEqual(self.ack_files(self.km, [v]), 1)
        self.assertEqual(self.prune()["media"], 1)
        self.assertFalse(self.exists(v))
        r = self.get(self.bo, v)
        self.assertEqual(r.status_code, 410)
        self.assertEqual(r.json()["reason"], "delivered")
        self.assertEqual(self.events(), [seq])  # the post stays

    def test_the_uploader_and_later_devices_dont_hold_it_back(self):
        v = self.uploaded(self.ana)
        self.post(self.ana, [v])
        late = self.join("Cy", "c@x")
        with self.m.db() as c:
            c.execute("UPDATE devices SET requested_at = requested_at + 10 WHERE id = ?", (late["device_id"],))
        self.ack_files(self.bo, [v])
        self.ack_files(self.km, [v])
        self.prune()
        self.assertFalse(self.exists(v))

    def test_revoked_and_removed_devices_dont_count(self):
        v = self.uploaded(self.ana)
        self.post(self.ana, [v])
        self.ack_files(self.km, [v])
        r = self.c.post(f"/api/v1/members/{self.bo['member_id']}/remove", headers=self.km["auth"])
        self.assertEqual(r.status_code, 200, r.text)
        self.prune()
        self.assertFalse(self.exists(v))

    def test_an_upload_no_post_refers_to_yet_isnt_delivered(self):
        v = self.uploaded(self.ana)
        self.ack_files(self.bo, [v])
        self.ack_files(self.km, [v])
        self.prune()
        self.assertTrue(self.exists(v))
        self.post(self.ana, [v])
        self.prune()
        self.assertFalse(self.exists(v))

    # --- TTL ---------------------------------------------------------------------

    def test_a_video_goes_after_the_ttl_whatever_the_acks(self):
        v = self.uploaded(self.ana)
        seq = self.post(self.ana, [v])
        self.prune(13.9)
        self.assertTrue(self.exists(v))
        self.prune(14.1)
        self.assertFalse(self.exists(v))
        self.assertEqual(self.get(self.bo, v).json()["reason"], "ttl")
        self.assertEqual(self.events(), [seq])
        # The tombstone itself goes a week after the TTL.
        self.prune(14 + 14 + 7 + 1)
        self.assertEqual(self.get(self.bo, v).status_code, 404)

    def test_tombstones_are_per_group(self):
        v = self.uploaded(self.ana)
        self.post(self.ana, [v])
        self.prune(15)
        other = self.join("Zed", "z@x", setup=self.m.issue_setup_token()[0], group="Other")
        self.assertEqual(self.get(other, v).status_code, 404)
        self.assertEqual(self.get(self.bo, v).status_code, 410)

    # --- caps --------------------------------------------------------------------

    def test_the_group_cap_evicts_oldest_first_at_upload(self):
        self.m.VIDEO_GROUP_CAP_BYTES = 250
        a = self.uploaded(self.ana)
        self.post(self.ana, [a])
        self.age(a, 1)
        b = self.uploaded(self.ana)
        self.post(self.ana, [b])
        c = self.uploaded(self.ana)  # 300 > 250: the oldest goes
        self.assertFalse(self.exists(a))
        self.assertTrue(self.exists(b) and self.exists(c))
        self.assertEqual(self.get(self.bo, a).json()["reason"], "cap")
        # Photos don't count.
        self.uploaded(self.ana, "image", 1000)
        self.assertTrue(self.exists(b))

    def test_fresh_unposted_uploads_are_never_evicted_so_a_full_store_says_507(self):
        self.m.VIDEO_GROUP_CAP_BYTES = 250
        a, b = self.uploaded(self.ana), self.uploaded(self.ana)  # neither posted yet
        r = self.upload(self.ana)
        self.assertEqual(r.status_code, 507, r.text)
        self.assertTrue(self.exists(a) and self.exists(b))
        with self.m.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM media").fetchone()[0], 2)
        self.assertEqual(len(list((self.m.MEDIA_DIR / self.group).iterdir())), 2)  # no stray file

    def test_the_server_cap_spans_groups(self):
        self.m.VIDEO_CAP_BYTES = 250
        other = self.join("Zed", "z@x", setup=self.m.issue_setup_token()[0], group="Other")
        a = self.uploaded(other)
        self.post(other, [a])
        self.age(a, 1)
        b = self.uploaded(self.ana)
        self.post(self.ana, [b])
        self.uploaded(self.ana)
        self.assertFalse(self.exists(a))
        self.assertTrue(self.exists(b))

    def test_prune_enforces_a_lowered_cap(self):
        a = self.uploaded(self.ana)
        self.post(self.ana, [a])
        self.age(a, 1)
        b = self.uploaded(self.ana)
        self.post(self.ana, [b])
        self.m.VIDEO_GROUP_CAP_BYTES = 150
        self.prune()
        self.assertFalse(self.exists(a))
        self.assertTrue(self.exists(b))

    # --- acks --------------------------------------------------------------------

    def test_acks_only_for_files_the_device_may_fetch(self):
        other = self.join("Zed", "z@x", setup=self.m.issue_setup_token()[0], group="Other")
        v = self.uploaded(self.ana)
        self.assertEqual(self.ack_files(other, [v, "nonexistent"]), 0)
        self.assertEqual(self.ack_files(self.bo, [v, v]), 1)
        r = self.c.post(f"/api/v1/media/{v}/ack", headers=self.km["auth"])
        self.assertEqual(r.json(), {"acked": 1})
        too_many = self.c.post("/api/v1/media/acks", headers=self.bo["auth"],
                               json={"ids": ["x"] * (self.m.MAX_MEDIA_ACKS + 1)})
        self.assertEqual(too_many.status_code, 422)

    def test_an_empty_ack_marks_the_device(self):
        self.assertEqual(self.ack_files(self.bo, []), 0)
        with self.m.db() as c:
            flags = {r["id"]: r["media_acks"] for r in c.execute("SELECT id, media_acks FROM devices")}
        self.assertEqual(flags, {self.km["device_id"]: 0, self.ana["device_id"]: 0, self.bo["device_id"]: 1})

    # --- direct messages ---------------------------------------------------------

    def send_dm(self, sender, to, devices, media=()):
        body = {
            "conversation_id": self.m.conversation_id(self.group, sender["member_id"], to["member_id"]),
            "recipient_member_id": to["member_id"],
            "ciphertext": b64(b"ct"), "signature": b64(b"s" * 64), "media_ids": list(media),
            "sealed_keys": [{"device_id": d["device_id"], "sealed_key": b64(os.urandom(80))} for d in devices],
        }
        r = self.c.post("/api/v1/dms", headers=sender["auth"], json=body)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["seq"]

    def dm_count(self):
        with self.m.db() as c:
            return c.execute("SELECT COUNT(*) FROM dm_messages").fetchone()[0]

    def test_a_dm_video_is_for_the_two_people_and_keeps_its_message(self):
        v = self.uploaded(self.ana)
        seq = self.send_dm(self.ana, self.bo, [self.bo], [v])
        self.assertEqual(self.get(self.km, v).status_code, 404)  # a third member
        self.assertEqual(self.ack_files(self.km, [v]), 0)
        # Bo's app syncs the message (cursor) but hasn't the video yet: both stay.
        self.assertEqual(self.c.post("/api/v1/dms/ack", headers=self.bo["auth"], json={"seq": seq}).status_code, 200)
        self.prune()
        self.assertEqual(self.dm_count(), 1)
        self.assertTrue(self.exists(v))
        # Only Bo's device counts, not the Key Master's.
        self.ack_files(self.bo, [v])
        self.prune()
        self.assertFalse(self.exists(v))
        self.assertEqual(self.dm_count(), 0)

    def test_a_dm_video_past_the_ttl_lets_its_message_go(self):
        v = self.uploaded(self.ana)
        seq = self.send_dm(self.ana, self.bo, [self.bo], [v])
        self.c.post("/api/v1/dms/ack", headers=self.bo["auth"], json={"seq": seq})
        self.prune(15)
        self.assertFalse(self.exists(v))
        self.assertEqual(self.dm_count(), 0)


class FeedPhotoAckTest(Base):
    """With SIDETRAY_HISTORY_DAYS=0 an event used to go as soon as every cursor
    was past it, photos and all, even if a device hadn't downloaded them."""
    history_days = "0"

    def test_an_event_waits_for_its_photos(self):
        p = self.uploaded(self.ana, "image")
        seq = self.post(self.ana, [p])
        for d in (self.km, self.ana, self.bo):
            self.ack_events(d, seq)
        # Bo's app acks files but hasn't downloaded this one: the event stays.
        self.ack_files(self.bo, [])
        self.prune(0.01)
        self.assertEqual(self.events(), [seq])
        self.assertTrue(self.exists(p))
        # The Key Master's app doesn't ack files (older version): only its cursor counts.
        self.ack_files(self.bo, [p])
        self.prune(0.01)
        self.assertEqual(self.events(), [])
        self.assertFalse(self.exists(p))

    def test_retention_still_wins(self):
        p = self.uploaded(self.ana, "image")
        seq = self.post(self.ana, [p])
        self.ack_files(self.bo, [])
        self.ack_events(self.bo, seq)
        self.prune(91)
        self.assertEqual(self.events(), [])


del Base  # setup only; its subclasses run the tests

if __name__ == "__main__":
    unittest.main()
