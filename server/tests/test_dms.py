"""Phase 5b server side: direct messages. Who may send to whom, the sealed
keys covering exactly the right devices, who can fetch a message and its
photos, acks, pruning by participants only, and removed members.

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


class DmTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        import app.main as main
        self.m = importlib.reload(main)
        self.m.init_db()
        from fastapi.testclient import TestClient
        self.c = TestClient(self.m.app)
        self.km = self.join("Km", "k@x", setup="env-token")
        self.ana = self.join("Ana", "a@x")
        self.ana2 = self.join("Ana", "a@x")  # a second device of Ana's
        self.bo = self.join("Bo", "b@x")
        self.group = self.km["group_id"]

    def tearDown(self):
        os.environ.pop("SIDETRAY_SETUP_TOKEN", None)
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

    def send(self, sender, to, devices, media=(), conv=None):
        body = {
            "conversation_id": conv or self.m.conversation_id(self.group, sender["member_id"], to["member_id"]),
            "recipient_member_id": to["member_id"],
            "ciphertext": b64(b"ciphertext only"),
            "signature": b64(b"s" * 64),
            "media_ids": list(media),
            "sealed_keys": [{"device_id": d["device_id"], "sealed_key": b64(os.urandom(80))} for d in devices],
        }
        return self.c.post("/api/v1/dms", headers=sender["auth"], json=body)

    def fetch(self, dev, after=0):
        r = self.c.get(f"/api/v1/dms?after={after}", headers=dev["auth"])
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_conversation_id_matches_the_rust_crate(self):
        # Same vector as crypto::dm::tests.
        self.assertEqual(self.m.conversation_id("g_1", "m_a", "m_b"), "dbc7a9437fdca0816b5a0237c041d789")
        self.assertEqual(self.m.conversation_id("g_1", "m_b", "m_a"), "dbc7a9437fdca0816b5a0237c041d789")

    def test_only_the_participants_devices_get_the_message(self):
        r = self.send(self.ana, self.bo, [self.bo, self.ana2])
        self.assertEqual(r.status_code, 201, r.text)
        seq = r.json()["seq"]
        for dev in (self.bo, self.ana2):
            msgs = self.fetch(dev)["messages"]
            self.assertEqual([m["seq"] for m in msgs], [seq])
            # Every sealed key comes along, for the signature check.
            self.assertEqual(sorted(k["device_id"] for k in msgs[0]["sealed_keys"]),
                             sorted([self.bo["device_id"], self.ana2["device_id"]]))
            self.assertEqual(msgs[0]["sender_member_id"], self.ana["member_id"])
            self.assertEqual(msgs[0]["recipient_member_id"], self.bo["member_id"])
            self.assertEqual(base64.b64decode(msgs[0]["ciphertext"]), b"ciphertext only")
        # A third member, even a Key Master, gets nothing.
        self.assertEqual(self.fetch(self.km)["messages"], [])
        # Feed sync is unaffected.
        self.assertEqual(self.c.get("/api/v1/events", headers=self.km["auth"]).json()["events"], [])

    def test_sealed_keys_must_cover_exactly_the_right_devices(self):
        self.assertEqual(self.send(self.ana, self.bo, [self.bo]).status_code, 422)  # Ana's other device left out
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2, self.km]).status_code, 422)  # outsider
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2, self.ana]).status_code, 422)  # itself
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.bo, self.ana2]).status_code, 422)  # twice
        r = self.send(self.ana, self.bo, [self.bo, self.ana2], conv="0" * 32)
        self.assertEqual(r.status_code, 422)  # not this pair's conversation
        self.assertEqual(self.send(self.ana, self.ana, [self.ana2]).status_code, 422)  # yourself
        # A pending device doesn't count; it isn't active yet.
        pending = self.c.post("/api/v1/join", json={"group_name": "G", "display_name": "Bo", "email": "b@x",
                                                    "enc_pubkey": key(), "sign_pubkey": key()}).json()
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2]).status_code, 201)
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2, pending]).status_code, 422)

    def test_other_groups_and_removed_members_cant_be_messaged(self):
        other = self.join("Zed", "z@x", setup=self.m.issue_setup_token()[0], group="Other")
        self.assertEqual(self.send(self.ana, other, [other, self.ana2]).status_code, 404)
        r = self.c.post(f"/api/v1/members/{self.bo['member_id']}/remove", headers=self.km["auth"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2]).status_code, 404)
        # And a removed member can't send or fetch.
        self.assertEqual(self.send(self.bo, self.ana, [self.ana, self.ana2]).status_code, 401)
        self.assertEqual(self.c.get("/api/v1/dms", headers=self.bo["auth"]).status_code, 401)

    def test_photos_are_only_for_the_participants(self):
        up = self.c.post("/api/v1/media", headers=self.ana["auth"], content=b"encrypted photo")
        mid = up.json()["id"]
        # Someone else's upload can't be attached.
        self.assertEqual(self.send(self.bo, self.ana, [self.ana, self.ana2], media=[mid]).status_code, 422)
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2], media=[mid]).status_code, 201)
        for dev in (self.ana, self.ana2, self.bo):
            r = self.c.get(f"/api/v1/media/{mid}", headers=dev["auth"])
            self.assertEqual((r.status_code, r.content), (200, b"encrypted photo"))
        self.assertEqual(self.c.get(f"/api/v1/media/{mid}", headers=self.km["auth"]).status_code, 404)
        # It can't be reused in a group post or another message.
        r = self.c.post("/api/v1/events", headers=self.ana["auth"], json={
            "kind": "post", "key_version": 1, "ciphertext": "eA==", "signature": "eA==", "media_ids": [mid]})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.send(self.ana, self.bo, [self.bo, self.ana2], media=[mid]).status_code, 422)

    def test_acks_and_pruning_count_only_the_participants(self):
        up = self.c.post("/api/v1/media", headers=self.ana["auth"], content=b"photo").json()["id"]
        first = self.send(self.ana, self.bo, [self.bo, self.ana2], media=[up]).json()["seq"]
        second = self.send(self.bo, self.ana, [self.ana, self.ana2]).json()["seq"]
        self.assertEqual((first, second), (1, 2))
        self.assertEqual(self.c.post("/api/v1/dms/ack", headers=self.bo["auth"], json={"seq": 9}).status_code, 422)
        # Bo has it, Ana's second device doesn't yet: it stays.
        self.c.post("/api/v1/dms/ack", headers=self.bo["auth"], json={"seq": first})
        self.assertEqual(self.m.prune()["dms"], 0)
        # The Key Master never acks anything, and doesn't need to.
        self.c.post("/api/v1/dms/ack", headers=self.ana2["auth"], json={"seq": first})
        out = self.m.prune()
        self.assertEqual(out["dms"], 1)
        with self.m.db() as c:
            self.assertEqual([r[0] for r in c.execute("SELECT seq FROM dm_messages")], [second])
            self.assertIsNone(c.execute("SELECT 1 FROM media WHERE id = ?", (up,)).fetchone())
            self.assertEqual(c.execute("SELECT COUNT(*) FROM dm_keys").fetchone()[0], 2)
        # Acks only move forward.
        r = self.c.post("/api/v1/dms/ack", headers=self.ana2["auth"], json={"seq": 0})
        self.assertEqual(r.json()["last_seq"], first)
        # A revoked device doesn't hold a message back.
        self.c.post("/api/v1/dms/ack", headers=self.ana["auth"], json={"seq": second})
        self.c.post(f"/api/v1/devices/{self.ana2['device_id']}/revoke", headers=self.km["auth"])
        self.assertEqual(self.m.prune()["dms"], 1)

    def test_retention_and_numbering_per_group(self):
        self.send(self.ana, self.bo, [self.bo, self.ana2])
        other = self.join("Zed", "z@x", setup=self.m.issue_setup_token()[0], group="Other")
        zoe = self.join("Zoe", "zoe@x", group="Other")
        r = self.send(other, zoe, [zoe], conv=self.m.conversation_id(other["group_id"], other["member_id"],
                                                                       zoe["member_id"]))
        self.assertEqual(r.json()["seq"], 1)  # numbering is per group
        with self.m.db() as c:
            c.execute("UPDATE dm_messages SET created_at = 0 WHERE group_id = ?", (self.group,))
        self.assertEqual(self.m.prune()["dms"], 1)
        self.assertEqual(len(self.fetch(zoe)["messages"]), 1)

    def test_removed_senders_are_listed_with_their_cut_off(self):
        self.send(self.bo, self.ana, [self.ana, self.ana2])
        self.c.post(f"/api/v1/members/{self.bo['member_id']}/remove", headers=self.km["auth"])
        former = self.c.get("/api/v1/members", headers=self.ana["auth"]).json()["former"]
        devices = [d for m in former for d in m["devices"]]
        self.assertEqual([(d["id"], d["revoked_dm_seq"]) for d in devices], [(self.bo["device_id"], 1)])
        # Ana's devices can still fetch what Bo sent before.
        self.assertEqual(len(self.fetch(self.ana)["messages"]), 1)


if __name__ == "__main__":
    unittest.main()
