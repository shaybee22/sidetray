"""Phase 8 server side: POST /leave. A member leaves on their own: all their
devices are revoked, the key needs rotating, the last Key Master can't
leave others behind, and other groups don't notice.

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


def key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


class LeaveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SIDETRAY_DATA"] = self.tmp.name
        self._saved = os.environ.get("SIDETRAY_SETUP_TOKEN")
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        import app.main as main
        self.m = importlib.reload(main)
        self.m.init_db()
        self.c = TestClient(self.m.app)
        self.km = self.join("G", "Km", setup="env-token")
        self.ana = self.join("G", "Ana")
        self.ana2 = self.join("G", "Ana")  # Ana's second device
        self.bo = self.join("G", "Bo")
        self.group = self.km["group_id"]

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("SIDETRAY_SETUP_TOKEN", None)
        else:
            os.environ["SIDETRAY_SETUP_TOKEN"] = self._saved
        self.tmp.cleanup()

    def join(self, group, name, setup=None, active=True):
        body = {"group_name": group, "display_name": name, "email": f"{name.lower()}@x.test",
                "enc_pubkey": key(), "sign_pubkey": key()}
        if setup:
            body["setup_token"] = setup
        r = self.c.post("/api/v1/join", json=body)
        self.assertEqual(r.status_code, 201, r.text)
        dev = r.json()
        if active:
            with self.m.db() as c:
                c.execute("UPDATE devices SET status = 'active' WHERE id = ?", (dev["device_id"],))
        dev["auth"] = {"Authorization": f"Bearer {dev['token']}"}
        return dev

    def leave(self, dev):
        return self.c.post("/api/v1/leave", headers=dev["auth"])

    def post(self, dev):
        return self.c.post("/api/v1/events", headers=dev["auth"],
                           json={"kind": "post", "key_version": 1, "ciphertext": "eA==", "signature": "eA=="})

    def make_keymaster(self, dev):
        with self.m.db() as c:
            c.execute("UPDATE members SET role = 'keymaster' WHERE id = ?", (dev["member_id"],))

    def rotation_pending(self, group=None):
        with self.m.db() as c:
            return bool(c.execute("SELECT rotation_pending FROM groups WHERE id = ?",
                                  (group or self.group,)).fetchone()[0])

    def test_leaving_revokes_every_device_of_the_member(self):
        pending = self.join("G", "Ana", active=False)  # a third device, still waiting
        self.assertEqual(self.post(self.ana).status_code, 201)
        r = self.leave(self.ana)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["status"], "left")
        self.assertEqual(set(body["revoked_devices"]),
                         {self.ana["device_id"], self.ana2["device_id"], pending["device_id"]})
        self.assertTrue(body["rotation_pending"])
        self.assertTrue(self.rotation_pending())
        # Tokens stop working; join status says where they stand.
        for dev in (self.ana, self.ana2):
            self.assertEqual(self.post(dev).status_code, 401)
            s = self.c.get("/api/v1/join/status", headers=dev["auth"])
            self.assertEqual(s.json()["status"], "left")
        # Bo is unaffected.
        self.assertEqual(self.post(self.bo).status_code, 201)
        # Ana's earlier post still verifies for others: her device is a former one with a cut-off.
        roster = self.c.get("/api/v1/members", headers=self.bo["auth"]).json()
        self.assertNotIn(self.ana["member_id"], [m["id"] for m in roster["members"]])
        former = {d["id"]: d for m in roster["former"] for d in m["devices"]}
        self.assertIn(self.ana["device_id"], former)
        self.assertGreaterEqual(former[self.ana["device_id"]]["revoked_seq"], 1)

    def test_leaving_twice_is_refused(self):
        self.assertEqual(self.leave(self.bo).status_code, 200)
        self.assertEqual(self.leave(self.bo).status_code, 401)

    def test_the_only_key_master_must_promote_someone_first(self):
        r = self.leave(self.km)
        self.assertEqual(r.status_code, 409)
        self.assertIn("Promote someone else", r.json()["detail"])
        self.assertEqual(self.post(self.km).status_code, 201)
        self.assertFalse(self.rotation_pending())

    def test_a_key_master_with_a_co_key_master_can_leave(self):
        self.make_keymaster(self.bo)
        self.assertEqual(self.leave(self.km).status_code, 200)
        self.assertEqual(self.post(self.km).status_code, 401)
        self.assertTrue(self.rotation_pending())

    def test_the_last_member_can_leave(self):
        for dev in (self.ana, self.bo):
            self.assertEqual(self.leave(dev).status_code, 200)
        r = self.leave(self.km)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["rotation_pending"])  # nobody left to rotate for

    def test_other_groups_are_untouched(self):
        tok, _ = self.m.issue_setup_token()
        other_km = self.join("H", "Km", setup=tok)
        other_ana = self.join("H", "Ana")  # the same person, in another group
        self.assertEqual(self.leave(self.ana).status_code, 200)
        self.assertEqual(self.post(other_ana).status_code, 201)
        self.assertEqual(self.post(other_km).status_code, 201)
        self.assertFalse(self.rotation_pending(other_km["group_id"]))

    def test_leaving_needs_an_active_device(self):
        waiting = self.join("G", "Cy", active=False)
        self.assertEqual(self.leave(waiting).status_code, 401)
        self.assertEqual(self.c.post("/api/v1/leave").status_code, 401)


if __name__ == "__main__":
    unittest.main()
