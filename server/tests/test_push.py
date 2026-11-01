"""Android A3 server side: UnifiedPush endpoints (GET/POST/DELETE /push) and
the empty wake-ups the relay sends to devices that have no /ws socket open.

A local HTTP server stands in for ntfy: SIDETRAY_NTFY_URL is the public
address phones see, SIDETRAY_NTFY_INTERNAL points the relay at the stand-in.

Run from server/:  python -m unittest discover tests   (needs httpx for TestClient)
"""

import base64
import importlib
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

NTFY = "https://push.example.org:8443"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def key() -> str:
    return b64(os.urandom(32))


class FakeNtfy:
    """Records every request; answers with `status` (a dict path -> code can override)."""

    def __init__(self):
        self.hits = []
        self.status = {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                outer.hits.append((self.path, body, dict(self.headers), time.monotonic()))
                code = outer.status.get(self.path.split("?")[0], 200)
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def wait(self, n, timeout=3.0):
        end = time.monotonic() + timeout
        while len(self.hits) < n and time.monotonic() < end:
            time.sleep(0.02)
        return len(self.hits)

    def close(self):
        self.server.shutdown()


class PushTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ntfy = FakeNtfy()
        os.environ.update({
            "SIDETRAY_DATA": self.tmp.name,
            "SIDETRAY_SETUP_TOKEN": "env-token",
            "SIDETRAY_NTFY_URL": NTFY,
            "SIDETRAY_NTFY_INTERNAL": self.ntfy.url,
            "SIDETRAY_PUSH_HOSTS": "push.other.example",
            "SIDETRAY_WAKE_EVERY_SECONDS": "0.6",
        })
        import app.main as main
        self.m = importlib.reload(main)
        from fastapi.testclient import TestClient
        self.client = TestClient(self.m.app)
        self.c = self.client.__enter__()  # runs the lifespan: init_db, the waker's loop
        self.km = self.join("Km", "k@x", setup="env-token")
        self.ana = self.join("Ana", "a@x")
        self.bo = self.join("Bo", "b@x")

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.ntfy.close()
        for k in ("SIDETRAY_SETUP_TOKEN", "SIDETRAY_NTFY_URL", "SIDETRAY_NTFY_INTERNAL",
                  "SIDETRAY_PUSH_HOSTS", "SIDETRAY_WAKE_EVERY_SECONDS"):
            os.environ.pop(k, None)
        self.tmp.cleanup()

    def join(self, name, email, setup=None):
        body = {"group_name": "G", "display_name": name, "email": email, "enc_pubkey": key(), "sign_pubkey": key()}
        if setup:
            body["setup_token"] = setup
        r = self.c.post("/api/v1/join", json=body)
        self.assertEqual(r.status_code, 201, r.text)
        dev = r.json()
        with self.m.db() as c:
            c.execute("UPDATE devices SET status = 'active' WHERE id = ?", (dev["device_id"],))
        dev["auth"] = {"Authorization": f"Bearer {dev['token']}"}
        return dev

    def register(self, dev, endpoint):
        return self.c.post("/api/v1/push", headers=dev["auth"], json={"endpoint": endpoint})

    def post(self, dev, kind="post"):
        r = self.c.post("/api/v1/events", headers=dev["auth"], json={
            "kind": kind, "key_version": 1, "ciphertext": b64(b"secret words"), "signature": b64(b"s" * 64)})
        self.assertEqual(r.status_code, 201, r.text)

    # --- endpoints -------------------------------------------------------------

    def test_which_endpoints_are_accepted(self):
        t = self.m.push_target
        self.assertEqual(t(f"{NTFY}/upAbC_d-9?up=1"), f"{self.ntfy.url}/upAbC_d-9?up=1")
        self.assertEqual(t(f"{NTFY}/upAbC"), f"{self.ntfy.url}/upAbC")
        self.assertEqual(t("https://PUSH.EXAMPLE.ORG:8443/upX?up=1"), f"{self.ntfy.url}/upX?up=1")
        self.assertEqual(t("https://push.other.example/anything/at/all?x=1"), "https://push.other.example/anything/at/all?x=1")
        for bad in (
            "http://push.example.org:8443/upX",          # not https
            "https://push.example.org/upX",              # ntfy's host, wrong port
            "https://push.example.org:8443/a/b",          # not a single topic
            "https://push.example.org:8443/../admin",
            "https://push.example.org:8443/upX?up=1&x=2",
            "https://push.example.org:8443/",
            "https://user:pw@push.example.org:8443/upX",
            "https://push.example.org:8443/upX#frag",
            "https://evil.example/upX",
            "https://127.0.0.1/upX",
            "https://push.other.example.evil.example/x",
            "https://push.example.org:8443/up X",
            "file:///etc/passwd",
            "not a url",
        ):
            self.assertIsNone(t(bad), bad)

    def test_register_replace_and_delete(self):
        r = self.c.get("/api/v1/push", headers=self.ana["auth"])
        self.assertEqual(r.json(), {"offered": True, "ntfy": NTFY, "hosts": ["push.other.example"], "endpoint": None})
        self.assertEqual(self.register(self.ana, f"{NTFY}/upOne?up=1").status_code, 200)
        self.assertEqual(self.register(self.ana, f"{NTFY}/upTwo?up=1").status_code, 200)
        self.assertEqual(self.c.get("/api/v1/push", headers=self.ana["auth"]).json()["endpoint"], f"{NTFY}/upTwo?up=1")
        r = self.register(self.ana, "https://ntfy.sh/upThree?up=1")
        self.assertEqual(r.status_code, 400)
        self.assertIn(NTFY, r.json()["detail"])
        # Another device registering the same endpoint takes it over.
        self.assertEqual(self.register(self.bo, f"{NTFY}/upTwo?up=1").status_code, 200)
        self.assertIsNone(self.c.get("/api/v1/push", headers=self.ana["auth"]).json()["endpoint"])
        self.assertEqual(self.c.delete("/api/v1/push", headers=self.bo["auth"]).json(), {"deleted": True})
        self.assertEqual(self.c.delete("/api/v1/push", headers=self.bo["auth"]).json(), {"deleted": False})
        self.assertEqual(self.c.post("/api/v1/push", json={"endpoint": f"{NTFY}/upX"}).status_code, 401)

    def test_ntfy_sh_is_allowed_by_default(self):
        # No SIDETRAY_PUSH_HOSTS at all: phones can use the ntfy app's default server
        # with no setup. Set but empty: only the server's own ntfy.
        os.environ.pop("SIDETRAY_PUSH_HOSTS")
        m = importlib.reload(self.m)
        self.assertEqual(m.PUSH_HOSTS, {"ntfy.sh"})
        self.assertEqual(m.push_target("https://ntfy.sh/upAbc123?up=1"), "https://ntfy.sh/upAbc123?up=1")
        os.environ["SIDETRAY_PUSH_HOSTS"] = ""
        m = importlib.reload(self.m)
        self.assertEqual(m.PUSH_HOSTS, set())
        self.assertIsNone(m.push_target("https://ntfy.sh/upAbc123?up=1"))

    def test_not_offered_without_ntfy(self):
        os.environ.pop("SIDETRAY_NTFY_URL")
        os.environ.pop("SIDETRAY_PUSH_HOSTS")
        self.m.NTFY_URL, self.m.PUSH_HOSTS = "", set()
        self.assertFalse(self.c.get("/api/v1/push", headers=self.ana["auth"]).json()["offered"])
        self.assertEqual(self.register(self.ana, f"{NTFY}/upX?up=1").status_code, 404)

    # --- wake-ups --------------------------------------------------------------

    def test_a_post_wakes_other_devices_with_an_empty_request(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        self.register(self.km, f"{NTFY}/upKm?up=1")
        self.post(self.km)
        self.assertEqual(self.ntfy.wait(1), 1)
        time.sleep(0.2)
        self.assertEqual(len(self.ntfy.hits), 1, "the author isn't woken")
        path, body, headers, _ = self.ntfy.hits[0]
        self.assertEqual(path, "/upAna?up=1")
        self.assertEqual(body, b"")
        # Nothing that identifies the group, the member or the content.
        sent = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        for secret in ("km", "ana", self.km["group_id"].lower(), self.ana["device_id"].lower(), "bearer", "secret"):
            self.assertNotIn(secret, sent.replace("keep-alive", ""))

    def test_wake_ups_are_coalesced_but_the_last_change_still_wakes(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        for _ in range(4):
            self.post(self.km)
        self.assertEqual(self.ntfy.wait(2, timeout=3), 2)
        time.sleep(0.8)
        hits = self.ntfy.hits
        self.assertEqual(len(hits), 2, "one at once, one when the interval is up")
        self.assertGreaterEqual(hits[1][3] - hits[0][3], 0.5)

    def test_reactions_and_profiles_dont_wake(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        self.post(self.km, "reaction")
        self.post(self.km, "profile")
        time.sleep(0.4)
        self.assertEqual(self.ntfy.hits, [])
        self.post(self.km, "comment")
        self.assertEqual(self.ntfy.wait(1), 1)

    def test_a_device_with_a_socket_gets_no_wake_up(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        self.register(self.bo, f"{NTFY}/upBo?up=1")
        with self.c.websocket_connect("/api/v1/ws", headers=self.ana["auth"]) as ws:
            self.assertEqual(ws.receive_json()["type"], "hello")
            self.post(self.km)
            self.assertEqual(ws.receive_json()["type"], "new_event")
            self.assertEqual(self.ntfy.wait(1), 1)
            time.sleep(0.3)
            self.assertEqual([h[0] for h in self.ntfy.hits], ["/upBo?up=1"])

    def test_direct_messages_and_join_requests_wake_only_their_devices(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        self.register(self.bo, f"{NTFY}/upBo?up=1")
        self.register(self.km, f"{NTFY}/upKm?up=1")
        r = self.c.post("/api/v1/dms", headers=self.ana["auth"], json={
            "conversation_id": self.m.conversation_id(self.km["group_id"], self.ana["member_id"], self.bo["member_id"]),
            "recipient_member_id": self.bo["member_id"],
            "ciphertext": b64(b"hi"), "signature": b64(b"s" * 64), "media_ids": [],
            "sealed_keys": [{"device_id": self.bo["device_id"], "sealed_key": b64(os.urandom(80))}],
        })
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(self.ntfy.wait(1), 1)
        time.sleep(0.2)
        self.assertEqual([h[0] for h in self.ntfy.hits], ["/upBo?up=1"])
        # A join request: Key Masters only.
        body = {"group_name": "G", "display_name": "New", "email": "n@x", "enc_pubkey": key(), "sign_pubkey": key()}
        self.assertEqual(self.c.post("/api/v1/join", json=body).status_code, 201)
        self.assertEqual(self.ntfy.wait(2), 2)
        time.sleep(0.2)
        self.assertEqual([h[0] for h in self.ntfy.hits], ["/upBo?up=1", "/upKm?up=1"])

    def test_revoking_a_device_wakes_it_once_and_forgets_its_endpoint(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        r = self.c.post(f"/api/v1/members/{self.ana['member_id']}/remove", headers=self.km["auth"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.ntfy.wait(1), 1)
        with self.m.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM push_endpoints").fetchone()[0], 0)
        self.post(self.km)
        time.sleep(0.3)
        self.assertEqual(len(self.ntfy.hits), 1)

    def test_an_endpoint_the_push_server_calls_gone_is_deleted(self):
        self.register(self.ana, f"{NTFY}/upAna?up=1")
        self.ntfy.status["/upAna"] = 410
        self.post(self.km)
        self.assertEqual(self.ntfy.wait(1), 1)
        for _ in range(50):
            if self.c.get("/api/v1/push", headers=self.ana["auth"]).json()["endpoint"] is None:
                break
            time.sleep(0.02)
        self.assertIsNone(self.c.get("/api/v1/push", headers=self.ana["auth"]).json()["endpoint"])


if __name__ == "__main__":
    unittest.main()
