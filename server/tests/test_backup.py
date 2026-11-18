"""Phase 11: schema version, maintenance mode, snapshots and restores
(what `sidetray-admin backup` and install.sh --restore run in the container).

Run from server/:  python -m unittest discover tests   (needs httpx for TestClient)
"""

import base64
import contextlib
import importlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def key() -> str:
    return b64(os.urandom(32))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.use_data(self.tmp.name)
        self.km = self.join("Km", "k@x", setup="env-token")
        self.ana = self.join("Ana", "a@x")
        self.group = self.km["group_id"]

    def use_data(self, path):
        os.environ["SIDETRAY_DATA"] = str(path)
        os.environ["SIDETRAY_SETUP_TOKEN"] = "env-token"
        import app.main as main
        import app.admin as admin
        self.m = importlib.reload(main)
        self.a = importlib.reload(admin)
        self.m.init_db()
        from fastapi.testclient import TestClient
        self.c = TestClient(self.m.app)

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

    def post(self, dev, media=()):
        return self.c.post("/api/v1/events", headers=dev["auth"], json={
            "kind": "post", "key_version": 1, "ciphertext": b64(os.urandom(16)), "signature": b64(b"s" * 64),
            "media_ids": list(media)})

    def upload(self, dev, kind="image", size=100):
        r = self.c.post(f"/api/v1/media?kind={kind}", headers=dev["auth"], content=os.urandom(size))
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["id"]

    def admin(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.a.run(list(argv))
        return code, out.getvalue(), err.getvalue()


class SchemaVersion(Base):
    def test_init_db_stamps_the_current_version(self):
        with self.m.db() as c:
            self.assertEqual(self.m.schema_version(c), self.m.SCHEMA_VERSION)

    def test_an_old_database_is_brought_up_to_date(self):
        with self.m.db() as c:
            c.execute("PRAGMA user_version = 0")
        self.m.init_db()
        with self.m.db() as c:
            self.assertEqual(self.m.schema_version(c), self.m.SCHEMA_VERSION)

    def test_a_newer_database_is_refused(self):
        with self.m.db() as c:
            c.execute(f"PRAGMA user_version = {self.m.SCHEMA_VERSION + 1}")
        with self.assertRaises(self.m.NewerSchemaError):
            self.m.init_db()
        code, _, err = self.admin("list-groups")
        self.assertEqual(code, 4)
        self.assertIn("schema version", err)


class Maintenance(Base):
    def test_writes_refused_reads_and_acks_allowed(self):
        self.assertEqual(self.post(self.ana).status_code, 201)
        mid = self.upload(self.ana)
        self.assertEqual(self.admin("maintenance", "on")[0], 0)
        self.assertIn("maintenance=on", self.admin("maintenance", "status")[1])

        r = self.post(self.ana)
        self.assertEqual(r.status_code, 503)
        self.assertIn("moving to a new host", r.json()["detail"])
        self.assertEqual(r.headers["Retry-After"], "300")
        r = self.c.post("/api/v1/media?kind=image", headers=self.ana["auth"], content=b"x" * 10)
        self.assertEqual(r.status_code, 503)
        r = self.c.post("/api/v1/join", json={"group_name": "G", "display_name": "Cy", "email": "c@x",
                                              "enc_pubkey": key(), "sign_pubkey": key()})
        self.assertEqual(r.status_code, 503)
        r = self.c.post("/api/v1/keys/rotate", headers=self.km["auth"], json={})
        self.assertEqual(r.status_code, 503)

        self.assertTrue(self.c.get("/api/v1/health").json()["maintenance"])
        self.assertEqual(self.c.get("/api/v1/events?after=0", headers=self.km["auth"]).status_code, 200)
        self.assertEqual(self.c.get(f"/api/v1/media/{mid}", headers=self.km["auth"]).status_code, 200)
        self.assertEqual(self.c.post("/api/v1/ack", headers=self.km["auth"], json={"seq": 1}).status_code, 200)
        self.assertNotEqual(self.c.post(f"/api/v1/media/{mid}/ack", headers=self.km["auth"]).status_code, 503)
        self.assertNotEqual(self.c.post("/api/v1/media/acks", headers=self.km["auth"],
                                        json={"ids": [mid]}).status_code, 503)

        self.admin("maintenance", "off")
        self.assertNotIn("maintenance", self.c.get("/api/v1/health").json())
        self.assertEqual(self.post(self.ana).status_code, 201)


class SnapshotRestore(Base):
    def make_history(self):
        photo = self.upload(self.ana, "image")
        video = self.upload(self.ana, "video")
        self.assertEqual(self.post(self.ana, [photo]).status_code, 201)
        self.assertEqual(self.post(self.ana, [video]).status_code, 201)
        self.assertEqual(self.post(self.km).status_code, 201)
        return photo, video

    def snapshot(self, *flags):
        snap = Path(self.tmp.name) / ".backup"
        code, out, err = self.admin("snapshot", str(snap), *flags)
        self.assertEqual(code, 0, err)
        return snap, json.loads(out)

    def fresh_server(self):
        """A second, empty data folder: the new host."""
        self.new = tempfile.TemporaryDirectory()
        self.addCleanup(self.new.cleanup)
        self.use_data(self.new.name)

    def test_snapshot_is_consistent_while_writes_go_on(self):
        stop = threading.Event()
        errors = []

        def writer():
            conn = sqlite3.connect(self.m.DB_PATH, timeout=10)
            i = 0
            while not stop.is_set():
                try:
                    conn.execute("INSERT INTO setup_tokens (token_hash, created_at, expires_at) VALUES (?, 0, 0)",
                                 (f"h{i}",))
                    conn.commit()
                except sqlite3.Error as e:  # pragma: no cover
                    errors.append(e)
                i += 1
                stop.wait(0.001)
            conn.close()

        t = threading.Thread(target=writer)
        t.start()
        try:
            for _ in range(5):
                snap, info = self.snapshot()
        finally:
            stop.set()
            t.join()
        self.assertEqual(errors, [])
        conn = sqlite3.connect(snap / "sidetray.db")
        self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], self.m.SCHEMA_VERSION)
        conn.close()
        self.assertFalse((snap / "sidetray.db-wal").exists())
        self.assertEqual(info["groups"], 1)

    def test_snapshot_media_and_no_videos(self):
        photo, video = self.make_history()
        snap, info = self.snapshot()
        self.assertEqual((info["media_files"], info["videos_left_out"]), (2, 0))
        snap, info = self.snapshot("--no-videos")
        self.assertEqual((info["media_files"], info["videos_left_out"]), (1, 1))
        files = {p.name for p in (snap / "media").rglob("*") if p.is_file()}
        self.assertEqual(files, {photo})
        self.assertEqual(self.admin("snapshot-clean", str(snap))[0], 0)
        self.assertFalse(snap.exists())

    def test_snapshot_folder_must_be_inside_data_outside_media(self):
        for bad in ("/", self.tmp.name, str(Path(self.tmp.name) / "media" / "x")):
            with self.assertRaises(SystemExit):
                self.admin("snapshot", bad)

    def test_restore_onto_a_fresh_server(self):
        photo, video = self.make_history()
        old_events = self.c.get("/api/v1/events?after=0", headers=self.km["auth"]).json()
        self.admin("maintenance", "on")
        snap, _ = self.snapshot("--no-videos")
        self.fresh_server()
        code, out, err = self.admin("restore-data", str(snap), "--id", "b1")
        self.assertEqual(code, 0, err)
        info = json.loads(out)
        self.assertEqual((info["groups"], info["media_marked_gone"]), (1, 1))
        # Same devices, same tokens, same history: clients carry on unchanged.
        self.assertEqual(self.c.get("/api/v1/events?after=0", headers=self.km["auth"]).json(), old_events)
        self.assertEqual(self.c.get(f"/api/v1/media/{photo}", headers=self.km["auth"]).status_code, 200)
        r = self.c.get(f"/api/v1/media/{video}", headers=self.km["auth"])
        self.assertEqual((r.status_code, r.json()["reason"]), (410, "migrated"))
        # The old server's maintenance flag doesn't come along.
        self.assertEqual(self.post(self.ana).status_code, 201)

    def test_restore_is_safe_to_rerun_and_guards_a_live_server(self):
        self.make_history()
        snap, _ = self.snapshot()
        self.fresh_server()
        self.assertEqual(self.admin("restore-data", str(snap), "--id", "b1")[0], 0)
        # Re-running the same restore (say it failed after copying) works.
        self.assertEqual(self.admin("restore-data", str(snap), "--id", "b1")[0], 0)
        # A different backup onto a server with groups needs --force.
        code, _, err = self.admin("restore-data", str(snap), "--id", "b2")
        self.assertEqual(code, 3)
        self.assertIn("--force-restore", err)
        self.assertEqual(self.admin("restore-data", str(snap), "--id", "b2", "--force")[0], 0)

    def test_restore_after_a_crash_midway(self):
        self.make_history()
        snap, _ = self.snapshot()
        self.fresh_server()
        # Marker written, staging half full, live data already removed.
        (Path(self.new.name) / ".restored-from").write_text("b1\n")
        (Path(self.new.name) / ".restore-tmp").mkdir()
        (Path(self.new.name) / ".restore-tmp" / "junk").write_text("x")
        code, out, err = self.admin("restore-data", str(snap), "--id", "b1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["groups"], 1)
        self.assertFalse((Path(self.new.name) / ".restore-tmp").exists())

    def test_older_backup_is_migrated_newer_is_refused(self):
        snap, _ = self.snapshot()
        conn = sqlite3.connect(snap / "sidetray.db")
        conn.execute("PRAGMA user_version = 0")
        conn.close()
        self.fresh_server()
        code, out, err = self.admin("restore-data", str(snap), "--id", "old")
        self.assertEqual(code, 0, err)
        info = json.loads(out)
        self.assertEqual((info["schema_version_before"], info["schema_version"]), (0, self.m.SCHEMA_VERSION))

        conn = sqlite3.connect(snap / "sidetray.db")
        conn.execute(f"PRAGMA user_version = {self.m.SCHEMA_VERSION + 1}")
        conn.close()
        newer = tempfile.TemporaryDirectory()
        self.addCleanup(newer.cleanup)
        self.use_data(newer.name)
        code, _, err = self.admin("restore-data", str(snap), "--id", "new")
        self.assertEqual(code, 4)
        self.assertIn("schema version", err)
        self.assertFalse((Path(newer.name) / ".restored-from").exists())


if __name__ == "__main__":
    unittest.main()
