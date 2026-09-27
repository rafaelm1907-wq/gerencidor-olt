import tempfile
import unittest
import sqlite3
import os
from pathlib import Path

import auth_store

class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = auth_store.DB_PATH
        auth_store.DB_PATH = Path(self.temp.name) / "auth.db"
        auth_store.initialize()
        auth_store.seed_user("admin", "test-admin-secret", "superadmin")
        auth_store.seed_user("cohabnet", "test-viewer-secret", "viewer")

    def tearDown(self):
        auth_store.DB_PATH = self.previous
        self.temp.cleanup()

    def test_roles_sessions_and_revocation(self):
        admin = auth_store.authenticate("admin", "test-admin-secret", "127.0.0.1")
        viewer = auth_store.authenticate("cohabnet", "test-viewer-secret", "127.0.0.1")
        self.assertEqual(admin["role"], "superadmin")
        self.assertEqual(viewer["role"], "viewer")
        token = auth_store.create_session(viewer["id"])
        self.assertEqual(auth_store.current_session(token)["username"], "cohabnet")
        auth_store.set_password("cohabnet", "new-viewer-secret")
        self.assertIsNone(auth_store.current_session(token))
        self.assertIsNotNone(auth_store.authenticate("cohabnet", "new-viewer-secret", "127.0.0.1"))

    def test_disabling_viewer_revokes_access(self):
        viewer = auth_store.authenticate("cohabnet", "test-viewer-secret", "127.0.0.1")
        token = auth_store.create_session(viewer["id"])
        auth_store.set_enabled("cohabnet", False)
        self.assertIsNone(auth_store.current_session(token))
        self.assertIsNone(auth_store.authenticate("cohabnet", "test-viewer-secret", "127.0.0.1"))
        auth_store.set_enabled("cohabnet", True)
        self.assertIsNotNone(auth_store.authenticate("cohabnet", "test-viewer-secret", "127.0.0.1"))

    def test_password_is_not_plaintext_and_file_private(self):
        data = auth_store.DB_PATH.read_bytes()
        self.assertNotIn(b"test-admin-secret", data)
        self.assertEqual(auth_store.DB_PATH.stat().st_mode & 0o777, 0o600)

    def test_admin_creates_at_most_three_viewers_and_session_limits_apply(self):
        root = auth_store.authenticate("admin", "test-admin-secret", "127.0.0.1")
        auth_store.create_user(root, "operator", "operator-secret", "admin")
        operator = auth_store.authenticate("operator", "operator-secret", "127.0.0.1")
        for name in ("viewer1", "viewer2", "viewer3"):
            auth_store.create_user(operator, name, "viewer-secret", "viewer")
        with self.assertRaises(ValueError): auth_store.create_user(operator, "viewer4", "viewer-secret", "viewer")
        viewer = auth_store.authenticate("viewer1", "viewer-secret", "127.0.0.1")
        self.assertIsNotNone(auth_store.create_session(viewer["id"]))
        self.assertIsNotNone(auth_store.create_session(viewer["id"]))
        self.assertIsNone(auth_store.create_session(viewer["id"]))
        self.assertIsNotNone(auth_store.create_session(operator["id"]))
        self.assertIsNone(auth_store.create_session(operator["id"]))

    def test_legacy_admin_is_migrated_to_superadmin(self):
        legacy = Path(self.temp.name) / "legacy.db"
        salt = os.urandom(16)
        with sqlite3.connect(legacy) as db:
            db.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','viewer')),salt BLOB NOT NULL,password_hash BLOB NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);CREATE TABLE sessions (token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,csrf TEXT NOT NULL,expires_at INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));CREATE TABLE login_failures (id INTEGER PRIMARY KEY,username TEXT NOT NULL,ip TEXT NOT NULL,created_at INTEGER NOT NULL);""")
            db.execute("INSERT INTO users VALUES(1,'admin','admin',?,?,1,1,1)", (salt, auth_store.password_hash("legacy-secret", salt)))
        previous = auth_store.DB_PATH; auth_store.DB_PATH = legacy
        try:
            auth_store.initialize()
            self.assertEqual("superadmin", auth_store.user_info("admin")["role"])
        finally: auth_store.DB_PATH = previous

if __name__ == "__main__": unittest.main()
