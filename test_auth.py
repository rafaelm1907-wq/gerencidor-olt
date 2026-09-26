import tempfile
import unittest
from pathlib import Path

import auth_store

class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = auth_store.DB_PATH
        auth_store.DB_PATH = Path(self.temp.name) / "auth.db"
        auth_store.initialize()
        auth_store.seed_user("admin", "test-admin-secret", "admin")
        auth_store.seed_user("cohabnet", "test-viewer-secret", "viewer")

    def tearDown(self):
        auth_store.DB_PATH = self.previous
        self.temp.cleanup()

    def test_roles_sessions_and_revocation(self):
        admin = auth_store.authenticate("admin", "test-admin-secret", "127.0.0.1")
        viewer = auth_store.authenticate("cohabnet", "test-viewer-secret", "127.0.0.1")
        self.assertEqual(admin["role"], "admin")
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

if __name__ == "__main__": unittest.main()
