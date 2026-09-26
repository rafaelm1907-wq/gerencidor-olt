import importlib
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


class LicenseManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.environ["DATA_ROOT"] = str(self.root / "data")
        os.environ["LICENSE_FILE"] = str(self.root / "license.env")
        import license_manager
        self.manager = importlib.reload(license_manager)

    def tearDown(self):
        self.temp.cleanup()
        os.environ.pop("DATA_ROOT", None)
        os.environ.pop("LICENSE_FILE", None)

    def test_valid_license_is_cached(self):
        self.manager.set_license_key("LVL-example-key")
        answer = {"valid": True, "product": self.manager.PRODUCT, "expires_at": "2030-01-01T00:00:00-03:00",
                  "check_again_after_hours": 24, "offline_grace_days": 14}
        with patch.object(self.manager, "_remote_validate", return_value=answer) as remote:
            result = self.manager.status(force=True)
            cached = self.manager.status()
        self.assertTrue(result["active"])
        self.assertEqual("valid", cached["mode"])
        remote.assert_called_once()
        state = json.loads((self.root / "data" / "license-state.json").read_text())
        self.assertTrue(state["device_id"])

    def test_previous_valid_license_uses_offline_grace(self):
        self.manager.set_license_key("LVL-example-key")
        state = {"device_id": "test-device", "last_validated_at": datetime.now(timezone.utc).isoformat(),
                 "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
                 "check_again_after_hours": 1, "offline_grace_days": 14,
                 "key_fingerprint": hashlib.sha256(b"LVL-example-key").hexdigest()}
        self.manager._save_json(self.root / "data" / "license-state.json", state)
        self.manager.MEMORY.update({"checked": None, "status": None})
        with patch.object(self.manager, "_remote_validate", side_effect=OSError("offline")):
            result = self.manager.status(force=True)
        self.assertTrue(result["active"])
        self.assertEqual("grace", result["mode"])

    def test_invalid_answer_blocks_access(self):
        self.manager.set_license_key("LVL-example-key")
        with patch.object(self.manager, "_remote_validate", return_value={"valid": False, "product": self.manager.PRODUCT}):
            result = self.manager.status(force=True)
        self.assertFalse(result["active"])
        self.assertEqual("invalid", result["mode"])
