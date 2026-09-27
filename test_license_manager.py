import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class LicenseManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ["DATA_ROOT"] = str(Path(self.temp.name) / "data")
        os.environ["LICENSE_FILE"] = str(Path(self.temp.name) / "license.env")
        import license_manager
        self.module = importlib.reload(license_manager)
        self.module.set_license_key("LVL-test")

    def tearDown(self):
        self.temp.cleanup(); os.environ.pop("DATA_ROOT", None); os.environ.pop("LICENSE_FILE", None)

    def test_claims_host_and_stores_license_state(self):
        def response(path, _payload):
            if path == "/hosts/claim": return {"valid": True, "host_limit": 3, "hosts_in_use": 1}, 200
            return {"valid": True, "product": self.module.PRODUCT, "expires_at": "2030-01-01T00:00:00-03:00", "check_again_after_hours": 24, "offline_grace_days": 14}, 200
        with patch.object(self.module, "post", side_effect=response): result = self.module.status(force=True)
        self.assertTrue(result["active"]); self.assertEqual(3, result["host_limit"]); self.assertEqual(1, result["hosts_in_use"])

    def test_host_limit_blocks_panel(self):
        with patch.object(self.module, "post", return_value=({"valid": False, "reason": "host_limit_reached"}, 403)):
            result = self.module.status(force=True)
        self.assertFalse(result["active"]); self.assertEqual("host_limit", result["mode"])

