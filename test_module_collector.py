import unittest
from module_collector import parse_module_state


class ModuleParserTests(unittest.TestCase):
    def test_huawei_port_state_inventory(self):
        text = """
Last down cause              LOS
Last up time                 2026-09-28 00:09:22+08:00
Last down time               2026-09-28 00:08:28+08:00
Vendor name                  HISILICON
Vendor rev                   Unspecified
Vendor PN                    SSX1T1LTD
Vendor SN                    032MGA6TH8000681
Date Code                    17-08-25
Module type                  GPON
Module sub-type              CLASS C+
Max Distance(Km)             20
Max rate(Kbps)               2500000
Wave length(nm)              1490
Connector                    SC
"""
        parsed = parse_module_state(text)
        self.assertEqual(parsed["vendor_name"], "HISILICON")
        self.assertEqual(parsed["vendor_pn"], "SSX1T1LTD")
        self.assertEqual(parsed["vendor_sn"], "032MGA6TH8000681")
        self.assertEqual(parsed["module_subtype"], "CLASS C+")
        self.assertEqual(parsed["last_down_cause"], "LOS")
        self.assertEqual(parsed["last_up_time"], "2026-09-28 00:09:22+08:00")
        self.assertNotIn("vendor_rev", parsed)


if __name__ == "__main__":
    unittest.main()
