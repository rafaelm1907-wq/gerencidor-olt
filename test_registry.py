import unittest
from unittest.mock import patch

import olt_registry

class RegistryTests(unittest.TestCase):
    def test_validate_private_ipv4(self):
        self.assertEqual(olt_registry.validate("10.55.1.2", "comm", "Teste")[0], "10.55.1.2")
        for address in ("127.0.0.1", "169.254.1.1", "8.8.8.8", "localhost"):
            with self.assertRaises(ValueError): olt_registry.validate(address, "comm")

    def test_probe_discovers_boards_and_ports(self):
        status = {"4194304000":"1", "4194304256":"1", "4194312192":"2"}
        names = {"4194304000":"GPON 0/0/0", "4194304256":"GPON 0/0/1", "4194312192":"GPON 0/1/0"}
        cli = {"ok":True,"elapsed":1.0,"ont_count":10,"vlan_count":10,"optical_count":1,
               "vlan_command":"display this | include vlan","recommended_interval":300}
        with patch.object(olt_registry, "snmp_rows", side_effect=[status,names]), patch.object(olt_registry, "cli_probe", return_value=cli):
            found = olt_registry.probe("10.55.1.2", "comm", "Teste", "telnet", "reader", "password")
        self.assertEqual(found["boards"], ["0/0", "0/1"])
        self.assertEqual(found["ports"], ["0/0/0", "0/0/1", "0/1/0"])

    def test_collection_interval_is_capped_and_limited_to_half(self):
        self.assertEqual(olt_registry.interval_bounds(900), (5, 10))
        self.assertEqual(olt_registry.chosen_interval(600, "5"), 300)
        self.assertEqual(olt_registry.chosen_interval(600, "10"), 600)
        with self.assertRaises(ValueError): olt_registry.chosen_interval(600, "4")
        with self.assertRaises(ValueError): olt_registry.chosen_interval(600, "11")

if __name__ == "__main__": unittest.main()
