import unittest
from unittest.mock import patch

import fast_collector

class FastTrafficTests(unittest.TestCase):
    def test_counter32_wrap(self):
        previous = {"123": (2**32-100, 2**32-200, 10.0)}
        with patch.object(fast_collector, "read_counters", side_effect=[{"123":100},{"123":200}]), patch.object(fast_collector.time, "monotonic", return_value=20.0):
            sample = fast_collector.traffic_samples("10.55.1.2", "test", previous)["123"]
        self.assertEqual(sample["in_bps"], 160.0)
        self.assertEqual(sample["out_bps"], 320.0)

if __name__ == "__main__": unittest.main()
