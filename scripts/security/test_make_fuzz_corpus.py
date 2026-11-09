"""Unit tests for deterministic fuzz-corpus layout and bounds."""
import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_fuzz_corpus import MAGIC, frame, request, seeds


class CorpusTests(unittest.TestCase):
    def test_generated_request_framing(self):
        packet = request()
        self.assertEqual(len(packet), 1024)
        self.assertEqual(packet[:8], MAGIC)
        self.assertEqual(struct.unpack("<I", packet[8:12])[0], 1012)

    def test_seed_target_names_and_edge_cases(self):
        s = seeds()
        self.assertEqual(set(s), {"roughtime_parser", "roughtime_exchange"})
        self.assertTrue(len(s["roughtime_parser"]["over_16k_frame"]) > 16 * 1024)
        self.assertEqual(s["roughtime_parser"]["max_tag_count"], frame(b"\xff" * 4))
        self.assertTrue(s["roughtime_exchange"]["real_request_bad_response"].startswith(
            struct.pack("<H", 1024) + request()
        ))


if __name__ == "__main__":
    unittest.main()
