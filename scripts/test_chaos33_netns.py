"""Netns partition protocol negative tests; does not invoke root/ip."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import chaos33_netns as lab


class PartitionProbeTests(unittest.TestCase):
    def payload(self, phase):
        result = {
            "schema": lab.PROBE_SCHEMA,
            "phase": phase, "dna": "test-dna", "agent": "test-agent",
            "target": "test-target", "evidence_complete": False,
            "verdict_scope": "caller_supplied"
        }
        if phase == "split":
            result.update({"observation": "new_remote_witness_unavailable_rejected",
                           "witness_hash": "new-witness-not-in-observer"})
        else:
            result.update({"observation": "signed_supplied_bounds_verified",
                           "author_chain_flagged": False, "not_before_us": 100,
                           "not_after_us": 200})
        return result

    def test_baseline_and_rejoin_share_bound_identity(self):
        self.assertEqual(lab.check_probe("baseline", self.payload("baseline")),
                         lab.check_probe("rejoined", self.payload("rejoined")))

    def test_missing_witness_must_be_explicitly_rejected(self):
        value = self.payload("split")
        self.assertEqual(lab.check_probe("split", value)[:2], ("test-dna", "test-agent"))
        value["observation"] = "healthy"
        with self.assertRaises(ValueError):
            lab.check_probe("split", value)

    def test_unknown_author_chain_never_passes_as_trusted(self):
        for health in (None, True):
            value = self.payload("rejoined")
            value["author_chain_flagged"] = health
            with self.assertRaises(ValueError):
                lab.check_probe("rejoined", value)

    def test_fake_completeness_is_rejected_in_every_phase(self):
        for phase in lab.PHASES:
            value = self.payload(phase)
            value["evidence_complete"] = True
            with self.assertRaises(ValueError):
                lab.check_probe(phase, value)

    def test_missing_signed_bounds_are_blocked(self):
        for invalid in (None, "100", True):
            value = self.payload("baseline")
            value["not_before_us"] = invalid
            with self.assertRaises(ValueError):
                lab.check_probe("baseline", value)

    def test_network_lab_rejects_comment_as_data_root(self):
        root = Path("/tmp/chaos33-disposable")
        self.assertFalse(lab.config_binds_root(
            "# data_root_path: /tmp/chaos33-disposable\n", root
        ))
        self.assertTrue(lab.config_binds_root(
            "data_root_path: /tmp/chaos33-disposable\n", root
        ))

    def test_wrong_phase_cannot_reuse_old_probe(self):
        with self.assertRaises(ValueError):
            lab.check_probe("rejoined", self.payload("baseline"))


if __name__ == "__main__":
    unittest.main()
