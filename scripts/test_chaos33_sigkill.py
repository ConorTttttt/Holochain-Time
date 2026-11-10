"""Sprint 33 SIGKILL lab refuses fake conductor claims and unsafe probes."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import chaos33_sigkill as chaos


class SigkillGateTests(unittest.TestCase):
    def sample(self):
        return {
            "schema": chaos.PROBE_SCHEMA,
            "dna": "test-dna",
            "agent": "test-agent",
            "target": "test-target",
            "not_before_us": 100,
            "not_after_us": 110,
            "author_chain_flagged": False,
            "verdict_scope": "caller_supplied",
            "evidence_complete": False,
        }

    def test_valid_probe_never_claims_global_completeness(self):
        self.assertEqual(chaos.fingerprint(self.sample())[-2:], (100, 110))

    def test_incomplete_or_unknown_health_is_blocked(self):
        for value in (None, True):
            probe = self.sample()
            probe["author_chain_flagged"] = value
            with self.assertRaises(ValueError):
                chaos.fingerprint(probe)

    def test_forged_complete_evidence_is_blocked(self):
        probe = self.sample()
        probe["evidence_complete"] = True
        with self.assertRaises(ValueError):
            chaos.fingerprint(probe)

    def test_wrong_dna_or_time_bound_is_detected_after_restart(self):
        before = self.sample()
        after = self.sample()
        after["dna"] = "foreign-dna"
        self.assertNotEqual(chaos.fingerprint(before), chaos.fingerprint(after))
        after = self.sample()
        after["not_after_us"] = 105
        self.assertNotEqual(chaos.fingerprint(before), chaos.fingerprint(after))
        after["not_after_us"] = 99
        with self.assertRaises(ValueError):
            chaos.fingerprint(after)

    def test_forbid_shell_string(self):
        with self.assertRaises(ValueError):
            chaos.parsed_argv("holochain --config-path /tmp/file")
        self.assertEqual(chaos.parsed_argv('["holochain", "--help"]'),
                         ["holochain", "--help"])

    def test_disposable_root_must_be_explicit_config_field(self):
        root = Path("/tmp/chaos33-disposable")
        self.assertFalse(chaos.config_binds_root(
            "# data_root_path: /tmp/chaos33-disposable\nother: /tmp/chaos33-disposable\n", root
        ))
        self.assertTrue(chaos.config_binds_root(
            'data_root_path: "/tmp/chaos33-disposable"\n', root
        ))

    def test_python_worker_does_not_qualify_as_holochain(self):
        self.assertFalse(chaos.check_executable(
            __import__("os").getpid(), Path("/does-not-exist/holochain")
        ))


if __name__ == "__main__":
    unittest.main()
