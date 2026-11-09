"""Offline generator safety tests. No Roughtime signer is mocked here."""
import base64
import unittest
from make_signed_test_manifest import ManifestError, make_manifest
from check_test_dna_config import check

TEMPLATE = """---
manifest_version: "0"
name: vtime
integrity:
  network_seed: ~
  properties:
    roughtime_servers:
      - "REPLACE_WITH_SERVER_1="
      - "REPLACE_WITH_SERVER_2="
    oracles:
      - "uhCAkREPLACE_WITH_ORACLE"
    max_faulty: 1
    min_sources: 3
"""

def fixture():
    return {"test_only": True,
            "roughtime_servers": [
                base64.b64encode(bytes([i])*32).decode() for i in range(1, 5)]}

class SignedManifestTests(unittest.TestCase):
    def test_four_keys_zero_oracles_still_meet_3_of_4(self):
        text = make_manifest(TEMPLATE, fixture(), "0011223344556677")
        v = check(text)
        self.assertEqual((v["roughtime_count"], v["oracle_count"]), (4, 0))
        self.assertEqual((v["min_sources"], v["max_faulty"]), (3, 1))
        self.assertFalse(v["operator_independence_proven"])
        self.assertIn("DO-NOT-DEPLOY", text)
        self.assertNotIn("REPLACE_WITH", text)

    def test_duplicate_key_is_rejected(self):
        x = fixture()
        x["roughtime_servers"][2] = x["roughtime_servers"][0]
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE, x, "0011223344556677")

    def test_non_test_fixture_refused(self):
        x = fixture()
        x["test_only"] = False
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE, x, "0011223344556677")

    def test_three_keys_instead_of_four_refused(self):
        x = fixture()
        x["roughtime_servers"].pop()
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE, x, "0011223344556677")

    def test_noncanonical_key_refused(self):
        x = fixture()
        x["roughtime_servers"][0] += "="
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE, x, "0011223344556677")

    def test_never_replace_real_credentials(self):
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE.replace("REPLACE_WITH", "REAL"),
                          fixture(), "0011223344556677")

    def test_invalid_seed_refused(self):
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE, fixture(), "prod")

    def test_unexpected_yaml_refused(self):
        with self.assertRaises(ManifestError):
            make_manifest(TEMPLATE.replace("  network_seed: ~",
                                           '  network_seed: "prod"'),
                          fixture(), "0011223344556677")

if __name__ == "__main__":
    unittest.main()
