#!/usr/bin/env python3
"""Synthetic unit tests for the Sprint 36A consistency checker.

They verify parser/graph/error handling, not Rust advisory exploitation.
"""
import hashlib
import unittest

from scripts.security import sprint36a_validate as v


def fixture() -> dict:
    return v.parse_lock(b'''version = 4

[[package]]
name = "hc-vtime-conductor-smoke"
version = "0.0.0"
dependencies = ["holochain"]

[[package]]
name = "holochain"
version = "0.7.1"
dependencies = ["holochain_metrics"]

[[package]]
name = "holochain_metrics"
version = "0.7.1"
dependencies = ["zip 8.6.0"]

[[package]]
name = "zip"
version = "8.6.0"

[[package]]
name = "zip"
version = "9.5.0"
''')


class InventoryValidationTests(unittest.TestCase):
    def test_fixture_contains_both_zip_versions(self):
        packages = fixture()
        self.assertIn(("zip", "8.6.0"), packages)
        self.assertIn(("zip", "9.5.0"), packages)

    def test_exact_version_dependency_edge(self):
        pkgs = fixture()
        parent = ("holochain_metrics", "0.7.1")
        self.assertTrue(v.dependency_edge_present(pkgs, parent, ("zip", "8.6.0")))
        self.assertFalse(v.dependency_edge_present(pkgs, parent, ("zip", "9.5.0")))

    def test_valid_transitive_path(self):
        v.check_path(fixture(), [
            "hc-vtime-conductor-smoke@0.0.0", "holochain@0.7.1",
            "holochain_metrics@0.7.1", "zip@8.6.0",
        ], "zip", "8.6.0")

    def test_wrong_zip_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no Cargo.lock dependency edge"):
            v.check_path(fixture(), [
                "hc-vtime-conductor-smoke@0.0.0", "holochain@0.7.1",
                "holochain_metrics@0.7.1", "zip@9.5.0",
            ], "zip", "9.5.0")

    def test_missing_direct_edge_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no Cargo.lock dependency edge"):
            v.check_path(fixture(), [
                "hc-vtime-conductor-smoke@0.0.0", "zip@8.6.0",
            ], "zip", "8.6.0")

    def test_duplicate_lockfile_package_is_rejected(self):
        raw = b'''[[package]]
name = "zip"
version = "8.6.0"
[[package]]
name = "zip"
version = "8.6.0"
'''
        with self.assertRaisesRegex(ValueError, "duplicate"):
            v.parse_lock(raw)

    def test_git_blob_hash_matches_git_object_encoding(self):
        raw = b"hello\n"
        expected = hashlib.sha1(b"blob 6\0hello\n").hexdigest()
        self.assertEqual(v.git_blob_sha(raw), expected)

    def test_node_must_contain_name_and_version(self):
        for broken in ("zip", "zip@", "@8.6.0"):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                v.split_node(broken)

    def test_original_inventory_has_elevent_unique_advisories(self):
        self.assertEqual(len(v.ORIGINAL_IDS), 11)
        self.assertNotIn("RUSTSEC-2026-0341", v.ORIGINAL_IDS)
        self.assertNotIn("RUSTSEC-2026-0343", v.ORIGINAL_IDS)


if __name__ == "__main__":
    unittest.main()
