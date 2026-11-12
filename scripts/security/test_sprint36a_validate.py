#!/usr/bin/env python3
"""Synthetic unit tests for the Sprint 36A consistency checker.

They verify parser/graph/error handling, not Rust advisory exploitation.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

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


ROOT_LOCK = b'''version = 4

[[package]]
name = "rustix"
version = "1.1.5"

[[package]]
name = "vtime_core"
version = "0.1.0"
dependencies = ["rustix"]
'''

ROOT_LOCK_PATCHED_RUSTIX = ROOT_LOCK.replace(b'"1.1.5"', b'"1.1.6"')

APP_LOCK = b'''version = 4

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
'''

# A hypothetical reviewed upstream fix: metrics now resolves zip 9.x only.
APP_LOCK_REMEDIATED = b'''version = 4

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
dependencies = ["zip"]

[[package]]
name = "zip"
version = "9.5.0"
'''

PATH = ["hc-vtime-conductor-smoke@0.0.0", "holochain@0.7.1",
        "holochain_metrics@0.7.1", "zip@8.6.0"]


class HistoricalBaselineTests(unittest.TestCase):
    """Lockfile upgrades must not fail merely because historical bytes changed.

    Uses a real temporary Git object store, so blob retrieval and re-hashing
    are exercised exactly as on a full clone.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "integration/conductor").mkdir(parents=True)
        (self.repo / "integration/load").mkdir(parents=True)

    def write(self, path: str, raw: bytes, store: bool = True) -> str:
        target = self.repo / path
        target.write_bytes(raw)
        if store:
            subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", path],
                           check=True, capture_output=True)
        return v.git_blob_sha(raw)

    def baseline(self, store: bool = True) -> dict:
        blobs = {
            "Cargo.lock": self.write("Cargo.lock", ROOT_LOCK, store),
            "integration/conductor/Cargo.lock":
                self.write("integration/conductor/Cargo.lock", APP_LOCK, store),
            "integration/load/Cargo.lock":
                self.write("integration/load/Cargo.lock", APP_LOCK, store),
        }
        return {
            "schema": "hc-vtime/sprint36a-dependency-vulnerabilities/v1",
            "approved_risk_acceptances": [],
            "release_verdict": "NO-GO",
            "lockfile_git_blob_shas": blobs,
            "advisories": [
                {"advisory_id": advisory, "package": "zip", "original_version": "8.6.0",
                 "status": "UNRESOLVED", "updated_version": None,
                 "functionality_exercised": "NOT VERIFIED", "dependency_type": "transitive",
                 "dependency_paths": {"conductor": PATH, "load": PATH}}
                for advisory in sorted(v.ORIGINAL_IDS)
            ],
        }

    def test_unchanged_locks_pass_and_report_unchanged(self):
        result = v.check_matrix(self.repo, self.baseline())
        self.assertEqual(result["status"], "PASS")
        for state in result["lockfile_states"].values():
            self.assertEqual(state["state"], "UNCHANGED_FROM_HISTORICAL_BASELINE")
        self.assertEqual(result["historical_rows_superseded_by_current_lock"], [])

    def test_changed_root_lock_preserves_baseline_and_reports_delta(self):
        matrix = self.baseline()
        self.write("Cargo.lock", ROOT_LOCK_PATCHED_RUSTIX)
        result = v.check_matrix(self.repo, matrix)
        root = result["lockfile_states"]["Cargo.lock"]
        self.assertEqual(root["state"], "CHANGED_SINCE_HISTORICAL_BASELINE")
        self.assertEqual(root["historical_git_blob"], v.git_blob_sha(ROOT_LOCK))
        self.assertEqual(root["current_git_blob"], v.git_blob_sha(ROOT_LOCK_PATCHED_RUSTIX))
        self.assertEqual(root["packages_removed"], ["rustix@1.1.5"])
        self.assertEqual(root["packages_added"], ["rustix@1.1.6"])
        self.assertFalse(result["dependency_patch_verified"])
        self.assertFalse(result["production_ready"])

    def test_remediated_application_lock_is_not_rejected(self):
        matrix = self.baseline()
        self.write("integration/conductor/Cargo.lock", APP_LOCK_REMEDIATED)
        result = v.check_matrix(self.repo, matrix)
        self.assertEqual(result["status"], "PASS")
        presence = result["original_vulnerable_version_present_in_current_lock"]
        for advisory in v.ORIGINAL_IDS:
            self.assertEqual(presence[advisory], {"conductor": False, "load": True})
        self.assertEqual(sorted(v.ORIGINAL_IDS),
                         result["historical_rows_superseded_by_current_lock"])
        self.assertIn("zip@8.6.0", result["lockfile_states"][
            "integration/conductor/Cargo.lock"]["packages_removed"])
        # Absence from the lock is reported, never converted into PATCHED.
        self.assertFalse(result["dependency_patch_verified"])

    def test_missing_historical_blob_fails_closed(self):
        matrix = self.baseline(store=False)
        self.write("Cargo.lock", ROOT_LOCK_PATCHED_RUSTIX, store=False)
        with self.assertRaisesRegex(ValueError, "unavailable in Git object store"):
            v.check_matrix(self.repo, matrix)

    def test_vulnerable_version_introduced_into_current_root_fails(self):
        matrix = self.baseline()
        self.write("Cargo.lock", APP_LOCK)
        with self.assertRaisesRegex(ValueError, "current exact-commit"):
            v.check_matrix(self.repo, matrix)

    def test_patched_claim_still_rejected_after_lock_change(self):
        matrix = self.baseline()
        self.write("integration/conductor/Cargo.lock", APP_LOCK_REMEDIATED)
        matrix["advisories"][0]["status"] = "PATCHED"
        with self.assertRaisesRegex(ValueError, "PATCHED requires"):
            v.check_matrix(self.repo, matrix)

    def test_historical_path_must_still_match_baseline(self):
        matrix = self.baseline()
        self.write("integration/load/Cargo.lock", APP_LOCK_REMEDIATED)
        matrix["advisories"][0]["dependency_paths"]["load"] = PATH[:-1] + ["zip@9.5.0"]
        with self.assertRaisesRegex(ValueError, "does not end at recorded vulnerable version"):
            v.check_matrix(self.repo, matrix)

    def test_invalid_blob_id_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid historical lockfile blob ID"):
            v.read_historical_blob(self.repo, "not-a-sha")

    def test_tampered_object_store_bytes_fail_rehash(self):
        blob = v.git_blob_sha(ROOT_LOCK)
        tampered = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"tampered")
        with mock.patch.object(v.subprocess, "run", return_value=tampered):
            with self.assertRaisesRegex(ValueError, "failed re-hash verification"):
                v.read_historical_blob(self.repo, blob)


if __name__ == "__main__":
    unittest.main()
