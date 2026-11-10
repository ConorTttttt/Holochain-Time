#!/usr/bin/env python3
"""Offline, negative-first Sprint 35 audit bundle tests using disposable Git repos."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package as pack
import verify as audit


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args],
                            check=True, capture_output=True, text=True)
    return result.stdout.strip()


class AuditBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hc-vtime-s35-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "Disposable Test")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "THREAT.md").write_text("audit candidate, not release\n")
        for relative in pack.REQUIRED_LOCKS:
            dest = self.repo / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                'version = 3\n\n[[package]]\nname = "sample"\nversion = "0.1.0"\n'
            )
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "disposable provenance fixture")
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.out = self.root / "audit"

    def make(self) -> None:
        pack.create(self.repo, self.head, self.out)

    def repair_sums(self):
        sums = "".join(f"{hashlib.sha256((self.out / fn).read_bytes()).hexdigest()}  {fn}\n"
                       for fn in pack.FILES)
        (self.out / "SHA256SUMS").write_text(sums)

    def test_archives_reproduce_source_and_dependency_graph(self):
        self.make()
        report = audit.verify(self.repo, self.head, self.out)
        self.assertEqual(report["status"], "EXACT_SOURCE_REPRODUCED")
        other = self.root / "second"
        pack.create(self.repo, self.head, other)
        self.assertEqual((self.out / "source.tar.gz").read_bytes(),
                         (other / "source.tar.gz").read_bytes())
        self.assertFalse(report["production_release_ready"])
        deps = json.loads((self.out / "dependencies.json").read_text())
        self.assertFalse(deps["vulnerabilities_assessed"])
        self.assertEqual(len(deps["locks"]), 3)

    def test_mismatched_commit_and_dirty_tree_block_packaging(self):
        with self.assertRaises(pack.PackageError):
            pack.create(self.repo, "0"*40, self.out)
        (self.repo / "untracked.txt").write_text("dirty")
        with self.assertRaises(pack.PackageError):
            self.make()
        self.assertFalse(self.out.exists())

    def test_cannot_package_inside_repository_or_overwrite(self):
        with self.assertRaises(pack.PackageError):
            pack.create(self.repo, self.head, self.repo / "evidence")
        self.make()
        with self.assertRaises(pack.PackageError):
            self.make()

    def test_tamper_archive_then_rehash_is_still_detected(self):
        self.make()
        p = self.out / "source.tar.gz"
        body = bytearray(p.read_bytes())
        body[-9] ^= 1
        p.write_bytes(body)
        self.repair_sums()
        with self.assertRaises(audit.VerificationError):
            audit.verify(self.repo, self.head, self.out)

    def test_false_success_flag_even_with_rehashed_manifest_fails_closed(self):
        self.make()
        p = self.out / "provenance.json"
        manifest = json.loads(p.read_text())
        manifest["production_release_ready"] = True
        p.write_text(json.dumps(manifest))
        self.repair_sums()
        with self.assertRaises(audit.VerificationError):
            audit.verify(self.repo, self.head, self.out)

    def test_forged_dependencies_even_with_rehashed_manifest_are_detected(self):
        self.make()
        p = self.out / "dependencies.json"
        deps = json.loads(p.read_text())
        deps["locks"][0]["packages"][0]["version"] = "99.0.0"
        p.write_text(json.dumps(deps))
        provenance = self.out / "provenance.json"
        manifest = json.loads(provenance.read_text())
        manifest["dependency_inventory_sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        provenance.write_text(json.dumps(manifest))
        self.repair_sums()
        with self.assertRaises(audit.VerificationError):
            audit.verify(self.repo, self.head, self.out)

    def test_extra_evidence_and_corrupt_checksum_are_rejected(self):
        self.make()
        (self.out / "FAKE_PASS.log").write_text("PASS")
        with self.assertRaises(audit.VerificationError):
            audit.verify(self.repo, self.head, self.out)
        (self.out / "FAKE_PASS.log").unlink()
        (self.out / "SHA256SUMS").write_text("PASS\n")
        with self.assertRaises(audit.VerificationError):
            audit.verify(self.repo, self.head, self.out)

    def test_missing_required_lockfile_blocks_creation(self):
        (self.repo / "integration/load/Cargo.lock").unlink()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "remove lock")
        latest = git(self.repo, "rev-parse", "HEAD")
        with self.assertRaises(pack.PackageError):
            pack.create(self.repo, latest, self.out)

    def test_verification_requires_original_commit(self):
        self.make()
        git(self.repo, "commit", "--allow-empty", "-qm", "later commit")
        with self.assertRaises(audit.VerificationError):
            audit.verify(self.repo, self.head, self.out)


if __name__ == "__main__":
    unittest.main()
