#!/usr/bin/env python3
"""Regression tests for Sprint 38 release controls.

Synthetic fixtures only: these exercise decision rules of the conductor
release-profile checker, the data-root/restore guard and the QUIC
configuration audit. They do not establish exploitability or clear advisories.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.security import conductor_release_profile as crp
from scripts.security import datastore_guard as dg
from scripts.security import quic_transport_config_audit as qa

REPO = Path(__file__).resolve().parents[2]


def lockfile(path: Path, packages: dict[str, str], registry=True) -> Path:
    src = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n' if registry else ""
    path.write_text("version = 4\n\n" + "\n".join(
        f'[[package]]\nname = "{n}"\nversion = "{v}"\n{src}' for n, v in packages.items()))
    return path


REVIEWED = {"holochain": "0.7.1", "noq-proto": "1.4.0", "iroh": "1.4.1",
            "kitsune2_transport_iroh": "0.5.3"}


class ReleaseProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reviewed_conductor_lock_satisfies_profile(self):
        report = crp.check_lock(REPO / "integration/conductor/Cargo.lock")
        self.assertEqual(report["violations"], [])
        self.assertEqual(report["facts"]["quic_stack"]["noq-proto"], ["1.4.0"])

    def test_load_lock_satisfies_profile(self):
        self.assertEqual(crp.check_lock(REPO / "integration/load/Cargo.lock")["violations"], [])

    def test_older_quic_stack_rejected(self):
        lock = lockfile(self.dir / "Cargo.lock", {**REVIEWED, "noq-proto": "1.2.0",
                                                  "iroh": "1.1.0"})
        problems = crp.check_lock(lock)["violations"]
        self.assertTrue(any("noq-proto 1.2.0" in p for p in problems))
        self.assertTrue(any("iroh 1.1.0" in p for p in problems))

    def test_missing_quic_crate_rejected(self):
        packages = dict(REVIEWED)
        del packages["kitsune2_transport_iroh"]
        problems = crp.check_lock(lockfile(self.dir / "Cargo.lock", packages))["violations"]
        self.assertTrue(any("kitsune2_transport_iroh not present" in p for p in problems))

    def test_wrong_holochain_rejected(self):
        lock = lockfile(self.dir / "Cargo.lock", {**REVIEWED, "holochain": "0.7.0"})
        self.assertTrue(any("holochain must be exactly" in p
                            for p in crp.check_lock(lock)["violations"]))

    def test_two_noq_versions_one_old_rejected(self):
        lock = self.dir / "Cargo.lock"
        lockfile(lock, REVIEWED)
        lock.write_text(lock.read_text() + '\n[[package]]\nname = "noq-proto"\nversion = "1.3.0"\n')
        self.assertTrue(any("1.3.0" in p for p in crp.check_lock(lock)["violations"]))

    def test_binary_embedded_versions(self):
        good = self.dir / "good.bin"
        good.write_bytes(b"\x00/registry/src/x/noq-proto-1.4.0/src/a.rs\x00iroh-1.4.1/src\x00"
                         b"kitsune2_transport_iroh-0.5.3/src/lib.rs\x00holochain-0.7.1/src\x00")
        self.assertEqual(crp.check_binary(good)["violations"], [])
        bad = self.dir / "bad.bin"
        bad.write_bytes(b"noq-proto-1.1.0/src\x00iroh-1.0.3/src\x00"
                        b"kitsune2_transport_iroh-0.5.0/src\x00holochain-0.7.0/src\x00")
        problems = crp.check_binary(bad)["violations"]
        self.assertEqual(len(problems), 4)

    def test_binary_without_quic_paths_fails_closed(self):
        empty = self.dir / "empty.bin"
        empty.write_bytes(b"nothing here")
        self.assertEqual(len(crp.check_binary(empty)["violations"]), 3)

    def test_sqlcipher_source_id_identified(self):
        blob = self.dir / "s.bin"
        blob.write_bytes(b"x2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a1e33y")
        facts = crp.check_binary(blob)["facts"]["sqlite_source_ids"]
        self.assertEqual(facts[0]["identified"]["sqlcipher"], "4.6.1")

    def test_forbidden_env_any_value(self):
        env_file = self.dir / "conductor.env"
        env_file.write_text("# comment\nRUST_LOG=info\nexport HOLOCHAIN_INFLUXIVE_CHILD_SVC=0\n")
        env = crp.parse_env_file(env_file)
        self.assertEqual(len(crp.check_env(env, "f")["violations"]), 1)
        self.assertEqual(crp.check_env({"RUST_LOG": "info"}, "f")["violations"], [])

    def test_malformed_env_file_invalid(self):
        env_file = self.dir / "bad.env"
        env_file.write_text("NOEQUALS\n")
        with self.assertRaises(crp.ProfileError):
            crp.parse_env_file(env_file)

    def test_target_classification_never_claims_policy(self):
        linux = crp.check_target("x86_64-unknown-linux-gnu")
        self.assertEqual(linux["violations"], [])
        self.assertEqual(linux["platform_policy"], "PLATFORM_POLICY_APPROVAL_PENDING")
        self.assertTrue(crp.check_target("x86_64-pc-windows-msvc")["violations"])
        self.assertTrue(crp.check_target("riscv64gc-unknown-freebsd")["violations"])
        with self.assertRaises(crp.ProfileError):
            crp.check_target("../../etc")

    def test_main_exit_codes_and_no_gate_claim(self):
        out = self.dir / "r.json"
        rc = crp.main(["--lock", str(REPO / "integration/conductor/Cargo.lock"),
                       "--output", str(out)])
        self.assertEqual(rc, 0)
        self.assertIs(json.loads(out.read_text())["clears_supply_chain_gate"], False)
        self.assertEqual(crp.main(["--target", "x86_64-pc-windows-gnu"]), 2)
        self.assertEqual(crp.main([]), 3)


class DatastoreGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def db(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        header = bytearray(dg.SQLITE_MAGIC + b"\x10\x00\x02\x02" + bytes(80))
        path.write_bytes(bytes(header) + os.urandom(4000))
        return path

    def backup_set(self) -> Path:
        root = self.dir / "backup"
        self.db(root / "databases/conductor/conductor.sqlite3")
        self.db(root / "databases/dht/dht.sqlite3")
        (root / "conductor-config.yaml").write_text("data_root_path: x\n")
        return root

    def test_private_root_passes(self):
        root = self.dir / "data"
        root.mkdir(mode=0o700)
        db = self.db(root / "databases/a.sqlite3")
        os.chmod(root / "databases", 0o700)
        os.chmod(db, 0o600)
        self.assertEqual(dg.audit_root(root, os.getuid()), [])

    def test_loose_permissions_symlink_hardlink_and_owner_flagged(self):
        root = self.dir / "data"
        root.mkdir(mode=0o755)
        db = self.db(root / "a.sqlite3")
        os.chmod(db, 0o644)
        (root / "link").symlink_to(db)
        os.link(db, root / "b.sqlite3")
        problems = dg.audit_root(root, os.getuid())
        joined = "\n".join(problems)
        self.assertIn("directory mode 0755", joined)
        self.assertIn("file mode 0644", joined)
        self.assertIn("symlink", joined)
        self.assertIn("hard links", joined)
        self.assertTrue(dg.audit_root(root, os.getuid() + 1))

    def test_symlinked_root_invalid(self):
        real = self.dir / "real"
        real.mkdir()
        (self.dir / "alias").symlink_to(real)
        with self.assertRaises(dg.GuardError):
            dg.audit_root(self.dir / "alias", os.getuid())

    def test_manifest_round_trip(self):
        root = self.backup_set()
        manifest = dg.make_manifest(root)
        self.assertEqual(len(manifest["files"]), 3)
        self.assertEqual(dg.verify_restore(root, manifest), [])

    def test_manifest_refuses_uncheckpointed_backup(self):
        root = self.backup_set()
        (root / "databases/dht/dht.sqlite3-wal").write_bytes(b"x")
        with self.assertRaises(dg.GuardError):
            dg.make_manifest(root)

    def test_stray_wal_and_shm_rejected_on_restore(self):
        root = self.backup_set()
        manifest = dg.make_manifest(root)
        (root / "databases/dht/dht.sqlite3-wal").write_bytes(b"x" * 64)
        (root / "databases/dht/dht.sqlite3-shm").write_bytes(b"x")
        problems = dg.verify_restore(root, manifest)
        self.assertEqual(sum("stray SQLite side file" in p for p in problems), 2)

    def test_tamper_extra_missing_symlink_rejected(self):
        root = self.backup_set()
        manifest = dg.make_manifest(root)
        with (root / "databases/dht/dht.sqlite3").open("ab") as handle:
            handle.write(b"tamper")
        (root / "extra.sqlite3").write_bytes(b"x")
        (root / "conductor-config.yaml").unlink()
        (root / "ln").symlink_to(root / "extra.sqlite3")
        joined = "\n".join(dg.verify_restore(root, manifest))
        for needle in ("SHA-256 mismatch", "not listed", "missing from restore set", "symlink"):
            self.assertIn(needle, joined)

    def test_non_sqlite_database_rejected(self):
        root = self.backup_set()
        bogus = root / "databases/conductor/conductor.sqlite3"
        bogus.write_bytes(b"not sqlite" * 20)
        manifest = dg.make_manifest(root)
        self.assertTrue(any("plaintext header" in p for p in dg.verify_restore(root, manifest)))

    def test_hostile_manifest_rejected(self):
        root = self.backup_set()
        manifest = dg.make_manifest(root)
        for evil in ("../escape.sqlite3", "/etc/passwd", "a/../../b", "x.sqlite3-wal"):
            bad = json.loads(json.dumps(manifest))
            bad["files"][evil] = "0" * 64
            self.assertTrue(dg.verify_restore(root, bad), evil)
        bad = json.loads(json.dumps(manifest))
        bad["wal_checkpointed_by_operator"] = False
        with self.assertRaises(dg.GuardError):
            dg.verify_restore(root, bad)
        with self.assertRaises(dg.GuardError):
            dg.verify_restore(root, {"schema": "other", "files": {}})

    def test_cli_exit_codes(self):
        root = self.backup_set()
        manifest = self.dir / "m.json"
        self.assertEqual(dg.main(["make-manifest", str(root), "--output", str(manifest)]), 0)
        self.assertEqual(dg.main(["verify-restore", str(root), "--manifest", str(manifest)]), 0)
        (root / "databases/dht/dht.sqlite3-wal").write_bytes(b"x")
        self.assertEqual(dg.main(["verify-restore", str(root), "--manifest", str(manifest)]), 2)
        self.assertEqual(dg.main(["verify-restore", str(self.dir / "nope"),
                                  "--manifest", str(manifest)]), 3)


class QuicConfigAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.registry = self.dir / "registry"

    def tearDown(self):
        self.tmp.cleanup()

    def crate(self, name, version, files):
        for rel, text in files.items():
            path = self.registry / f"{name}-{version}" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def base(self):
        self.crate("noq-proto", "1.4.0", {
            "src/config/transport.rs":
                "pub struct AckFrequencyConfig {\n}\nimpl Default for AckFrequencyConfig {\n"
                "    fn default() -> Self { Self {} }\n}\n",
            "src/tests/mod.rs": "cfg.ack_frequency_config(Some(AckFrequencyConfig::default()));\n",
        })
        self.crate("iroh", "1.4.1", {
            "src/quic.rs": "pub fn ack_frequency_config(mut self, value: Option<AckFrequencyConfig>)"
                           " -> Self { self.0.ack_frequency_config(value); self }\n"})
        return lockfile(self.dir / "Cargo.lock", {"noq-proto": "1.4.0", "iroh": "1.4.1"})

    def test_passthrough_and_tests_do_not_fail(self):
        self.assertEqual(qa.audit(self.base(), self.registry)["result"], "PASS")

    def test_enabling_call_detected(self):
        lock = self.base()
        self.crate("iroh", "1.4.1", {"src/endpoint.rs":
                   "let c = cfg.ack_frequency_config(Some(AckFrequencyConfig::default()));\n"})
        report = qa.audit(lock, self.registry)
        self.assertEqual(report["result"], "FAIL")
        self.assertIn("iroh/src/endpoint.rs:1", report["violations"][0])

    def test_struct_literal_detected_but_cfg_test_ignored(self):
        lock = self.base()
        self.crate("iroh", "1.4.1", {"src/x.rs": "let a = AckFrequencyConfig { x: 1 };\n"
                                                  "#[cfg(test)]\nmod t { fn f(){ AckFrequencyConfig::default(); } }\n"})
        self.assertEqual(len(qa.audit(lock, self.registry)["violations"]), 1)

    def test_unreviewed_quic_version_fails(self):
        self.crate("noq-proto", "1.2.0", {"src/lib.rs": "\n"})
        lock = lockfile(self.dir / "Cargo.lock", {"noq-proto": "1.2.0"})
        report = qa.audit(lock, self.registry)
        self.assertTrue(any("not been manually reviewed" in v for v in report["violations"]))

    def test_missing_sources_invalid(self):
        lock = lockfile(self.dir / "Cargo.lock", {"noq-proto": "1.4.0"})
        with self.assertRaises(qa.AuditError):
            qa.audit(lock, self.registry)

    def test_quic_stack_removed_fails(self):
        self.crate("iroh", "1.4.1", {"src/lib.rs": "\n"})
        lock = lockfile(self.dir / "Cargo.lock", {"iroh": "1.4.1"})
        self.assertEqual(qa.audit(lock, self.registry)["result"], "FAIL")


if __name__ == "__main__":
    unittest.main()
