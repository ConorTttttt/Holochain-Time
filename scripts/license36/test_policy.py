#!/usr/bin/env python3
"""Behavioral regressions; cargo-deny fixtures run only when tools are present."""
import copy
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from source_policy import (
    CRATES_IO, GRAPHS, check_policy_text, inspect_lock, inspect_manifest,
    packages_from_lock, review_expression,
)

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "deny.toml"


def lock_one(source=CRATES_IO, checksum="a" * 64, local=False):
    item = {"name": "vtime_core" if local else "safe-example", "version": "1.0.0"}
    if not local:
        item.update(source=source, checksum=checksum)
    # Other expected local entries make the source test focus on the changed entry.
    items = [item]
    for name in sorted(GRAPHS["Cargo.lock"] - {"vtime_core" if local else ""}):
        items.append({"name": name, "version": "0.1.0"})
    def encode(p):
        return "\n".join(f'{k} = "{v}"' for k, v in p.items())
    return "version = 4\n\n" + "".join("[[package]]\n" + encode(p) + "\n\n" for p in items)


class OfflinePolicyChecks(unittest.TestCase):
    def test_policy_is_constrained(self):
        self.assertEqual(check_policy_text(POLICY.read_text()), [])

    def test_unknown_license(self):
        self.assertEqual(review_expression(None), "UNKNOWN_MISSING_METADATA")
        self.assertTrue(review_expression("LicenseRef-Unreviewed").startswith("REVIEW_REQUIRED"))

    def test_unapproved_alternative_is_flagged(self):
        self.assertTrue(review_expression("MIT OR GPL-3.0-only").startswith("REVIEW_REQUIRED"))
        self.assertEqual(review_expression("MIT OR Apache-2.0"),
                         "REVIEW_REQUIRED_ALTERNATIVE_EXPRESSION")

    def test_permitted_single_and_conjunctive_expressions(self):
        self.assertTrue(review_expression("MIT AND Apache-2.0").startswith("PROPOSED_POLICY_MATCH"))

    def test_unauthorized_exception_rejected(self):
        p = POLICY.read_text().replace("exceptions = []", 
            'exceptions = [{ crate = "bad", allow = ["GPL-3.0-only"] }]')
        self.assertIn("UNAUTHORIZED_EXCEPTION_OR_PRIVATE_BYPASS", check_policy_text(p))

    def test_unreviewed_clarification_and_graph_exclusion_rejected(self):
        p = POLICY.read_text() + "\n[[licenses.clarify]]\ncrate = 'mystery'\nexpression = 'MIT'\n"
        self.assertTrue(any("POLICY_KEYS_CHANGED_REVIEW_REQUIRED" in e
                            for e in check_policy_text(p)))
        p = POLICY.read_text().replace("all-features = true",
                                       'all-features = true\nexclude = ["critical@1.0.0"]')
        self.assertIn("POLICY_KEYS_CHANGED_REVIEW_REQUIRED:graph", check_policy_text(p))

    def test_yanked_and_source_bypass_rejected(self):
        p = POLICY.read_text().replace('yanked = "deny"', 'yanked = "warn"')
        self.assertIn("YANKED_ADVISORY_POLICY_WEAKENED", check_policy_text(p))
        p = POLICY.read_text().replace('unknown-git = "deny"', 'unknown-git = "warn"')
        self.assertIn("UNREVIEWED_SOURCES_ALLOWED", check_policy_text(p))

    def test_weakened_advisory_rejected(self):
        p = POLICY.read_text().replace("ignore = []", 'ignore = ["RUSTSEC-2026-0001"]')
        self.assertIn("RUSTSEC_IGNORES_NOT_AUTHORIZED", check_policy_text(p))

    def test_unexpected_registry_and_git(self):
        for origin in ("registry+https://evil.example/index", "git+https://github.com/evil/lib"):
            with self.subTest(origin=origin):
                self.assertTrue(any("UNAPPROVED_SOURCE" in x for x in
                                    inspect_lock(lock_one(source=origin), "Cargo.lock")))

    def test_checksum_missing_or_invalid(self):
        self.assertTrue(any("MISSING_OR_BAD_CHECKSUM" in x for x in
                            inspect_lock(lock_one(checksum="bad"), "Cargo.lock")))

    def test_unapproved_local_and_duplicate_identity(self):
        s = lock_one(local=True)
        self.assertFalse(any("UNAPPROVED_PATH" in x for x in inspect_lock(s, "Cargo.lock")))
        altered = s.replace('name = "vtime_core"', 'name = "unapproved"', 1)
        self.assertTrue(any("UNAPPROVED_PATH" in x for x in inspect_lock(altered, "Cargo.lock")))
        with self.assertRaises(ValueError):
            packages_from_lock(s + "[[package]]\nname = \"vtime_core\"\nversion = \"1.0.0\"\n")

    def test_manifest_origin_and_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            file = root / "Cargo.toml"
            file.write_text('[package]\nname="demo"\nversion="0.1.0"')
            doc = {"dependencies": {"x": {"git": "https://evil.example"}},
                   "patch": {"crates-io": {"z": {"path": "../outside"}}}}
            findings = inspect_manifest(doc, file, root)
            self.assertTrue(any("UNREVIEWED_SOURCE_SUBSTITUTION" in x for x in findings))
            self.assertTrue(any("UNREVIEWED_DEPENDENCY_ORIGIN" in x for x in findings))

    def test_external_path_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            file = root / "Cargo.toml"
            self.assertTrue(any("UNAPPROVED_EXTERNAL" in x for x in inspect_manifest(
                {"dependencies": {"evil": {"path": "../elsewhere"}}}, file, root)))

    def test_invalid_config_toml_rejected(self):
        with self.assertRaises(tomllib.TOMLDecodeError):
            check_policy_text("[licenses\nallow=['MIT']")


@unittest.skipUnless(shutil.which("cargo") and shutil.which("cargo-deny"),
                     "NOT RUN: cargo + cargo-deny required; local static checks are not substitutes")
class CargoDenyBehavior(unittest.TestCase):
    def fixture(self, license_expr, config=None):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        manifest = root / "Cargo.toml"
        body = '[package]\nname = "sprint36b-policy-fixture"\nversion = "0.1.0"\nedition = "2021"\n'
        if license_expr is not None:
            body += f'license = "{license_expr}"\n'
        body += "\n[workspace]\n"
        manifest.write_text(body)
        (root / "src").mkdir()
        (root / "src/lib.rs").write_text("pub fn fixture() {}\n")
        created = subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path",
                                  str(manifest)], text=True, capture_output=True, timeout=60)
        if created.returncode:
            self.fail(f"cargo fixture lock failed: {created.stderr[:600]}")
        p = subprocess.run(["cargo", "deny", "--config", str(config or POLICY),
                            "--manifest-path", str(manifest), "--locked",
                            "check", "licenses", "sources"],
                           text=True, capture_output=True, timeout=120)
        return p

    def test_positive_permitted_license(self):
        p = self.fixture("MIT")
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])

    def test_negative_unapproved_license(self):
        self.assertNotEqual(self.fixture("GPL-3.0-only").returncode, 0)

    def test_negative_unknown_and_missing_license(self):
        self.assertNotEqual(self.fixture("LicenseRef-Unreviewed").returncode, 0)
        self.assertNotEqual(self.fixture(None).returncode, 0)

    def test_negative_invalid_spdx(self):
        self.assertNotEqual(self.fixture("THIS IS NOT SPDX").returncode, 0)

    def test_negative_malformed_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            malformed = Path(tmp) / "deny.toml"
            malformed.write_text("[licenses\nallow = ['MIT']\n")
            self.assertNotEqual(self.fixture("MIT", malformed).returncode, 0)


if __name__ == "__main__":
    unittest.main()
