#!/usr/bin/env python3
"""Tests for the Sprint 37 per-artifact license inventory (synthetic metadata)."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import artifact_licenses as a  # noqa: E402


def pkg(name, license_, source="registry+x", proc_macro=False):
    return {"id": f"{name}-id", "name": name, "version": "1.0.0", "license": license_,
            "repository": None, "source": source, "manifest_path": f"/nonexistent/{name}/Cargo.toml",
            "targets": [{"kind": ["proc-macro" if proc_macro else "lib"]}]}


def dep(name, *kinds):
    return {"pkg": f"{name}-id", "dep_kinds": [{"kind": k} for k in (kinds or (None,))]}


METADATA = {
    "packages": [
        pkg("zome", "Apache-2.0", source=None),
        pkg("hdi", "CAL-1.0"),
        pkg("serde", "MIT OR Apache-2.0"),
        pkg("derive_macro", "MIT", proc_macro=True),
        pkg("macro_helper", "GPL-3.0"),
        pkg("test_only", "AGPL-3.0"),
        pkg("build_only", "GPL-2.0"),
    ],
    "resolve": {"nodes": [
        {"id": "zome-id", "deps": [dep("hdi"), dep("derive_macro"), dep("test_only", "dev"),
                                   dep("build_only", "build")]},
        {"id": "hdi-id", "deps": [dep("serde")]},
        {"id": "serde-id", "deps": []},
        {"id": "derive_macro-id", "deps": [dep("macro_helper")]},
        {"id": "macro_helper-id", "deps": []},
        {"id": "test_only-id", "deps": []},
        {"id": "build_only-id", "deps": []},
    ]},
}


class ClosureTests(unittest.TestCase):
    def test_closure_excludes_dev_build_and_proc_macro_subtrees(self):
        names = {c.name for c in a.linked_closure(METADATA, "zome")}
        self.assertEqual(names, {"zome", "hdi", "serde"})

    def test_root_must_be_a_workspace_crate(self):
        with self.assertRaisesRegex(ValueError, "not found exactly once"):
            a.linked_closure(METADATA, "serde")

    def test_dependency_used_both_normal_and_dev_is_linked(self):
        md = {"packages": METADATA["packages"], "resolve": {"nodes": [
            {"id": "zome-id", "deps": [dep("test_only", "dev", None)]},
            {"id": "test_only-id", "deps": []}]}}
        self.assertIn("test_only", {c.name for c in a.linked_closure(md, "zome")})


class ClassificationTests(unittest.TestCase):
    def test_copyleft_is_flagged_not_approved(self):
        c = a.classify("CAL-1.0")
        self.assertEqual(c["review"], "OUTSIDE_PROPOSED_ALLOWLIST")
        self.assertEqual(c["copyleft"], ["CAL-1.0"])

    def test_alternative_with_unlisted_option_requires_owner_election(self):
        c = a.classify("CC0-1.0 OR MIT-0 OR Apache-2.0")
        self.assertEqual(c["review"], "ALTERNATIVE_ELECTION_REQUIRED")
        self.assertTrue(c["election_needed"])
        self.assertEqual(c["copyleft"], [])

    def test_legacy_slash_alternative_is_parsed(self):
        self.assertEqual(a.classify("MIT/Apache-2.0")["review"],
                         "ALTERNATIVE_WITHIN_PROPOSED_ALLOWLIST")

    def test_missing_license_is_unknown(self):
        self.assertEqual(a.classify(None)["review"], "UNKNOWN_MISSING_METADATA")

    def test_conjunction_with_unlisted_term_is_outside_allowlist(self):
        self.assertEqual(a.classify("(MIT OR Apache-2.0) AND MPL-2.0")["review"],
                         "OUTSIDE_PROPOSED_ALLOWLIST")

    def test_inventory_never_claims_approval_and_excludes_own_crates(self):
        roots = list(a.ARTIFACTS)
        md = {"packages": [pkg(r, "Apache-2.0", source=None) for r in roots]
              + [pkg("hdi", "CAL-1.0"), pkg("serde", "MIT OR Apache-2.0")],
              "resolve": {"nodes": [{"id": f"{r}-id", "deps": [dep("hdi")]} for r in roots]
                          + [{"id": "hdi-id", "deps": [dep("serde")]},
                             {"id": "serde-id", "deps": []}]}}
        inv = a.build_inventory(Path("."), lambda target: md)
        self.assertEqual(inv["approval"], "LICENSE_POLICY_APPROVAL_PENDING")
        self.assertIs(inv["legal_review_obtained"], False)
        self.assertIs(inv["alternatives_elected"], False)
        for root in roots:
            names = [r["crate"] for r in inv["artifacts"][root]["third_party_crates"]]
            self.assertEqual(names, ["hdi", "serde"])  # own workspace crate excluded
        self.assertNotIn("CAL-1.0", a.PROPOSED_ALLOW)


if __name__ == "__main__":
    unittest.main()
