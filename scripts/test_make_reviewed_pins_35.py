"""Offline negative/positive tests for live-head Sprint 28–35 pin policy."""
from __future__ import annotations

import copy
import hashlib
import unittest

import make_reviewed_pins_35 as p

CANDIDATE = "c" * 40


class PinPolicy(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "schema": p.SCOPE_SCHEMA,
            "mode": "complete",
            "included_prs": [number for number, _ in p.AUTHORITATIVE],
            "excluded_prs": [],
            "reviewed_extras": [{"sha": "d" * 40,
                                 "reason": "manually reviewed integration merge commit"}],
            "reviewer": "offline test reviewer",
            "reviewed_at_utc": "2026-11-10T19:00:00Z",
        }
        self.tips = {number: f"{i+1:040x}" for i, (number, _) in enumerate(p.AUTHORITATIVE)}
        self.prs = {
            number: {"state": "open", "base": {"ref": "main"},
                     "head": {"ref": branch, "sha": self.tips[number],
                              "repo": {"full_name": p.REPO}}}
            for number, branch in p.AUTHORITATIVE
        }
        self.tracking = {"main": p.BASE}
        self.tracking.update({branch: self.tips[number]
                              for number, branch in p.AUTHORITATIVE})
        self.ancestors = {(p.BASE, CANDIDATE)}
        self.ancestors.update({(p.BASE, sha) for sha in self.tips.values()})
        self.ancestors.update({(sha, CANDIDATE) for sha in self.tips.values()})

    def build(self, scope=None, *, partial=False, extras=None):
        return p.construct_manifest(
            CANDIDATE, self.prs, self.tracking,
            lambda a, b: (a, b) in self.ancestors,
            scope if scope is not None else self.scope,
            ["d" * 40] if extras is None else extras,
            hashlib.sha256(b"human reviewed external scope").hexdigest(),
            partial_authorized=partial)

    def test_all_live_heads_complete_are_validated(self):
        manifest = self.build()
        self.assertEqual(len(manifest["branches"]), 8)
        self.assertTrue(all(x["tip_is_candidate_ancestor"] for x in manifest["branches"]))
        self.assertTrue(manifest["development_scope_complete"])
        self.assertFalse(manifest["release_ready"])
        p.validate_manifest(manifest, candidate=CANDIDATE)

    def test_reviewed_partial_records_excluded_and_blocks_full_development(self):
        partial = copy.deepcopy(self.scope)
        partial["mode"] = "reviewed_partial"
        partial["included_prs"].remove(74)
        partial["excluded_prs"] = [{"pr": 74, "reason": "known package audit blocker"}]
        self.ancestors.remove((self.tips[74], CANDIDATE))
        self.assertRaisesRegex(ValueError, "allow-partial", self.build, partial)
        manifest = self.build(partial, partial=True)
        self.assertFalse(manifest["development_scope_complete"])
        self.assertEqual(len(manifest["branches"]), 8)
        self.assertFalse(manifest["branches"][-1]["included"])
        self.assertRaises(ValueError, p.validate_manifest, manifest, candidate=CANDIDATE)
        p.validate_manifest(manifest, candidate=CANDIDATE, allow_partial=True)

    def test_cannot_silently_drop_failed_or_unmerged_pr(self):
        self.ancestors.remove((self.tips[76], CANDIDATE))
        self.assertRaisesRegex(ValueError, "PR #76", self.build)
        self.scope["included_prs"].remove(76)
        self.assertRaisesRegex(ValueError, "scope omits", self.build)

    def test_duplicate_or_unexpected_scope_input_rejected(self):
        self.scope["included_prs"].append(67)
        self.assertRaisesRegex(ValueError, "duplicate", self.build)
        self.scope["included_prs"].pop()
        self.scope["included_prs"].append(99)
        self.assertRaisesRegex(ValueError, "scope omits", self.build)

    def test_missing_stale_and_foreign_pr_fails(self):
        del self.prs[68]
        self.assertRaisesRegex(ValueError, "PR #68", self.build)
        self.prs[68] = copy.deepcopy(self.prs[67])
        self.assertRaisesRegex(ValueError, "PR #68", self.build)
        self.prs[68] = {"state": "closed", "base": {"ref": "main"},
                        "head": {"ref": "sprint31/dht-resource-bounds-agent-u",
                                 "sha": self.tips[68],
                                 "repo": {"full_name": p.REPO}}}
        self.assertRaisesRegex(ValueError, "PR #68", self.build)

    def test_remote_branch_movement_and_baseline_movement_rejected(self):
        branch = p.EXPECTED[77]
        self.tracking[branch] = "f" * 40
        self.assertRaisesRegex(ValueError, "stale/missing", self.build)
        self.tracking[branch] = self.tips[77]
        self.tracking["main"] = "f" * 40
        self.assertRaisesRegex(ValueError, "origin/main", self.build)

    def test_tip_missing_base_or_duplicate_tip_is_rejected(self):
        self.ancestors.remove((p.BASE, self.tips[69]))
        self.assertRaisesRegex(ValueError, "PR #69", self.build)
        self.ancestors.add((p.BASE, self.tips[69]))
        self.prs[69]["head"]["sha"] = self.tips[67]
        self.assertRaisesRegex(ValueError, "duplicate/invalid", self.build)

    def test_integration_only_unreviewed_commit_rejected(self):
        self.assertRaisesRegex(ValueError, "unreviewed", self.build, extras=["e" * 40])
        self.scope["reviewed_extras"] = []
        self.assertRaisesRegex(ValueError, "unreviewed", self.build)

    def test_invalid_scope_and_candidate_sha_rejected(self):
        self.scope["reviewer"] = ""
        self.assertRaisesRegex(ValueError, "reviewer", self.build)
        self.scope["reviewer"] = "reviewer"
        self.assertRaisesRegex(ValueError, "candidate", p.construct_manifest,
                               "abc", self.prs, self.tracking,
                               lambda a, b: True, self.scope, [], "1" * 64)

    def test_manifest_tamper_and_missing_record_fail(self):
        manifest = self.build()
        manifest["branches"].pop()
        self.assertRaisesRegex(ValueError, "eight", p.validate_manifest,
                               manifest, candidate=CANDIDATE)
        manifest = self.build()
        manifest["branches"][0]["included"] = False
        self.assertRaisesRegex(ValueError, "PR #67", p.validate_manifest,
                               manifest, candidate=CANDIDATE)
        manifest = self.build()
        self.assertRaisesRegex(ValueError, "identity", p.validate_manifest,
                               manifest, candidate="f" * 40)


if __name__ == "__main__":
    unittest.main()
