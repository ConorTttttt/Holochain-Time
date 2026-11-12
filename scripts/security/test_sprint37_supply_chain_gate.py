#!/usr/bin/env python3
"""Regression tests for the Sprint 37 fail-closed supply-chain gate evaluator.

Synthetic fixtures exercise the decision rules; they are not vulnerability
scans and do not establish exploitability.
"""
import copy
import json
from pathlib import Path
import unittest

from scripts.security import sprint37_supply_chain_gate as g

REPO = Path(__file__).resolve().parents[2]

LOCKS = {
    "root": {("rustix", "1.1.6"): []},
    "conductor": {("zip", "8.6.0"): [], ("noq-proto", "1.4.0"): []},
    "load": {("zip", "8.6.0"): [], ("noq-proto", "1.4.0"): []},
}


def audit(vulns=(), warnings=None):
    return {
        "vulnerabilities": {
            "found": bool(vulns), "count": len(vulns),
            "list": [{"advisory": {"id": i}, "package": {"name": p, "version": v}}
                     for i, p, v in vulns],
        },
        "warnings": warnings or {},
    }


AUDITS = {
    "root": audit(),
    "conductor": audit([("RUSTSEC-2026-0369", "zip", "8.6.0")]),
    "load": audit([("RUSTSEC-2026-0369", "zip", "8.6.0")]),
}

HUMAN_APPROVAL = {
    "approver": "Jane Owner", "approver_kind": "human", "role": "Project security owner",
    "approved_at_utc": "2026-11-20T10:00:00Z",
    "reviewed_commit": "a" * 40, "scope": "Linux-only deployments",
    "evidence_refs": ["cargo tree --target x86_64-unknown-linux-gnu -i zip@8.6.0"],
}


def matrix():
    return {
        "schema": g.SCHEMA,
        "production_release_ready": False,
        "findings": [
            {"finding_id": "RUSTSEC-2026-0369", "source": "rustsec", "kind": "vulnerability",
             "package": "zip", "version": "8.6.0", "graphs": ["conductor", "load"],
             "severity": "CRITICAL", "status": "UNRESOLVED",
             "proposed_disposition": "NOT_APPLICABLE_WITH_APPROVED_EVIDENCE", "approval": None},
            {"finding_id": "RUSTSEC-2026-0486", "source": "rustsec", "kind": "unsound",
             "package": "rustix", "version": "1.1.5", "graphs": ["root"],
             "severity": "unsound", "status": "PATCHED_AND_TESTED",
             "proposed_disposition": "PATCHED_AND_TESTED", "approval": None,
             "fixed_version": "1.1.6", "remediation_commit": "b" * 40,
             "tests": ["cargo test --workspace --locked"]},
            {"finding_id": "HCVT-S37-NOQ-ACKFREQ", "source": "manual-review",
             "kind": "latent-vulnerability", "package": "noq-proto", "version": "1.4.0",
             "graphs": ["conductor", "load"], "severity": "HIGH if enabled",
             "status": "UNRESOLVED",
             "proposed_disposition": "NOT_APPLICABLE_WITH_APPROVED_EVIDENCE", "approval": None},
        ],
    }


def approve_all(m):
    for row in m["findings"]:
        if row["status"] != "PATCHED_AND_TESTED":
            row["status"] = row["proposed_disposition"]
            row["approval"] = dict(HUMAN_APPROVAL)
    return m


class GateDecisionTests(unittest.TestCase):
    def run_gate(self, m=None, audits=None, locks=None):
        return g.evaluate(m or matrix(), audits or copy.deepcopy(AUDITS),
                          locks or copy.deepcopy(LOCKS))

    def test_unresolved_findings_block_the_gate(self):
        result = self.run_gate()
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertEqual({r["finding_id"] for r in result["blocking_findings"]},
                         {"RUSTSEC-2026-0369", "HCVT-S37-NOQ-ACKFREQ"})
        self.assertEqual(result["scanner_findings_reviewed"], 2)
        self.assertFalse(result["production_release_ready"])

    def test_hypothetical_clear_is_reported_but_gate_stays_blocked(self):
        result = self.run_gate()
        self.assertTrue(result["hypothetical_if_all_proposals_approved"]["would_clear"])
        self.assertIn("NOT AN APPROVAL", result["hypothetical_if_all_proposals_approved"]["label"])
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertEqual(result["approvals_recorded"], 0)

    def test_complete_human_approvals_clear_the_gate(self):
        self.assertEqual(self.run_gate(approve_all(matrix()))["gate"], "CLEAR")

    def test_unreviewed_scanner_finding_is_invalid(self):
        audits = copy.deepcopy(AUDITS)
        audits["load"]["vulnerabilities"]["list"].append(
            {"advisory": {"id": "RUSTSEC-2099-0001"}, "package": {"name": "zip", "version": "8.6.0"}})
        audits["load"]["vulnerabilities"]["count"] += 1
        with self.assertRaisesRegex(ValueError, "unreviewed scanner finding RUSTSEC-2099-0001"):
            self.run_gate(audits=audits)

    def test_unreviewed_warning_is_invalid(self):
        audits = copy.deepcopy(AUDITS)
        audits["root"]["warnings"] = {"unmaintained": [
            {"advisory": {"id": "RUSTSEC-2024-0436"}, "package": {"name": "paste", "version": "1.0.15"}}]}
        with self.assertRaisesRegex(ValueError, "unreviewed scanner finding RUSTSEC-2024-0436"):
            self.run_gate(audits=audits)

    def test_finding_reviewed_for_other_graph_only_is_invalid(self):
        m = matrix()
        m["findings"][0]["graphs"] = ["conductor"]
        locks = copy.deepcopy(LOCKS)
        with self.assertRaisesRegex(ValueError, "unreviewed scanner finding .* in load"):
            self.run_gate(m, locks=locks)

    def test_patched_claim_rejected_while_scanner_reports_it(self):
        m = matrix()
        m["findings"][0].update(status="PATCHED_AND_TESTED", fixed_version="9.5.1",
                                remediation_commit="c" * 40, tests=["x"])
        with self.assertRaisesRegex(ValueError, "scanner still reports it"):
            self.run_gate(m)

    def test_patched_claim_rejected_while_version_still_locked(self):
        locks = copy.deepcopy(LOCKS)
        locks["root"][("rustix", "1.1.5")] = []
        with self.assertRaisesRegex(ValueError, "still locked"):
            self.run_gate(locks=locks)

    def test_patched_claim_requires_fixed_version_locked(self):
        locks = copy.deepcopy(LOCKS)
        del locks["root"][("rustix", "1.1.6")]
        with self.assertRaisesRegex(ValueError, "fixed_version"):
            self.run_gate(locks=locks)

    def test_patched_claim_requires_tests_and_commit(self):
        m = matrix()
        m["findings"][1]["tests"] = []
        with self.assertRaisesRegex(ValueError, "requires tests and a commit"):
            self.run_gate(m)

    def test_approved_status_without_approval_record_is_invalid(self):
        m = matrix()
        m["findings"][0]["status"] = "NOT_APPLICABLE_WITH_APPROVED_EVIDENCE"
        with self.assertRaisesRegex(ValueError, "requires an approval record"):
            self.run_gate(m)

    def test_automated_self_approval_is_rejected(self):
        for approver in ("Claude Code", "Codex automated review", "release-bot"):
            with self.subTest(approver=approver):
                m = approve_all(matrix())
                m["findings"][0]["approval"]["approver"] = approver
                with self.assertRaisesRegex(ValueError, "automated tooling cannot approve"):
                    self.run_gate(m)

    def test_incomplete_or_non_human_approval_is_rejected(self):
        cases = [("approver_kind", "service", "must be a human"),
                 ("reviewed_commit", "HEAD", "exact reviewed commit"),
                 ("approved_at_utc", "yesterday", "UTC ISO-8601"),
                 ("evidence_refs", [], "missing evidence_refs")]
        for field, value, message in cases:
            with self.subTest(field=field):
                m = approve_all(matrix())
                m["findings"][0]["approval"][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.run_gate(m)

    def test_approval_on_open_status_is_rejected(self):
        m = matrix()
        m["findings"][0]["approval"] = dict(HUMAN_APPROVAL)
        with self.assertRaisesRegex(ValueError, "approval recorded on a non-approved status"):
            self.run_gate(m)

    def test_stale_open_row_is_invalid(self):
        audits = copy.deepcopy(AUDITS)
        audits["load"] = audit()
        with self.assertRaisesRegex(ValueError, "stale row"):
            self.run_gate(audits=audits)

    def test_manual_finding_must_be_locked_as_recorded(self):
        locks = copy.deepcopy(LOCKS)
        del locks["load"][("noq-proto", "1.4.0")]
        with self.assertRaisesRegex(ValueError, "manual finding noq-proto@1.4.0 not locked"):
            self.run_gate(locks=locks)

    def test_kind_mismatch_is_invalid(self):
        m = matrix()
        m["findings"][0]["kind"] = "unmaintained"
        with self.assertRaisesRegex(ValueError, "matrix kind"):
            self.run_gate(m)

    def test_audit_count_mismatch_is_invalid(self):
        audits = copy.deepcopy(AUDITS)
        audits["conductor"]["vulnerabilities"]["count"] = 0
        with self.assertRaisesRegex(ValueError, "count does not match"):
            self.run_gate(audits=audits)

    def test_production_readiness_claim_is_invalid(self):
        m = matrix()
        m["production_release_ready"] = True
        with self.assertRaisesRegex(ValueError, "production readiness"):
            self.run_gate(m)

    def test_missing_graph_evidence_is_invalid(self):
        audits = copy.deepcopy(AUDITS)
        del audits["load"]
        with self.assertRaisesRegex(ValueError, "root, conductor and load"):
            self.run_gate(audits=audits)


class CommittedMatrixTests(unittest.TestCase):
    """Static invariants of the committed matrix (no scan output required)."""

    def setUp(self):
        path = REPO / "docs/security/sprint37_remediation_matrix.json"
        self.matrix = json.loads(path.read_text(encoding="utf-8"))

    def test_schema_and_no_release_claim(self):
        self.assertEqual(self.matrix["schema"], g.SCHEMA)
        self.assertIs(self.matrix["production_release_ready"], False)
        self.assertEqual(self.matrix["release_verdict"], "NO-GO")

    def test_no_approval_is_recorded_without_a_human_decision(self):
        for row in self.matrix["findings"]:
            with self.subTest(row=row["finding_id"]):
                self.assertNotIn(row["status"], g.NEEDS_APPROVAL)
                self.assertIsNone(row["approval"])

    def test_original_eleven_advisories_are_still_tracked(self):
        from scripts.security import sprint36a_validate as s36a
        ids = {r["finding_id"] for r in self.matrix["findings"]}
        self.assertTrue(s36a.ORIGINAL_IDS <= ids)

    def test_every_patched_row_cites_commit_and_tests(self):
        for row in self.matrix["findings"]:
            if row["status"] == "PATCHED_AND_TESTED":
                with self.subTest(row=row["finding_id"]):
                    self.assertRegex(row["remediation_commit"], r"\A[0-9a-f]{40}\Z")
                    self.assertTrue(row["tests"])
                    self.assertTrue(row["fixed_version"])


if __name__ == "__main__":
    unittest.main()
