#!/usr/bin/env python3
"""Tests for the PROPOSED (inactive) reviewed-disposition gate policy.

Synthetic fixtures only. They check the rejection rules the owner asked
for; they are not scans and do not approve anything.
"""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from scripts.security import proposed_disposition_gate as p
from scripts.security import test_sprint37_supply_chain_gate as base

SHA = "c" * 40
NOW = datetime(2026, 12, 1, 12, 0, 0, tzinfo=timezone.utc)
POLICY_SHA = "d" * 64


def approval(row, **over):
    record = {
        "approver": "Jane Owner", "approver_kind": "human", "role": "Project security owner",
        "approved_at_utc": "2026-11-20T10:00:00Z", "reviewed_commit": SHA,
        "expires_at_utc": "2027-02-12T00:00:00Z",
        "scope": {"finding_id": row["finding_id"], "package": row["package"],
                  "version": row["version"], "status": row["proposed_disposition"],
                  "graphs": list(row["graphs"])},
        "evidence_refs": ["docs/security/sprint38_disposition_matrix.json"],
    }
    record.update(over)
    return record


def approved_matrix(**over):
    m = base.matrix()
    for row in m["findings"]:
        if row["status"] != "PATCHED_AND_TESTED":
            row["status"] = row["proposed_disposition"]
            row["approval"] = approval(row, **over)
    return m


def scans(**deny_over):
    out = {}
    for graph, audit in base.AUDITS.items():
        deny = {"advisories": 1 if audit["vulnerabilities"]["count"] else 0,
                "licenses": 0, "bans": 0, "sources": 0}
        deny.update(deny_over)
        out[graph] = {"audit": copy.deepcopy(audit), "audit_exit_code": deny["advisories"],
                      "deny_exit_codes": deny,
                      "scanner_versions": {"cargo-audit": "0.22.2", "cargo-deny": "0.20.2"},
                      "artifact_sha256": {"audit.json": "e" * 64}}
    return out


def activation(**over):
    record = {"schema": p.ACTIVATION_SCHEMA, "approver": "Jane Owner", "approver_kind": "human",
              "role": "Release owner (#1)", "approved_at_utc": "2026-11-25T09:00:00Z",
              "policy_sha256": POLICY_SHA, "reviewed_commit": SHA,
              "expires_at_utc": "2027-02-12T00:00:00Z"}
    record.update(over)
    return record


class ProposedPolicyTests(unittest.TestCase):
    def run_policy(self, m=None, s=None, act="default", now=NOW):
        return p.evaluate(m or approved_matrix(), s or scans(), copy.deepcopy(base.LOCKS),
                          SHA, POLICY_SHA, activation() if act == "default" else act, now)

    def test_inactive_by_default_even_when_everything_is_approved(self):
        result = self.run_policy(act=None)
        self.assertEqual(result["policy_status"], "PROPOSED_INACTIVE")
        self.assertEqual(result["gate"], "BLOCKED")

    def test_active_and_fully_approved_clears(self):
        result = self.run_policy()
        self.assertEqual(result["gate"], "CLEAR")
        self.assertFalse(result["production_release_ready"])

    def test_unapproved_rows_block(self):
        result = self.run_policy(m=base.matrix())
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertIn("RUSTSEC-2026-0369", result["blocking_findings"])

    def test_missing_approval_record_rejected(self):
        m = approved_matrix()
        m["findings"][0]["approval"] = None
        with self.assertRaises(ValueError):
            self.run_policy(m=m)

    def test_wrong_source_commit_rejected(self):
        with self.assertRaisesRegex(ValueError, "approval is for commit"):
            self.run_policy(m=approved_matrix(reviewed_commit="a" * 40))

    def test_expired_and_future_approvals_rejected(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            self.run_policy(m=approved_matrix(expires_at_utc="2026-11-30T00:00:00Z"))
        with self.assertRaisesRegex(ValueError, "future"):
            self.run_policy(m=approved_matrix(approved_at_utc="2026-12-24T00:00:00Z"))
        with self.assertRaises(ValueError):
            self.run_policy(m=approved_matrix(expires_at_utc=""))

    def test_mismatched_scope_rejected(self):
        m = approved_matrix()
        m["findings"][0]["approval"]["scope"]["version"] = "8.5.0"
        with self.assertRaisesRegex(ValueError, "scope version"):
            self.run_policy(m=m)
        m = approved_matrix()
        m["findings"][0]["approval"]["scope"]["status"] = "FORMALLY_ACCEPTED_RESIDUAL_RISK"
        with self.assertRaisesRegex(ValueError, "scope status"):
            self.run_policy(m=m)

    def test_finding_outside_approved_graph_scope_rejected(self):
        m = approved_matrix()
        m["findings"][0]["approval"]["scope"]["graphs"] = ["conductor"]
        with self.assertRaisesRegex(ValueError, "outside approved scope"):
            self.run_policy(m=m)

    def test_newly_introduced_vulnerability_rejected(self):
        s = scans()
        s["conductor"]["audit"]["vulnerabilities"]["list"].append(
            {"advisory": {"id": "RUSTSEC-2099-0002"}, "package": {"name": "zip", "version": "8.6.0"}})
        s["conductor"]["audit"]["vulnerabilities"]["count"] += 1
        with self.assertRaisesRegex(ValueError, "unreviewed scanner finding RUSTSEC-2099-0002"):
            self.run_policy(s=s)

    def test_missing_scanners_rejected(self):
        s = scans()
        del s["load"]
        with self.assertRaisesRegex(ValueError, "exactly root, conductor and load"):
            self.run_policy(s=s)
        s = scans()
        s["root"]["scanner_versions"].pop("cargo-deny")
        with self.assertRaisesRegex(ValueError, "missing scanner"):
            self.run_policy(s=s)
        s = scans()
        del s["conductor"]["deny_exit_codes"]["licenses"]
        with self.assertRaisesRegex(ValueError, "cargo-deny exit codes"):
            self.run_policy(s=s)

    def test_license_ban_source_failures_never_waived(self):
        result = self.run_policy(s=scans(licenses=1))
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertEqual(result["non_advisory_deny_failures"]["root"], ["licenses"])

    def test_raw_scanner_results_preserved(self):
        result = self.run_policy()
        self.assertEqual(result["raw_scanner_results"]["conductor"]["audit_exit_code"], 1)
        self.assertIn("artifact_sha256", result["raw_scanner_results"]["root"])

    def test_residual_risk_distinguished_from_patched(self):
        m = approved_matrix()
        row = m["findings"][2]
        row["status"] = "FORMALLY_ACCEPTED_RESIDUAL_RISK"
        row["approval"] = approval(row)
        row["approval"]["scope"]["status"] = "FORMALLY_ACCEPTED_RESIDUAL_RISK"
        result = self.run_policy(m=m)
        self.assertEqual(result["patched_and_tested"], ["RUSTSEC-2026-0486"])
        self.assertEqual(result["accepted_residual_risk"], ["HCVT-S37-NOQ-ACKFREQ"])
        self.assertEqual(result["not_applicable_approved"], ["RUSTSEC-2026-0369"])

    def test_activation_binding(self):
        for bad in (activation(approver_kind="automated"), activation(approver="Claude Code"),
                    activation(policy_sha256="0" * 64), activation(reviewed_commit="a" * 40),
                    activation(expires_at_utc="2026-11-01T00:00:00Z"), {"schema": "x"}):
            with self.assertRaises(ValueError):
                self.run_policy(act=bad)

    def test_history_is_hash_chained_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            first = p.append_history(history, {"gate": "BLOCKED"}, NOW)
            second = p.append_history(history, {"gate": "BLOCKED"}, NOW)
            self.assertNotEqual(first, second)
            lines = history.read_text().splitlines()
            self.assertEqual(json.loads(lines[1])["prev_sha256"], first)
            entry = json.loads(lines[0])
            entry["gate"] = "CLEAR"
            history.write_text(json.dumps(entry, sort_keys=True) + "\n" + lines[1] + "\n")
            with self.assertRaisesRegex(ValueError, "altered"):
                p.append_history(history, {"gate": "BLOCKED"}, NOW)
            history.write_text(lines[1] + "\n")
            with self.assertRaisesRegex(ValueError, "broken hash chain"):
                p.append_history(history, {"gate": "BLOCKED"}, NOW)


if __name__ == "__main__":
    unittest.main()
