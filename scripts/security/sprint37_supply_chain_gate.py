#!/usr/bin/env python3
"""Sprint 37 supply-chain remediation gate evaluator (fail-closed).

Cross-checks exact-commit `cargo audit --json` output for all three locked
dependency graphs against the reviewed remediation matrix
`docs/security/sprint37_remediation_matrix.json` and the CURRENT lockfiles.

It never edits scan output and never treats a proposal as an approval:

* every scanner-reported advisory (vulnerability, unsound, unmaintained,
  yanked) must have a matrix row for that graph, or the run is INVALID;
* a row claiming PATCHED_AND_TESTED must be absent from the scan, absent from
  the current lockfile at the vulnerable version, and cite its tests;
* an open row whose package/version is no longer locked is a stale row;
* NOT_APPLICABLE_WITH_APPROVED_EVIDENCE / FORMALLY_ACCEPTED_RESIDUAL_RISK need
  a complete human approval record (a provenance declaration, NOT a
  cryptographic proof of identity); automated tooling cannot approve;
* the gate is CLEAR only when every row has a gate-clearing status.

A separate, explicitly hypothetical evaluation states whether approving every
proposed disposition WOULD clear the gate. That result is not an approval.

Exit codes: 0 gate CLEAR, 2 gate BLOCKED, 3 invalid input or evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sprint36a_validate as s36a  # type: ignore[import-not-found]
else:  # pragma: no cover - exercised when imported as scripts.security
    from . import sprint36a_validate as s36a

SCHEMA = "hc-vtime/sprint37-supply-chain-remediation/v1"
GRAPHS = {
    "root": "Cargo.lock",
    "conductor": "integration/conductor/Cargo.lock",
    "load": "integration/load/Cargo.lock",
}
STATUSES = {
    "PATCHED_AND_TESTED",
    "NOT_APPLICABLE_WITH_APPROVED_EVIDENCE",
    "FORMALLY_ACCEPTED_RESIDUAL_RISK",
    "UNRESOLVED",
    "NOT_VERIFIED",
}
CLEARING = {
    "PATCHED_AND_TESTED",
    "NOT_APPLICABLE_WITH_APPROVED_EVIDENCE",
    "FORMALLY_ACCEPTED_RESIDUAL_RISK",
}
NEEDS_APPROVAL = CLEARING - {"PATCHED_AND_TESTED"}
PROPOSALS = STATUSES  # a proposal may also honestly be UNRESOLVED
APPROVAL_FIELDS = ("approver", "approver_kind", "role", "approved_at_utc",
                   "reviewed_commit", "scope", "evidence_refs")
AUTOMATED = re.compile(r"claude|codex|gpt|automat|\bbot\b|agent", re.I)
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def scanner_findings(audit: dict) -> set[tuple[str, str, str, str]]:
    """Return {(advisory_id, package, version, kind)} from cargo-audit JSON."""
    found = set()
    vulns = audit.get("vulnerabilities")
    if not isinstance(vulns, dict) or not isinstance(vulns.get("list"), list):
        raise ValueError("cargo-audit JSON lacks vulnerabilities.list")
    if vulns.get("count") != len(vulns["list"]):
        raise ValueError("cargo-audit vulnerability count does not match list")
    for item in vulns["list"]:
        found.add((item["advisory"]["id"], item["package"]["name"],
                   item["package"]["version"], "vulnerability"))
    for kind, items in (audit.get("warnings") or {}).items():
        for item in items:
            advisory = item.get("advisory") or {}
            ident = advisory.get("id") or f"{kind.upper()}:{item['package']['name']}"
            found.add((ident, item["package"]["name"], item["package"]["version"], kind))
    return found


def check_approval(row: dict) -> None:
    approval = row.get("approval")
    if not isinstance(approval, dict):
        raise ValueError(f"{row['finding_id']}: {row['status']} requires an approval record")
    for field in APPROVAL_FIELDS:
        if not approval.get(field):
            raise ValueError(f"{row['finding_id']}: approval record missing {field}")
    if approval["approver_kind"] != "human":
        raise ValueError(f"{row['finding_id']}: approval must be a human decision")
    if AUTOMATED.search(str(approval["approver"])):
        raise ValueError(f"{row['finding_id']}: automated tooling cannot approve a disposition")
    if not SHA40.fullmatch(approval["reviewed_commit"]):
        raise ValueError(f"{row['finding_id']}: approval must name an exact reviewed commit")
    if not UTC.fullmatch(approval["approved_at_utc"]):
        raise ValueError(f"{row['finding_id']}: approval timestamp must be UTC ISO-8601")


def evaluate(matrix: dict, audits: dict[str, dict],
             locks: dict[str, dict[tuple[str, str], list[str]]]) -> dict:
    if matrix.get("schema") != SCHEMA:
        raise ValueError("unknown remediation matrix schema")
    if set(audits) != set(GRAPHS) or set(locks) != set(GRAPHS):
        raise ValueError("audit and lockfile evidence required for root, conductor and load")
    if matrix.get("production_release_ready") is not False:
        raise ValueError("matrix must not claim production readiness")
    rows = matrix.get("findings")
    if not isinstance(rows, list) or not rows:
        raise ValueError("matrix has no findings")
    keys = set()
    index: dict[tuple[str, str, str], dict] = {}
    for row in rows:
        key = (row["finding_id"], row["package"], row["version"])
        if key in keys:
            raise ValueError(f"duplicate matrix row {key}")
        keys.add(key)
        index[key] = row
        if row["status"] not in STATUSES:
            raise ValueError(f"{row['finding_id']}: invalid status {row['status']!r}")
        if row.get("proposed_disposition") not in PROPOSALS:
            raise ValueError(f"{row['finding_id']}: invalid proposed_disposition")
        graphs = row.get("graphs")
        if not graphs or not set(graphs) <= set(GRAPHS):
            raise ValueError(f"{row['finding_id']}: graphs must name root/conductor/load")
        if row["status"] in NEEDS_APPROVAL:
            check_approval(row)
        elif row.get("approval") is not None:
            raise ValueError(f"{row['finding_id']}: approval recorded on a non-approved status")

    # 1. Every scanner finding must be reviewed in the matrix for that graph.
    reported: dict[tuple[str, str, str], set[str]] = {}
    for graph, audit in audits.items():
        for ident, package, version, kind in scanner_findings(audit):
            row = index.get((ident, package, version))
            if row is None or graph not in row["graphs"]:
                raise ValueError(
                    f"unreviewed scanner finding {ident} {package}@{version} ({kind}) in {graph}")
            if row.get("kind") != kind:
                raise ValueError(f"{ident}: matrix kind {row.get('kind')!r} != scanner {kind!r}")
            reported.setdefault((ident, package, version), set()).add(graph)

    # 2. Matrix rows must agree with the current scan and current lockfiles.
    for key, row in index.items():
        ident, package, version = key
        locked = {g for g in row["graphs"] if (package, version) in locks[g]}
        if row["status"] == "PATCHED_AND_TESTED":
            if reported.get(key):
                raise ValueError(f"{ident}: PATCHED_AND_TESTED but scanner still reports it "
                                 f"in {sorted(reported[key])}")
            if locked:
                raise ValueError(f"{ident}: PATCHED_AND_TESTED but {package}@{version} still "
                                 f"locked in {sorted(locked)}")
            fixed = row.get("fixed_version")
            if not fixed or not all((package, fixed) in locks[g] for g in row["graphs"]):
                raise ValueError(f"{ident}: fixed_version {fixed!r} not locked in every graph")
            if not row.get("tests") or not row.get("remediation_commit"):
                raise ValueError(f"{ident}: PATCHED_AND_TESTED requires tests and a commit")
        elif row.get("source") == "rustsec":
            if locked != set(row["graphs"]):
                raise ValueError(f"{ident}: stale row; {package}@{version} locked only in "
                                 f"{sorted(locked)} but matrix lists {sorted(row['graphs'])}")
            if reported.get(key, set()) != set(row["graphs"]):
                raise ValueError(f"{ident}: stale row; scanner reports it in "
                                 f"{sorted(reported.get(key, set()))}")
        else:
            # Manual (non-RustSec) findings: scanners cannot see them, so
            # require the reviewed package/version to be locked as recorded.
            if locked != set(row["graphs"]):
                raise ValueError(f"{ident}: manual finding {package}@{version} not locked in "
                                 f"{sorted(set(row['graphs']) - locked)}")

    blocking = [r for r in rows if r["status"] not in CLEARING]
    hypothetical_unclearable = [r for r in rows
                                if r["status"] not in CLEARING
                                and r["proposed_disposition"] not in CLEARING]
    return {
        "schema": "hc-vtime/sprint37-supply-chain-gate-result/v1",
        "gate": "CLEAR" if not blocking else "BLOCKED",
        "finding_count": len(rows),
        "status_counts": {s: sum(r["status"] == s for r in rows) for s in sorted(STATUSES)},
        "blocking_findings": [
            {"finding_id": r["finding_id"], "package": r["package"], "version": r["version"],
             "kind": r["kind"], "severity": r["severity"], "status": r["status"],
             "proposed_disposition": r["proposed_disposition"]}
            for r in blocking
        ],
        "scanner_findings_reviewed": sum(len(g) for g in reported.values()),
        "hypothetical_if_all_proposals_approved": {
            "label": "HYPOTHETICAL — NOT AN APPROVAL",
            "would_clear": not hypothetical_unclearable,
            "still_blocking": sorted({r["finding_id"] for r in hypothetical_unclearable}),
        },
        "approvals_recorded": sum(r["status"] in NEEDS_APPROVAL for r in rows),
        "production_release_ready": False,
    }


def git_head(repo: Path) -> str:
    p = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "HEAD^{commit}"],
                       capture_output=True, text=True, check=True, timeout=30)
    return p.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--matrix", type=Path,
                        default=Path("docs/security/sprint37_remediation_matrix.json"))
    parser.add_argument("--audit", action="append", default=[], metavar="GRAPH=PATH",
                        help="cargo audit --json output; repeat for root, conductor, load")
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="JSON result written OUTSIDE the checkout")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    output = args.output.resolve()
    if output == repo or repo in output.parents:
        print("result must be written outside the checkout", file=sys.stderr)
        return 3
    try:
        head = git_head(repo)
        if not SHA40.fullmatch(args.expected_sha) or head != args.expected_sha:
            raise ValueError("HEAD does not equal the requested exact commit SHA")
        audits = {}
        for item in args.audit:
            graph, _, path = item.partition("=")
            if graph not in GRAPHS or not path or graph in audits:
                raise ValueError(f"invalid --audit {item!r}")
            audits[graph] = json.loads(Path(path).read_text(encoding="utf-8"))
        locks = {g: s36a.parse_lock((repo / p).read_bytes()) for g, p in GRAPHS.items()}
        matrix_path = args.matrix if args.matrix.is_absolute() else repo / args.matrix
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        result = evaluate(matrix, audits, locks)
        result["source_commit_sha"] = head
        code = 0 if result["gate"] == "CLEAR" else 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        result = {"gate": "INVALID", "reason": str(exc), "production_release_ready": False}
        code = 3
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"gate": result["gate"], "reason": result.get("reason"),
                      "blocking": len(result.get("blocking_findings", []))}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
