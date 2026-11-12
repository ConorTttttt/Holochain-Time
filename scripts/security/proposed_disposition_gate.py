#!/usr/bin/env python3
"""PROPOSED (inactive) reviewed-disposition policy for ``s35_supply_chain``.

**Not wired into any gate. Not approved.** The current gate keeps enforcing
raw scanner exit codes. This evaluator exists so the owner can review an
alternative policy and its tests. It stays fail-closed: without a human
activation record bound to this policy file and the evaluated commit, every
result is ``BLOCKED``.

On top of the Sprint 37 evaluator (unreviewed scanner findings, automated
approvers, stale rows and malformed approvals are all rejected there), it
requires:

* scanner outputs for every graph: ``cargo audit --json`` plus separate
  ``cargo deny check {advisories,licenses,bans,sources}`` exit codes and
  scanner versions. A missing scanner is INVALID. License, ban and source
  failures are never waived by this policy;
* every approval is bound to the exact evaluated commit, has an unexpired
  ``expires_at_utc``, names the same finding/package/version, approves the
  row's status, and its ``scope.graphs`` covers every graph where the
  scanner reports the finding;
* raw scanner artefacts are preserved by SHA-256 and raw exit code in the
  result;
* each evaluation appends a hash-chained entry to an append-only history
  file, after verifying the existing chain;
* patched findings, not-applicable findings and accepted residual risk are
  reported separately.

Exit codes: 0 CLEAR (only possible with an active policy), 2 BLOCKED, 3 INVALID.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sprint37_supply_chain_gate as s37  # type: ignore[import-not-found]
    import sprint36a_validate as s36a  # type: ignore[import-not-found]
else:  # pragma: no cover
    from . import sprint37_supply_chain_gate as s37
    from . import sprint36a_validate as s36a

SCHEMA = "hc-vtime/proposed-disposition-gate-result/v1"
ACTIVATION_SCHEMA = "hc-vtime/disposition-policy-activation/v1"
HISTORY_SCHEMA = "hc-vtime/disposition-gate-history/v1"
DENY_CHECKS = ("advisories", "licenses", "bans", "sources")
NEVER_WAIVED = ("licenses", "bans", "sources")
SCANNERS = ("cargo-audit", "cargo-deny")


class PolicyError(ValueError):
    """Invalid input or evidence (exit 3)."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_utc(text: str, what: str) -> datetime:
    if not isinstance(text, str) or not s37.UTC.fullmatch(text):
        raise PolicyError(f"{what} must be UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def check_activation(activation: dict | None, policy_sha: str, sha: str,
                     now: datetime) -> tuple[bool, str]:
    """Return (active, reason). Inactive is the default, not an error."""
    if activation is None:
        return False, "no activation record: proposed policy is INACTIVE"
    if activation.get("schema") != ACTIVATION_SCHEMA:
        raise PolicyError("unknown activation record schema")
    for field in ("approver", "approver_kind", "role", "approved_at_utc",
                  "policy_sha256", "reviewed_commit", "expires_at_utc"):
        if not activation.get(field):
            raise PolicyError(f"activation record missing {field}")
    if activation["approver_kind"] != "human" or s37.AUTOMATED.search(str(activation["approver"])):
        raise PolicyError("activation must be a human decision")
    if activation["policy_sha256"] != policy_sha:
        raise PolicyError("activation is for a different policy file")
    if activation["reviewed_commit"] != sha:
        raise PolicyError("activation is for a different source commit")
    parse_utc(activation["approved_at_utc"], "activation approved_at_utc")
    if parse_utc(activation["expires_at_utc"], "activation expires_at_utc") <= now:
        raise PolicyError("activation record expired")
    return True, "active"


def check_scanners(scans: dict) -> dict:
    """Validate per-graph scanner evidence; return raw-result summary."""
    if set(scans) != set(s37.GRAPHS):
        raise PolicyError("scanner evidence required for exactly root, conductor and load")
    raw = {}
    for graph, scan in scans.items():
        versions = scan.get("scanner_versions") or {}
        missing = [s for s in SCANNERS if not versions.get(s)]
        if missing:
            raise PolicyError(f"{graph}: missing scanner {missing}")
        deny = scan.get("deny_exit_codes") or {}
        if set(deny) != set(DENY_CHECKS) or not all(type(v) is int for v in deny.values()):
            raise PolicyError(f"{graph}: cargo-deny exit codes required for {DENY_CHECKS}")
        if type(scan.get("audit_exit_code")) is not int:
            raise PolicyError(f"{graph}: cargo-audit exit code missing")
        if not isinstance(scan.get("audit"), dict):
            raise PolicyError(f"{graph}: cargo-audit JSON missing")
        raw[graph] = {"audit_exit_code": scan["audit_exit_code"],
                      "deny_exit_codes": deny, "scanner_versions": versions,
                      "artifact_sha256": scan.get("artifact_sha256", {})}
    return raw


def check_approval_binding(row: dict, sha: str, now: datetime, reported_graphs: set[str]) -> None:
    approval = row["approval"]
    ident = row["finding_id"]
    if approval["reviewed_commit"] != sha:
        raise PolicyError(f"{ident}: approval is for commit {approval['reviewed_commit']}, not {sha}")
    if parse_utc(approval.get("expires_at_utc", ""), f"{ident} expires_at_utc") <= now:
        raise PolicyError(f"{ident}: approval expired")
    if parse_utc(approval["approved_at_utc"], f"{ident} approved_at_utc") > now:
        raise PolicyError(f"{ident}: approval dated in the future")
    scope = approval.get("scope")
    if not isinstance(scope, dict):
        raise PolicyError(f"{ident}: approval scope must be an object")
    for field in ("finding_id", "package", "version", "status"):
        if scope.get(field) != row[field]:
            raise PolicyError(f"{ident}: approval scope {field} does not match the finding")
    graphs = scope.get("graphs")
    if not isinstance(graphs, list) or not reported_graphs <= set(graphs):
        raise PolicyError(f"{ident}: scanner reports it in {sorted(reported_graphs)}, outside "
                          f"approved scope {graphs}")


def evaluate(matrix: dict, scans: dict, locks: dict, sha: str, policy_sha: str,
             activation: dict | None, now: datetime) -> dict:
    raw = check_scanners(scans)
    audits = {g: s["audit"] for g, s in scans.items()}
    try:
        base = s37.evaluate(matrix, audits, locks)  # rejects new/unreviewed findings
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    reported: dict[str, set[str]] = {}
    for graph, audit in audits.items():
        for ident, _pkg, _ver, _kind in s37.scanner_findings(audit):
            reported.setdefault(ident, set()).add(graph)
    for row in matrix["findings"]:
        if row["status"] in s37.NEEDS_APPROVAL:
            check_approval_binding(row, sha, now, reported.get(row["finding_id"], set()))
    active, reason = check_activation(activation, policy_sha, sha, now)
    waived_failures = {g: [c for c in NEVER_WAIVED if r["deny_exit_codes"][c] != 0]
                       for g, r in raw.items()}
    hard_fail = {g: c for g, c in waived_failures.items() if c}
    by = lambda status: sorted(r["finding_id"] for r in matrix["findings"] if r["status"] == status)
    clear = active and base["gate"] == "CLEAR" and not hard_fail
    return {
        "schema": SCHEMA,
        "policy_status": "ACTIVE" if active else "PROPOSED_INACTIVE",
        "policy_reason": reason,
        "gate": "CLEAR" if clear else "BLOCKED",
        "source_commit_sha": sha,
        "policy_sha256": policy_sha,
        "raw_scanner_results": raw,
        "non_advisory_deny_failures": hard_fail,
        "patched_and_tested": by("PATCHED_AND_TESTED"),
        "not_applicable_approved": by("NOT_APPLICABLE_WITH_APPROVED_EVIDENCE"),
        "accepted_residual_risk": by("FORMALLY_ACCEPTED_RESIDUAL_RISK"),
        "blocking_findings": [b["finding_id"] for b in base["blocking_findings"]],
        "approvals_recorded": base["approvals_recorded"],
        "production_release_ready": False,
    }


def append_history(path: Path, result: dict, now: datetime) -> str:
    """Verify the hash chain in ``path`` and append one entry. Returns entry hash."""
    prev = "0" * 64
    if path.exists():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            entry = json.loads(line)
            body = {k: v for k, v in entry.items() if k != "entry_sha256"}
            if entry.get("schema") != HISTORY_SCHEMA or body.get("prev_sha256") != prev:
                raise PolicyError(f"history line {number}: broken hash chain")
            digest = sha256_bytes(json.dumps(body, sort_keys=True).encode())
            if digest != entry.get("entry_sha256"):
                raise PolicyError(f"history line {number}: entry altered")
            prev = digest
    body = {"schema": HISTORY_SCHEMA, "prev_sha256": prev,
            "recorded_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "result_sha256": sha256_bytes(json.dumps(result, sort_keys=True).encode()),
            "gate": result.get("gate"), "policy_status": result.get("policy_status"),
            "source_commit_sha": result.get("source_commit_sha"),
            "reason": result.get("reason")}
    digest = sha256_bytes(json.dumps(body, sort_keys=True).encode())
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({**body, "entry_sha256": digest}, sort_keys=True) + "\n")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--scan", action="append", default=[], metavar="GRAPH=PATH",
                        help="scan evidence JSON (audit, exit codes, versions) per graph")
    parser.add_argument("--activation", type=Path, help="human policy activation record")
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    repo = args.repo.resolve()
    try:
        for target in (args.output.resolve(), args.history.resolve()):
            if target == repo or repo in target.parents:
                raise PolicyError("result and history must be written outside the checkout")
        head = s37.git_head(repo)
        if not s37.SHA40.fullmatch(args.expected_sha) or head != args.expected_sha:
            raise PolicyError("HEAD does not equal the requested exact commit SHA")
        scans = {}
        for item in args.scan:
            graph, _, path = item.partition("=")
            if graph not in s37.GRAPHS or graph in scans or not path:
                raise PolicyError(f"invalid --scan {item!r}")
            scans[graph] = json.loads(Path(path).read_text(encoding="utf-8"))
        locks = {g: s36a.parse_lock((repo / p).read_bytes()) for g, p in s37.GRAPHS.items()}
        matrix = json.loads(args.matrix.read_text(encoding="utf-8"))
        activation = json.loads(args.activation.read_text()) if args.activation else None
        policy_sha = sha256_bytes(Path(__file__).read_bytes())
        result = evaluate(matrix, scans, locks, head, policy_sha, activation, now)
        code = 0 if result["gate"] == "CLEAR" else 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"schema": SCHEMA, "gate": "INVALID", "reason": str(exc),
                  "source_commit_sha": args.expected_sha, "production_release_ready": False}
        code = 3
    try:
        append_history(args.history, result, now)
    except (OSError, ValueError) as exc:
        result = {"schema": SCHEMA, "gate": "INVALID", "reason": f"history: {exc}",
                  "production_release_ready": False}
        code = 3
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"gate": result["gate"], "policy_status": result.get("policy_status"),
                      "reason": result.get("reason")}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
