#!/usr/bin/env python3
"""Per-artifact third-party license inventory (Sprint 37, distribution view).

The Sprint 36B inventory lists every package in each lockfile. Licensing
obligations, however, attach to what is actually *distributed*. This tool
computes, for each shipped artifact root, the closure of crates compiled into
it for its real target: normal dependencies only, excluding dev/build
dependencies and proc-macro crates (which execute on the build host and are
not linked into the artifact).

The result is an inventory for human/legal review. It never approves a
license, never elects an alternative on the owner's behalf and never grants
a license for this project's own code.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys

ARTIFACTS = {
    # artifact root crate -> (target triple, distribution form)
    "vtime_integrity": ("wasm32-unknown-unknown", "WASM zome inside DNA/hApp bundle"),
    "vtime": ("wasm32-unknown-unknown", "WASM zome inside DNA/hApp bundle"),
    "vtime_core": ("x86_64-unknown-linux-gnu", "native library for operator services"),
    "vtime_oracle_state": ("x86_64-unknown-linux-gnu", "native library for operator services"),
}
# Proposed (NOT approved) baseline from deny.toml, Sprint 36B.
PROPOSED_ALLOW = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC",
                  "Unicode-3.0", "Zlib"}
COPYLEFT = {"CAL-1.0": "network copyleft (legal review required)",
            "MPL-2.0": "file-level weak copyleft",
            "MPL-2.0+": "file-level weak copyleft",
            "LGPL-2.1": "weak copyleft", "LGPL-3.0": "weak copyleft",
            "GPL-2.0": "strong copyleft", "GPL-3.0": "strong copyleft",
            "AGPL-3.0": "network strong copyleft", "CDDL-1.0": "file-level weak copyleft"}
NOTICE_REQUIRED = {"BSD-2-Clause", "BSD-3-Clause", "MIT", "ISC", "Zlib", "Unicode-3.0",
                   "Apache-2.0", "CAL-1.0", "MPL-2.0", "BSD-2-Clause-Patent"}
NOTICE_FILE = re.compile(r"^(notice|copyright|authors|third[-_]party)", re.I)
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|unlicense)", re.I)
TOKEN = re.compile(r"[A-Za-z0-9.\-+]+(?: WITH [A-Za-z0-9.\-]+)?")


@dataclass(frozen=True)
class Crate:
    name: str
    version: str
    license: str | None
    repository: str | None
    source: str | None
    manifest_path: str


def license_ids(expr: str | None) -> list[str]:
    if not expr:
        return []
    normalised = expr.replace("/", " OR ").replace("(", " ").replace(")", " ")
    return [t for t in TOKEN.findall(normalised) if t not in ("OR", "AND")]


def classify(expr: str | None) -> dict:
    """Describe review needs; NEVER chooses an alternative for the owner."""
    ids = license_ids(expr)
    if not ids:
        return {"review": "UNKNOWN_MISSING_METADATA", "copyleft": [], "election_needed": False}
    copyleft = sorted({i for i in ids if i in COPYLEFT})
    is_or = (" OR " in (expr or "") or "/" in (expr or "")) and " AND " not in (expr or "")
    outside = sorted(set(ids) - PROPOSED_ALLOW)
    if is_or and any(i in PROPOSED_ALLOW for i in ids):
        review = "ALTERNATIVE_ELECTION_REQUIRED" if outside else "ALTERNATIVE_WITHIN_PROPOSED_ALLOWLIST"
    elif outside:
        review = "OUTSIDE_PROPOSED_ALLOWLIST"
    else:
        review = "WITHIN_PROPOSED_ALLOWLIST"
    return {"review": review, "copyleft": copyleft if not is_or else [],
            "election_needed": is_or and len(ids) > 1,
            "outside_proposed_allowlist": outside}


def linked_closure(metadata: dict, root_name: str) -> list[Crate]:
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = [pid for pid, p in packages.items()
             if p["name"] == root_name and p.get("source") is None]
    if len(roots) != 1:
        raise ValueError(f"artifact root {root_name!r} not found exactly once in workspace")

    def proc_macro(pid: str) -> bool:
        return any("proc-macro" in t["kind"] for t in packages[pid]["targets"])

    seen: set[str] = set()
    stack = [roots[0]]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            kinds = [k.get("kind") for k in dep.get("dep_kinds", [])]
            if None not in kinds:      # dev / build only -> not linked
                continue
            if proc_macro(dep["pkg"]):  # executes on build host only
                continue
            stack.append(dep["pkg"])
    out = []
    for pid in seen:
        p = packages[pid]
        out.append(Crate(p["name"], p["version"], p.get("license"), p.get("repository"),
                         p.get("source"), p["manifest_path"]))
    return sorted(out, key=lambda c: (c.name, c.version))


def package_files(crate: Crate) -> tuple[list[str], list[str]]:
    folder = Path(crate.manifest_path).parent
    try:
        names = sorted(x.name for x in folder.iterdir() if x.is_file())
    except OSError:
        return [], []
    return ([n for n in names if LICENSE_FILE.match(n)],
            [n for n in names if NOTICE_FILE.match(n)])


def build_inventory(repo: Path, metadata_for) -> dict:
    artifacts = {}
    for root, (target, form) in ARTIFACTS.items():
        rows = []
        for crate in linked_closure(metadata_for(target), root):
            if crate.source is None:
                continue  # this project's own crates are covered by its own license decision
            license_files, notice_files = package_files(crate)
            rows.append({"crate": crate.name, "version": crate.version,
                         "license": crate.license, "repository": crate.repository,
                         "license_files_in_package": license_files,
                         "notice_files_in_package": notice_files,
                         **classify(crate.license)})
        artifacts[root] = {"target": target, "distribution_form": form,
                           "third_party_crates": rows}
    return {"schema": "hc-vtime/sprint37-artifact-licenses/v1",
            "approval": "LICENSE_POLICY_APPROVAL_PENDING",
            "legal_review_obtained": False,
            "alternatives_elected": False,
            "note": "Inventory for review only; no license, election or exception is approved",
            "artifacts": artifacts}


def cargo_metadata(repo: Path, target: str) -> dict:
    p = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1",
                        "--filter-platform", target],
                       cwd=repo, capture_output=True, text=True, check=True, timeout=600)
    return json.loads(p.stdout)


def render_markdown(inv: dict, sha: str) -> str:
    lines = [f"# Third-party licenses compiled into shipped artifacts — DRAFT",
             "", f"Generated from commit `{sha}` by `scripts/license37/artifact_licenses.py`.",
             "**Status: LICENSE_POLICY_APPROVAL_PENDING. Not legal advice; no election or "
             "exception approved.**", ""]
    for root, art in inv["artifacts"].items():
        rows = art["third_party_crates"]
        lines += [f"## `{root}` — {art['distribution_form']} (`{art['target']}`)", "",
                  f"{len(rows)} third-party crates.", "",
                  "| Crate | Version | License | Review | Notice files |",
                  "| --- | --- | --- | --- | --- |"]
        for r in rows:
            lines.append(f"| {r['crate']} | {r['version']} | {r['license'] or 'MISSING'} | "
                         f"{r['review']} | {', '.join(r['notice_files_in_package']) or '—'} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    out = args.output_dir.resolve()
    if out == repo or repo in out.parents:
        print("output must be outside the checkout", file=sys.stderr)
        return 3
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != args.expected_sha:
        print("HEAD does not equal --expected-sha", file=sys.stderr)
        return 3
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain",
                            "--untracked-files=all"],
                           capture_output=True, text=True, check=True).stdout.strip()
    if dirty:
        print("dirty checkout: exact-commit inventory requires a clean tree", file=sys.stderr)
        return 3
    cache: dict[str, dict] = {}
    inv = build_inventory(repo, lambda t: cache.setdefault(t, cargo_metadata(repo, t)))
    inv["source_commit_sha"] = head
    out.mkdir(parents=True, exist_ok=False)
    (out / "artifact-licenses.json").write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n")
    (out / "THIRD_PARTY_LICENSES.draft.md").write_text(render_markdown(inv, head))
    summary = {root: len(a["third_party_crates"]) for root, a in inv["artifacts"].items()}
    print(json.dumps({"status": "INVENTORY_GENERATED_NOT_APPROVED", "crates": summary}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
