#!/usr/bin/env python3
"""Sprint 36B lockfile/manifest/source checks, independent of cargo-deny.

This is defense in depth, not a legal license verifier or cargo-audit substitute.
Unexpected registry/git/path/patch origins fail; version upgrades remain possible.
"""
from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

ROOT_GRAPH = "Cargo.lock"
GRAPHS = {
    ROOT_GRAPH: frozenset({"unyt_harness", "vtime", "vtime_core",
                           "vtime_oracle_state", "vtime_integrity"}),
    "integration/conductor/Cargo.lock": frozenset(
        {"hc-vtime-conductor-smoke", "vtime_core"}),
    "integration/load/Cargo.lock": frozenset(
        {"hc-vtime-conductor-smoke", "vtime_core"}),
}
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
REVIEWED_LICENSE_TOKENS = frozenset({
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unicode-3.0", "Zlib",
})
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SPDX_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*")


def packages_from_lock(data: str) -> list[dict]:
    doc = tomllib.loads(data)
    pkgs = doc.get("package")
    if not isinstance(pkgs, list) or not pkgs:
        raise ValueError("lockfile has no [[package]] records")
    if len(pkgs) != len({(p.get("name"), p.get("version"), p.get("source"))
                         for p in pkgs}):
        raise ValueError("duplicate package identity in lockfile")
    return pkgs


def inspect_lock(data: str, graph: str) -> list[str]:
    """Return enforceable source findings; do not infer licenses from Cargo.lock."""
    if graph not in GRAPHS:
        raise ValueError("unknown dependency graph")
    findings = []
    local = set()
    for p in packages_from_lock(data):
        name, ver, origin = p.get("name"), p.get("version"), p.get("source")
        ident = f"{name}@{ver}"
        if not isinstance(name, str) or not isinstance(ver, str):
            findings.append(f"INVALID_PACKAGE_ID:{ident}")
            continue
        if origin is None:
            local.add(name)
            if name not in GRAPHS[graph]:
                findings.append(f"UNAPPROVED_PATH_OR_LOCAL:{graph}:{ident}")
            if "checksum" in p:
                findings.append(f"UNEXPECTED_LOCAL_CHECKSUM:{graph}:{ident}")
        else:
            if origin != CRATES_IO:
                findings.append(f"UNAPPROVED_SOURCE:{graph}:{ident}:{origin}")
            checksum = p.get("checksum")
            if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
                findings.append(f"MISSING_OR_BAD_CHECKSUM:{graph}:{ident}")
    missing = GRAPHS[graph] - local
    for name in sorted(missing):
        findings.append(f"EXPECTED_LOCAL_PACKAGE_MISSING:{graph}:{name}")
    return findings


def inspect_manifest(doc: dict, file: Path, root: Path) -> list[str]:
    errors: list[str] = []
    for key in ("patch", "replace"):
        if doc.get(key):
            errors.append(f"UNREVIEWED_SOURCE_SUBSTITUTION:{file}:{key}")

    def inspect_deps(deps: object, scope: str) -> None:
        if not isinstance(deps, dict):
            return
        for name, item in deps.items():
            if not isinstance(item, dict):
                continue
            if "git" in item or "registry" in item or "registry-index" in item:
                errors.append(f"UNREVIEWED_DEPENDENCY_ORIGIN:{file}:{scope}:{name}")
            if "path" in item:
                path = item["path"]
                if not isinstance(path, str):
                    errors.append(f"INVALID_PATH:{file}:{scope}:{name}")
                    continue
                dest = (file.parent / path).resolve()
                if not dest.is_relative_to(root.resolve()) or not (dest / "Cargo.toml").is_file():
                    errors.append(f"UNAPPROVED_EXTERNAL_OR_MISSING_PATH:{file}:{scope}:{name}")

    for dep_scope in ("dependencies", "dev-dependencies", "build-dependencies"):
        inspect_deps(doc.get(dep_scope), dep_scope)
        workspace = doc.get("workspace", {})
        if isinstance(workspace, dict):
            inspect_deps(workspace.get(dep_scope), "workspace." + dep_scope)
    target = doc.get("target", {})
    if isinstance(target, dict):
        for condition, table in target.items():
            if isinstance(table, dict):
                for scope in ("dependencies", "dev-dependencies", "build-dependencies"):
                    inspect_deps(table.get(scope), f"target.{condition}.{scope}")
    return errors


def inspect_manifests(root: Path) -> list[str]:
    result: list[str] = []
    names = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                           check=True, capture_output=True).stdout.decode().split("\0")
    for name in sorted(n for n in names if n == "Cargo.toml" or n.endswith("/Cargo.toml")):
        path = root / name
        try:
            result.extend(inspect_manifest(tomllib.loads(path.read_text()), path, root))
        except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
            result.append(f"INVALID_MANIFEST:{name}:{type(e).__name__}")
    return result


def review_expression(expression: str | None) -> str:
    """Additional owner review; never claim SPDX parser correctness."""
    if not expression:
        return "UNKNOWN_MISSING_METADATA"
    tokens = [x for x in SPDX_TOKEN.findall(expression) if x not in ("AND", "OR", "WITH")]
    if not tokens or any(t not in REVIEWED_LICENSE_TOKENS for t in tokens):
        return "REVIEW_REQUIRED_UNLISTED_OR_INVALID_EXPRESSION"
    if "OR" in SPDX_TOKEN.findall(expression):
        return "REVIEW_REQUIRED_ALTERNATIVE_EXPRESSION"
    return "PROPOSED_POLICY_MATCH_APPROVAL_PENDING"


def check_policy_text(text: str) -> list[str]:
    """Guard against silent broadening of an unapproved policy."""
    doc = tomllib.loads(text)
    errors = []
    licenses, advisories, sources = (doc.get(k, {}) for k in
                                    ("licenses", "advisories", "sources"))
    if set(licenses.get("allow", [])) != REVIEWED_LICENSE_TOKENS:
        errors.append("LICENSE_ALLOWLIST_CHANGED_REVIEW_REQUIRED")
    if licenses.get("exceptions") != [] or licenses.get("private", {}).get("ignore") is not False:
        errors.append("UNAUTHORIZED_EXCEPTION_OR_PRIVATE_BYPASS")
    if licenses.get("confidence-threshold", 0) < 0.93:
        errors.append("LICENSE_CONFIDENCE_WEAKENED")
    if licenses.get("include-dev") is not True or licenses.get("include-build") is not True:
        errors.append("LICENSE_DEPENDENCY_SCOPE_WEAKENED")
    if advisories.get("ignore") != []:
        errors.append("RUSTSEC_IGNORES_NOT_AUTHORIZED")
    if advisories.get("unmaintained") != "all" or advisories.get("unsound") != "all":
        errors.append("ADVISORY_SCOPE_WEAKENED")
    if sources.get("unknown-registry") != "deny" or sources.get("unknown-git") != "deny":
        errors.append("UNREVIEWED_SOURCES_ALLOWED")
    if sources.get("allow-registry") != [CRATES_IO.replace("registry+", "")] or sources.get("allow-git") != []:
        errors.append("SOURCE_ALLOWLIST_CHANGED_REVIEW_REQUIRED")
    if sources.get("required-git-spec") != "rev":
        errors.append("GIT_SOURCE_PINNING_WEAKENED")
    return errors
