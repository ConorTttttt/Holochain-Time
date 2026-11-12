#!/usr/bin/env python3
"""Conductor data-root and restore-set guard (Sprint 38 SQLCipher controls).

Compensating controls for inherited SQLite/SQLCipher findings
(RUSTSEC-2026-0459 / CVE-2026-119375 and HCVT-S37-SQLCIPHER-CORE). They reduce
the chance that the conductor opens a database or ``-wal`` file written by a
less-trusted party. They do NOT patch SQLite and do not clear any finding.

Read-only. This tool never modifies, deletes or moves files; the only file it
writes is an explicitly requested JSON report or manifest.

Subcommands
  audit-root DIR         permissions/ownership audit of a live data root
  make-manifest DIR      SHA-256 manifest of a (WAL-checkpointed) backup set
  verify-restore DIR     validate a backup set against its manifest before restore

Exit codes: 0 pass, 2 violations found, 3 invalid input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SCHEMA_REPORT = "hc-vtime/datastore-guard-report/v1"
SCHEMA_MANIFEST = "hc-vtime/restore-set-manifest/v1"
# SQLite side files that must never accompany a restore set: a sibling -wal is
# the input of CVE-2026-119375, and -shm/-journal carry uncheckpointed state.
SIDE_FILE = re.compile(r"(-wal|-shm|-journal|\.wal|\.shm)\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SQLITE_MAGIC = b"SQLite format 3\x00"
# Holochain applies cipher_plaintext_header_size=32, so an encrypted database
# still begins with the plaintext SQLite header.


class GuardError(ValueError):
    """Invalid input (exit 3)."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def walk(root: Path):
    """Yield (path, lstat) for every entry below root, never following links."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError as exc:
            raise GuardError(f"cannot list {current}: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            info = path.lstat()
            yield path, info
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)


def audit_root(root: Path, expect_uid: int) -> list[str]:
    try:
        info = root.lstat()
    except OSError as exc:
        raise GuardError(f"cannot stat data root {root}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise GuardError(f"data root {root} is not a directory (or is a symlink)")
    problems = []

    def check(path: Path, st: os.stat_result) -> None:
        rel = "." if path == root else str(path.relative_to(root))
        mode = stat.S_IMODE(st.st_mode)
        if st.st_uid != expect_uid:
            problems.append(f"{rel}: owned by uid {st.st_uid}, expected {expect_uid}")
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{rel}: symlink inside data root")
        elif stat.S_ISDIR(st.st_mode):
            if mode & 0o077:
                problems.append(f"{rel}: directory mode {mode:04o} grants group/other access (want 0700)")
        elif stat.S_ISREG(st.st_mode):
            if mode & 0o077:
                problems.append(f"{rel}: file mode {mode:04o} grants group/other access (want 0600)")
            if st.st_nlink > 1:
                problems.append(f"{rel}: regular file has {st.st_nlink} hard links")
        else:
            problems.append(f"{rel}: unexpected file type in data root")

    check(root, info)
    for path, st in walk(root):
        check(path, st)
    return problems


def make_manifest(backup: Path) -> dict:
    files = {}
    problems = []
    for path, st in walk(backup):
        rel = path.relative_to(backup).as_posix()
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{rel}: not a regular file")
            continue
        if SIDE_FILE.search(rel):
            problems.append(f"{rel}: SQLite side file present; checkpoint (PRAGMA "
                            "wal_checkpoint(TRUNCATE)) and stop writers before backup")
            continue
        files[rel] = sha256_file(path)
    if problems:
        raise GuardError("; ".join(problems))
    if not files:
        raise GuardError("backup set is empty")
    return {"schema": SCHEMA_MANIFEST, "files": files,
            "wal_checkpointed_by_operator": True}


def safe_rel(rel: str) -> bool:
    pure = PurePosixPath(rel)
    return (bool(rel) and not pure.is_absolute() and ".." not in pure.parts
            and "\\" not in rel and pure.as_posix() == rel)


def verify_restore(backup: Path, manifest: dict) -> list[str]:
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA_MANIFEST:
        raise GuardError("unknown restore manifest schema")
    listed = manifest.get("files")
    if not isinstance(listed, dict) or not listed:
        raise GuardError("manifest lists no files")
    if manifest.get("wal_checkpointed_by_operator") is not True:
        raise GuardError("manifest does not declare a WAL-checkpointed backup")
    problems = []
    for rel, digest in listed.items():
        if not isinstance(rel, str) or not safe_rel(rel):
            problems.append(f"manifest path {rel!r} is not a safe relative path")
        elif SIDE_FILE.search(rel):
            problems.append(f"manifest lists SQLite side file {rel}")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            problems.append(f"manifest digest for {rel!r} is not lowercase SHA-256")
    if problems:
        return problems
    seen = set()
    for path, st in walk(backup):
        rel = path.relative_to(backup).as_posix()
        if stat.S_ISDIR(st.st_mode):
            continue
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{rel}: symlink in restore set")
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{rel}: not a regular file")
            continue
        if SIDE_FILE.search(rel):
            problems.append(f"{rel}: stray SQLite side file; refusing restore")
            continue
        if rel not in listed:
            problems.append(f"{rel}: not listed in manifest")
            continue
        seen.add(rel)
        if sha256_file(path) != listed[rel]:
            problems.append(f"{rel}: SHA-256 mismatch")
            continue
        if rel.endswith((".sqlite3", ".sqlite", ".db")):
            with path.open("rb") as handle:
                header = handle.read(100)
            if len(header) < 100 or not header.startswith(SQLITE_MAGIC):
                problems.append(f"{rel}: missing SQLite plaintext header")
    for rel in sorted(set(listed) - seen):
        if not any(p.startswith(f"{rel}: ") for p in problems):
            problems.append(f"{rel}: listed in manifest but missing from restore set")
    return problems


def emit(report: dict, output: Path | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output:
        output.write_text(text)
    print(text, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit-root")
    a.add_argument("root", type=Path)
    a.add_argument("--expect-uid", type=int, default=os.getuid())
    a.add_argument("--output", type=Path)
    m = sub.add_parser("make-manifest")
    m.add_argument("backup", type=Path)
    m.add_argument("--output", type=Path, required=True)
    v = sub.add_parser("verify-restore")
    v.add_argument("backup", type=Path)
    v.add_argument("--manifest", type=Path, required=True)
    v.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "audit-root":
            problems = audit_root(args.root, args.expect_uid)
            emit({"schema": SCHEMA_REPORT, "command": "audit-root", "root": str(args.root),
                  "violations": problems,
                  "result": "FAIL" if problems else "PASS"}, args.output)
            return 2 if problems else 0
        if args.command == "make-manifest":
            if not args.backup.is_dir() or args.backup.is_symlink():
                raise GuardError("backup path must be a real directory")
            manifest = make_manifest(args.backup)
            args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            print(json.dumps({"schema": SCHEMA_REPORT, "command": "make-manifest",
                              "files": len(manifest["files"]), "result": "PASS"}))
            return 0
        if not args.backup.is_dir() or args.backup.is_symlink():
            raise GuardError("restore set must be a real directory")
        try:
            manifest = json.loads(args.manifest.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise GuardError(f"cannot read manifest: {exc}") from exc
        problems = verify_restore(args.backup, manifest)
        emit({"schema": SCHEMA_REPORT, "command": "verify-restore",
              "backup": str(args.backup), "violations": problems,
              "result": "FAIL" if problems else "PASS"}, args.output)
        return 2 if problems else 0
    except GuardError as exc:
        print(json.dumps({"schema": SCHEMA_REPORT, "result": "INVALID", "reason": str(exc)}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
