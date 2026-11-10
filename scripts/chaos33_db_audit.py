#!/usr/bin/env python3
"""Sprint 33: integrity audit of a STOPPED conductor database snapshot.

Never corrupt a running data root. This checks copy manifests and SQLite
integrity; it is NOT a Holochain-native validation of signed DHT evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

SCHEMA = "hc-vtime/chaos33-offline-db-audit/v1"


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for piece in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(piece)
    return result.hexdigest()


def entries(root: Path) -> dict[str, dict]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("snapshot must be a regular directory, not a symlink")
    result = {}
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink():
            raise ValueError(f"symlink in data snapshot: {candidate.relative_to(root)}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise ValueError("non-regular snapshot node")
        relative = candidate.relative_to(root).as_posix()
        result[relative] = {"bytes": candidate.stat().st_size, "sha256": digest(candidate)}
    if not result:
        raise ValueError("empty snapshot")
    return result


def capture(root: Path) -> dict:
    return {"schema": SCHEMA, "snapshot_files": entries(root),
            "note": "offline checksum baseline, not an author-chain or Holochain safety proof"}


def sqlite_check(path: Path) -> tuple[bool, str]:
    # Open a stopped snapshot only, never a live conductor SQLite database.
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        try:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
            ok = rows == [("ok",)]
            return ok, "ok" if ok else "sqlite integrity_check failed"
        finally:
            connection.close()
    except sqlite3.DatabaseError:
        return False, "sqlite unreadable/corrupt"


def verify(root: Path, manifest: dict, check_sqlite: bool = True) -> dict:
    errors = []
    if manifest.get("schema") != SCHEMA or not isinstance(manifest.get("snapshot_files"), dict):
        return {"schema": SCHEMA, "status": "BLOCKED", "problems": ["invalid baseline manifest"],
                "database_restored": False, "release_approved": False}
    try:
        current = entries(root)
    except (OSError, ValueError) as error:
        return {"schema": SCHEMA, "status": "BLOCKED", "problems": [str(error)],
                "database_restored": False, "release_approved": False}
    baseline = manifest["snapshot_files"]
    if baseline != current:
        errors.append("snapshot files or content differ from the recorded stopped baseline")
    checks = {}
    for relative in sorted(current):
        if check_sqlite and Path(relative).suffix.lower() in (".sqlite", ".sqlite3", ".db"):
            checks[relative] = sqlite_check(root / relative)[0]
            if not checks[relative]:
                errors.append(f"SQLite integrity failed for {relative}")
    return {
        "schema": SCHEMA, "status": "BLOCKED" if errors else "OFFLINE_SNAPSHOT_INTACT",
        "problems": errors, "files_checked": len(current), "sqlite_integrity": checks,
        "database_restored": False, "holochain_startup_verified": False,
        "signed_chain_integrity_proven": False, "release_approved": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="STOPPED disposable DB snapshot")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capture", action="store_true")
    group.add_argument("--manifest", type=Path, help="prior capture manifest to verify")
    args = parser.parse_args(argv)
    try:
        if args.capture:
            result = capture(args.root)
        else:
            result = verify(args.root, json.loads(args.manifest.read_text()))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        result = {"schema": SCHEMA, "status": "BLOCKED", "problems": [str(error)],
                  "release_approved": False}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in (None, "OFFLINE_SNAPSHOT_INTACT") else 3


if __name__ == "__main__":
    sys.exit(main())
