#!/usr/bin/env python3
"""Sprint 34 authenticated, bounded local telemetry admission.

Per-producer HMAC authenticates the configured *telemetry emitter*, NOT a
Holochain warrant, oracle signature, independent operator or time proof.
Messages are accepted only into this separate authenticated journal. Sprint 25
raw event JSONL or imported diagnostic markers are never silently promoted.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any

sys.dont_write_bytecode = True
OPS = Path(__file__).resolve().parents[1] / "ops"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from events import (UnsafeEvent, json_unique, parse_time, validate_event,
                    make_event, require)

SCHEMA = "hc-vtime/ops-auth-frame/v1"
KEYRING_SCHEMA = "hc-vtime/ops-producers/v1"
ROLES = {
    "roughtime_probe": {"time_source_probe", "quorum_check", "heartbeat",
                        "signature_validation"},
    "oracle_runtime": {"oracle_sign", "oracle_state", "heartbeat",
                       "signature_validation"},
    "queue_runtime": {"seal_queue", "seal_retry", "heartbeat"},
    "seal_runtime": {"seal_submit", "heartbeat"},
    "conductor_observer": {"conductor", "fork_warrant", "heartbeat"},
}
ROLE_COMPONENTS = {
    "roughtime_probe": {"roughtime"},
    "oracle_runtime": {"oracle", "storage"},
    "queue_runtime": {"queue"},
    "seal_runtime": {"seal"},
    "conductor_observer": {"conductor", "dht"},
}
PRODUCER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FRAME_BYTES = 4096
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_FRAMES = 2048
MAX_PRODUCERS = 16
MAX_SKEW_SECONDS = 300
ZERO = "0" * 64
FRAME_FIELDS = {"schema", "producer", "seq", "prev_sha256", "event", "mac"}


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def strict_object(data: bytes) -> dict:
    try:
        parsed = json.loads(data, object_pairs_hook=json_unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                UnsafeEvent("nonfinite JSON value")))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise UnsafeEvent("invalid authenticated event JSON") from exc
    require(type(parsed) is dict, "authenticated event must be an object")
    return parsed


def private_file(path: Path, *, expected_mode: int = 0o600) -> None:
    path = Path(path)
    require(not path.is_symlink() and path.is_file(),
            "missing or symlinked private file")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and
            info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
            "private file must be current-user-owned mode 0600")
    parent = path.parent
    require(parent.is_dir() and not parent.is_symlink() and
            parent.stat().st_uid == os.geteuid() and
            (parent.stat().st_mode & 0o077) == 0,
            "private file directory must be owner-only (0700)")


def keyring(path: Path) -> dict[str, tuple[str, bytes]]:
    private_file(path)
    require(path.stat().st_size <= 32_768, "producer keyring too large")
    payload = strict_object(Path(path).read_bytes())
    require(set(payload) == {"schema", "producers"} and
            payload["schema"] == KEYRING_SCHEMA,
            "unrecognized producer keyring")
    entries = payload["producers"]
    require(type(entries) is dict and 1 <= len(entries) <= MAX_PRODUCERS,
            "producer keyring must define 1..16 emitters")
    authorized = {}
    secret_hashes = set()
    for producer, row in entries.items():
        require(type(producer) is str and PRODUCER.fullmatch(producer) and
                type(row) is dict and set(row) == {"role", "key_hex"},
                "invalid producer entry")
        role, secret = row["role"], row["key_hex"]
        require(type(role) is str and role in ROLES and
                type(secret) is str and HEX64.fullmatch(secret),
                "invalid role or 256-bit key encoding")
        key = bytes.fromhex(secret)
        digest = hashlib.sha256(key).digest()
        require(digest not in secret_hashes,
                "telemetry keys must not be shared between producers")
        secret_hashes.add(digest)
        authorized[producer] = (role, key)
    return authorized


def allowed(event: dict, role: str) -> None:
    validate_event(event)
    require(event["event"] in ROLES[role] and
            event["component"] in ROLE_COMPONENTS[role],
            "producer role is not allowed to assert that operational event")
    if event["event"] == "quorum_check":
        require(role == "roughtime_probe",
                "only the pinned verified-source probe may report a quorum")
    if event["event"] == "fork_warrant" and event["status"] == "warrant_observed":
        require(role == "conductor_observer",
                "only the authorized conductor observer can report local warrant")
    if event["event"] == "oracle_state" and event["status"] == "replay_rejected":
        require(role == "oracle_runtime", "oracle replay report requires runtime producer")


def frame_body(producer: str, seq: int, previous: str, event: dict) -> dict:
    require(type(producer) is str and PRODUCER.fullmatch(producer),
            "invalid producer ID")
    require(type(seq) is int and 1 <= seq <= (1 << 63) - 1,
            "producer sequence must be a bounded positive integer")
    require(type(previous) is str and HEX64.fullmatch(previous),
            "missing canonical predecessor hash")
    validate_event(event)
    return {"schema": SCHEMA, "producer": producer, "seq": seq,
            "prev_sha256": previous, "event": event}


def sign_frame(producer: str, seq: int, previous: str,
               event: dict, key: bytes) -> dict:
    body = frame_body(producer, seq, previous, event)
    return {**body, "mac": hmac.new(key, canonical(body), hashlib.sha256).hexdigest()}


def verify_frame(value: dict, authorized: dict) -> dict:
    require(type(value) is dict and set(value) == FRAME_FIELDS and
            value.get("schema") == SCHEMA,
            "unknown or missing authenticated envelope fields")
    who = value.get("producer")
    require(type(who) is str and who in authorized,
            "unknown telemetry producer")
    role, key = authorized[who]
    body = frame_body(who, value.get("seq"), value.get("prev_sha256"),
                      value.get("event"))
    allowed(body["event"], role)
    supplied = value["mac"]
    require(type(supplied) is str and HEX64.fullmatch(supplied),
            "malformed authentication tag")
    expected = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    require(hmac.compare_digest(supplied, expected),
            "telemetry producer authentication failed")
    return value


def private_journal_open(path: Path, *, create: bool, write: bool) -> int:
    path = Path(path)
    parent = path.parent
    require(parent.is_dir() and not parent.is_symlink() and
            parent.stat().st_uid == os.geteuid() and
            (parent.stat().st_mode & 0o077) == 0,
            "authenticated journal directory must be a private 0700 directory")
    require(not path.is_symlink(), "authenticated journal symlink refused")
    flags = os.O_RDWR if write else os.O_RDONLY
    if create:
        flags |= os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                (st.st_mode & 0o077) == 0,
                "authenticated journal must be owned mode-0600 regular file")
        fcntl.flock(fd, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
        require(os.fstat(fd).st_size <= MAX_JOURNAL_BYTES,
                "authenticated journal exceeds configured byte cap")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _verified_locked(fd: int, authorized: dict) -> tuple[list[dict], str, dict, set]:
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, MAX_JOURNAL_BYTES + 1)
    require(len(raw) <= MAX_JOURNAL_BYTES,
            "authenticated journal exceeds permitted size")
    if not raw:
        return [], ZERO, {}, set()
    require(raw.endswith(b"\n"), "journal contains a truncated incomplete event")
    seen, last_seq, events, previous = set(), {}, [], ZERO
    for index, line in enumerate(raw.splitlines(), 1):
        require(index <= MAX_FRAMES and len(line) + 1 <= MAX_FRAME_BYTES,
                "authenticated event count or frame byte budget exceeded")
        frame = verify_frame(strict_object(line), authorized)
        require(frame["prev_sha256"] == previous,
                "authentication journal hash chain does not match")
        who = frame["producer"]
        require(frame["seq"] == last_seq.get(who, 0) + 1,
                "duplicate, skipped, or replayed producer sequence")
        key = frame["event"]["id"]
        require(key not in seen, "duplicate event ID in authenticated journal")
        seen.add(key)
        last_seq[who] = frame["seq"]
        events.append(frame)
        previous = hashlib.sha256(line + b"\n").hexdigest()
    return events, previous, last_seq, seen


def read_authenticated(path: Path, keys: dict) -> list[dict]:
    fd = private_journal_open(path, create=False, write=False)
    try:
        frames, _, _, _ = _verified_locked(fd, keys)
        return frames
    finally:
        os.close(fd)


def append_authenticated(path: Path, keys: dict, producer: str,
                         event: dict, *, at: datetime | None = None) -> dict:
    """Single-process local trusted runtime hook; never publish its HMAC key."""
    require(producer in keys, "unknown authorized telemetry producer")
    role, key = keys[producer]
    allowed(event, role)
    now = at or datetime.now(timezone.utc)
    require(now.tzinfo is not None, "clock must be timezone aware")
    require(abs((now - parse_time(event["ts"])).total_seconds()) <= MAX_SKEW_SECONDS,
            "event timestamp too old or too far in future")
    fd = private_journal_open(path, create=True, write=True)
    try:
        frames, previous, last_seq, ids = _verified_locked(fd, keys)
        require(len(frames) < MAX_FRAMES, "authentication journal requires rotation")
        require(event["id"] not in ids, "event ID replay")
        seq = last_seq.get(producer, 0) + 1
        frame = sign_frame(producer, seq, previous, event, key)
        line = canonical(frame) + b"\n"
        require(len(line) <= MAX_FRAME_BYTES, "authenticated event too large")
        require(os.fstat(fd).st_size + len(line) <= MAX_JOURNAL_BYTES,
                "authenticated journal full; rotate without discarding records")
        os.lseek(fd, 0, os.SEEK_END)
        written = os.write(fd, line)
        require(written == len(line), "partial journal append")
        os.fsync(fd)
        return {"schema": SCHEMA, "producer": producer, "seq": seq,
                "authenticated": True, "cryptographic_proof_verified": False}
    finally:
        os.close(fd)


def append_supplied(path: Path, keys: dict, frame: dict, *,
                    at: datetime | None = None) -> dict:
    """Accept a transport-supplied authenticated frame WITHOUT signing it.

    Sequence and predecessor must be exact. Never re-sign an unauthenticated
    diagnostic, even if the caller knows a claimed producer name.
    """
    verify_frame(frame, keys)
    now = at or datetime.now(timezone.utc)
    require(abs((now - parse_time(frame["event"]["ts"])).total_seconds())
            <= MAX_SKEW_SECONDS, "remote event is stale or in the future")
    fd = private_journal_open(path, create=True, write=True)
    try:
        frames, previous, seq, ids = _verified_locked(fd, keys)
        require(len(frames) < MAX_FRAMES, "authenticated journal requires rotation")
        require(frame["seq"] == seq.get(frame["producer"], 0) + 1 and
                frame["prev_sha256"] == previous and
                frame["event"]["id"] not in ids,
                "replayed, reordered or unrelated authenticated envelope")
        line = canonical(frame) + b"\n"
        require(len(line) <= MAX_FRAME_BYTES and
                os.fstat(fd).st_size + len(line) <= MAX_JOURNAL_BYTES,
                "authenticated transport journal over resource limit")
        os.lseek(fd, 0, os.SEEK_END)
        require(os.write(fd, line) == len(line), "short journal write")
        os.fsync(fd)
        return {"schema": SCHEMA, "producer": frame["producer"],
                "seq": frame["seq"], "authenticated": True,
                "cryptographic_proof_verified": False}
    finally:
        os.close(fd)


def example_for_role(role: str, *, at: datetime | None = None) -> dict:
    """Safe synthetic heartbeat used ONLY by opt-in test/incident exercises."""
    component = {
        "roughtime_probe": "roughtime", "oracle_runtime": "oracle",
        "queue_runtime": "queue", "seal_runtime": "seal",
        "conductor_observer": "conductor",
    }[role]
    return make_event(component, "heartbeat", "ok", at=at)
