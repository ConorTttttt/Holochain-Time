"""Sprint 25 safe operational event contract (Python stdlib, no external service).

Deliberate allowlist: no private keys, public keys, signatures, packet bodies,
target hashes, network addresses, user data, raw exception strings or freeform
tags. Stable source_ref is *only* the first 16 hex chars of a SHA-256 of a public
key/registered source ID, not the key itself. IDs are low-cardinality opaque
diagnostic labels, never proof of identity. Consumers MUST authenticate emitters
via file permissions and deployment-level process trust; this format is NOT
a signed telemetry channel.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat

SCHEMA = "hc-vtime/ops-event/v1"
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
MAX_EVENT_BYTES = 2048
MAX_EVENT_FILE_BYTES = 32 * 1024 * 1024
EVENTS = {
    "time_source_probe": {"ok", "timeout", "unreachable", "invalid_signature",
                          "unsupported_protocol"},
    "quorum_check": {"ok", "unavailable", "invalid"},
    "seal_submit": {"ok", "failed", "rejected", "timeout"},
    "seal_queue": {"observed", "saturated", "wait_timeout"},
    "seal_retry": {"head_moved", "exhausted"},
    "oracle_sign": {"ok", "rejected", "unexpected"},
    "signature_validation": {"ok", "invalid"},
    "conductor": {"starting", "running", "stopped", "restarting", "recovered",
                  "failed"},
    "fork_warrant": {"suspected", "warrant_observed", "conflict"},
    "dependency": {"ok", "degraded", "unavailable"},
    "oracle_state": {"ok", "recovery", "corrupt", "sequence_conflict",
                     "backup_failed", "replay_rejected"},
    "heartbeat": {"ok"},
}
COMPONENTS = {"roughtime", "oracle", "conductor", "seal", "queue", "storage",
              "dht", "unyt", "integration"}
NUMBERS = {"latency_ms", "queue_depth", "queue_capacity",
           "retry_count", "available_sources", "required_sources",
           "oldest_wait_ms", "signed_count"}
FIELDS = {"schema", "id", "ts", "component", "event", "status",
          "source_ref", "latency_ms", "queue_depth", "queue_capacity",
          "retry_count", "available_sources", "required_sources",
          "oldest_wait_ms", "signed_count"}
INTEGER_FIELDS = {"queue_depth", "queue_capacity", "retry_count",
                  "available_sources", "required_sources", "signed_count"}


class UnsafeEvent(ValueError):
    """Event rejected without leaking its supplied contents."""


def require(test, reason):
    if not test:
        raise UnsafeEvent(reason)


def reference(value: str | bytes) -> str:
    """Hash PUBLIC operator identity to an opaque, bounded telemetry ref."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    require(isinstance(value, bytes) and 1 <= len(value) <= 256,
            "source identity must be bounded bytes/text")
    return hashlib.sha256(value).hexdigest()[:16]


def pubkey_ref(key_b64: str) -> str:
    """Only for already-public 32-byte signer root; NEVER accept secret keys."""
    require(isinstance(key_b64, str), "public key must be canonical b64")
    try:
        raw = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError) as error:
        raise UnsafeEvent("invalid public-key encoding") from error
    require(len(raw) == 32 and base64.b64encode(raw).decode() == key_b64,
            "expected canonical 32-byte PUBLIC signer root")
    return reference(raw)


def json_unique(items):
    record = {}
    for key, value in items:
        require(key not in record, "duplicate JSON key")
        record[key] = value
    return record


def strict_json(line: str | bytes):
    require(len(line) <= MAX_EVENT_BYTES,
            "event line exceeds fixed size limit")
    try:
        return json.loads(line, object_pairs_hook=json_unique,
                          parse_constant=lambda x: (_ for _ in ()).throw(
                              UnsafeEvent("non-finite JSON numeric value")))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise UnsafeEvent("event JSON could not be parsed") from exc


def parse_time(timestamp: str) -> datetime:
    require(isinstance(timestamp, str) and len(timestamp) <= 32 and
            timestamp.endswith("Z"),
            "timestamp must be UTC ISO 8601 ending Z")
    try:
        value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UnsafeEvent("invalid UTC timestamp") from exc
    require(value.utcoffset().total_seconds() == 0,
            "event timestamp must be UTC")
    require(value.year >= 2020, "timestamp before supported telemetry epoch")
    return value


def validate_event(record: dict) -> dict:
    require(type(record) is dict, "event must be an object")
    require(set(record) <= FIELDS and
            {"schema", "id", "ts", "component", "event", "status"} <= set(record),
            "unknown or missing event fields: possible sensitive information")
    require(record["schema"] == SCHEMA, "unsupported diagnostic event version")
    require(isinstance(record["id"], str) and HEX32.fullmatch(record["id"]),
            "event ID must be 128-bit random lowercase hexadecimal")
    parse_time(record["ts"])
    require(record["component"] in COMPONENTS and record["event"] in EVENTS and
            record["status"] in EVENTS[record["event"]],
            "unknown component/event/status classification")
    if "source_ref" in record:
        require(type(record["source_ref"]) is str and
                HEX16.fullmatch(record["source_ref"]),
                "source_ref must be opaque 16-hex fingerprint, never a raw key")
    for name in NUMBERS & record.keys():
        value = record[name]
        if name in INTEGER_FIELDS:
            require(type(value) is int and 0 <= value <= 100_000,
                    f"{name} must be a bounded unsigned integer")
        else:
            require(type(value) in (int, float) and
                    math.isfinite(value) and 0 <= value <= 600_000,
                    f"{name} must be a bounded finite millisecond duration")
    if "queue_depth" in record or "queue_capacity" in record:
        require("queue_depth" in record and "queue_capacity" in record and
                record["queue_capacity"] >= 1,
                "queue depth and nonzero capacity required together")
    if "available_sources" in record or "required_sources" in record:
        require(record["event"] == "quorum_check" and
                "available_sources" in record and "required_sources" in record and
                record["required_sources"] >= 3,
                "explicit quorum telemetry must never declare fewer than 3 required")
    if record["event"] == "quorum_check":
        require("available_sources" in record and "required_sources" in record,
                "quorum event missing available/required source counts")
        require((record["status"] == "ok") ==
                (record["available_sources"] >= record["required_sources"]),
                "quorum result inconsistent with measured source count")
    if record["event"] == "seal_queue":
        require("queue_depth" in record and "queue_capacity" in record,
                "queue state requires depth and capacity")
    if record["event"] == "seal_retry":
        require("retry_count" in record and record["retry_count"] >= 1,
                "retry event requires positive retry count")
    if record["event"] == "time_source_probe" and record["status"] == "ok":
        require("latency_ms" in record, "successful source probe needs measured latency")
    if record["event"] == "oracle_sign" and record["status"] == "ok":
        require("source_ref" in record, "successful signing must specify opaque oracle ref")
    return record


def make_event(component: str, event: str, status: str, *,
               at: datetime | None = None, **safe_fields):
    when = at or datetime.now(timezone.utc)
    require(when.tzinfo is not None, "event time must be timezone-aware")
    payload = {
        "schema": SCHEMA,
        "id": secrets.token_hex(16),
        "ts": when.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "component": component,
        "event": event,
        "status": status,
        **safe_fields,
    }
    return validate_event(payload)


def safe_json(record: dict) -> bytes:
    validate_event(record)
    value = (json.dumps(record, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    require(len(value) <= MAX_EVENT_BYTES, "event exceeds sanitized size budget")
    return value


def append_event(path: Path, record: dict):
    """Append atomic JSONL in private local file. Do not emit raw application logs.

    The file's parent is a trusted operator-controlled directory; callers must
    not use a shared writable directory. Fail closed on symlinks and permissive
    existing files. On POSIX, flock serializes all cooperating emitters.
    """
    raw = safe_json(record)
    path = Path(path)
    require(not path.is_symlink(), "event log symlink forbidden")
    require(path.parent.is_dir() and not path.parent.is_symlink() and
            (path.parent.stat().st_mode & 0o077) == 0,
            "event log parent must be a pre-created owner-only 0700 directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and (info.st_mode & 0o077) == 0,
                "event file must be regular and mode 0600")
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Inspect file size *after* acquiring the append lock to avoid
        # cross-process limit races between concurrent writers.
        info = os.fstat(fd)
        require(info.st_size + len(raw) <= MAX_EVENT_FILE_BYTES,
                "bounded event journal full; rotate and archive securely")
        n = os.write(fd, raw)
        require(n == len(raw), "short event-log append")
        os.fsync(fd)
    finally:
        os.close(fd)


def read_events(path: Path, *, max_bytes=MAX_EVENT_FILE_BYTES, max_events=100_000):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(),
            "missing or linked operational JSONL file")
    require(path.stat().st_size <= max_bytes,
            "operational event journal exceeds read budget")
    results = []
    with path.open("rb") as stream:
        for idx, raw in enumerate(stream, 1):
            require(idx <= max_events, "too many operational events")
            try:
                value = strict_json(raw)
                results.append(validate_event(value))
            except UnsafeEvent as error:
                # Never copy or log the raw rejected line.
                raise UnsafeEvent(f"event journal line {idx}: {error}") from error
    return results


def fingerprint_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
