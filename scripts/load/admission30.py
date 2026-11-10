#!/usr/bin/env python3
"""Sprint 30 native-sidecar admission CONTRACT, not a deployed Holochain service.

Asyncio API; stdlib SQLite FULL-sync local write fences and one OS process
lock. Nothing here can sign, call a conductor, or prove cross-host exclusivity.
Sprint 29 owns canonical v3 request-ID/signing journal/remote checkpoint state.
Every unknown or cancelled write is permanently ambiguous until a DIFFERENT,
independently authenticated recovery path proves the actual committed action.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from enum import Enum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Protocol

HEX32 = re.compile(r"[0-9a-f]{64}\Z")
MAX_CREDENTIAL = 4096
VERSION = 30


class Blocked(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Blocked(reason)


def holo_hash(value: str, prefix: bytes) -> bool:
    """Canonical typed Holochain hash, including 4-byte location checksum."""
    if type(value) is not str or not value.startswith("u"):
        return False
    if re.fullmatch(r"[A-Za-z0-9_-]+", value[1:]) is None:
        return False
    try:
        raw = base64.urlsafe_b64decode(value[1:] + "=" * (-len(value[1:]) % 4))
    except (ValueError, base64.binascii.Error):
        return False
    if len(raw) != 39 or raw[:3] != prefix:
        return False
    d = hashlib.blake2b(raw[3:35], digest_size=16).digest()
    check = bytes(d[k] ^ d[k+4] ^ d[k+8] ^ d[k+12] for k in range(4))
    return raw[35:] == check and (
        "u" + base64.urlsafe_b64encode(raw).decode().rstrip("=") == value
    )


@dataclass(frozen=True)
class SealIntent:
    # Must be a globally unique AUTHENTICATED Sprint 29 32-byte request ID.
    request_id: str
    # Digest of the exact canonical, reviewed seal command bytes; NOT a
    # caller-asserted arbitrary payload hash in a production adapter.
    payload_sha256: str
    dna: str
    author: str
    caller: str

    def __post_init__(self) -> None:
        require(type(self.request_id) is str and HEX32.fullmatch(self.request_id) is not None
                and self.request_id != "0" * 64,
                "nonzero 32-byte canonical request ID required")
        require(type(self.payload_sha256) is str and
                HEX32.fullmatch(self.payload_sha256) is not None,
                "canonical payload commitment required")
        require(holo_hash(self.dna, b"\x84\x2d\x24"), "invalid DNA hash")
        require(holo_hash(self.author, b"\x84\x20\x24"), "invalid author key")
        require(holo_hash(self.caller, b"\x84\x20\x24"), "invalid caller key")


@dataclass(frozen=True)
class Policy:
    allowed_lanes: frozenset[tuple[str, str]]
    capacity: int = 128
    per_caller_inflight: int = 4
    max_callers: int = 1024
    max_history: int = 20_000
    requests_per_window: int = 16
    window_ms: int = 1000
    wait_ms: int = 30_000
    head_moved_retries: int = 2

    def __post_init__(self) -> None:
        require(type(self.allowed_lanes) is frozenset and
                1 <= len(self.allowed_lanes) <= 256, "immutable allowed author lanes required")
        for dna, author in self.allowed_lanes:
            require(holo_hash(dna, b"\x84\x2d\x24")
                    and holo_hash(author, b"\x84\x20\x24"),
                    "invalid allowed DNA/author identity")
        for field, lo, hi in (
            ("capacity", 1, 4096), ("per_caller_inflight", 1, 4096),
            ("max_callers", 1, 4096), ("max_history", 1, 100_000),
            ("requests_per_window", 1, 1000), ("window_ms", 100, 60_000),
            ("wait_ms", 1, 600_000), ("head_moved_retries", 0, 8),
        ):
            value = getattr(self, field)
            require(type(value) is int and lo <= value <= hi, "invalid bound: " + field)
        require(self.per_caller_inflight < self.capacity or self.capacity == 1,
                "one caller may not reserve entire multi-caller capacity")


def policy_digest(policy: Policy) -> str:
    """Pin all admission parameters to durable state; no silent rate/author drift."""
    names = (
        "capacity", "per_caller_inflight", "max_callers", "max_history",
        "requests_per_window", "window_ms", "wait_ms", "head_moved_retries",
    )
    payload = {name: getattr(policy, name) for name in names}
    payload["allowed_lanes"] = sorted([list(lane) for lane in policy.allowed_lanes])
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"hc-vtime/sprint30-admission-policy/v1" + bytes([0]) + raw).hexdigest()


class WriteKind(Enum):
    COMMITTED = "committed"
    PROVEN_NOT_WRITTEN_HEAD_MOVED = "proven_not_written_head_moved"
    PROVEN_NOT_WRITTEN_REJECTED = "proven_not_written_rejected"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class WriteAnswer:
    kind: WriteKind
    action_hash: str | None = None


class Authenticator(Protocol):
    def authorize(self, credential: bytes, request: SealIntent) -> str | None:
        """Return transport-verified caller identity, not a caller JSON claim."""


class SignedReceiptVerifier(Protocol):
    def verify_committed(self, request: SealIntent, action_hash: str) -> bool:
        """Verify signed native action, author, DNA, target and request binding."""


class RecoveryAuthority(Protocol):
    def permit_reconciliation(self, credential: bytes, request: SealIntent) -> bool:
        """Authorize audited recovery on a distinct privileged path."""

    def independently_verify_committed(self, request: SealIntent, action_hash: str) -> bool:
        """Verify native source-chain action and independent peer, not JSON/hash only."""


class SealWriter(Protocol):
    async def submit_once(self, request: SealIntent) -> WriteAnswer:
        """Real conductor adapter supplies typed NOT-WRITTEN proof or ambiguity."""


@dataclass(frozen=True)
class AdmissionResult:
    status: str
    action_hash: str | None = None
    attempts: int = 0
    queue_wait_ms: float = 0.0


class Admission:
    """One process/one immutable author allowlist; zero production adapters.

    An OS exclusive lock prevents a second sidecar using this SQLite path.
    It does NOT ensure another host/conductor process cannot write as author.
    A production owner must enforce cross-host single-writer authority.
    """

    def __init__(self, path: Path, policy: Policy, *,
                 initialize: bool = False, clock_ms=None):
        self.path = path
        self.policy = policy
        self._closed = False
        self._poisoned = False
        self._active = 0
        self._caller_active: dict[str, int] = {}
        self._lanes = {key: asyncio.Lock() for key in policy.allowed_lanes}
        self.metrics: dict[str, int] = {
            name: 0 for name in (
                "admitted", "auth_denied", "rate_limited", "saturated",
                "caller_saturated", "queue_wait_timeout", "started",
                "committed", "cached", "key_conflict", "ambiguous",
                "head_moved_retries", "known_not_written", "recovered",
                "storage_failed", "payload_replay",
            )
        }
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        require(path.parent.is_dir() and not path.parent.is_symlink(),
                "existing nonsymlink state directory required")
        require(not path.is_symlink(), "database path may not be a symlink")
        exists = path.exists()
        require(exists != initialize,
                "explicit one-time initialization required, never silently reset")
        if exists:
            require(path.is_file(), "database must be a regular file")
        lock = path.with_name(path.name + ".writer.lock")
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if initialize:
                dbfd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                os.close(dbfd)
            self._db = sqlite3.connect(path, isolation_level="DEFERRED")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA busy_timeout=0")
            if initialize:
                with self._db:
                    self._db.executescript("""
                        CREATE TABLE requests(
                            id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                            dna TEXT NOT NULL, author TEXT NOT NULL,
                            caller TEXT NOT NULL, state TEXT NOT NULL,
                            action TEXT, attempts INTEGER NOT NULL,
                            UNIQUE(dna, author, payload)
                        );
                        CREATE TABLE quotas(
                            caller TEXT PRIMARY KEY,
                            window INTEGER NOT NULL, used INTEGER NOT NULL
                        );
                        CREATE TABLE meta(
                            name TEXT PRIMARY KEY, value TEXT NOT NULL
                        );
                        PRAGMA user_version=30;
                    """)
            require(self._db.execute("PRAGMA user_version").fetchone()[0] == VERSION,
                    "missing/legacy admission state; reviewed migration required")
            if initialize:
                with self._db:
                    self._db.execute("INSERT INTO meta VALUES(?,?)",
                                     ("policy_digest", policy_digest(policy)))
            pinned = self._db.execute(
                "SELECT value FROM meta WHERE name='policy_digest'"
            ).fetchone()
            require(pinned == (policy_digest(policy),),
                    "admission author/rate policy changed; reviewed migration required")
            require(self._db.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                    "database corruption; no automatic repair/reset")
            self._fd = fd
        except BaseException:
            if hasattr(self, "_db"):
                self._db.close()
            os.close(fd)
            raise

    def close(self) -> None:
        require(self._active == 0, "do not close while requests are in flight")
        if not self._closed:
            self._closed = True
            self._db.close()
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)

    def _bind(self, row: tuple, intent: SealIntent) -> None:
        require(row[:4] == (intent.payload_sha256, intent.dna,
                            intent.author, intent.caller),
                "global request ID reused with different payload/identity")

    def _row(self, intent: SealIntent):
        return self._db.execute(
            "SELECT payload,dna,author,caller,state,action,attempts "
            "FROM requests WHERE id=?", (intent.request_id,)
        ).fetchone()

    def _read_known(self, intent: SealIntent) -> AdmissionResult | None:
        row = self._row(intent)
        if row is None:
            return None
        self._bind(row, intent)
        state, action, attempts = row[4:]
        if state == "INFLIGHT":
            return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY", attempts=attempts)
        if state == "COMMITTED":
            return AdmissionResult("CACHED_LOCAL_COMMIT_REVERIFY_NATIVE", action, attempts)
        if state == "NOT_WRITTEN":
            return AdmissionResult("DEFINITIVELY_NOT_WRITTEN", attempts=attempts)
        raise Blocked("corrupt admission state: unknown record status")

    def _debit(self, caller: str) -> bool:
        """Durable fixed-window per-authenticated-caller quota; clock rollback rejects."""
        at = self._clock_ms()
        require(type(at) is int and 0 <= at < 2**63,
                "invalid monitored admission clock")
        window = at // self.policy.window_ms
        with self._db:
            row = self._db.execute(
                "SELECT window,used FROM quotas WHERE caller=?", (caller,)
            ).fetchone()
            if row is None:
                count = self._db.execute("SELECT COUNT(*) FROM quotas").fetchone()[0]
                if count >= self.policy.max_callers:
                    return False
                self._db.execute("INSERT INTO quotas VALUES(?,?,?)",
                                 (caller, window, 1))
                return True
            old, used = row
            require(window >= old, "admission clock rollback, refusing reset")
            if window == old:
                if used >= self.policy.requests_per_window:
                    return False
                self._db.execute("UPDATE quotas SET used=used+1 WHERE caller=?",
                                 (caller,))
            else:
                self._db.execute("UPDATE quotas SET window=?,used=1 WHERE caller=?",
                                 (window, caller))
        return True

    def _begin(self, intent: SealIntent) -> AdmissionResult | None:
        with self._db:
            known = self._read_known(intent)
            if known:
                return known
            duplicate = self._db.execute(
                "SELECT id FROM requests WHERE dna=? AND author=? AND payload=?",
                (intent.dna, intent.author, intent.payload_sha256),
            ).fetchone()
            require(duplicate is None,
                    "canonical author payload replay under a different request ID")
            total = self._db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            require(total < self.policy.max_history,
                    "durable idempotency history full; operator archive required")
            self._db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                (intent.request_id, intent.payload_sha256, intent.dna,
                 intent.author, intent.caller, "INFLIGHT", None, 0)
            )
        return None

    def _attempt(self, intent: SealIntent) -> int:
        with self._db:
            self._db.execute(
                "UPDATE requests SET attempts=attempts+1 "
                "WHERE id=? AND state='INFLIGHT'", (intent.request_id,)
            )
            return self._db.execute(
                "SELECT attempts FROM requests WHERE id=?",
                (intent.request_id,)
            ).fetchone()[0]

    def _finish(self, intent: SealIntent, state: str, action: str | None) -> None:
        with self._db:
            changed = self._db.execute(
                "UPDATE requests SET state=?,action=? "
                "WHERE id=? AND state='INFLIGHT'",
                (state, action, intent.request_id)
            ).rowcount
            require(changed == 1, "unexpected idempotency state during commit")

    def _storage_error(self) -> AdmissionResult:
        self._poisoned = True
        self.metrics["storage_failed"] += 1
        self.metrics["ambiguous"] += 1
        return AdmissionResult("AMBIGUOUS_STORAGE_QUARANTINE")

    async def submit(self, intent: SealIntent, credential: bytes,
                     authenticator: Authenticator, writer: SealWriter,
                     receipts: SignedReceiptVerifier) -> AdmissionResult:
        """Fail closed: no backend request before an fsynced INFLIGHT row.

        Cancellation/transport error is NOT a proof the conductor did not
        commit. Caller must retry the same ID only to query status, never
        submit a second native write. Sprint29 signing IDs cannot be remapped.
        """
        if self._closed or self._poisoned:
            return AdmissionResult("UNAVAILABLE_QUARANTINED")
        if (type(credential) is not bytes or
                not 0 < len(credential) <= MAX_CREDENTIAL):
            self.metrics["auth_denied"] += 1
            return AdmissionResult("UNAUTHENTICATED")
        try:
            caller = authenticator.authorize(credential, intent)
        except Exception:
            caller = None
        if caller != intent.caller or not holo_hash(caller, b"\x84\x20\x24"):
            self.metrics["auth_denied"] += 1
            return AdmissionResult("UNAUTHENTICATED")
        lane_key = (intent.dna, intent.author)
        if lane_key not in self._lanes:
            self.metrics["auth_denied"] += 1
            return AdmissionResult("UNAUTHORIZED_AUTHOR")
        try:
            debit = self._debit(intent.caller)
            if not debit:
                self.metrics["rate_limited"] += 1
                return AdmissionResult("CALLER_RATE_LIMITED")
            known = self._read_known(intent)
        except (sqlite3.Error, Blocked) as error:
            if isinstance(error, Blocked) and "global request ID reused" in str(error):
                self.metrics["key_conflict"] += 1
                return AdmissionResult("IDEMPOTENCY_KEY_CONFLICT")
            return self._storage_error()
        if known:
            self.metrics["cached"] += 1
            return known
        if self._active >= self.policy.capacity:
            self.metrics["saturated"] += 1
            return AdmissionResult("BACKPRESSURE_QUEUE_FULL")
        if self._caller_active.get(intent.caller, 0) >= self.policy.per_caller_inflight:
            self.metrics["caller_saturated"] += 1
            return AdmissionResult("CALLER_INFLIGHT_LIMIT")
        self._active += 1
        self._caller_active[intent.caller] = self._caller_active.get(intent.caller, 0) + 1
        self.metrics["admitted"] += 1
        started = time.monotonic()
        held = False
        lane = self._lanes[lane_key]
        try:
            try:
                await asyncio.wait_for(lane.acquire(), self.policy.wait_ms / 1000)
                held = True
            except asyncio.TimeoutError:
                self.metrics["queue_wait_timeout"] += 1
                return AdmissionResult("BACKPRESSURE_WAIT_TIMEOUT")
            wait_ms = (time.monotonic() - started) * 1000
            try:
                # A prior ambiguous native write may still have committed.
                # Quarantine its ENTIRE author lane until a separately
                # authenticated recovery proves the action. No new head
                # can be written on an unknown source-chain predecessor.
                pending = self._db.execute(
                    "SELECT id FROM requests WHERE dna=? AND author=? "
                    "AND state='INFLIGHT' AND id<>? LIMIT 1",
                    (intent.dna, intent.author, intent.request_id),
                ).fetchone()
                if pending is not None:
                    self.metrics["ambiguous"] += 1
                    return AdmissionResult("AUTHOR_LANE_QUARANTINED_PENDING_RECOVERY",
                                           queue_wait_ms=wait_ms)
            except sqlite3.Error:
                return self._storage_error()
            try:
                known = self._begin(intent)
            except Blocked as error:
                if "global request ID reused" in str(error):
                    self.metrics["key_conflict"] += 1
                    return AdmissionResult("IDEMPOTENCY_KEY_CONFLICT")
                if "payload replay" in str(error):
                    self.metrics["payload_replay"] += 1
                    return AdmissionResult("IDEMPOTENCY_PAYLOAD_REPLAY")
                return self._storage_error()
            except sqlite3.Error:
                return self._storage_error()
            if known:
                self.metrics["cached"] += 1
                return known
            self.metrics["started"] += 1
            for retry in range(self.policy.head_moved_retries + 1):
                try:
                    # Persist EACH attempt before invoking the native backend.
                    attempts = self._attempt(intent)
                except (sqlite3.Error, Blocked):
                    return self._storage_error()
                try:
                    response = await writer.submit_once(intent)
                except asyncio.CancelledError:
                    self.metrics["ambiguous"] += 1
                    raise
                except BaseException:
                    self.metrics["ambiguous"] += 1
                    return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY",
                                           attempts=attempts, queue_wait_ms=wait_ms)
                if type(response) is not WriteAnswer or type(response.kind) is not WriteKind:
                    self.metrics["ambiguous"] += 1
                    return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY",
                                           attempts=attempts, queue_wait_ms=wait_ms)
                if response.kind is WriteKind.COMMITTED:
                    if not holo_hash(response.action_hash, b"\x84\x29\x24"):
                        self.metrics["ambiguous"] += 1
                        return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY",
                                               attempts=attempts, queue_wait_ms=wait_ms)
                    try:
                        verified = receipts.verify_committed(intent, response.action_hash)
                    except Exception:
                        verified = False
                    if verified is not True:
                        self.metrics["ambiguous"] += 1
                        return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY",
                                               attempts=attempts, queue_wait_ms=wait_ms)
                    try:
                        self._finish(intent, "COMMITTED", response.action_hash)
                    except (sqlite3.Error, Blocked):
                        return self._storage_error()
                    self.metrics["committed"] += 1
                    return AdmissionResult("LOCAL_COMMIT_REVERIFY_NATIVE",
                                           response.action_hash, attempts, wait_ms)
                if response.action_hash is not None:
                    self.metrics["ambiguous"] += 1
                    return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY",
                                           attempts=attempts, queue_wait_ms=wait_ms)
                if (response.kind is WriteKind.PROVEN_NOT_WRITTEN_HEAD_MOVED
                        and retry < self.policy.head_moved_retries):
                    self.metrics["head_moved_retries"] += 1
                    await asyncio.sleep(min(0.25, 0.02 * 2**retry))
                    continue
                if response.kind in (
                    WriteKind.PROVEN_NOT_WRITTEN_HEAD_MOVED,
                    WriteKind.PROVEN_NOT_WRITTEN_REJECTED,
                ):
                    try:
                        self._finish(intent, "NOT_WRITTEN", None)
                    except (sqlite3.Error, Blocked):
                        return self._storage_error()
                    self.metrics["known_not_written"] += 1
                    return AdmissionResult("DEFINITIVELY_NOT_WRITTEN",
                                           attempts=attempts, queue_wait_ms=wait_ms)
                self.metrics["ambiguous"] += 1
                return AdmissionResult("AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY",
                                       attempts=attempts, queue_wait_ms=wait_ms)
            raise AssertionError("bounded retry loop must always return")
        finally:
            if held:
                lane.release()
            self._active -= 1
            self._caller_active[intent.caller] -= 1
            if not self._caller_active[intent.caller]:
                del self._caller_active[intent.caller]

    def reconcile_commit(self, intent: SealIntent, action_hash: str,
                         admin_credential: bytes, authority: RecoveryAuthority) -> AdmissionResult:
        """Administrative ONLY: accept an independently proven existing action.

        Never resolve an ambiguous SIGNING as NOT WRITTEN or invoke the signer.
        A success here requires real source-chain/HSM/peer evidence in the
        production RecoveryAuthority, which this repository does not supply.
        """
        require(not self._closed and not self._poisoned,
                "cannot reconcile unavailable/poisoned admission store")
        require(self._active == 0,
                "quiesce all in-flight writes before administrative reconciliation")
        require(type(admin_credential) is bytes and
                0 < len(admin_credential) <= MAX_CREDENTIAL,
                "reviewed recovery credential required")
        require(holo_hash(action_hash, b"\x84\x29\x24"),
                "invalid native action hash")
        row = self._row(intent)
        require(row is not None, "cannot recover unknown request ID")
        self._bind(row, intent)
        require(row[4] == "INFLIGHT", "only ambiguous INFLIGHT requests can reconcile")
        require(authority.permit_reconciliation(admin_credential, intent) is True,
                "operator not authorized for recovery")
        require(authority.independently_verify_committed(intent, action_hash) is True,
                "native signed receipt and independent source-chain unverified")
        try:
            self._finish(intent, "COMMITTED", action_hash)
        except (sqlite3.Error, Blocked) as error:
            self._poisoned = True
            raise Blocked("ambiguous reconciliation storage error; quarantine") from error
        self.metrics["recovered"] += 1
        return AdmissionResult("RECOVERED_VERIFIED_NATIVE_COMMIT", action_hash, row[6])

    def snapshot_metrics(self) -> dict:
        return {
            **self.metrics, "inflight_local": self._active,
            "writer_lanes": len(self._lanes),
            "pending_ambiguous": self._db.execute(
                "SELECT COUNT(*) FROM requests WHERE state='INFLIGHT'"
            ).fetchone()[0],
            "commits_recorded_locally": self._db.execute(
                "SELECT COUNT(*) FROM requests WHERE state='COMMITTED'"
            ).fetchone()[0],
            "production_service_connected": False,
            "external_single_writer_proven": False,
            "independent_native_receipts_proven": False,
        }
