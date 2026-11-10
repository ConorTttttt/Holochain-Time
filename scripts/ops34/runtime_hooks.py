"""Sprint 34 safe hooks for authorized runtime callbacks, not log scraping.

HMAC authenticates an authorized producer process; this module does NOT
verify Holochain warrants, oracle signatures or independent operator control.
"""
from __future__ import annotations
from pathlib import Path
import sys

OPS = Path(__file__).resolve().parents[1] / "ops"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from events import make_event, require
from .auth import append_authenticated, allowed, keyring

class RuntimePublisher:
    def __init__(self, producer: str, keyring_path: Path, journal: Path):
        self.keys = keyring(keyring_path)
        require(producer in self.keys, "unregistered runtime telemetry producer")
        self.producer = producer
        self.role = self.keys[producer][0]
        self.journal = Path(journal)

    def event(self, item: dict) -> dict:
        allowed(item, self.role)
        return append_authenticated(self.journal, self.keys, self.producer, item)

    def heartbeat(self) -> dict:
        from .auth import example_for_role
        return self.event(example_for_role(self.role))

    def source_probe(self, native_event: dict) -> dict:
        """Call only after the PINNED native Roughtime verifier ran."""
        require(self.role == "roughtime_probe" and native_event.get("event") in
                ("time_source_probe", "quorum_check", "heartbeat"),
                "wrong verified-source producer or event")
        return self.event(native_event)

    def oracle_result(self, result: str, *, source_ref: str | None = None,
                      signed_count: int | None = None) -> dict:
        """Invoke after v3 durable COMMIT+external checkpoint, or actual refusal.

        Do not infer committed signatures from a PREPARE or untrusted log.
        The deployed v2 coordinator is NOT connected to this draft v3 hook.
        """
        require(self.role == "oracle_runtime", "wrong oracle producer")
        outcomes = {"signed_committed": ("oracle_sign", "ok"),
                    "rejected": ("oracle_sign", "rejected"),
                    "unexpected": ("oracle_sign", "unexpected"),
                    "replay_rejected": ("oracle_state", "replay_rejected"),
                    "sequence_conflict": ("oracle_state", "sequence_conflict"),
                    "corrupt": ("oracle_state", "corrupt"),
                    "restarting": ("oracle_state", "recovery"),
                    "recovered": ("oracle_state", "ok"),
                    "backup_failed": ("oracle_state", "backup_failed")}
        require(result in outcomes, "unrecognized oracle runtime result")
        event, status = outcomes[result]
        fields = {"source_ref": source_ref} if source_ref is not None else {}
        if signed_count is not None:
            require(result == "signed_committed", "counts only for signed commits")
            fields["signed_count"] = signed_count
        return self.event(make_event("oracle", event, status, **fields))

    def queue_snapshot(self, *, depth: int, capacity: int,
                       oldest_wait_ms: float = 0.0) -> dict:
        """Use a genuine CURRENT queue gauge, never admission-depth samples."""
        require(self.role == "queue_runtime", "wrong queue producer")
        require(type(depth) is int and type(capacity) is int and
                0 <= depth <= capacity, "invalid current queue state")
        return self.event(make_event("queue", "seal_queue",
            "saturated" if depth == capacity else "observed",
            queue_depth=depth, queue_capacity=capacity,
            oldest_wait_ms=oldest_wait_ms))

    def queue_retry(self, retries: int, *, exhausted: bool) -> dict:
        require(self.role == "queue_runtime" and type(retries) is int and
                retries > 0 and type(exhausted) is bool,
                "retry metrics require real positive bounded attempt count")
        return self.event(make_event("queue", "seal_retry",
            "exhausted" if exhausted else "head_moved", retry_count=retries))

    def seal_outcome(self, status: str, *, latency_ms: float | None = None) -> dict:
        require(self.role == "seal_runtime" and
                status in ("ok", "failed", "rejected", "timeout"),
                "unexpected seal outcome")
        fields = {} if latency_ms is None else {"latency_ms": latency_ms}
        return self.event(make_event("seal", "seal_submit", status, **fields))

    def conductor_state(self, status: str) -> dict:
        require(self.role == "conductor_observer" and status in
                ("starting", "running", "stopped", "restarting", "recovered", "failed"),
                "invalid conductor transition")
        return self.event(make_event("conductor", "conductor", status))

    def warrant_observation(self, status: str, *,
                            integrated_warrant_count: int | None = None,
                            origin: str) -> dict:
        """Call after an ACTUAL local DHT get_warrants_by_warrantee observation.

        Never turn fork test markers, unauthenticated JSON or a generic error
        into an authenticated locally-observed warrant.
        """
        require(self.role == "conductor_observer" and
                origin == "local_conductor_dht_store" and
                status in ("suspected", "warrant_observed", "conflict"),
                "unsupported or unauthenticated warrant observation origin")
        if status == "warrant_observed":
            require(type(integrated_warrant_count) is int and
                    1 <= integrated_warrant_count <= 100_000,
                    "a positive integrated warrant observation is required")
        else:
            require(integrated_warrant_count is None,
                    "warrant count is not established by a suspicion")
        # No warrant bytes/hashes, actor identity or raw exception contents.
        return self.event(make_event("dht", "fork_warrant", status))
