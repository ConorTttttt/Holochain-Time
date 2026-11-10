#!/usr/bin/env python3
"""Convert existing Sprint 12/21/22/23 diagnostics into sanitized ops-event/v1.

Reads raw test/integration logs in a trusted local environment ONLY. Never
copies exception strings, action hashes, Roughtime request/response bytes,
keys, URLs, actor names, arbitrary JSON fields or raw log lines. This is an
adapter for existing harnesses, not proof that a production sidecar is wired
into the conductor. All output is unauthenticated telemetry.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from events import UnsafeEvent, append_event, make_event, pubkey_ref, require

MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 65_536
PREFIXES = {
    "HC_LOAD_SAMPLE ": "load",
    "HC_LOAD_META ": "load_meta",
    "HC_RT_VERIFIED ": "native_roughtime",
    "HC_RT_CONDUCTOR ": "live_conductor",
}
FORK_CASE = re.compile(r"FORK_RECOVERY_CASE=([a-z0-9_]{1,90}):PASS\b")
RESILIENCE_CASE = re.compile(r"RESILIENCE_CASE=([a-z0-9_]{1,90}):PASS\b")
WARRANT_COUNT = re.compile(r"FORK_RECOVERY_WARRANT_COUNT=([0-9]{1,6})\b")


def to_events(line, observed_at):
    """Translate only known marker schemas. Everything else is discarded."""
    events = []
    for prefix, origin in PREFIXES.items():
        pos = line.find(prefix)
        if pos < 0:
            continue
        try:
            record = json.loads(line[pos+len(prefix):])
        except json.JSONDecodeError as exc:
            raise UnsafeEvent(f"malformed supported structured marker {prefix.strip()}") from exc
        require(type(record) is dict, "supported marker must contain a JSON object")
        if origin == "load" and record.get("kind") == "queued_seal_action":
            ok = record.get("ok")
            require(type(ok) is bool, "load sample must declare explicit boolean success")
            events.append(make_event(
                "seal", "seal_submit", "ok" if ok else "failed",
                at=observed_at,
                latency_ms=record["latency_ms"],
            ))
            depth = record.get("queue_depth_at_admission")
            # This is the admission depth, NOT a current global queue gauge.
            # Capacity is unknown from sample alone, so do not manufacture it.
            retries = record.get("head_moved_retries")
            if type(retries) is int and retries > 0:
                events.append(make_event("queue", "seal_retry",
                                         "head_moved" if retries <= 3 else "exhausted",
                                         at=observed_at,
                                         retry_count=retries))
            code = record.get("error_code")
            if code in ("queue_full", "queue_wait_timeout"):
                # Capacity required by the event schema: a sample lacking it
                # cannot be counted as a trustworthy numeric depth reading.
                # Only report failure through seal_submit above.
                pass
        elif origin == "load_meta" and record.get("kind") == "queued_seal_action":
            count = record.get("queue_capacity")
            if type(count) is int and 1 <= count <= 100_000:
                # This is a declared capacity only; a queue-depth snapshot
                # needs separate runtime instrumentation.
                pass
        elif origin == "native_roughtime" and record.get("schema") == (
                "hc-vtime/native-roughtime-verification/v1"):
            count = record.get("verified_count")
            require(type(count) is int and 0 <= count <= 32,
                    "native source count must be bounded")
            events.append(make_event(
                "roughtime", "quorum_check",
                "ok" if count >= 3 else "unavailable",
                available_sources=count, required_sources=3, at=observed_at,
            ))
        elif origin == "live_conductor" and record.get("schema") == (
                "hc-vtime/live-conductor-acceptance/v1"):
            count = record.get("signed_roots")
            require(type(count) is int and 0 <= count <= 32,
                    "live conductor root count must be bounded")
            events.append(make_event(
                "roughtime", "quorum_check",
                "ok" if count >= 3 else "unavailable",
                available_sources=count, required_sources=3, at=observed_at,
            ))
        return events

    marker = FORK_CASE.search(line)
    if marker:
        name = marker.group(1)
        if "restart" in name or "rejoin" in name:
            events.append(make_event("conductor", "conductor", "recovered",
                                     at=observed_at))
        # A laboratory case marker is NOT actual production fork detection.
        # Deliberately do not raise an authenticated warrant from a PASS marker.
        return events
    marker = RESILIENCE_CASE.search(line)
    if marker:
        name = marker.group(1)
        if "restart" in name or "rejoin" in name:
            events.append(make_event("conductor", "conductor", "recovered",
                                     at=observed_at))
        return events
    marker = WARRANT_COUNT.search(line)
    if marker:
        # This comes from a test-only fixture, not trusted production warrant
        # observation. The monitor does not equate this with a real warrant.
        return []
    return events


def import_capture(receipt, observed_at):
    """Read Sprint 23 attempt outcomes; never export signed packet bytes."""
    require(type(receipt) is dict and receipt.get("schema") ==
            "hc-vtime/roughtime-receipt/v1", "not a versioned Roughtime receipt")
    attempts = receipt.get("attempts")
    require(type(attempts) is list and len(attempts) <= 32,
            "missing or oversized source attempt list")
    result = []
    verified = 0
    for attempt in attempts:
        require(type(attempt) is dict and
                type(attempt.get("outcome")) is str,
                "invalid candidate attempt")
        # Reference an operator NAME by fingerprint, never include it verbatim.
        operator = attempt.get("operator")
        require(type(operator) is str and 1 <= len(operator) <= 120,
                "missing bounded operator identifier")
        from events import reference
        ref = reference(operator.casefold().strip())
        outcome = attempt["outcome"].lower()
        if outcome == "verified":
            verified += 1
            # The receipt may be forged. An adapter output is just a reported
            # status; native Roughtime crypto must be verified separately.
            # No latency in Sprint 23's receipt, so DO NOT make one up.
            result.append(make_event("roughtime", "dependency", "ok",
                                     source_ref=ref, at=observed_at))
        else:
            state = "invalid_signature" if any(x in outcome for x in
                ("invalid", "signature", "certificate", "nonce", "malformed")
            ) else "unreachable"
            result.append(make_event("roughtime", "time_source_probe", state,
                                     source_ref=ref, at=observed_at))
    result.append(make_event("roughtime", "quorum_check",
                             "ok" if verified >= 3 else "unavailable",
                             available_sources=verified, required_sources=3,
                             at=observed_at))
    return result


def ingest_log(path, observed_at):
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size <= MAX_LOG_BYTES,
            "input raw log missing, symlinked or exceeds budget")
    accepted = []
    with path.open("rb") as stream:
        for number, data in enumerate(stream, 1):
            require(len(data) <= MAX_LINE_BYTES,
                    f"untrusted raw log line {number} too long")
            try:
                line = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise UnsafeEvent("raw input log is not UTF-8") from exc
            accepted.extend(to_events(line, observed_at))
            require(len(accepted) <= 100_000,
                    "input generated too many bounded event records")
    return accepted


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log", type=Path, help="approved local integration log")
    ap.add_argument("--receipt", type=Path, help="Sprint 23 signed receipt JSON; unverified until native replay")
    ap.add_argument("--events", type=Path, required=True,
                    help="private pre-existing output journal or new file in private directory")
    ap.add_argument("--observed-at", help="UTC Z; defaults to current UTC time")
    args = ap.parse_args(argv)
    if (args.log is None) == (args.receipt is None):
        ap.error("select exactly one of --log or --receipt")
    from events import parse_time
    try:
        clock = parse_time(args.observed_at) if args.observed_at else datetime.now(timezone.utc)
        if args.log:
            events = ingest_log(args.log, clock)
        else:
            require(args.receipt.is_file() and not args.receipt.is_symlink() and
                    args.receipt.stat().st_size <= 256_000, "unsafe/missing receipt")
            receipt = json.loads(args.receipt.read_bytes())
            events = import_capture(receipt, clock)
        for event in events:
            append_event(args.events, event)
        # No original raw content or signer identities in stdout.
        print(json.dumps({"status": "INGESTED", "events_emitted": len(events),
                          "input_authentication_proven": False,
                          "release_ready": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnsafeEvent) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error)}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
