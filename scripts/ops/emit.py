#!/usr/bin/env python3
"""Emit one strictly sanitized, fsync'd operational event to a private JSONL file.

Operational sidecars should call this after the underlying cryptographic
operation has actually completed. No signing keys, network packet bytes,
target hashes, arbitrary error text, URLs or human-identifying labels accepted.
An emitted status is an operator observation, NOT cryptographic attestation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from events import (COMPONENTS, EVENTS, UnsafeEvent, append_event,
                    make_event, pubkey_ref, reference, parse_time)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", type=Path, required=True,
                    help="private append-only JSONL journal in a precreated owner-only directory")
    ap.add_argument("--component", choices=sorted(COMPONENTS), required=True)
    ap.add_argument("--event", choices=sorted(EVENTS), required=True)
    ap.add_argument("--status", required=True)
    ap.add_argument("--source-public-key-b64",
                    help="ONLY an already-public 32-byte operator key; never pass secrets")
    ap.add_argument("--source-id",
                    help="nonsecret stable public source identifier; hashed before storage")
    ap.add_argument("--latency-ms", type=float)
    ap.add_argument("--queue-depth", type=int)
    ap.add_argument("--queue-capacity", type=int)
    ap.add_argument("--retry-count", type=int)
    ap.add_argument("--available-sources", type=int)
    ap.add_argument("--required-sources", type=int)
    ap.add_argument("--oldest-wait-ms", type=float)
    ap.add_argument("--signed-count", type=int)
    ap.add_argument("--at", help="explicit UTC ISO8601 for imported historical metrics")
    options = ap.parse_args(argv)
    if options.source_public_key_b64 is not None and options.source_id is not None:
        ap.error("select no more than one public source reference")
    fields = {}
    for name in (
        "latency_ms", "queue_depth", "queue_capacity", "retry_count",
        "available_sources", "required_sources", "oldest_wait_ms", "signed_count",
    ):
        value = getattr(options, name)
        if value is not None:
            fields[name] = value
    try:
        if options.source_public_key_b64:
            fields["source_ref"] = pubkey_ref(options.source_public_key_b64)
        elif options.source_id:
            fields["source_ref"] = reference(options.source_id)
        timestamp = parse_time(options.at) if options.at else None
        event = make_event(options.component, options.event, options.status,
                           at=timestamp, **fields)
        append_event(options.events, event)
        # Never print raw arguments even on failed validation.
        print(json.dumps({"status": "RECORDED", "schema": event["schema"],
                          "event": event["event"], "component": event["component"],
                          "sensitive_material_recorded": False}))
        return 0
    except (UnsafeEvent, OSError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
