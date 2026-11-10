#!/usr/bin/env python3
"""Local authenticated producer-frame collector (one frame on stdin).

A caller must already have a channel to this collector (e.g., Unix socket
ACL or reviewed mTLS termination). This is NOT a production network server.
No untrusted JSON event is signed by the collector; HMAC + sequence and role
are verified against the independent owner-only keyring.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .auth import (MAX_FRAME_BYTES, UnsafeEvent, append_supplied,
                   keyring, strict_object, require)


def accept_input(raw: bytes, keys: dict, journal: Path, *, at=None):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME_BYTES,
            "frame exceeds fixed transport byte budget")
    require(raw.endswith(b"\n"), "frame must have a complete newline terminator")
    value = strict_object(raw)
    return append_supplied(journal, keys, value, at=at)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keyring", type=Path, required=True)
    ap.add_argument("--journal", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        keys = keyring(args.keyring)
        raw = sys.stdin.buffer.read(MAX_FRAME_BYTES + 1)
        result = accept_input(raw, keys, args.journal)
        # No key, event payload or raw sender strings ever echoed.
        print(json.dumps({"status": "RECORDED", "sequence": result["seq"],
                          "producer_authenticated": True,
                          "security_evidence_verified": False}))
        return 0
    except (UnsafeEvent, OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "BLOCKED",
                          "reason": "producer frame authentication or admission failed",
                          "producer_authenticated": False,
                          "security_evidence_verified": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
