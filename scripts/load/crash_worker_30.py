#!/usr/bin/env python3
"""Test-only child for Sprint 30: actual OS SIGKILL after SQLite write fence."""
from __future__ import annotations
import asyncio
from pathlib import Path
import sys

try:
    from . import admission30 as a
    from .test_admission30 import Auth, DNA, AUTHOR, intent, policy, Receipts
except ImportError:
    import admission30 as a
    from test_admission30 import Auth, DNA, AUTHOR, intent, policy, Receipts


class NeverWrites:
    async def submit_once(self, request):
        # Reached only AFTER Admission._begin and _attempt transactions COMMIT.
        print("FENCED_BEFORE_NATIVE_WRITE", flush=True)
        await asyncio.Event().wait()
        raise AssertionError("must be killed before this path")


async def run(db: Path):
    # Deliberately do not close on crash. Linux releases fcntl OS locks on kill.
    service = a.Admission(db, policy(), initialize=True, clock_ms=lambda: 123_456)
    await service.submit(intent(), b"valid-transport", Auth(),
                         NeverWrites(), Receipts())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: crash_worker_30.py /path/to/disposable-admission.sqlite")
    asyncio.run(run(Path(sys.argv[1])))
