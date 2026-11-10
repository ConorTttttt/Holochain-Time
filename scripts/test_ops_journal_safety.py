"""Security regression tests for Sprint 25's private operational journal.

Found by the existing `python3 -m unittest discover -s scripts -p 'test_*.py'`.
Tests are synthetic; they do not establish live conductor instrumentation.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True
OPS = Path(__file__).resolve().parent / "ops"
sys.path.insert(0, str(OPS))

from events import UnsafeEvent, append_event, make_event, read_events  # noqa: E402


class PrivateJournalSecurity(unittest.TestCase):
    def event(self):
        return make_event("conductor", "heartbeat", "ok",
                          at=datetime(2026, 11, 10, tzinfo=timezone.utc))

    def test_append_rejects_shared_writable_or_readable_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "shared"
            parent.mkdir()
            os.chmod(parent, 0o755)
            with self.assertRaises(UnsafeEvent):
                append_event(parent / "journal.jsonl", self.event())
            self.assertFalse((parent / "journal.jsonl").exists())

    def test_read_rejects_public_journal_and_link(self):
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp)
            os.chmod(private, 0o700)
            journal = private / "ops.jsonl"
            append_event(journal, self.event())
            os.chmod(journal, 0o644)
            with self.assertRaises(UnsafeEvent):
                read_events(journal)
            os.chmod(journal, 0o600)
            link = private / "linked.jsonl"
            link.symlink_to(journal)
            with self.assertRaises(UnsafeEvent):
                read_events(link)

    def test_reader_blocks_until_exclusive_writer_lock_released(self):
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp)
            os.chmod(private, 0o700)
            journal = private / "ops.jsonl"
            append_event(journal, self.event())
            writer_fd = os.open(journal, os.O_RDWR)
            started = threading.Event()
            try:
                fcntl.flock(writer_fd, fcntl.LOCK_EX)

                def read():
                    started.set()
                    return read_events(journal)

                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(read)
                    self.assertTrue(started.wait(timeout=2))
                    time.sleep(0.05)
                    self.assertFalse(future.done(),
                                     "reader bypassed the exclusive writer lock")
                    fcntl.flock(writer_fd, fcntl.LOCK_UN)
                    self.assertEqual(len(future.result(timeout=3)), 1)
            finally:
                fcntl.flock(writer_fd, fcntl.LOCK_UN)
                os.close(writer_fd)


if __name__ == "__main__":
    unittest.main()
