"""Sprint 30: offline-only admission, concurrency, resource-exhaustion and crash tests.

No Holochain conductor or signing credentials are present. 'receipt verified'
below is a deliberately fake test verifier; never report it as real evidence.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    from . import admission30 as a
except ImportError:
    import admission30 as a


def b64(prefix: bytes, seed: int) -> str:
    raw = bytes([seed]) * 32
    h = hashlib.blake2b(raw, digest_size=16).digest()
    check = bytes(h[i] ^ h[i+4] ^ h[i+8] ^ h[i+12] for i in range(4))
    return "u" + base64.urlsafe_b64encode(prefix + raw + check).decode().rstrip("=")


DNA = b64(b"\x84\x2d\x24", 1)
AUTHOR = b64(b"\x84\x20\x24", 2)
AUTHOR2 = b64(b"\x84\x20\x24", 3)
CALLER = b64(b"\x84\x20\x24", 4)
CALLER2 = b64(b"\x84\x20\x24", 5)
ACTION = b64(b"\x84\x29\x24", 6)
ACTION2 = b64(b"\x84\x29\x24", 7)
LANES = frozenset({(DNA, AUTHOR), (DNA, AUTHOR2)})


def intent(n: int = 1, *, author: str = AUTHOR, caller: str = CALLER,
           payload: int | None = None) -> a.SealIntent:
    # Distinct requests get distinct canonical test command commitments.
    value = n + 100 if payload is None else payload
    return a.SealIntent(f"{n:064x}", f"{value:064x}", DNA, author, caller)


def policy(**overrides) -> a.Policy:
    values = dict(
        allowed_lanes=LANES, capacity=8, per_caller_inflight=2,
        requests_per_window=100, window_ms=1000, wait_ms=100,
        head_moved_retries=2, max_history=1000,
    )
    values.update(overrides)
    return a.Policy(**values)


class Auth:
    def authorize(self, credential, request):
        return request.caller if credential == b"valid-transport" else None


class Receipts:
    def __init__(self, valid=True):
        self.valid = valid
        self.calls = 0

    def verify_committed(self, request, action):
        self.calls += 1
        return self.valid


class Recovery:
    def __init__(self, *, approved=True, found=True):
        self.approved = approved
        self.found = found
        self.verifications = 0

    def permit_reconciliation(self, credential, request):
        return self.approved and credential == b"reviewed-admin"

    def independently_verify_committed(self, request, action):
        self.verifications += 1
        return self.found


class Writer:
    def __init__(self, answers=None, wait=None, started=None):
        self.answers = list(answers or [a.WriteAnswer(a.WriteKind.COMMITTED, ACTION)])
        self.wait = wait
        self.started = started
        self.calls = 0
        self.active = 0
        self.peak = 0

    async def submit_once(self, request):
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            if self.started:
                self.started.set()
            if self.wait:
                await self.wait.wait()
            return self.answers[min(self.calls - 1, len(self.answers) - 1)]
        finally:
            self.active -= 1


class OfflineAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = Path(self.tmp.name) / "admission.sqlite"
        self.clock = [123_456]
        self.ad = a.Admission(self.file, policy(),
                              initialize=True, clock_ms=lambda: self.clock[0])
        self.addAsyncCleanup(self._close)

    async def _close(self):
        self.ad.close()

    def new_policy_store(self, updated_policy: a.Policy):
        """Switch to a fresh, explicitly provisioned local test-only identity."""
        self.ad.close()
        self.file = Path(self.tmp.name) / (
            f"fresh-policy-{len(list(Path(self.tmp.name).glob('fresh-policy-*'))) + 1}.sqlite"
        )
        self.ad = a.Admission(self.file, updated_policy, initialize=True,
                              clock_ms=lambda: self.clock[0])

    async def run_req(self, item, writer=None, credential=b"valid-transport",
                      receipts=None):
        return await self.ad.submit(
            item, credential, Auth(), writer or Writer(), receipts or Receipts())

    async def test_local_commit_idempotent_after_restart_and_not_second_write(self):
        w = Writer()
        first = await self.run_req(intent(), w)
        self.assertEqual(first.status, "LOCAL_COMMIT_REVERIFY_NATIVE")
        self.assertEqual(first.action_hash, ACTION)
        second = await self.run_req(intent(), w)
        self.assertEqual(second.status, "CACHED_LOCAL_COMMIT_REVERIFY_NATIVE")
        self.assertEqual(w.calls, 1)
        self.ad.close()
        self.ad = a.Admission(self.file, policy(), clock_ms=lambda: self.clock[0])
        again = await self.run_req(intent(), w)
        self.assertEqual(again.action_hash, ACTION)
        self.assertEqual(w.calls, 1)
        self.assertFalse(self.ad.snapshot_metrics()["production_service_connected"])

    async def test_new_id_cannot_replay_same_canonical_author_payload(self):
        writer = Writer()
        self.assertEqual((await self.run_req(intent(1), writer)).action_hash, ACTION)
        replay = await self.run_req(intent(2, payload=101), writer)
        self.assertEqual(replay.status, "IDEMPOTENCY_PAYLOAD_REPLAY")
        self.assertEqual(writer.calls, 1)
        self.ad.close()
        self.ad = a.Admission(self.file, policy(), clock_ms=lambda: self.clock[0])
        replay_again = await self.run_req(intent(2, payload=101), writer)
        self.assertEqual(replay_again.status, "IDEMPOTENCY_PAYLOAD_REPLAY")
        self.assertEqual(writer.calls, 1)

    async def test_same_id_different_payload_or_caller_refused(self):
        w = Writer()
        await self.run_req(intent(), w)
        wrong = await self.run_req(intent(payload=10), w)
        self.assertEqual(wrong.status, "IDEMPOTENCY_KEY_CONFLICT")
        wrong = await self.run_req(intent(caller=CALLER2), w)
        self.assertEqual(wrong.status, "IDEMPOTENCY_KEY_CONFLICT")
        self.assertEqual(w.calls, 1)

    async def test_unauthenticated_and_unapproved_author_do_not_write(self):
        w = Writer()
        self.assertEqual((await self.run_req(intent(), w, b"bad")).status,
                         "UNAUTHENTICATED")
        self.assertEqual((await self.run_req(intent(), w, b"")).status,
                         "UNAUTHENTICATED")
        third_author = b64(b"\x84\x20\x24", 99)
        item = intent(2, author=third_author)
        self.assertEqual((await self.run_req(item, w)).status, "UNAUTHORIZED_AUTHOR")
        self.assertEqual(w.calls, 0)

    async def test_per_caller_rate_limit_durable_across_restart(self):
        self.new_policy_store(policy(requests_per_window=2))
        w = Writer()
        await self.run_req(intent(1), w)
        await self.run_req(intent(2), w)
        self.assertEqual((await self.run_req(intent(3), w)).status,
                         "CALLER_RATE_LIMITED")
        self.ad.close()
        self.ad = a.Admission(self.file, policy(requests_per_window=2),
                              clock_ms=lambda: self.clock[0])
        self.assertEqual((await self.run_req(intent(3), w)).status,
                         "CALLER_RATE_LIMITED")
        self.clock[0] += 1000
        self.assertEqual((await self.run_req(intent(3), w)).status,
                         "LOCAL_COMMIT_REVERIFY_NATIVE")

    async def test_clock_rollback_does_not_replenish_tokens(self):
        await self.run_req(intent(1))
        self.clock[0] -= 9999
        w = Writer()
        outcome = await self.run_req(intent(2), w)
        self.assertEqual(outcome.status, "AMBIGUOUS_STORAGE_QUARANTINE")
        self.assertEqual(w.calls, 0)

    async def test_single_author_serialization_across_two_callers(self):
        release = asyncio.Event()
        started = asyncio.Event()
        w = Writer(wait=release, started=started)
        first = asyncio.create_task(self.run_req(intent(1), w))
        await started.wait()
        second = asyncio.create_task(
            self.run_req(intent(2, caller=CALLER2), w))
        await asyncio.sleep(0.015)
        self.assertEqual(w.calls, 1)
        release.set()
        results = await asyncio.gather(first, second)
        self.assertEqual([x.status for x in results],
                         ["LOCAL_COMMIT_REVERIFY_NATIVE"] * 2)
        self.assertEqual(w.peak, 1)

    async def test_independent_author_lanes_overlap(self):
        release = asyncio.Event()
        w = Writer(wait=release)
        a1 = asyncio.create_task(self.run_req(intent(1), w))
        a2 = asyncio.create_task(
            self.run_req(intent(2, author=AUTHOR2, caller=CALLER2), w))
        for _ in range(50):
            if w.calls == 2:
                break
            await asyncio.sleep(0.002)
        self.assertEqual(w.calls, 2)
        self.assertEqual(w.peak, 2)
        release.set()
        result = await asyncio.gather(a1, a2)
        self.assertTrue(all(x.action_hash == ACTION for x in result))

    async def test_same_caller_quota_and_other_caller_preserved(self):
        self.new_policy_store(policy(per_caller_inflight=1))
        release = asyncio.Event()
        started = asyncio.Event()
        w = Writer(wait=release, started=started)
        first = asyncio.create_task(self.run_req(intent(1), w))
        await started.wait()
        self.assertEqual((await self.run_req(intent(2), w)).status,
                         "CALLER_INFLIGHT_LIMIT")
        other = asyncio.create_task(
            self.run_req(intent(3, author=AUTHOR2, caller=CALLER2), w))
        for _ in range(50):
            if w.calls == 2:
                break
            await asyncio.sleep(0.002)
        self.assertEqual(w.calls, 2)
        release.set()
        await asyncio.gather(first, other)

    async def test_queue_capacity_backpressure_invokes_no_backend(self):
        self.new_policy_store(policy(capacity=2, per_caller_inflight=1))
        release = asyncio.Event()
        started = asyncio.Event()
        w = Writer(wait=release, started=started)
        first = asyncio.create_task(self.run_req(intent(1), w))
        await started.wait()
        second = asyncio.create_task(
            self.run_req(intent(2, caller=CALLER2, author=AUTHOR2), w))
        for _ in range(50):
            if w.calls == 2:
                break
            await asyncio.sleep(0.002)
        third = await self.run_req(intent(3, caller=CALLER2), w)
        self.assertEqual(third.status, "BACKPRESSURE_QUEUE_FULL")
        self.assertEqual(w.calls, 2)
        release.set()
        await asyncio.gather(first, second)

    async def test_queue_wait_timeout_starts_no_third_write(self):
        self.new_policy_store(policy(wait_ms=10))
        release = asyncio.Event()
        started = asyncio.Event()
        w = Writer(wait=release, started=started)
        first = asyncio.create_task(self.run_req(intent(1), w))
        await started.wait()
        other = await self.run_req(intent(2, caller=CALLER2), w)
        self.assertEqual(other.status, "BACKPRESSURE_WAIT_TIMEOUT")
        self.assertEqual(w.calls, 1)
        release.set()
        await first

    async def test_only_proven_not_written_head_moved_retries(self):
        w = Writer([
            a.WriteAnswer(a.WriteKind.PROVEN_NOT_WRITTEN_HEAD_MOVED),
            a.WriteAnswer(a.WriteKind.PROVEN_NOT_WRITTEN_HEAD_MOVED),
            a.WriteAnswer(a.WriteKind.COMMITTED, ACTION),
        ])
        result = await self.run_req(intent(), w)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(w.calls, 3)
        self.assertEqual(self.ad.snapshot_metrics()["head_moved_retries"], 2)
        same = await self.run_req(intent(), w)
        self.assertEqual(same.action_hash, ACTION)
        self.assertEqual(w.calls, 3)

    async def test_head_moved_exhaustion_is_definitive_not_committed(self):
        w = Writer([a.WriteAnswer(a.WriteKind.PROVEN_NOT_WRITTEN_HEAD_MOVED)])
        result = await self.run_req(intent(), w)
        self.assertEqual(result.status, "DEFINITIVELY_NOT_WRITTEN")
        self.assertEqual(result.attempts, 3)
        self.assertEqual((await self.run_req(intent(), w)).status,
                         "DEFINITIVELY_NOT_WRITTEN")
        self.assertEqual(w.calls, 3)

    async def test_rejected_input_no_retry_or_spurious_seal(self):
        w = Writer([a.WriteAnswer(a.WriteKind.PROVEN_NOT_WRITTEN_REJECTED)])
        result = await self.run_req(intent(), w)
        self.assertEqual(result.status, "DEFINITIVELY_NOT_WRITTEN")
        self.assertEqual(w.calls, 1)

    async def test_unverified_receipt_and_exception_are_ambiguous(self):
        w = Writer()
        bad = await self.run_req(intent(1), w, receipts=Receipts(valid=False))
        self.assertEqual(bad.status, "AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY")
        self.assertEqual(w.calls, 1)
        self.assertEqual((await self.run_req(intent(2), w)).status,
                         "AUTHOR_LANE_QUARANTINED_PENDING_RECOVERY")
        self.assertEqual(w.calls, 1)
        # Separate author can still make progress.
        ok = await self.run_req(intent(3, author=AUTHOR2, caller=CALLER2), w)
        self.assertEqual(ok.action_hash, ACTION)

    async def test_unknown_transport_error_never_reinvoked(self):
        class Bad:
            def __init__(self):
                self.calls = 0

            async def submit_once(self, _):
                self.calls += 1
                raise TimeoutError("transport ambiguity")
        bad = Bad()
        result = await self.run_req(intent(), bad)
        self.assertEqual(result.status, "AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY")
        self.assertEqual((await self.run_req(intent(), bad)).status,
                         "AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY")
        self.assertEqual(bad.calls, 1)

    async def test_cancellation_after_durable_fence_quarantines_lane(self):
        started = asyncio.Event()
        blocked = asyncio.Event()
        w = Writer(wait=blocked, started=started)
        task = asyncio.create_task(self.run_req(intent(1), w))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.ad.snapshot_metrics()["pending_ambiguous"], 1)
        self.ad.close()
        self.ad = a.Admission(self.file, policy(), clock_ms=lambda: self.clock[0])
        old = await self.run_req(intent(1), w)
        self.assertEqual(old.status, "AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY")
        new = await self.run_req(intent(2), w)
        self.assertEqual(new.status, "AUTHOR_LANE_QUARANTINED_PENDING_RECOVERY")
        self.assertEqual(w.calls, 1)

    async def test_recovery_requires_distinct_admin_and_independently_verified_commit(self):
        w = Writer([a.WriteAnswer(a.WriteKind.AMBIGUOUS)])
        await self.run_req(intent(), w)
        r = Recovery()
        with self.assertRaisesRegex(a.Blocked, "operator not authorized"):
            self.ad.reconcile_commit(intent(), ACTION, b"wrong-admin", r)
        with self.assertRaisesRegex(a.Blocked, "unverified"):
            self.ad.reconcile_commit(intent(), ACTION, b"reviewed-admin",
                                     Recovery(found=False))
        out = self.ad.reconcile_commit(intent(), ACTION, b"reviewed-admin", r)
        self.assertEqual(out.status, "RECOVERED_VERIFIED_NATIVE_COMMIT")
        self.assertEqual(out.action_hash, ACTION)
        self.assertEqual((await self.run_req(intent(), w)).action_hash, ACTION)
        self.assertEqual(w.calls, 1)

    async def test_unapproved_recovery_cannot_clear_unknown(self):
        w = Writer([a.WriteAnswer(a.WriteKind.AMBIGUOUS)])
        await self.run_req(intent(), w)
        with self.assertRaisesRegex(a.Blocked, "operator not authorized"):
            self.ad.reconcile_commit(intent(), ACTION, b"reviewed-admin",
                                     Recovery(approved=False))
        self.assertEqual(self.ad.snapshot_metrics()["pending_ambiguous"], 1)

    async def test_restart_with_changed_author_or_rate_policy_blocked(self):
        self.ad.close()
        with self.assertRaisesRegex(a.Blocked, "policy changed"):
            a.Admission(self.file, policy(requests_per_window=1),
                        clock_ms=lambda: self.clock[0])
        with self.assertRaisesRegex(a.Blocked, "policy changed"):
            a.Admission(self.file, policy(
                allowed_lanes=frozenset({(DNA, AUTHOR)})),
                clock_ms=lambda: self.clock[0])
        self.ad = a.Admission(self.file, policy(),
                              clock_ms=lambda: self.clock[0])

    async def test_one_service_instance_per_state_path(self):
        with self.assertRaises((BlockingIOError, OSError)):
            a.Admission(self.file, policy())
        self.ad.close()
        self.ad = a.Admission(self.file, policy(), clock_ms=lambda: self.clock[0])

    async def test_corruption_does_not_reset_or_bootstrap(self):
        self.ad.close()
        self.file.write_bytes(b"not-a-sqlite-database")
        with self.assertRaises((a.Blocked, Exception)):
            self.ad = a.Admission(self.file, policy(), clock_ms=lambda: self.clock[0])
        # Cleanup must not call close() on an invalid temporary path.
        class Closed:
            def close(self):
                pass
        self.ad = Closed()

    async def test_idempotency_storage_is_bounded_fail_closed(self):
        self.new_policy_store(policy(max_history=1))
        w = Writer()
        self.assertEqual((await self.run_req(intent(1), w)).action_hash, ACTION)
        self.assertEqual((await self.run_req(intent(2), w)).status,
                         "AMBIGUOUS_STORAGE_QUARANTINE")
        self.assertEqual(w.calls, 1)

    async def test_hash_input_exhaustion_and_untrusted_labels(self):
        for value in ("X" * 64, "0" * 63, "0" * 100000, "0" * 64 + "garbage"):
            with self.subTest(value=value[:16]):
                with self.assertRaises(a.Blocked):
                    a.SealIntent(value, "a" * 64, DNA, AUTHOR, CALLER)
        with self.assertRaises(a.Blocked):
            a.SealIntent("a" * 64, "b" * 64, AUTHOR, AUTHOR, CALLER)

    async def test_mock_results_never_assert_deployed_production(self):
        self.assertEqual(self.ad.snapshot_metrics()["independent_native_receipts_proven"],
                         False)
        self.assertEqual(self.ad.snapshot_metrics()["external_single_writer_proven"],
                         False)
        self.assertEqual(self.ad.snapshot_metrics()["production_service_connected"],
                         False)


class ProcessCrashTests(unittest.TestCase):
    def test_sigkill_after_write_fence_requires_reconciliation(self):
        """Genuine child process exits by SIGKILL with a durable INFLIGHT row."""
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "admission.sqlite"
            worker = Path(__file__).with_name("crash_worker_30.py")
            p = subprocess.Popen(
                [sys.executable, str(worker), str(db)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            try:
                line = p.stdout.readline().strip()
                if line != "FENCED_BEFORE_NATIVE_WRITE":
                    p.kill()
                    _, errors = p.communicate(timeout=5)
                    self.fail(f"child did not reach durable write fence: {line} {errors}")
                p.kill()
                p.communicate(timeout=5)
                self.assertNotEqual(p.returncode, 0)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.communicate(timeout=5)
            new = a.Admission(db, policy(), clock_ms=lambda: 123_456)
            try:
                self.assertEqual(new.snapshot_metrics()["pending_ambiguous"], 1)
                outcome = asyncio.run(new.submit(
                    intent(), b"valid-transport", Auth(), Writer(), Receipts()
                ))
                self.assertEqual(outcome.status,
                                 "AMBIGUOUS_NEEDS_INDEPENDENT_RECOVERY")
                self.assertEqual(asyncio.run(new.submit(
                    intent(2), b"valid-transport", Auth(), Writer(), Receipts()
                )).status, "AUTHOR_LANE_QUARANTINED_PENDING_RECOVERY")
            finally:
                new.close()


if __name__ == "__main__":
    unittest.main()
