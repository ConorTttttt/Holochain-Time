"""Offline Sprint 21 benchmark-report acceptance tests; no conductor required."""
from pathlib import Path
import copy
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import run_21 as reporter
import run as v13


def realistic_metadata(attempts):
    return [{
        "kind": "queued_seal_action",
        "requested": attempts, "successful": attempts, "failed": 0,
        "unique_success_action_hashes": attempts,
        "conductor_count": 3, "head_moved_retries": 0,
        "third_party_verified_receipts": 12,
        "completion_wall_ms": 30000.0,
        "successful_seals_per_second": attempts / 30.0,
        "external_roughtime_network": False,
        "production_independence_proven": False,
    }]


def samples(attempts):
    return [{
        "kind": "queued_seal_action",
        "attempt": i, "conductor": i % 3, "ok": True, "admitted": True,
        "action_hash": "uhCkk" + str(i).zfill(5) + "x"*48,
        "error": None, "error_code": None,
        "latency_ms": 200.0 + i, "queue_wait_ms": 100.0,
        "service_ms": 100.0 + i, "queue_depth_at_admission": i+1,
        "write_attempts": 1, "head_moved_retries": 0,
    } for i in range(attempts)]


class QueuedReportTests(unittest.TestCase):
    def test_exact_120_synthetic_samples_can_validate_reporting_only(self):
        count = 120
        accepted = reporter.validate_queued(samples(count), realistic_metadata(count), count)
        self.assertEqual(accepted["status"], "PASS")
        self.assertEqual(accepted["successful"], 120)
        self.assertEqual(accepted["unique_action_hashes"], 120)
        self.assertEqual(accepted["third_party_verified_receipts"], 12)
        self.assertEqual(accepted["head_moved_retries"], 0)
        self.assertEqual(accepted["latency_ms"]["queue_wait_ms"]["p95"], 100.0)

    def test_missing_and_duplicate_rows_rejected(self):
        rows, meta = samples(120), realistic_metadata(120)
        self.assertEqual(reporter.validate_queued(rows[:-1], meta, 120)["status"], "FAIL")
        rows[1]["attempt"] = rows[0]["attempt"]
        self.assertEqual(reporter.validate_queued(rows, meta, 120)["status"], "FAIL")

    def test_duplicate_hash_rejected_even_all_calls_say_success(self):
        rows = samples(120)
        rows[1]["action_hash"] = rows[0]["action_hash"]
        self.assertEqual(
            reporter.validate_queued(rows, realistic_metadata(120), 120)["status"],
            "FAIL",
        )

    def test_failing_seal_or_replayable_error_is_rejected(self):
        rows = samples(120)
        rows[9]["ok"] = False
        rows[9]["error"] = "HeadMoved"
        rows[9]["error_code"] = "head_moved_retry_exhausted"
        self.assertEqual(
            reporter.validate_queued(rows, realistic_metadata(120), 120)["status"],
            "FAIL",
        )

    def test_retry_counters_must_be_bounded_and_match_meta(self):
        rows = samples(120)
        rows[0]["head_moved_retries"] = 4
        rows[0]["write_attempts"] = 5
        self.assertEqual(
            reporter.validate_queued(rows, realistic_metadata(120), 120)["status"],
            "FAIL",
        )
        rows[0]["head_moved_retries"] = 1
        rows[0]["write_attempts"] = 2
        self.assertEqual(
            reporter.validate_queued(rows, realistic_metadata(120), 120)["status"],
            "FAIL",
        )
        meta = realistic_metadata(120)
        meta[0]["head_moved_retries"] = 1
        self.assertEqual(reporter.validate_queued(rows, meta, 120)["status"], "PASS")

    def test_fake_independent_operator_claim_and_missing_verify_are_rejected(self):
        rows, meta = samples(120), realistic_metadata(120)
        meta[0]["production_independence_proven"] = True
        self.assertEqual(reporter.validate_queued(rows, meta, 120)["status"], "FAIL")
        meta[0]["production_independence_proven"] = False
        meta[0]["third_party_verified_receipts"] = 0
        self.assertEqual(reporter.validate_queued(rows, meta, 120)["status"], "FAIL")
        meta[0]["third_party_verified_receipts"] = 12
        meta[0]["external_roughtime_network"] = True
        self.assertEqual(reporter.validate_queued(rows, meta, 120)["status"], "FAIL")

    def test_invalid_duration_or_conductor_index_rejected(self):
        rows = samples(120)
        rows[0]["latency_ms"] = -1
        self.assertEqual(
            reporter.validate_queued(rows, realistic_metadata(120), 120)["status"],
            "FAIL",
        )
        rows[0]["latency_ms"] = 1
        rows[0]["conductor"] = 5
        self.assertEqual(
            reporter.validate_queued(rows, realistic_metadata(120), 120)["status"],
            "FAIL",
        )

    def test_fixture_requires_exact_sha_success_and_bundle_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sha = "a"*40
            dna = root / "vtime.dna"
            dna.write_bytes(b"pretend DNA; not a valid conductor archive")
            (root / "dna.yaml").write_text(
                "# HC_VTIME_SIGNED_TEST_ONLY -- known insecure keys -- NEVER DEPLOY\n"
                "  network_seed: \"DO-NOT-DEPLOY-signed-quorum-0123456789abcdef\"\n"
            )
            (root / "provenance.txt").write_text(
                f"git_sha={sha}\n"
                f"packed_dna_sha256={v13.sha256(dna)}\n"
                "signed_quorum_command_exit=0\n"
                "conductor_smoke_command_exit=0\n"
            )
            fixture = reporter.check_fixture(dna, sha)
            self.assertEqual(fixture["git_sha"], sha)
            with self.assertRaisesRegex(ValueError, "source SHA mismatch"):
                reporter.check_fixture(dna, "b"*40)
            dna.write_bytes(b"tampered content")
            with self.assertRaisesRegex(ValueError, "packed DNA SHA-256 differs"):
                reporter.check_fixture(dna, sha)

    def test_report_never_infers_independent_operators(self):
        data = {
            "status": "NOT RUN", "commit": "a"*40,
            "dna_sha256": "b"*64, "requested": 120, "stages": [],
            "queued_gate": None, "errors": ["missing cargo"],
        }
        note = reporter.report_md(data)
        self.assertIn("NOT RUN", note)
        self.assertIn("not independent", note.lower())


if __name__ == "__main__":
    unittest.main()
