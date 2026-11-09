"""Offline unit tests for the Sprint 13 reporter (no Holochain dependency)."""
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as load_runner  # noqa: E402


class LoadReportTests(unittest.TestCase):
    def test_nearest_rank_percentiles(self):
        values = list(range(1, 101))
        self.assertEqual(load_runner.percentile(values, 0.50), 50)
        self.assertEqual(load_runner.percentile(values, 0.95), 95)
        self.assertEqual(load_runner.percentile(values, 0.99), 99)
        self.assertIsNone(load_runner.percentile([], 0.95))

    def test_failure_counts_are_not_silently_discarded(self):
        summary = load_runner.summaries([
            {"kind": "seal_action", "ok": True, "latency_ms": 10.0},
            {"kind": "seal_action", "ok": False, "latency_ms": 20.0, "error": "chain head moved"},
            {"kind": "seal_action", "ok": False, "latency_ms": 30.0, "error": "chain head moved"},
            {"kind": "oversized_witnesses", "ok": True, "latency_ms": 5.0},
        ])
        self.assertEqual(summary["seal_action"]["attempted"], 3)
        self.assertEqual(summary["seal_action"]["failed_or_unexpected"], 2)
        self.assertEqual(summary["seal_action"]["latency_ms"]["p95"], 30.0)
        self.assertEqual(summary["seal_action"]["error_counts"]["chain head moved"], 2)
        self.assertEqual(summary["oversized_witnesses"]["successful_or_correctly_rejected"], 1)

    def test_sample_extraction_reports_bad_json(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "seal_load.log").write_text(
                'test started HC_LOAD_SAMPLE {"kind":"seal_action","ok":true,"latency_ms":1.2}\n'
                'HC_LOAD_META {"wall_ms":5}\n'
                'HC_LOAD_SAMPLE {invalid-json}\n'
            )
            samples, meta, errors = load_runner.extract_samples(
                out, [{"log": "seal_load.log"}]
            )
            self.assertEqual(len(samples), 1)
            self.assertEqual(len(meta), 1)
            self.assertEqual(len(errors), 1)

    def test_subprocess_reporting_preserves_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            record = load_runner.run_command(
                "synthetic_failure",
                [sys.executable, "-c", "import sys; print('fake error'); sys.exit(7)"],
                {}, Path(directory), timeout=30,
            )
            self.assertEqual(record["exit_code"], 7)
            self.assertFalse(record["timed_out"])
            self.assertIn("fake error", (Path(directory) / "synthetic_failure.log").read_text())


if __name__ == "__main__":
    unittest.main()
