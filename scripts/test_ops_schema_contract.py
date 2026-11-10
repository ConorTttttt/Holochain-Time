"""Root-discoverable Sprint 25 event/schema fixture-compatibility regressions.

The standard scripts/verify_local.sh discovers -s scripts -p test_*.py.
No external JSON Schema library, private data, or live network is required.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / "scripts/ops"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from events import COMPONENTS, EVENTS, EVENT_COMPONENTS, FIELDS, SCHEMA, UnsafeEvent, make_event, safe_json  # noqa: E402
from monitor import read_policy  # noqa: E402


class Sprint25MachineSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            (ROOT / "config/ops-event.schema.json").read_text(encoding="utf-8")
        )

    def test_schema_matches_runtime_event_and_status_allowlist(self):
        props = self.schema["properties"]
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(self.schema["required"],
                         ["schema", "id", "ts", "component", "event", "status"])
        self.assertEqual(set(props), FIELDS)
        self.assertEqual(props["schema"]["const"], SCHEMA)
        self.assertEqual(set(props["event"]["enum"]), set(EVENTS))
        self.assertEqual(set(props["component"]["enum"]), COMPONENTS)
        for name, statuses in EVENTS.items():
            branches = [
                entry for entry in self.schema["allOf"]
                if entry.get("if", {}).get("properties", {}).get(
                    "event", {}).get("const") == name
            ]
            self.assertEqual(len(branches), 1, name)
            self.assertEqual(set(branches[0]["then"]["properties"]["status"]["enum"]),
                             statuses, name)
            self.assertEqual(
                set(branches[0]["then"]["properties"]["component"]["enum"]),
                EVENT_COMPONENTS[name], name
            )

    def test_no_sensitive_or_high_cardinality_metadata_is_in_schema(self):
        for forbidden in (
            "private_key", "secret", "signature", "signed_packet",
            "nonce", "evidence", "address", "agent_id", "action_hash",
            "dna_hash", "operator", "exception_text", "raw_log",
        ):
            self.assertNotIn(forbidden, self.schema["properties"])
        self.assertEqual(
            self.schema["properties"]["source_ref"]["pattern"],
            "^[0-9a-f]{16}$"
        )

    def test_example_fixture_validates_under_runtime_contract(self):
        example = self.schema["examples"][0]
        self.assertEqual(example["event"], "quorum_check")
        self.assertTrue(safe_json(example).endswith(bytes([10])))
        self.assertIn(b"quorum_check", safe_json(example))
        altered = dict(example, available_sources=2, status="ok")
        with self.assertRaises(UnsafeEvent):
            safe_json(altered)

    def test_operator_policy_compatible_and_downgrade_rejected(self):
        policy = read_policy(ROOT / "config/ops-monitor.example.json")
        self.assertFalse(policy["oracle_signing_enabled"])
        self.assertEqual(policy["authorized_oracle_refs"], [])
        self.assertIn("roughtime", policy["expected_heartbeat_components"])
        with tempfile.TemporaryDirectory() as temp:
            invalid = dict(policy, oracle_signing_enabled=True)
            invalid["authorized_oracle_refs"] = ["secret-label"]
            bad = Path(temp) / "bad.json"
            bad.write_text(json.dumps(invalid))
            with self.assertRaises(UnsafeEvent):
                read_policy(bad)


if __name__ == "__main__":
    unittest.main()
