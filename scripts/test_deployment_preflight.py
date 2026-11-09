"""Sprint 20 offline negative configuration tests. NO real live Roughtime or money."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import deployment_preflight as p
from check_test_dna_config import location
from pack_release_dna import pack

ROOT = Path(__file__).resolve().parent.parent
KNOWN_INSECURE = "F8t5+ytBIPKx7GXkGY1uCLKOgT/rAeSkAIObheGAgM4="


def fake_key(n):
    return base64.b64encode(hashlib.sha256(f"synthetic-public-{n}".encode()).digest()).decode()


class ReleaseSafetyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        template = (ROOT / "deployment/environments/production.dna.example.yaml").read_text()
        for n in range(1, 5):
            template = template.replace(f"REPLACE_WITH_PINNED_RT_KEY_{n}", fake_key(n))
        template = template.replace("REPLACE_WITH_NEW_DNA_SEED_UNIQUE_32_CHARS",
                                    "unique-vtime-release-network-seed-november-2026-A7BX")
        self.manifest = self.root / "dna.yaml"
        self.manifest.write_text(template)
        self.policy = json.loads((ROOT / "deployment/environments/production.policy.example.json").read_text())
        self.policy["network_id"] = "synthetic-local-only-no-real-service"
        for n, record in enumerate(self.policy["sources"], 1):
            record.update(
                key=fake_key(n), operator_id=f"fake-operator-{n}",
                operator_label=f"Fake Independent Organisation {n}",
                key_provenance=f"https://fixture.example.org/operator/{n}",
                review_ref=f"manual-fixture-review-number-{n}",
                endpoint=f"roughtime{n}.fake-operator.org:2002", protocol="rfc10049",
            )
        self.policy_path = self.root / "policy.json"
        self.approval_path = self.root / "approval.json"
        self.approval = {
            "schema": "hc-vtime/deployment-approval/v1",
            "environment": "production", "manifest_sha256": "",
            "policy_sha256": "", "approval_status": "approved",
            "reviewers": [
                {"name": "Synthetic Reviewer One", "review_ref": "fixture-review-one"},
                {"name": "Synthetic Reviewer Two", "review_ref": "fixture-review-two"},
            ],
            "source_reviews": [{
                "operator_id": f"fake-operator-{n}",
                "key_control_checked": True, "admin_separation_checked": True,
                "shared_upstream_checked": True, "live_protocol_verified": True,
                "evidence_sha256": p.sha256(f"not-a-real-receipt-{n}".encode()),
            } for n in range(1, 5)],
        }
        self.persist()

    def persist(self):
        self.policy["manifest_sha256"] = p.sha256(self.manifest.read_bytes())
        self.policy_path.write_text(json.dumps(self.policy, indent=2) + "\n")
        self.approval["manifest_sha256"] = p.sha256(self.manifest.read_bytes())
        self.approval["policy_sha256"] = p.sha256(self.policy_path.read_bytes())
        self.approval_path.write_text(json.dumps(self.approval, indent=2) + "\n")

    def preflight(self, **options):
        return p.preflight(
            self.manifest, self.policy_path, self.approval_path,
            "production", expected_manifest_sha256=p.sha256(self.manifest.read_bytes()),
            expected_policy_sha256=p.sha256(self.policy_path.read_bytes()), **options)

    def blocked(self, phrase):
        with self.assertRaises(p.PreflightError) as failed:
            self.preflight()
        self.assertIn(phrase, str(failed.exception))

    def test_static_profile_pass_is_not_independence_evidence(self):
        result = self.preflight()
        self.assertEqual(result["status"], "PREFLIGHT_PASS")
        self.assertEqual(result["source_checks"]["sources_count"], 4)
        self.assertFalse(result["operator_independence_proven"])
        self.assertFalse(result["safe_to_install_proven"])

    def test_checked_in_production_example_must_fail_closed(self):
        dna = ROOT / "deployment/environments/production.dna.example.yaml"
        policy = ROOT / "deployment/environments/production.policy.example.json"
        with self.assertRaises(p.PreflightError):
            p.preflight(dna, policy, None, "production",
                        expected_manifest_sha256=p.sha256(dna.read_bytes()),
                        expected_policy_sha256=p.sha256(policy.read_bytes()))

    def test_minimum_three_source_and_outage_limit(self):
        self.manifest.write_text(self.manifest.read_text().replace("min_sources: 3", "min_sources: 2"))
        self.persist()
        self.blocked("min_sources")
        self.manifest.write_text(self.manifest.read_text().replace("min_sources: 2", "min_sources: 3")
                                 .replace("max_faulty: 1", "max_faulty: 2"))
        self.persist()
        self.blocked("2*max_faulty")

    def test_missing_outage_margin(self):
        self.manifest.write_text(self.manifest.read_text().replace(
            f'      - "{fake_key(4)}"\n', ""))
        self.policy["sources"].pop()
        self.approval["source_reviews"].pop()
        self.persist()
        self.blocked("min_sources + max_faulty")

    def test_duplicate_key(self):
        self.manifest.write_text(self.manifest.read_text().replace(fake_key(4), fake_key(1)))
        self.persist()
        self.blocked("duplicate raw signer identity")

    def test_duplicate_operator_even_with_four_different_keys(self):
        self.policy["sources"][3]["operator_id"] = "fake-operator-1"
        self.persist()
        self.blocked("duplicate operator")
        self.policy["sources"][3]["operator_id"] = "fake-operator-4"
        self.policy["sources"][3]["operator_label"] = "FAKE INDEPENDENT ORGANISATION 1"
        self.persist()
        self.blocked("duplicate operator")

    def test_known_insecure_roughtime_signer(self):
        self.manifest.write_text(self.manifest.read_text().replace(fake_key(1), KNOWN_INSECURE))
        self.policy["sources"][0]["key"] = KNOWN_INSECURE
        self.persist()
        self.blocked("known insecure Ed25519")

    def test_known_insecure_oracle_signer(self):
        raw = base64.b64decode("YqYRtHLYmw5fyTwGm59wC0xVLVW8Doe1YAjvF7ayvr4=")
        oracle = "u" + base64.urlsafe_b64encode(
            bytes([0x84, 0x20, 0x24]) + raw + location(raw)).decode().rstrip("=")
        self.manifest.write_text(self.manifest.read_text().replace(
            "    oracles: []", f'    oracles:\n      - "{oracle}"'))
        self.policy["sources"].append({
            "kind": "oracle", "key": oracle, "operator_id": "fixture-oracle",
            "operator_label": "Fixture Oracle", "key_provenance": "https://fixture.example.org",
            "review_ref": "fixture-review-reference",
        })
        self.approval["source_reviews"].append({
            "operator_id": "fixture-oracle", "key_control_checked": True,
            "admin_separation_checked": True, "shared_upstream_checked": True,
            "live_protocol_verified": True, "evidence_sha256": "a"*64,
        })
        self.persist()
        self.blocked("known insecure Ed25519")

    def test_protocol_and_local_endpoint(self):
        self.policy["sources"][0]["protocol"] = "draft11"
        self.persist()
        self.blocked("unsupported/unknown Roughtime protocol")
        self.policy["sources"][0]["protocol"] = "rfc10049"
        self.policy["sources"][0]["endpoint"] = "127.0.0.1:2002"
        self.persist()
        self.blocked("private/loopback")

    def test_unknown_or_unbound_key(self):
        self.policy["sources"][0]["key"] = fake_key(99)
        self.persist()
        self.blocked("not pinned in exact DNA")

    def test_no_approval_or_unsigned_approval(self):
        with self.assertRaisesRegex(p.PreflightError, "approval file is required"):
            p.preflight(self.manifest, self.policy_path, None, "production",
                        expected_manifest_sha256=p.sha256(self.manifest.read_bytes()),
                        expected_policy_sha256=p.sha256(self.policy_path.read_bytes()))
        self.approval["approval_status"] = "pending"
        self.persist()
        self.blocked("not approved")
        self.approval["approval_status"] = "approved"
        self.approval["source_reviews"][0]["admin_separation_checked"] = False
        self.persist()
        self.blocked("admin_separation_checked")

    def test_duplicate_reviewers_and_stale_approval_hash(self):
        self.approval["reviewers"][1]["name"] = "SYNTHETIC REVIEWER ONE"
        self.persist()
        self.blocked("not distinct")
        self.approval["reviewers"][1]["name"] = "Synthetic Reviewer Two"
        self.persist()
        self.approval["policy_sha256"] = "a"*64
        self.approval_path.write_text(json.dumps(self.approval))
        self.blocked("approval must bind")

    def test_missing_or_mismatched_external_manifest_pin(self):
        with self.assertRaisesRegex(p.PreflightError, "externally pinned"):
            p.preflight(self.manifest, self.policy_path, self.approval_path, "production",
                        expected_policy_sha256=p.sha256(self.policy_path.read_bytes()))
        with self.assertRaisesRegex(p.PreflightError, "matching policy SHA-256"):
            p.preflight(self.manifest, self.policy_path, self.approval_path, "production",
                        expected_manifest_sha256=p.sha256(self.manifest.read_bytes()),
                        expected_policy_sha256="0"*64)

    def test_yaml_anchors_duplicates_unknown_fields_and_placeholder(self):
        source = self.manifest.read_text()
        changes = [
            ("    min_sources: 3", "    min_sources: 3\n    min_sources: 3", "duplicate DNA property"),
            ("    min_sources: 3", "    insecure_unsigned: 1\n    min_sources: 3", "unknown DNA property"),
            ("  network_seed: ", "  network_seed: &alias ", "YAML anchors"),
            (fake_key(1), "REPLACE_WITH_SIGNING_KEY_1", "signing key placeholder"),
            ("name: vtime", "name: other", "DNA name"),
        ]
        for old, new, reason in changes:
            with self.subTest(reason=reason):
                self.manifest.write_text(source.replace(old, new))
                self.persist()
                self.blocked(reason)

    def test_duplicate_json_object_property(self):
        with self.assertRaisesRegex(p.PreflightError, "duplicate JSON key"):
            p.load_json(b'{"environment":"production","environment":"development"}',
                        "synthetic")

    def test_production_network_seed_cannot_be_null(self):
        self.manifest.write_text(self.manifest.read_text().replace(
            'network_seed: "unique-vtime-release-network-seed-november-2026-A7BX"',
            "network_seed: ~"))
        self.persist()
        self.blocked("network_seed")

    def test_production_disallows_development_test_opt_in(self):
        self.manifest.write_text(self.manifest.read_text().replace(fake_key(1), KNOWN_INSECURE))
        self.policy["sources"][0]["key"] = KNOWN_INSECURE
        self.persist()
        with self.assertRaisesRegex(p.PreflightError, "known insecure"):
            self.preflight(allow_dev_test_keys=True)

    def test_production_guarded_pack_aborts_before_artifact_or_hc(self):
        from argparse import Namespace
        args = Namespace(
            manifest=ROOT / "deployment/environments/production.dna.example.yaml",
            policy=ROOT / "deployment/environments/production.policy.example.json",
            approval=None, environment="production", expected_manifest_sha256=None,
            expected_policy_sha256=None, expected_integrity_wasm_sha256=None,
            expected_coordinator_wasm_sha256=None, expected_commit_sha=None,
            output_dir=self.root / "package", allow_development_test_keys=False)
        with self.assertRaises(p.PreflightError):
            pack(args)
        self.assertFalse(args.output_dir.exists())


class DevelopmentOptInTests(unittest.TestCase):
    def test_known_public_fixture_keys_only_allowed_by_explicit_development_opt_in(self):
        manifest = ROOT / "deployment/environments/development.dna.example.yaml"
        raw_policy = json.loads(
            (ROOT / "deployment/environments/development.policy.example.json").read_text()
        )
        raw_policy["manifest_sha256"] = p.sha256(manifest.read_bytes())
        for source in raw_policy["sources"]:
            source["key_provenance"] = "https://test.example.org/public-insecure-seed"
            source["review_ref"] = "local-insecure-fixture-approval-reference"
        with tempfile.TemporaryDirectory() as temp:
            policy = Path(temp) / "development.json"
            policy.write_text(json.dumps(raw_policy))
            with self.assertRaisesRegex(p.PreflightError, "known insecure"):
                p.preflight(manifest, policy, None, "development")
            result = p.preflight(manifest, policy, None, "development",
                                 allow_dev_test_keys=True)
            self.assertEqual(result["status"], "PREFLIGHT_PASS")
            self.assertFalse(result["operator_independence_proven"])
            self.assertFalse(result["safe_to_install_proven"])
            with self.assertRaises(p.PreflightError):
                p.preflight(manifest, policy, None, "production",
                            allow_dev_test_keys=True)



if __name__ == "__main__":
    unittest.main()
