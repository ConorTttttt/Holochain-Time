"""Sprint 14A: offline configuration, accounting and negative receipt fixtures.

No test keys below represent funded accounts or a live testnet.
"""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

config_tool = load("scripts/unyt/validate_testnet.py", "validate_unyt")
receipt_tool = load("scripts/unyt/verify_receipt.py", "verify_unyt")
journal_tool = load("scripts/unyt/verify_journal.py", "journal_unyt")
GENESIS = "ab" * 32
TX = "cd" * 32
AGENT = lambda n: "uhCAk" + chr(65 + n) * 45
DNA = "uhC0k" + "D" * 45

def configuration(kind="verified_time_release"):
    roles = ({"grantor": AGENT(1), "beneficiary": AGENT(2), "time_prover": AGENT(2)}
             if kind == "verified_time_release" else
             {"bonded_oracle": AGENT(1), "reporter": AGENT(2),
              "slash_beneficiary": AGENT(3)})
    fixed = ({"oracle_keys": [AGENT(3), AGENT(4), AGENT(5)],
              "oracle_dnas": [DNA], "max_faulty": 1, "min_oracles": 2}
             if kind == "verified_time_release" else
             {"bonded_oracle": AGENT(1), "unyt_index": "0",
              "reporter_reward": "50", "slash_beneficiary": AGENT(3),
              "bond_until": "1799776000000000",
              "challenge_period_us": "604800000000",
              "witness_oracles": [AGENT(4), AGENT(5), AGENT(6)],
              "oracle_dnas": [DNA], "max_faulty": 1, "min_oracles": 2})
    return {"schema": "hc-vtime/unyt-testnet/v1",
            "network": {"name": "testnet-only", "genesis_hash": GENESIS},
            "agreement": kind, "roles": roles, "fixed": fixed,
            "test_amount": "300" if kind == "verified_time_release" else "500",
            "deployment": {"adapter": "manual-authorized-client",
                           "approval": "required-at-execution"}}

def receipt(outcome, allocated, locked, status="committed"):
    allocations = ([{"receiver": AGENT(2), "amount": str(allocated), "source": "bond-parked"}]
                   if allocated else [])
    sources = ["bond-parked"] if allocated else []
    return {"schema": "hc-vtime/unyt-receipt/v1",
            "network_genesis": GENESIS, "agreement_id": "test-agreement",
            "tx_hash": TX, "execution_id": "execution-a",
            "outcome": outcome, "status": status,
            "input_total": "500", "allocations": allocations,
            "locked_remaining": str(locked), "spent_sources": sources}

def expectation(r):
    e = {k: v for k, v in r.items()
         if k not in ("schema", "tx_hash", "execution_id")}
    e["schema"] = "hc-vtime/unyt-expectation/v1"
    return e

class ConfigTests(unittest.TestCase):
    def test_both_agreement_types_validate_and_generate_offline_plan(self):
        for kind in ("verified_time_release", "time_oracle_bond"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                cfg = config_tool.validate(configuration(kind))
                out = Path(d) / "plan.json"
                config_tool.prepare(cfg, out)
                plan = json.loads(out.read_text())
                self.assertEqual(plan["status"], "OFFLINE_ONLY_NOT_DEPLOYED")
                self.assertEqual(len(plan["template_sha256"]), 5)

    def test_refuses_mainnet_placeholder_secret_or_weak_quorum(self):
        bad = configuration()
        for edit in (
            lambda x: x["network"].update(name="mainnet"),
            lambda x: x["fixed"].update(min_oracles=1),
            lambda x: x["fixed"].update(oracle_keys=[AGENT(1)]),
            lambda x: x.update(private_key="dont-store-keys"),
            lambda x: x["roles"].update(grantor="uhCAk_placeholder"),
            lambda x: x["network"].update(genesis_hash="not-pinned"),
            lambda x: x["deployment"].update(approval="auto"),
        ):
            with self.subTest(edit=edit):
                x = json.loads(json.dumps(bad))
                edit(x)
                with self.assertRaises(ValueError):
                    config_tool.validate(x)

    def test_bond_refund_cannot_use_bonded_oracle_as_witness(self):
        bad = configuration("time_oracle_bond")
        bad["fixed"]["witness_oracles"].append(bad["roles"]["bonded_oracle"])
        with self.assertRaises(ValueError):
            config_tool.validate(bad)

class ReceiptTests(unittest.TestCase):
    def check(self, r, e=None, mutate_attestation=None):
        e = e or expectation(r)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "receipt.json"
            p.write_text(json.dumps(r, sort_keys=True))
            a = {"schema": "hc-vtime/unyt-chain-attestation/v1",
                 "genesis_hash": GENESIS, "tx_hash": TX,
                 "receipt_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                 "verification_method": "independent-unyt-node",
                 "finality_verified": True, "independent_record": "sha256:" + "ef" * 32}
            if mutate_attestation:
                mutate_attestation(a)
            return receipt_tool.checked(p, a, e)

    def test_valid_financial_scenarios(self):
        for outcome, allocated, locked in (
            ("partial_release", 100, 400),
            ("final_release", 500, 0),
            ("slashed", 500, 0),
            ("refunded", 500, 0),
            ("invalid_proof", 0, 500),
            ("unauthorized", 0, 500),
            ("too_early", 0, 500),
            ("duplicate", 0, 500),
        ):
            with self.subTest(outcome=outcome):
                status = "rejected" if allocated == 0 else "committed"
                self.check(receipt(outcome, allocated, locked, status))

    def test_value_loss_double_spend_wrong_receiver_and_forged_attestation(self):
        original = receipt("partial_release", 100, 400)
        errors = [
            lambda x: x.update(locked_remaining="399"),
            lambda x: x["allocations"][0].update(amount="-100"),
            lambda x: x["allocations"][0].update(receiver=AGENT(8)),
            lambda x: x["spent_sources"].append("bond-parked"),
            lambda x: x.update(network_genesis="00" * 32),
        ]
        for edit in errors:
            with self.subTest(edit=edit):
                bad = json.loads(json.dumps(original))
                edit(bad)
                with self.assertRaises(ValueError):
                    self.check(bad, expectation(original))
        for change in (
            lambda a: a.update(finality_verified=False),
            lambda a: a.update(receipt_sha256="ff" * 32),
            lambda a: a.update(verification_method="explorer-screenshot"),
            lambda a: a.update(genesis_hash="00" * 32),
            lambda a: a.update(independent_record=""),
        ):
            with self.subTest(attestation=change):
                with self.assertRaises(ValueError):
                    self.check(original, mutate_attestation=change)

    def test_rejected_transaction_never_spends_anything(self):
        r = receipt("invalid_proof", 100, 400, status="rejected")
        with self.assertRaises(ValueError):
            self.check(r)

class JournalTests(unittest.TestCase):
    def rows(self):
        return [
            {"agreement_id": "vesting-1", "tx_hash": "tx-1",
             "execution_id": "execution-1", "previous_execution_id": None,
             "input_total": "300", "paid": "100", "locked_remaining": "200",
             "spent_sources": ["parked-initial"], "status": "committed",
             "outcome": "partial_release"},
            {"agreement_id": "vesting-1", "tx_hash": "tx-2",
             "execution_id": "execution-2", "previous_execution_id": "execution-1",
             "input_total": "200", "paid": "200", "locked_remaining": "0",
             "spent_sources": ["carryover-1"], "status": "committed",
             "outcome": "final_release"},
        ]

    def journal(self, rows):
        return {"schema": "hc-vtime/unyt-receipt-journal/v1",
                "transactions": rows}

    def test_valid_chained_tranche_release(self):
        result = journal_tool.check_journal(self.journal(self.rows()))
        self.assertEqual(result["spent_sources"], 2)
        self.assertEqual(result["agreements"], 1)

    def test_duplicate_spend_missing_link_and_incorrect_carryover(self):
        for mutate in (
            lambda rows: rows[1].update(spent_sources=["parked-initial"]),
            lambda rows: rows[1].update(previous_execution_id="other"),
            lambda rows: rows[1].update(input_total="201"),
            lambda rows: rows[1].update(paid="201"),
            lambda rows: rows.append({
                **rows[1], "tx_hash": "tx-3", "execution_id": "execution-3",
                "previous_execution_id": "execution-2",
                "spent_sources": ["carryover-2"], "input_total": "0",
                "paid": "0", "locked_remaining": "0",
            }),
        ):
            with self.subTest(mutate=mutate):
                rows = self.rows()
                mutate(rows)
                with self.assertRaises(ValueError):
                    journal_tool.check_journal(self.journal(rows))

    def test_rejected_transaction_cannot_consume_sources(self):
        rows = self.rows()[:1]
        rows.append({"agreement_id": "vesting-1", "tx_hash": "rejected",
                     "execution_id": "attempt-x",
                     "previous_execution_id": "execution-1",
                     "input_total": "200", "paid": "0",
                     "locked_remaining": "200",
                     "spent_sources": [], "status": "rejected",
                     "outcome": "invalid_proof"})
        self.assertEqual(journal_tool.check_journal(self.journal(rows))["spent_sources"], 1)
        rows[-1]["spent_sources"] = ["parked-initial"]
        with self.assertRaises(ValueError):
            journal_tool.check_journal(self.journal(rows))

if __name__ == "__main__":
    unittest.main()
