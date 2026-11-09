#!/usr/bin/env python3
"""Validate inter-transaction financial continuity after per-receipt verification.

Not a consensus verifier. Use only receipts independently authenticated
through the testnet client + verified chain evidence from Sprint 14B.
"""
import argparse
import json
from pathlib import Path

def check_journal(journal):
    if not isinstance(journal, dict) or set(journal) != {"schema", "transactions"}:
        raise ValueError("unknown journal schema")
    if journal["schema"] != "hc-vtime/unyt-receipt-journal/v1":
        raise ValueError("unsupported journal version")
    rows = journal["transactions"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("empty transaction sequence")
    seen_transactions = set()
    spent = set()
    last_by_agreement = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "agreement_id", "tx_hash", "execution_id", "previous_execution_id",
            "input_total", "paid", "locked_remaining", "spent_sources",
            "status", "outcome",
        }:
            raise ValueError(f"journal row {i} has unknown fields")
        if not isinstance(row["agreement_id"], str) or not row["agreement_id"]:
            raise ValueError("empty agreement id")
        key = (row["agreement_id"], row["tx_hash"])
        if key in seen_transactions:
            raise ValueError("same transaction appears twice in journal")
        seen_transactions.add(key)
        if not all(isinstance(row[k], str) and row[k].isdigit()
                   and str(int(row[k])) == row[k]
                   for k in ("input_total", "paid", "locked_remaining")):
            raise ValueError("noncanonical journal amount")
        input_total, paid, locked = (
            int(row[k]) for k in ("input_total", "paid", "locked_remaining")
        )
        if not isinstance(row["spent_sources"], list) or len(set(row["spent_sources"])) != len(row["spent_sources"]):
            raise ValueError("duplicate sources in journal entry")
        if row["status"] == "rejected":
            if paid != 0 or locked != input_total or row["spent_sources"]:
                raise ValueError("rejected execution moved assets")
            continue
        if row["status"] != "committed":
            raise ValueError("journal contains nonfinalized status")
        if paid + locked != input_total:
            raise ValueError("journal row violates conservation")
        if not row["spent_sources"]:
            raise ValueError("committed execution must identify source links")
        if any(source in spent for source in row["spent_sources"]):
            raise ValueError("previously consumed source was spent twice")
        spent.update(row["spent_sources"])
        previous = last_by_agreement.get(row["agreement_id"])
        if previous is None:
            if row["previous_execution_id"] is not None:
                raise ValueError("initial agreement execution has a previous link")
        else:
            prev_exec_id, prev_locked, prev_outcome = previous
            if row["previous_execution_id"] != prev_exec_id:
                raise ValueError("execution chain has a missing/wrong predecessor")
            if prev_locked != input_total:
                raise ValueError("carryover input is not previous locked remainder")
            if prev_locked == 0 or prev_outcome in ("slashed", "refunded", "final_release"):
                raise ValueError("agreement already terminal")
        if row["outcome"] in ("slashed", "refunded", "final_release") and locked != 0:
            raise ValueError("terminal state retains locked assets")
        last_by_agreement[row["agreement_id"]] = (
            row["execution_id"], locked, row["outcome"]
        )
    return {"transactions": len(rows), "spent_sources": len(spent),
            "agreements": len(last_by_agreement)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    args = parser.parse_args()
    result = check_journal(json.loads(args.journal.read_text()))
    print("JOURNAL ACCOUNTING CHECKS PASSED:", result)
    print("NOT ON-CHAIN VALIDATION. Verify every underlying receipt independently.")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise SystemExit(f"REJECTED: {exc}")
