"""Tests for engine.py's rules layer (R1-R5).

Run: python tests/test_rules.py
Must print: RULES OK
"""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import build_sessions, evaluate_rules  # noqa: E402

DATA_DIR = ROOT / "data"
CYBER_CSV = DATA_DIR / "cyber_events.csv"
TXN_CSV = DATA_DIR / "transactions.csv"

# Actor -> expected rule per data/scenarios.md.
SCENARIO_RULES = {
    "S1": ("cust_0001", "R4"),  # account takeover -> new beneficiary + large transfer after risky login
    "S2": ("cust_0002", "R2"),  # credential stuffing -> success -> rapid transfers
    "S3": ("cust_0003", "R3"),  # dormant account burst
    "S4": ("sys_001", "R5"),    # HNDL exfiltration
    "S5": ("cust_0005", "R1"),  # impossible travel + transfer
}

# Customers with only ordinary background activity (no scripted scenario).
CLEAN_CUSTOMERS = ["cust_0010", "cust_0100", "cust_0400"]


def main():
    cyber_df = pd.read_csv(CYBER_CSV)
    txn_df = pd.read_csv(TXN_CSV)

    sessions = build_sessions(cyber_df, txn_df)
    hits = evaluate_rules(sessions, cyber_df)

    hits_by_actor = {}
    for h in hits:
        hits_by_actor.setdefault(h["customer_id"], set()).add(h["rule_id"])

    for label, (actor_id, expected_rule) in SCENARIO_RULES.items():
        fired = hits_by_actor.get(actor_id, set())
        assert expected_rule in fired, (
            f"{label}: expected {expected_rule} to fire for {actor_id!r}, "
            f"but it fired {fired or 'nothing'}"
        )

    for customer_id in CLEAN_CUSTOMERS:
        fired = hits_by_actor.get(customer_id, set())
        assert not fired, (
            f"known-clean customer {customer_id!r} unexpectedly fired {fired}"
        )

    print("RULES OK")


if __name__ == "__main__":
    main()
