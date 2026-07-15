"""Tests for engine.py build_sessions().

Run: python tests/test_sessions.py
Must print: SESSIONS OK
"""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import build_sessions  # noqa: E402

DATA_DIR = ROOT / "data"
CYBER_CSV = DATA_DIR / "cyber_events.csv"
TXN_CSV = DATA_DIR / "transactions.csv"

# Actor ids per data/scenarios.md.
SCENARIO_IDS = {
    "S1": "cust_0001",
    "S2": "cust_0002",
    "S3": "cust_0003",
    "S4": "sys_001",  # system-level: check cyber_events, not a session actor alone
    "S5": "cust_0005",
}


def main():
    cyber_df = pd.read_csv(CYBER_CSV)
    txn_df = pd.read_csv(TXN_CSV)

    sessions = build_sessions(cyber_df, txn_df)
    assert len(sessions) > 0, "build_sessions returned no sessions"

    sessions_by_customer = {}
    for s in sessions:
        sessions_by_customer.setdefault(s["customer_id"], []).append(s)

    for label, actor_id in SCENARIO_IDS.items():
        if label == "S4":
            found = any(
                any(evt["customer_id"] == actor_id for evt in s["cyber_events"])
                for s in sessions
            )
            assert found, f"{label}: system id {actor_id!r} not found in any session's cyber_events"
            continue

        actor_sessions = sessions_by_customer.get(actor_id, [])
        assert len(actor_sessions) >= 1, f"{label}: no sessions found for {actor_id!r}"
        assert any(s["correlated"] for s in actor_sessions), (
            f"{label}: actor {actor_id!r} has no correlated session "
            f"(>=1 cyber event AND >=1 transaction)"
        )

    print("SESSIONS OK")


if __name__ == "__main__":
    main()
