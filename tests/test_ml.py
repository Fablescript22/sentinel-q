"""Tests for engine.py's ML anomaly layer (score_anomalies / IsolationForest).

Run: python tests/test_ml.py
Must print: ML OK
"""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import build_sessions, evaluate_rules, score_anomalies  # noqa: E402

DATA_DIR = ROOT / "data"
CYBER_CSV = DATA_DIR / "cyber_events.csv"
TXN_CSV = DATA_DIR / "transactions.csv"

# actor -> rule expected to fire for that scenario's session, per
# data/scenarios.md and tests/test_rules.py's SCENARIO_RULES.
SCENARIO_RULES = {
    "S1": ("cust_0001", "R4"),
    "S2": ("cust_0002", "R2"),
    "S3": ("cust_0003", "R3"),
    "S4": ("sys_001", "R5"),
    "S5": ("cust_0005", "R1"),
}


def _scenario_session_ids(hits):
    """The one session per scenario actor where its expected rule fired."""
    fired_sessions = {}
    for h in hits:
        fired_sessions.setdefault((h["customer_id"], h["rule_id"]), []).append(h["session_id"])

    ids = []
    for label, (actor_id, rule_id) in SCENARIO_RULES.items():
        session_ids = fired_sessions.get((actor_id, rule_id))
        assert session_ids, f"{label}: no session found where {rule_id} fired for {actor_id!r}"
        ids.append(session_ids[0])
    return ids


def main():
    cyber_df = pd.read_csv(CYBER_CSV)
    txn_df = pd.read_csv(TXN_CSV)

    sessions = build_sessions(cyber_df, txn_df)
    hits = evaluate_rules(sessions, cyber_df)
    scenario_session_ids = set(_scenario_session_ids(hits))
    assert len(scenario_session_ids) == 5, (
        f"expected 5 distinct scenario sessions, found {len(scenario_session_ids)}"
    )

    scores_1 = score_anomalies(sessions, cyber_df, txn_df)
    scores_2 = score_anomalies(sessions, cyber_df, txn_df)

    all_session_ids = {s["session_id"] for s in sessions}
    assert set(scores_1.keys()) == all_session_ids, "anomaly scores missing for some sessions"

    for sid, result in scores_1.items():
        score = result["anomaly_score"]
        assert 0.0 <= score <= 1.0, f"{sid}: anomaly_score {score} out of [0,1]"
        assert "features" in result, f"{sid}: missing stored feature dict"

    for sid in all_session_ids:
        s1, s2 = scores_1[sid]["anomaly_score"], scores_2[sid]["anomaly_score"]
        assert s1 == s2, f"{sid}: two consecutive runs gave different scores ({s1} vs {s2})"

    other_session_ids = all_session_ids - scenario_session_ids
    scenario_scores = [scores_1[sid]["anomaly_score"] for sid in scenario_session_ids]
    other_scores = [scores_1[sid]["anomaly_score"] for sid in other_session_ids]

    scenario_mean = sum(scenario_scores) / len(scenario_scores)
    other_mean = sum(other_scores) / len(other_scores)
    assert scenario_mean > other_mean, (
        f"scenario sessions mean anomaly_score ({scenario_mean:.3f}) not higher than "
        f"other sessions mean ({other_mean:.3f})"
    )

    print("ML OK")


if __name__ == "__main__":
    main()
