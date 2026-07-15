"""Session builder for SENTINEL-Q.

Groups each actor's (customer or internal system) cyber events and
transactions into sessions using gap-based sessionization: a new session
starts whenever the gap since that actor's previous event exceeds 60
minutes. This is gap-based sessionization (a new session starts when the
inactivity gap exceeds 60 minutes), not a fixed sliding window.

Per CLAUDE.md: no rules, no ML, no scoring here — that comes later.
pandas/numpy only.
"""
import os

import pandas as pd

SESSION_GAP_MINUTES = 60

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CYBER_CSV = os.path.join(DATA_DIR, "cyber_events.csv")
TXN_CSV = os.path.join(DATA_DIR, "transactions.csv")


def build_sessions(cyber_df: pd.DataFrame, txn_df: pd.DataFrame) -> list:
    """Group each customer_id's cyber events + transactions into sessions.

    A session is a run of events for one customer_id (or internal system
    id) where no gap between consecutive events -- cyber events and
    transactions combined and sorted by ts -- exceeds SESSION_GAP_MINUTES.
    Sessions containing at least one cyber event AND at least one
    transaction are flagged "correlated": True.

    Returns a list of Session dicts, sorted by (customer_id, start_ts):
      {
        "session_id": str,
        "customer_id": str,
        "start_ts": pd.Timestamp,
        "end_ts": pd.Timestamp,
        "cyber_events": list[dict],
        "transactions": list[dict],
        "correlated": bool,
      }
    """
    cyber_cols = list(cyber_df.columns)
    txn_cols = list(txn_df.columns)

    cyber = cyber_df.copy()
    txn = txn_df.copy()
    cyber["ts"] = pd.to_datetime(cyber["ts"], format="ISO8601")
    txn["ts"] = pd.to_datetime(txn["ts"], format="ISO8601")
    cyber["_kind"] = "cyber"
    txn["_kind"] = "txn"

    combined = pd.concat([cyber, txn], ignore_index=True, sort=False)
    combined = combined.sort_values(["customer_id", "ts"], kind="stable").reset_index(drop=True)

    gap = combined.groupby("customer_id")["ts"].diff()
    new_session = gap.isna() | (gap > pd.Timedelta(minutes=SESSION_GAP_MINUTES))
    combined["_session_seq"] = new_session.groupby(combined["customer_id"]).cumsum()

    sessions = []
    for i, (_key, rows) in enumerate(
        combined.groupby(["customer_id", "_session_seq"], sort=False), start=1
    ):
        rows = rows.sort_values("ts")
        cyber_rows = rows[rows["_kind"] == "cyber"][cyber_cols]
        txn_rows = rows[rows["_kind"] == "txn"][txn_cols]
        sessions.append({
            "session_id": f"sess_{i:06d}",
            "customer_id": rows["customer_id"].iloc[0],
            "start_ts": rows["ts"].min(),
            "end_ts": rows["ts"].max(),
            "cyber_events": cyber_rows.to_dict("records"),
            "transactions": txn_rows.to_dict("records"),
            "correlated": bool(len(cyber_rows) > 0 and len(txn_rows) > 0),
        })

    return sessions


if __name__ == "__main__":
    cyber_df = pd.read_csv(CYBER_CSV)
    txn_df = pd.read_csv(TXN_CSV)
    sessions = build_sessions(cyber_df, txn_df)
    correlated = sum(1 for s in sessions if s["correlated"])
    print(f"{len(sessions)} total sessions, {correlated} correlated")
