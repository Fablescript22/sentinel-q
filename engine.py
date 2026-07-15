"""Session builder + rules layer for SENTINEL-Q.

build_sessions() groups each actor's (customer or internal system) cyber
events and transactions into sessions using gap-based sessionization: a new
session starts whenever the gap since that actor's previous event exceeds 60
minutes. This is gap-based sessionization (a new session starts when the
inactivity gap exceeds 60 minutes), not a fixed sliding window.

The rules layer (R1-R5) below is a transparent, threshold-based pass over
those sessions. Per CLAUDE.md INVARIANT 4, this layer only fires rules and
explains them in plain English — it does not score. ML-based scoring is a
separate later stage.
"""
import os
from datetime import timedelta

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

import crypto_agility

SESSION_GAP_MINUTES = 60
RANDOM_SEED = 42  # CLAUDE.md INVARIANT 1: RANDOM_SEED = 42 everywhere.

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CYBER_CSV = os.path.join(DATA_DIR, "cyber_events.csv")
TXN_CSV = os.path.join(DATA_DIR, "transactions.csv")

# ---------------------------------------------------------------------------
# Rule thresholds — plain, explainable numbers. No statistics/ML in this
# layer (that's IsolationForest's job elsewhere, per CLAUDE.md INVARIANT 4).
# ---------------------------------------------------------------------------
IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 90
NEW_BENEFICIARY_WINDOW_MINUTES = 60
LARGE_TRANSFER_THRESHOLD_INR = 500_000
RISKY_LOGIN_WINDOW_MINUTES = 60
CRED_STUFFING_MIN_FAILED_LOGINS = 20
CRED_STUFFING_TXN_WINDOW_MINUTES = 15
DORMANT_GAP_DAYS = 20
DORMANT_BURST_WINDOW_MINUTES = 60

RULE_SEVERITY = {
    "R1": "HIGH",      # impossible travel + transfer
    "R2": "HIGH",      # credential stuffing -> success -> rapid transfers
    "R3": "MEDIUM",    # dormant account burst
    "R4": "HIGH",      # new beneficiary + large transfer after a risky login
    "R5": "CRITICAL",  # HNDL pattern (weak crypto AND exfiltration-shaped bytes)
}

# ISO country code -> display name, used only to make explanation strings
# readable ("Germany" instead of "DE"). This is exactly the src_country the
# event recorded, just spelled out — not an added geolocation claim.
COUNTRY_NAMES = {
    "IN": "India", "US": "the United States", "GB": "the United Kingdom",
    "SG": "Singapore", "AE": "the UAE", "DE": "Germany", "NG": "Nigeria",
    "RU": "Russia", "CN": "China",
}


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


# ---------------------------------------------------------------------------
# small helpers shared by the rules
# ---------------------------------------------------------------------------

def _country_name(code):
    return COUNTRY_NAMES.get(code, code)


def _fmt_inr(amount):
    """Rs figures in lakh/crore, matching CONTRACTS.md's example style."""
    if amount >= 1e7:
        return f"Rs {amount / 1e7:.2f}Cr"
    if amount >= 1e5:
        return f"Rs {amount / 1e5:.2f}L"
    return f"Rs {amount:,.2f}"


def _fmt_time(ts):
    return f"{ts:%H:%M} IST"


def _parse_ts(value):
    return value if isinstance(value, pd.Timestamp) else pd.to_datetime(value)


def _sorted_logins(session, success=None):
    logins = [e for e in session["cyber_events"] if e["event_type"] == "login"]
    if success is not None:
        logins = [e for e in logins if e["success"] == success]
    return sorted(logins, key=lambda e: e["ts"])


def _no_fire(rule_id):
    return {"rule_id": rule_id, "fired": False, "severity": RULE_SEVERITY[rule_id], "explanation": None}


def _new_beneficiary_transfer_after(session, after_ts):
    """First transaction at/after after_ts whose beneficiary was added no
    more than NEW_BENEFICIARY_WINDOW_MINUTES before it, or None."""
    for txn in sorted(session["transactions"], key=lambda t: t["ts"]):
        if txn["ts"] < after_ts:
            continue
        benef_added = _parse_ts(txn["beneficiary_added_ts"])
        age_min = (txn["ts"] - benef_added).total_seconds() / 60
        if 0 <= age_min <= NEW_BENEFICIARY_WINDOW_MINUTES:
            return txn
    return None


# ---------------------------------------------------------------------------
# R1 — impossible travel + transfer
# ---------------------------------------------------------------------------

def rule_r1_impossible_travel(session):
    """Two successful logins from different countries close together,
    followed by a transfer to a beneficiary added shortly before it."""
    logins = _sorted_logins(session, success=True)
    for i in range(len(logins)):
        for j in range(i + 1, len(logins)):
            a, b = logins[i], logins[j]
            gap_min = (b["ts"] - a["ts"]).total_seconds() / 60
            if gap_min > IMPOSSIBLE_TRAVEL_WINDOW_MINUTES:
                break  # logins sorted ascending -> later j's only widen the gap
            if a["src_country"] == b["src_country"]:
                continue
            txn = _new_beneficiary_transfer_after(session, b["ts"])
            if txn is None:
                continue
            benef_age_min = (txn["ts"] - _parse_ts(txn["beneficiary_added_ts"])).total_seconds() / 60
            explanation = (
                f"Login from {_country_name(b['src_country'])} at {_fmt_time(b['ts'])}, "
                f"{gap_min:.0f} min after a login from {_country_name(a['src_country'])}, "
                f"followed by a {_fmt_inr(txn['amount_inr'])} {txn['channel']} transfer to a "
                f"beneficiary added {benef_age_min:.0f} minutes earlier."
            )
            return {"rule_id": "R1", "fired": True, "severity": RULE_SEVERITY["R1"], "explanation": explanation}
    return _no_fire("R1")


# ---------------------------------------------------------------------------
# R2 — credential stuffing then success then rapid transfers
# ---------------------------------------------------------------------------

def rule_r2_credential_stuffing(session):
    """20+ consecutive failed logins immediately followed by a successful
    login, then at least one transfer within a short window after it."""
    logins = _sorted_logins(session)
    i, n = 0, len(logins)
    while i < n:
        if logins[i]["success"]:
            i += 1
            continue
        j = i
        while j < n and not logins[j]["success"]:
            j += 1
        failed_count = j - i
        if failed_count >= CRED_STUFFING_MIN_FAILED_LOGINS and j < n:
            success_login = logins[j]
            window_end = success_login["ts"] + timedelta(minutes=CRED_STUFFING_TXN_WINDOW_MINUTES)
            rapid_txns = [
                t for t in session["transactions"]
                if success_login["ts"] <= t["ts"] <= window_end
            ]
            if rapid_txns:
                total = sum(t["amount_inr"] for t in rapid_txns)
                explanation = (
                    f"{failed_count} failed logins from {logins[i]['device_id']} between "
                    f"{_fmt_time(logins[i]['ts'])} and {_fmt_time(logins[j - 1]['ts'])}, followed by "
                    f"a successful login and {len(rapid_txns)} transfers totaling {_fmt_inr(total)} "
                    f"within {CRED_STUFFING_TXN_WINDOW_MINUTES} minutes."
                )
                return {"rule_id": "R2", "fired": True, "severity": RULE_SEVERITY["R2"], "explanation": explanation}
        i = j
    return _no_fire("R2")


# ---------------------------------------------------------------------------
# R3 — dormant account burst
# ---------------------------------------------------------------------------

def rule_r3_dormant_burst(session, silence_days):
    """silence_days: days of inactivity for this actor immediately before
    this session started (None if unknown). Fires on a long silence followed
    by a login and a large transfer soon after."""
    if silence_days is None or silence_days < DORMANT_GAP_DAYS:
        return _no_fire("R3")

    logins = _sorted_logins(session, success=True)
    if not logins:
        return _no_fire("R3")
    login = logins[0]
    window_end = login["ts"] + timedelta(minutes=DORMANT_BURST_WINDOW_MINUTES)
    big_txns = sorted(
        (t for t in session["transactions"]
         if login["ts"] <= t["ts"] <= window_end and t["amount_inr"] >= LARGE_TRANSFER_THRESHOLD_INR),
        key=lambda t: t["ts"],
    )
    if not big_txns:
        return _no_fire("R3")
    txn = big_txns[0]
    minutes = (txn["ts"] - login["ts"]).total_seconds() / 60
    explanation = (
        f"Account silent for {silence_days:.0f} days, then a login followed "
        f"{minutes:.0f} minutes later by a {_fmt_inr(txn['amount_inr'])} {txn['channel']} transfer."
    )
    return {"rule_id": "R3", "fired": True, "severity": RULE_SEVERITY["R3"], "explanation": explanation}


# ---------------------------------------------------------------------------
# R4 — new beneficiary + large transfer within 60 min of a risky login
# ---------------------------------------------------------------------------

def rule_r4_new_beneficiary_large_transfer(session):
    """A successful foreign login ("risky") followed within an hour by a
    large transfer to a beneficiary added shortly before it."""
    risky_logins = [e for e in _sorted_logins(session, success=True) if e["src_country"] != "IN"]
    for login in risky_logins:
        window_end = login["ts"] + timedelta(minutes=RISKY_LOGIN_WINDOW_MINUTES)
        for txn in sorted(session["transactions"], key=lambda t: t["ts"]):
            if not (login["ts"] <= txn["ts"] <= window_end):
                continue
            if txn["amount_inr"] < LARGE_TRANSFER_THRESHOLD_INR:
                continue
            benef_added = _parse_ts(txn["beneficiary_added_ts"])
            age_min = (txn["ts"] - benef_added).total_seconds() / 60
            if not (0 <= age_min <= NEW_BENEFICIARY_WINDOW_MINUTES):
                continue
            minutes = (txn["ts"] - login["ts"]).total_seconds() / 60
            explanation = (
                f"Login from {_country_name(login['src_country'])} at {_fmt_time(login['ts'])} "
                f"followed {minutes:.0f} minutes later by a {_fmt_inr(txn['amount_inr'])} "
                f"{txn['channel']} transfer to a beneficiary added {age_min:.0f} minutes earlier."
            )
            return {"rule_id": "R4", "fired": True, "severity": RULE_SEVERITY["R4"], "explanation": explanation}
    return _no_fire("R4")


# ---------------------------------------------------------------------------
# R5 — HNDL pattern (weak/vulnerable crypto AND exfiltration-shaped bytes_out)
# ---------------------------------------------------------------------------

def rule_r5_hndl_pattern(session, baseline_bytes_by_actor):
    """Delegates tiering + the crypto-AND-exfiltration gate to crypto_agility
    (per CLAUDE.md INVARIANT 2 — crypto posture alone is never enough).

    Scoped to system-level actors (customer_id prefix "sys_"), per
    data/scenarios.md's S4 being explicitly "system-level (cyber CSV only)":
    only systems get one stable per-actor baseline in the generator (a
    single distribution feeds all of a system's event types). Customer
    telemetry mixes low-byte event types (login/vpn) with high-byte ones
    (file_transfer/tls_session) under one actor, so a per-customer median
    baseline is not a meaningful "normal" to compare against.
    """
    for evt in sorted(session["cyber_events"], key=lambda e: e["ts"]):
        if not evt["customer_id"].startswith("sys_"):
            continue
        baseline = baseline_bytes_by_actor.get(evt["customer_id"])
        if not baseline:
            continue
        tier_info = crypto_agility.classify(evt.get("key_exchange"))
        if not crypto_agility.hndl_context(tier_info["tier"], evt["bytes_out"], baseline):
            continue
        multiple = evt["bytes_out"] / baseline
        explanation = (
            f"{evt['customer_id']} sent {evt['bytes_out']:,} bytes via {evt['event_type']} using "
            f"{evt['key_exchange']} ({tier_info['tier']}) — {multiple:.1f}x its baseline of "
            f"{baseline:,.0f} bytes, and that crypto is quantum-exposed."
        )
        return {"rule_id": "R5", "fired": True, "severity": RULE_SEVERITY["R5"], "explanation": explanation}
    return _no_fire("R5")


# ---------------------------------------------------------------------------
# context builders + driver
# ---------------------------------------------------------------------------

def compute_actor_baseline_bytes(cyber_df):
    """Median bytes_out per actor (customer_id or system id) — the 'normal'
    traffic volume R5 compares against."""
    return cyber_df.groupby("customer_id")["bytes_out"].median().to_dict()


def compute_silence_days(sessions):
    """Days of inactivity immediately before each session started, keyed by
    session_id. An actor's first session is measured from the dataset's
    earliest event; later sessions are measured from that actor's previous
    session end."""
    by_actor = {}
    for s in sessions:
        by_actor.setdefault(s["customer_id"], []).append(s)

    dataset_start = min(s["start_ts"] for s in sessions)

    silence_days = {}
    for actor_sessions in by_actor.values():
        actor_sessions = sorted(actor_sessions, key=lambda s: s["start_ts"])
        prev_end = None
        for s in actor_sessions:
            reference = prev_end if prev_end is not None else dataset_start
            silence_days[s["session_id"]] = (s["start_ts"] - reference).total_seconds() / 86400
            prev_end = s["end_ts"]
    return silence_days


def evaluate_session(session, silence_days, baseline_bytes_by_actor):
    """Run all 5 rules against one session. Returns {rule_id: result}."""
    return {
        "R1": rule_r1_impossible_travel(session),
        "R2": rule_r2_credential_stuffing(session),
        "R3": rule_r3_dormant_burst(session, silence_days.get(session["session_id"])),
        "R4": rule_r4_new_beneficiary_large_transfer(session),
        "R5": rule_r5_hndl_pattern(session, baseline_bytes_by_actor),
    }


def evaluate_rules(sessions, cyber_df):
    """Run all 5 rules over every session. Returns a flat list of fired hits:
    {session_id, customer_id, rule_id, severity, explanation}."""
    silence_days = compute_silence_days(sessions)
    baseline_bytes_by_actor = compute_actor_baseline_bytes(cyber_df)

    hits = []
    for session in sessions:
        results = evaluate_session(session, silence_days, baseline_bytes_by_actor)
        for rule_id, result in results.items():
            if result["fired"]:
                hits.append({
                    "session_id": session["session_id"],
                    "customer_id": session["customer_id"],
                    "rule_id": rule_id,
                    "severity": result["severity"],
                    "explanation": result["explanation"],
                })
    return hits


# ---------------------------------------------------------------------------
# ML anomaly layer — IsolationForest over engineered per-session features.
# Per CLAUDE.md INVARIANT 4, this layer only SCORES: it does not fire alerts
# and does not read or influence the rules (R1-R5) above in any way.
# ---------------------------------------------------------------------------
ML_CONTAMINATION = 0.05

# Sentinel value used ONLY when a session has zero transactions — large on
# purpose, so "no transactions" reads as "nothing recent" rather than
# colliding with a genuinely fresh (near-zero-minute) beneficiary. Sessions
# WITH transactions always get the real minimum beneficiary age, even if
# every beneficiary is old.
NEW_BENEFICIARY_NO_SIGNAL_MINUTES = 1_000_000.0

ML_FEATURE_NAMES = [
    "amount_zscore",
    "txn_velocity",
    "geo_velocity",
    "new_beneficiary_recency",
    "failed_login_count",
    "bytes_out_ratio",
]


def compute_customer_amount_stats(txn_df):
    """Per customer_id: (mean, std) of amount_inr across all their
    transactions in the dataset (the dataset window is 30 days, per
    data/scenarios.md) — the baseline compared against for amount_zscore."""
    grouped = txn_df.groupby("customer_id")["amount_inr"]
    mean = grouped.mean()
    std = grouped.std()
    stats = {}
    for customer_id in mean.index:
        s = std[customer_id]
        stats[customer_id] = (mean[customer_id], s if pd.notna(s) and s > 0 else 0.0)
    return stats


def _session_duration_minutes(session):
    return max((session["end_ts"] - session["start_ts"]).total_seconds() / 60.0, 1.0)


def _amount_zscore(session, customer_amount_stats):
    """Session's total transferred amount, z-scored against this customer's
    per-transaction amount distribution."""
    txns = session["transactions"]
    if not txns:
        return 0.0
    mean, std = customer_amount_stats.get(session["customer_id"], (0.0, 0.0))
    if std <= 0:
        return 0.0
    total = sum(t["amount_inr"] for t in txns)
    return (total - mean) / std


def _txn_velocity(session):
    """Transactions per hour of session duration."""
    return len(session["transactions"]) / (_session_duration_minutes(session) / 60.0)


def _geo_velocity(session):
    """Login source-country switches per hour of session duration — a proxy
    for impossible-travel-shaped behaviour without needing lat/long data."""
    logins = sorted(
        (e for e in session["cyber_events"] if e["event_type"] == "login"),
        key=lambda e: e["ts"],
    )
    if len(logins) < 2:
        return 0.0
    switches = sum(1 for a, b in zip(logins, logins[1:]) if a["src_country"] != b["src_country"])
    if switches == 0:
        return 0.0
    return switches / (_session_duration_minutes(session) / 60.0)


def _new_beneficiary_recency(session):
    """Minutes between the freshest beneficiary_added_ts and its transaction
    in this session — small values mean a beneficiary was added just before
    being paid. NEW_BENEFICIARY_NO_SIGNAL_MINUTES if the session has no
    transactions at all."""
    ages = []
    for t in session["transactions"]:
        added = _parse_ts(t["beneficiary_added_ts"])
        age_min = (_parse_ts(t["ts"]) - added).total_seconds() / 60.0
        ages.append(max(age_min, 0.0))
    if not ages:
        return NEW_BENEFICIARY_NO_SIGNAL_MINUTES
    return min(ages)


def _failed_login_count(session):
    return float(sum(
        1 for e in session["cyber_events"]
        if e["event_type"] == "login" and not e["success"]
    ))


def _bytes_out_ratio(session, baseline_bytes_by_actor):
    """Session's total bytes_out over this actor's baseline (median)
    bytes_out — reuses the same baseline R5 compares against."""
    cyber_events = session["cyber_events"]
    if not cyber_events:
        return 0.0
    baseline = baseline_bytes_by_actor.get(session["customer_id"])
    if not baseline or baseline <= 0:
        return 0.0
    total_bytes = sum(e["bytes_out"] for e in cyber_events)
    return total_bytes / baseline


def compute_session_features(session, customer_amount_stats, baseline_bytes_by_actor):
    """Engineer the per-session ML_FEATURE_NAMES feature dict for one
    session. Pure function of its inputs — no ML here, just numbers."""
    return {
        "amount_zscore": _amount_zscore(session, customer_amount_stats),
        "txn_velocity": _txn_velocity(session),
        "geo_velocity": _geo_velocity(session),
        "new_beneficiary_recency": _new_beneficiary_recency(session),
        "failed_login_count": _failed_login_count(session),
        "bytes_out_ratio": _bytes_out_ratio(session, baseline_bytes_by_actor),
    }


def score_anomalies(sessions, cyber_df, txn_df):
    """Fit IsolationForest over engineered per-session features and score
    every session. Returns {session_id: {"anomaly_score": float in [0,1],
    "features": {...}}} — the feature dict is stored per session for later
    explanation (e.g. contributing_features in CONTRACTS.md's alerts.json).

    ML-only: this function does not fire alerts and does not touch the
    rules layer (R1-R5) above, per CLAUDE.md INVARIANT 4.
    """
    baseline_bytes_by_actor = compute_actor_baseline_bytes(cyber_df)
    customer_amount_stats = compute_customer_amount_stats(txn_df)

    session_ids = [s["session_id"] for s in sessions]
    features_by_session = {
        s["session_id"]: compute_session_features(s, customer_amount_stats, baseline_bytes_by_actor)
        for s in sessions
    }

    X = np.array([
        [features_by_session[sid][name] for name in ML_FEATURE_NAMES]
        for sid in session_ids
    ])

    model = IsolationForest(random_state=RANDOM_SEED, contamination=ML_CONTAMINATION)
    model.fit(X)
    raw_anomaly = -model.score_samples(X)  # higher = more anomalous

    lo, hi = raw_anomaly.min(), raw_anomaly.max()
    spread = hi - lo
    normalized = (raw_anomaly - lo) / spread if spread > 0 else np.zeros_like(raw_anomaly)

    return {
        sid: {"anomaly_score": float(normalized[i]), "features": features_by_session[sid]}
        for i, sid in enumerate(session_ids)
    }


if __name__ == "__main__":
    cyber_df = pd.read_csv(CYBER_CSV)
    txn_df = pd.read_csv(TXN_CSV)
    sessions = build_sessions(cyber_df, txn_df)
    correlated = sum(1 for s in sessions if s["correlated"])
    print(f"{len(sessions)} total sessions, {correlated} correlated")

    hits = evaluate_rules(sessions, cyber_df)
    print(f"{len(hits)} rule hits across {len(sessions)} sessions")

    anomaly_scores = score_anomalies(sessions, cyber_df, txn_df)
    print(f"ML anomaly scores computed for {len(anomaly_scores)} sessions")
