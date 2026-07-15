"""End-to-end contract + scenario-detection test for data/alerts.json.

Run after `python generate_data.py && python engine.py`. Validates the
alert records against CONTRACTS.md's schema and CLAUDE.md INVARIANT 8 (all
5 labeled attack scenarios from data/scenarios.md must be detected).
"""
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
ALERTS_JSON = os.path.join(DATA_DIR, "alerts.json")

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_TIERS = {"PQC-READY", "QUANTUM-VULNERABLE", "CRITICAL"}
VALID_TIMELINE_TYPES = {"cyber", "txn"}

REQUIRED_ALERT_FIELDS = {
    "alert_id", "customer_id", "risk_score", "severity", "triggered_rules",
    "explanation", "contributing_features", "quantum_exposure",
    "recommended_action", "timeline",
}

# scenario_id -> raw actor id, per data/scenarios.md
SCENARIO_ACTORS = {
    "S1": "cust_0001",
    "S2": "cust_0002",
    "S3": "cust_0003",
    "S4": "sys_001",
    "S5": "cust_0005",
}


def _load_alerts():
    assert os.path.exists(ALERTS_JSON), f"{ALERTS_JSON} not found — run engine.py first"
    with open(ALERTS_JSON) as f:
        return json.load(f)


def validate_contract_shape(data):
    assert "alerts" in data and isinstance(data["alerts"], list), "alerts.json missing 'alerts' list"
    assert "kpis" in data and isinstance(data["kpis"], dict), "alerts.json missing 'kpis' dict"

    kpis = data["kpis"]
    for field in ("events_analyzed", "active_alerts", "fp_suppressed", "quantum_exposed_systems"):
        assert field in kpis, f"kpis missing '{field}'"

    for alert in data["alerts"]:
        missing = REQUIRED_ALERT_FIELDS - alert.keys()
        assert not missing, f"alert {alert.get('alert_id')} missing fields: {missing}"
        assert alert["severity"] in VALID_SEVERITIES, f"invalid severity {alert['severity']!r}"
        assert 0 <= alert["risk_score"] <= 100, f"risk_score out of range: {alert['risk_score']}"
        assert alert["customer_id"].startswith("cust_"), "customer_id must be pseudonymized (cust_ prefix)"

        qe = alert["quantum_exposure"]
        assert qe["tier"] in VALID_TIERS, f"invalid quantum_exposure.tier {qe['tier']!r}"
        assert isinstance(qe["hndl_flag"], bool)

        for rule in alert["triggered_rules"]:
            assert {"rule_id", "name", "severity"} <= rule.keys()
            assert rule["severity"] in VALID_SEVERITIES

        for feat in alert["contributing_features"]:
            assert {"feature", "value", "label"} <= feat.keys()

        for event in alert["timeline"]:
            assert {"ts", "type", "label"} <= event.keys()
            assert event["type"] in VALID_TIMELINE_TYPES, f"invalid timeline type {event['type']!r}"


def find_alert_for_actor(alerts, raw_actor_id):
    pseudo_id = engine.pseudonymize_customer_id(raw_actor_id)
    for alert in alerts:
        if alert["customer_id"] == pseudo_id:
            return alert
    return None


def _empty_session(customer_id, cyber_events=None, transactions=None):
    ts = pd.Timestamp("2026-01-01T00:00:00")
    return {
        "session_id": "sess_test_empty",
        "customer_id": customer_id,
        "start_ts": ts,
        "end_ts": ts,
        "cyber_events": cyber_events if cyber_events is not None else [],
        "transactions": transactions if transactions is not None else [],
        "correlated": False,
    }


def check_empty_window_customers_no_crash():
    """A session with zero cyber_events, zero transactions, or both must not
    crash evaluate_session/compute_session_features (empty-window customers
    with no correlated activity)."""
    no_cyber = _empty_session("cust_test_no_cyber", cyber_events=[])
    no_txn = _empty_session("cust_test_no_txn", transactions=[])
    both_empty = _empty_session("cust_test_both_empty")

    for session in (no_cyber, no_txn, both_empty):
        try:
            results = engine.evaluate_session(session, silence_days={}, baseline_bytes_by_actor={})
            features = engine.compute_session_features(
                session, customer_amount_stats={}, baseline_bytes_by_actor={}
            )
        except Exception as exc:  # noqa: BLE001 - we want to catch and report any crash
            raise AssertionError(
                f"empty-window session for {session['customer_id']!r} crashed: {exc!r}"
            ) from exc
        assert all(not r["fired"] for r in results.values()), (
            f"empty-window session for {session['customer_id']!r} unexpectedly fired a rule"
        )
        assert set(features.keys()) == set(engine.ML_FEATURE_NAMES)


def check_alerts_json_valid_json():
    """alerts.json must be well-formed JSON loadable by json.load."""
    assert os.path.exists(ALERTS_JSON), f"{ALERTS_JSON} not found — run engine.py first"
    with open(ALERTS_JSON) as f:
        try:
            json.load(f)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{ALERTS_JSON} is not valid JSON: {exc}") from exc


def check_kpis_block(data):
    """kpis block must be present and contain the 4 required CONTRACTS.md keys."""
    assert "kpis" in data, "alerts.json missing 'kpis' block"
    kpis = data["kpis"]
    required = {"events_analyzed", "active_alerts", "fp_suppressed", "quantum_exposed_systems"}
    missing = required - kpis.keys()
    assert not missing, f"kpis block missing keys: {missing}"


def main():
    check_alerts_json_valid_json()
    data = _load_alerts()
    validate_contract_shape(data)
    check_kpis_block(data)
    check_empty_window_customers_no_crash()
    alerts = data["alerts"]

    detected = 0
    s4_alert = None
    for scenario_id, raw_actor_id in SCENARIO_ACTORS.items():
        alert = find_alert_for_actor(alerts, raw_actor_id)
        assert alert is not None, f"{scenario_id} ({raw_actor_id}): no alert found"
        assert alert["severity"] in ("HIGH", "CRITICAL"), (
            f"{scenario_id} ({raw_actor_id}): expected HIGH/CRITICAL, got {alert['severity']}"
        )
        if scenario_id == "S4":
            s4_alert = alert
        detected += 1

    assert s4_alert is not None, "S4 (sys_001) alert not found"
    assert s4_alert["quantum_exposure"]["hndl_flag"] is True, "S4 must have hndl_flag true"

    hndl_true_alerts = [a for a in alerts if a["quantum_exposure"]["hndl_flag"] is True]
    assert hndl_true_alerts, "expected at least one alert with hndl_flag true"
    assert all(a is s4_alert for a in hndl_true_alerts), (
        "only the S4 system alert should have hndl_flag true"
    )
    for alert in hndl_true_alerts:
        rule_ids = {r["rule_id"] for r in alert["triggered_rules"]}
        assert "R5" in rule_ids, (
            f"{alert['alert_id']}: hndl_flag true without R5 (crypto+exfiltration) firing"
        )

    for alert in alerts:
        if alert not in hndl_true_alerts:
            assert alert["quantum_exposure"]["hndl_flag"] is False

    assert detected == 5, f"only {detected}/5 scenarios detected"
    print("5/5 scenarios detected — OK")


if __name__ == "__main__":
    main()
