"""Generates data/alerts.json — mock SOC alerts conforming to CONTRACTS.md.

Standalone stand-in for engine.py output so app.py can be built/demoed
before the real correlation engine is wired up.
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
# 20 alerts, weighted so the table looks like a real SOC queue, not a toy.
SEVERITY_PLAN = (
    ["CRITICAL"] * 3
    + ["HIGH"] * 6
    + ["MEDIUM"] * 7
    + ["LOW"] * 4
)

INDIAN_CITIES = ["Mumbai", "Pune", "Bengaluru", "Delhi", "Hyderabad", "Chennai", "Kolkata", "Ahmedabad", "Jaipur", "Kochi"]
FOREIGN_CITIES = ["Frankfurt", "Singapore", "Dubai", "London", "Lagos", "Moscow", "Hong Kong", "Amsterdam"]

CHANNELS = ["NEFT", "RTGS", "UPI"]

FIRST_NAMES = ["Aarav", "Vivaan", "Ishaan", "Ananya", "Diya", "Kabir", "Meera", "Rohan", "Sanya", "Arjun",
               "Priya", "Karan", "Neha", "Aditya", "Riya", "Yash", "Tanvi", "Dev", "Simran", "Rahul"]

RULE_CATALOG = [
    {"rule_id": "R1", "name": "Impossible travel + transfer", "severity": "HIGH"},
    {"rule_id": "R2", "name": "New beneficiary + high-value transfer", "severity": "HIGH"},
    {"rule_id": "R3", "name": "Multiple failed logins then success", "severity": "MEDIUM"},
    {"rule_id": "R4", "name": "Odd-hour transaction burst", "severity": "MEDIUM"},
    {"rule_id": "R5", "name": "Device fingerprint mismatch", "severity": "MEDIUM"},
    {"rule_id": "R6", "name": "SIM swap flag + fund transfer", "severity": "CRITICAL"},
    {"rule_id": "R7", "name": "Velocity breach across channels", "severity": "HIGH"},
    {"rule_id": "R8", "name": "Dormant account reactivation", "severity": "LOW"},
    {"rule_id": "R9", "name": "Geo-IP / billing address mismatch", "severity": "LOW"},
    {"rule_id": "R10", "name": "Large withdrawal after credential reset", "severity": "CRITICAL"},
]

FEATURE_POOL = [
    ("amount_zscore", "Amount is {v} SD above this customer's average", (2.0, 5.5)),
    ("login_velocity_zscore", "Login velocity is {v} SD above baseline", (1.8, 4.8)),
    ("beneficiary_age_minutes", "Beneficiary added only {v} minutes before transfer", (2, 45)),
    ("txn_hour_zscore", "Transaction hour deviates {v} SD from customer's usual pattern", (1.5, 4.0)),
    ("device_trust_score", "Device trust score dropped to {v}", (0.05, 0.4)),
    ("distance_km_per_min", "Implied travel speed of {v} km/min between logins", (8, 60)),
]

ACTIONS_BY_SEVERITY = {
    "CRITICAL": ["Freeze beneficiary, step-up auth", "Suspend account, escalate to fraud desk", "Block transaction, call customer on registered number"],
    "HIGH": ["Step-up authentication, hold transaction 24h", "Flag for manual review, notify RM", "Require OTP re-verification"],
    "MEDIUM": ["Monitor account for 48h", "Send customer alert notification", "Queue for analyst review"],
    "LOW": ["Log for periodic audit", "No immediate action, add to watchlist"],
}

QUANTUM_TIERS = ["PQC-READY", "QUANTUM-VULNERABLE", "CRITICAL"]


def pseudo_customer_id(n):
    # SHA-256 pseudonymization per CLAUDE.md invariant #6.
    import hashlib
    return "cust_" + hashlib.sha256(f"customer-{n}".encode()).hexdigest()[:8]


def make_timeline(base_hour, base_minute, channel, foreign_city, home_city, amount):
    base_dt = datetime(2026, 7, 13, base_hour, base_minute)
    login_gap = random.randint(15, 55)
    beneficiary_gap = random.randint(2, 12)
    transfer_gap = random.randint(3, 20)

    t1 = base_dt + timedelta(minutes=login_gap)
    t2 = t1 + timedelta(minutes=beneficiary_gap)
    t3 = t2 + timedelta(minutes=transfer_gap)

    def ts(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    events = [
        {"ts": ts(base_dt), "type": "cyber", "label": f"Login from {home_city}"},
        {"ts": ts(t1), "type": "cyber", "label": f"Login from {foreign_city}"},
        {"ts": ts(t2), "type": "cyber", "label": "New beneficiary added"},
        {"ts": ts(t3), "type": "txn", "label": f"{channel} transfer of Rs {amount:,}"},
    ]
    return events, login_gap, beneficiary_gap


def build_alert(idx, severity, hndl_flag):
    alert_num = idx + 1
    alert_id = f"A-{alert_num:04d}"
    customer_id = pseudo_customer_id(alert_num)

    n_rules = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 2, "LOW": 1}[severity]
    pool = [r for r in RULE_CATALOG if SEVERITIES.index(r["severity"]) <= SEVERITIES.index(severity)]
    triggered_rules = random.sample(pool, k=min(n_rules, len(pool)))

    home_city = random.choice(INDIAN_CITIES)
    foreign_city = random.choice(FOREIGN_CITIES)
    channel = random.choice(CHANNELS)
    amount = random.choice([48000, 125000, 480000, 250000, 75000, 999000, 15000, 32000, 610000, 88000]) if channel != "UPI" else random.choice([2000, 5000, 15000, 25000, 49000])

    base_hour = random.choice([1, 2, 3, 23])
    base_minute = random.randint(0, 59)

    timeline, login_gap, beneficiary_gap = make_timeline(base_hour, base_minute, channel, foreign_city, home_city, amount)

    n_features = random.randint(2, 3)
    chosen = random.sample(FEATURE_POOL, k=n_features)
    contributing_features = []
    for feat, label_tmpl, (lo, hi) in chosen:
        if feat == "beneficiary_age_minutes":
            v = random.randint(int(lo), int(hi))
            val_repr = v
        else:
            v = round(random.uniform(lo, hi), 1)
            val_repr = v
        contributing_features.append({
            "feature": feat,
            "value": val_repr,
            "label": label_tmpl.format(v=val_repr),
        })

    if severity == "CRITICAL":
        risk_score = random.randint(85, 98)
    elif severity == "HIGH":
        risk_score = random.randint(65, 84)
    elif severity == "MEDIUM":
        risk_score = random.randint(35, 64)
    else:
        risk_score = random.randint(5, 34)

    if hndl_flag:
        tier = "CRITICAL"
    else:
        # Crypto posture alone is never an alert (invariant #2) — tier here just
        # reflects the endpoint's crypto exposure, independent of alert severity.
        tier = random.choices(QUANTUM_TIERS, weights=[0.5, 0.35, 0.15])[0]
        if tier == "CRITICAL":
            tier = "QUANTUM-VULNERABLE"  # reserve CRITICAL tier for actual hndl_flag cases

    explanation = (
        f"Login from {foreign_city} at {timeline[1]['ts'][11:16]} IST, {login_gap} min "
        f"after a login from {home_city}, followed by a Rs {amount:,} {channel} to a beneficiary "
        f"added {beneficiary_gap} minutes earlier."
    )

    action = random.choice(ACTIONS_BY_SEVERITY[severity])

    return {
        "alert_id": alert_id,
        "customer_id": customer_id,
        "risk_score": risk_score,
        "severity": severity,
        "triggered_rules": triggered_rules,
        "explanation": explanation,
        "contributing_features": contributing_features,
        "quantum_exposure": {"tier": tier, "hndl_flag": hndl_flag},
        "recommended_action": action,
        "timeline": timeline,
    }


def main():
    severities = list(SEVERITY_PLAN)
    random.shuffle(severities)

    # Exactly 3 alerts get hndl_flag=true + tier=CRITICAL. Per invariant #2,
    # HNDL requires vulnerable crypto AND exfiltration-shaped behaviour, so
    # pin those 3 to CRITICAL-severity alerts (already exfiltration-shaped).
    hndl_indices = set()
    critical_positions = [i for i, s in enumerate(severities) if s == "CRITICAL"]
    hndl_indices.update(critical_positions[:3])

    alerts = []
    for i, severity in enumerate(severities):
        hndl_flag = i in hndl_indices
        alerts.append(build_alert(i, severity, hndl_flag))

    alerts.sort(key=lambda a: a["risk_score"], reverse=True)

    kpis = {
        "events_analyzed": 13842,
        "active_alerts": len(alerts),
        "fp_suppressed": 47,
        "quantum_exposed_systems": sum(
            1 for a in alerts if a["quantum_exposure"]["tier"] in ("QUANTUM-VULNERABLE", "CRITICAL")
        ),
    }

    output = {"alerts": alerts, "kpis": kpis}

    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)
    out_path = data_dir / "alerts.json"
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    hndl_count = sum(1 for a in alerts if a["quantum_exposure"]["hndl_flag"])
    print(f"Wrote {len(alerts)} alerts to {out_path} ({hndl_count} with hndl_flag=true)")


if __name__ == "__main__":
    main()
