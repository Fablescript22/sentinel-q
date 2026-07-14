# CONTRACTS.md — FROZEN. Changing anything here requires Shreya's written OK in the group chat.

## data/alerts.json — the ONLY interface between engine.py (Devu) and app.py (Shreya)
{
  "alerts": [{
    "alert_id": "A-0001",
    "customer_id": "cust_9f2a...",
    "risk_score": 87,
    "severity": "HIGH",
    "triggered_rules": [
      {"rule_id":"R1","name":"Impossible travel + transfer","severity":"HIGH"}
    ],
    "explanation": "Login from Frankfurt at 02:13 IST, 41 min after a login from Pune, followed by a Rs 4.8L NEFT to a beneficiary added 6 minutes earlier.",
    "contributing_features": [
      {"feature":"amount_zscore","value":4.2,"label":"Amount is 4.2 SD above this customer's average"}
    ],
    "quantum_exposure": {"tier":"CRITICAL","hndl_flag": true},
    "recommended_action": "Freeze beneficiary, step-up auth",
    "timeline": [{"ts":"2026-07-13T02:13:00","type":"cyber","label":"Login from Frankfurt"}]
  }],
  "kpis": {"events_analyzed": 13000, "active_alerts": 21,
           "fp_suppressed": 47, "quantum_exposed_systems": 9}
}

severity: LOW|MEDIUM|HIGH|CRITICAL
quantum_exposure.tier: PQC-READY|QUANTUM-VULNERABLE|CRITICAL
timeline.type: "cyber" or "txn"