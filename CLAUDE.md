# CLAUDE.md — SENTINEL-Q

## What this is
Correlation engine fusing bank cyber telemetry + transactions into one
explainable risk score, plus a quantum crypto-agility (HNDL) layer.
Hackathon MVP, 3 days. Judged: Business 40 / Security 30 / Unique 15 /
UX 5 / Scalability 5 / Ease of Dev 5.

## Stack
Python 3.11, pandas, numpy, faker, scikit-learn (IsolationForest),
streamlit, plotly. NOTHING ELSE. No DB, no Docker, no SHAP/LIME.

## Repo map (ONE OWNER PER FILE — do not edit files outside your task)
- generate_data.py   — synthetic data generator       [OWNER: Devu]
- engine.py          — rules + ML + scoring           [OWNER: Devu]
- crypto_agility.py  — quantum tier classifier        [OWNER: Shreya]
- explain.py         — z-score explanations           [OWNER: Shreya]
- app.py             — streamlit dashboard            [OWNER: Shreya]
- requirements.txt   — unpinned deps (see DECISIONS.md)  [OWNER: Shreya]
- mock_alerts.py     — mock generator per CONTRACTS   [OWNER: Shreya]
- tests/             — one test per module
- docs/, README.md, PRIVACY.md                        [OWNER: Meghna]
- data/              — generated CSVs
- CLAUDE.md, DECISIONS.md, CONTRACTS.md, HANDOFF.md   [OWNER: Shreya]

## INVARIANTS — violating any of these is a P0 bug
1. RANDOM_SEED = 42 everywhere.
2. Crypto posture alone is NEVER an alert. HNDL = vulnerable crypto AND
   exfiltration-shaped behaviour together.
3. Never claim to detect quantum computers. Language: "quantum exposure".
4. IsolationForest SCORES. Z-scores EXPLAIN. Never conflate.
5. UPI is NOT ISO 20022. Say "designed for compatibility with ISO 20022
   (RTGS/NEFT) and NPCI UPI specifications".
6. SHA-256 pseudonymization only. No tokenization claims.
7. Every slide claim maps to code that exists.
8. All 5 labeled attack scenarios must be detected after ANY change.

## FROZEN (do not modify without Shreya's written OK)
- alerts.json schema per CONTRACTS.md — app.py is built against it
- mock_alerts.py output shape (20 alerts, seed 42, 3 hndl_flag=true)
- RANDOM_SEED = 42

## How to verify anything
python generate_data.py && python engine.py && python tests/test_scenarios.py
Must print: "5/5 scenarios detected — OK"

## Current status
Hour 0. Nothing built yet.