# Privacy

## Data

All data used in SENTINEL-Q is synthetic, produced by `generate_data.py` using a fixed random seed for reproducibility. No real customer, account, or transaction data is used, stored, or referenced anywhere in this project. Anyone running the generator will produce the same labeled synthetic dataset, with no path by which real bank data could enter the system.

## Pseudonymization

Customer identifiers are passed through SHA-256 hashing before they ever appear in an alert, the correlation engine's output, or the Streamlit dashboard. Analysts working the SOC dashboard see only these pseudonyms, never raw customer identifiers, account numbers, or names. SHA-256 hashing is a one-way transformation as implemented here — it is not encryption, and this project does not perform key management, salting rotation, or reversible tokenization. Re-identification of a pseudonym to an actual customer is not something SENTINEL-Q performs or enables; it could only happen inside the bank's own systems, using the bank's own identifier mapping, under the bank's existing access-control and audit regime. SENTINEL-Q itself has no mechanism to reverse a hash back to a customer identity.

## Deployment posture

SENTINEL-Q is built in plain Python with no mandatory cloud dependencies, so it can be deployed entirely on-premise within a bank's own infrastructure. In an on-premise deployment, no transactional or telemetry data needs to leave the bank's environment to run the correlation engine or dashboard. The public-facing demo deployed on Streamlit Community Cloud operates exclusively on the synthetic dataset described above and never touches real bank data.

## Compliance mapping

| Requirement | Source | How SENTINEL-Q addresses it |
|---|---|---|
| SOC monitoring | RBI Cyber Security Framework 2016 | The Streamlit SOC dashboard provides real-time visibility into correlated alerts, risk scores, and event timelines, giving analysts a working monitoring surface. |
| Incident detection & response readiness | RBI Cyber Security Framework 2016 | The correlation engine's five transparent rules plus IsolationForest anomaly weighting generate risk-scored alerts with plain-English explanations and contributing z-score features, supporting faster triage and response decisions. |
| Data minimisation | DPDP Act 2023 | Customer identifiers are SHA-256 pseudonymized before display, so analysts work with only the minimum identifying information needed to act on an alert. |
| Purpose limitation | DPDP Act 2023 | Pseudonymized identifiers surfaced by the dashboard are usable only for security correlation and alert triage; the project defines no other use of customer-linked data and performs no re-identification itself. |
| CERT-In reporting readiness | CERT-In | Every alert is timestamped and exportable from the dashboard, designed for compatibility with the record-keeping needed to support CERT-In incident reporting timelines. |
| PQC readiness | ML-KEM FIPS 203 / ML-DSA FIPS 204 | The Quantum Risk Monitor tier-classifies systems by crypto posture (PQC-READY, QUANTUM-VULNERABLE, CRITICAL), designed to support an inventory of ML-KEM/ML-DSA readiness across the bank's crypto estate. |