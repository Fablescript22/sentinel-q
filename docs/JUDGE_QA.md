# SENTINEL-Q — Judge Q&A Prep
## Finspark Hackathon 2026 · Problem Statement 2 · Bank of Maharashtra

Ten hardest questions a judge is likely to ask, with honest, sayable-out-loud answers.

---

### 1. "How is this different from the FRM/SIEM tools we already run?"

Traditional FRM and SIEM tools score fraud and security events in separate silos, so an attacker who compromises a system and then moves money never triggers a single unified signal. SENTINEL-Q's correlation engine deliberately links cybersecurity telemetry (login anomalies, lateral movement, exfiltration-shaped traffic) with transactional behaviour (transfer size, velocity, destination risk) in the same scoring pass, using five transparent rules plus IsolationForest anomaly weighting. We are not claiming to replace your SIEM or FRM stack — SENTINEL-Q is a correlation layer that could sit on top of the alerts those systems already produce. The MVP proves the correlation logic and explainability model on synthetic data; it does not yet ingest live feeds from a production SIEM/FRM.

---

### 2. "Your data is synthetic — why should we believe the detection numbers?"

We built the synthetic generator specifically so we could label ground truth for five distinct attack scenarios, which is the only way to honestly measure detection rate, false positive rate, and explainability quality in a hackathon timeframe — no bank hands over real fraud-labeled data to a hackathon team. The numbers we report are [NUMBER NEEDED: precision/recall/F1 on synthetic test set] and should be read as a proof of concept for the correlation logic, not a production benchmark. What would validate this properly is a pilot on de-identified historical data from your environment, where the same rules and IsolationForest model get re-tuned against real transaction and telemetry distributions. We're not asking you to trust the numbers today — we're asking you to trust that the architecture and explainability approach are sound enough to justify that pilot.

---

### 3. "Can you actually detect quantum attacks?"

No one can detect a quantum computer — that capability doesn't exist yet and won't for years, so any product claiming to "detect quantum attacks" today is not being honest with you. What SENTINEL-Q actually does is detect harvest-now-decrypt-later exposure: it classifies systems by their current crypto posture — PQC-ready, quantum-vulnerable, or critical — and fires an HNDL alert only when vulnerable crypto and exfiltration-shaped behaviour occur together, right now, on infrastructure you control today. That's a real, measurable risk: encrypted data being harvested today for decryption once quantum capability exists. We deliberately use the phrase "quantum exposure," never "quantum detection," because the distinction matters.

---

### 4. "What happens with false positives?"

Every alert in the dashboard shows the plain-English explanation, the specific z-score features that contributed, and the event timeline, so a SOC analyst can triage in seconds rather than dig through raw logs — that's the main lever we have against alert fatigue in this MVP. We have not yet built a feedback loop where an analyst marking something "false positive" retrains or re-weights the model; today that would be a manual rule adjustment. Our current false positive rate on the synthetic scenarios is [NUMBER NEEDED: false positive rate], and the honest expectation is that this number will move once the rules and IsolationForest thresholds are retuned against real transaction volume and behaviour patterns, which vary a lot by institution.

---

### 5. "How does this comply with DPDP when it watches customer behaviour?"

The system pseudonymizes customer identifiers using SHA-256 before anything is displayed on the SOC dashboard, so analysts working alerts see a pseudonymous ID, not a name, account number, or PAN — that's the one privacy mechanism we've built, and we're not going to claim more than that. It supports two DPDP principles directly: data minimisation, because the correlation engine only needs behavioural features and telemetry, not raw PII, to score risk; and purpose limitation, because the pseudonymized ID is only usable for security triage, not for other purposes. We have not implemented encryption-at-rest, tokenization with re-identification controls, or a documented data retention/deletion policy — those are necessary for a production DPDP compliance posture and are explicitly out of scope for this MVP.

---

### 6. "How would this integrate with our core banking systems?"

SENTINEL-Q is designed for compatibility with ISO 20022 (RTGS/NEFT) and NPCI UPI specifications, meaning the correlation engine's transaction schema is built to map onto the fields those standards define. Honestly, the MVP itself doesn't have a live core banking connector — it reads CSV/JSON files, which is how we fed it synthetic transaction and telemetry data for this demo. Getting from here to production integration means building adapters for your actual core banking and SIEM/telemetry feeds, and that's a meaningful engineering step we haven't done yet. What we can defend is that the data model was designed with those standards in mind from day one, so the integration work is additive, not a redesign.

---

### 7. "What's your false negative rate — what gets missed?"

On the five labeled synthetic attack scenarios, our detection rate is [NUMBER NEEDED: recall/detection rate per scenario]. The honest limitation is that the five scenarios were chosen to demonstrate the correlation concept clearly — a live production environment will throw attack patterns at this system that we haven't modeled, and the rule-based layer in particular will miss anything that doesn't match its five defined patterns. That's exactly why we paired rules with IsolationForest: the rules catch known patterns with full explainability, and the anomaly weighting is there to flag behaviour that doesn't fit any known rule, even though it can't explain *why* on its own the way the rules can.

---

### 8. "Who explains the alert — the rules or the machine learning model?"

The five transparent rules generate the actual plain-English explanation an analyst reads, and the z-score features shown alongside it label which specific behavioural signals contributed to that rule firing. IsolationForest is used only to weight the overall anomaly score — it adjusts how urgent an alert looks, but it does not generate the explanation, and we're careful never to claim that the z-scores are "explaining" the ML model's internal decision, because they aren't; they're explaining the rule logic. We made this split deliberately because unexplainable ML-driven fraud alerts are a known adoption blocker in SOC teams — analysts don't act on scores they can't justify to a compliance officer.

---

### 9. "Is this actually deployable in a regulated bank environment today, or is it just a demo?"

Today it's a working MVP deployed live on Streamlit Community Cloud, and it runs on plain Python with no cloud dependency required to operate — so it is on-premise-capable, which matters for a regulated environment. What it is not yet is production-hardened: there's no audit logging, no role-based access control on the dashboard, no documented incident-response runbook, and no formal mapping exercise against the RBI Cyber Security Framework 2016's SOC and cyber-crisis management requirements beyond the design intent. We'd frame this honestly as: the core detection and correlation logic is real and demonstrable, the compliance and operational hardening layer is the next phase of work, not something we're claiming exists today.

---

### 10. "Why should Bank of Maharashtra invest in a quantum risk layer now, when quantum computers that break RSA/ECDH don't exist yet?"

Because harvest-now-decrypt-later doesn't require quantum computers to exist today — it requires an attacker to exfiltrate encrypted data now and hold it until decryption becomes feasible, which means any RSA or legacy-TLS system carrying sensitive data is exposed the moment it's built, not the moment quantum computing matures. The Quantum Risk Monitor tab classifies your systems into PQC-ready (ML-KEM, FIPS 203), quantum-vulnerable (ECDH), and critical (RSA, legacy TLS) tiers today, using standards — ML-KEM FIPS 203 and ML-DSA FIPS 204 — that are already finalized and available to migrate toward. This isn't a future problem you can defer; it's an inventory and migration-planning problem you can start now, and that's the honest case for building it into a SOC dashboard alongside conventional threat correlation rather than treating it as a separate future initiative.