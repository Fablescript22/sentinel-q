# data/scenarios.md — labeled attack scenarios

Hand-written documentation of the 5 attack scenarios injected by generate_data.py (RANDOM_SEED = 42). This file is maintained manually — the generator does NOT write or update it.. Window: 30 days,
2026-06-12T23:59:59+05:30 to 2026-07-12T23:59:59+05:30 (IST).

These 5 scenarios must be detected after ANY change to `generate_data.py`
or `engine.py` (see CLAUDE.md invariant #8). Verify with:

    python generate_data.py && python engine.py && python tests/test_scenarios.py

---

## S1 — Account takeover
**Actor:** `cust_0001`

- `2026-06-25T02:10:00+05:30` — login, `src_country=NG` (foreign), new/unseen device `dev_S1_ATTACKER`
- `2026-06-25T02:32:00+05:30` — beneficiary `ben_S1NEWBEN` added (`beneficiary_added_ts` on the txn below)
- `2026-06-25T02:55:00+05:30` — NEFT transfer of ₹725,000.00 to `ben_S1NEWBEN`

All three events fall within a 60-minute window (login → transfer = 45 min).
**Expected detection:** "Account takeover" — foreign login + new beneficiary + large transfer within 60 min.

---

## S2 — Credential stuffing
**Actor:** `cust_0002`

- `2026-06-18T03:00:00` to `03:10:00+05:30` — 21 failed logins, 30s apart, `device_id=dev_S2_ATTACKER`
- `2026-06-18T03:10:30+05:30` — 1 successful login (same device)
- `2026-06-18T03:11:30` through `03:15:30+05:30` — 5 rapid small UPI transfers (~₹500–1,050 each)

**Expected detection:** "Credential stuffing" — 20+ failed logins followed by success and rapid small transfers.

---

## S3 — Dormant burst
**Actor:** `cust_0003`

- No rows at all in `cyber_events.csv` or `transactions.csv` for the first ~27
  days of the window (fully silent — no baseline activity is generated for
  this customer).
- `2026-07-10T22:00:00+05:30` — sudden login, usual device `dev_S3_USUAL`
- `2026-07-10T22:12:00+05:30` — RTGS transfer of ₹10,000,000.00 (max amount in the generated range)

**Expected detection:** "Dormant account burst" — long silence then sudden max-amount transfer.

---

## S4 — HNDL exfiltration (system-level, cyber CSV only)
**Actor:** `sys_001` (internal system)

- Baseline: `sys_001` has ~25–45 background `file_transfer`/`tls_session`/`vpn`
  events across the window with `bytes_out` centered around a baseline of
  **50,000 bytes**.
- `2026-07-02T04:00:00+05:30` — one `file_transfer` event with
  `key_exchange=RSA-1024` (weak/legacy) **and** `bytes_out=500,000`
  (10x the system's baseline), in the same event.

**Expected detection:** "HNDL exfiltration risk" — per CLAUDE.md invariant #2,
weak crypto posture alone must NOT alert; this only fires because weak
crypto and exfiltration-shaped behavior (10x baseline bytes_out) occur
together on the same event.

---

## S5 — Impossible travel
**Actor:** `cust_0005`

- `2026-06-29T01:32:00+05:30` — login, `src_country=IN` ("Pune"), device `dev_S5_PUNE`
- `2026-06-29T02:13:00+05:30` — login, `src_country=DE` ("Frankfurt"), device `dev_S5_FRANKFURT` — 41 minutes after the Pune login (geographically impossible)
- `2026-06-29T02:14:00+05:30` — beneficiary `ben_S5NEWBEN` added
- `2026-06-29T02:20:00+05:30` — NEFT transfer of ₹480,000.00 to `ben_S5NEWBEN` (beneficiary added 6 minutes earlier)

**Expected detection:** "Impossible travel + transfer". This is the exact
scenario illustrated in `CONTRACTS.md`'s `alerts.json` example
("Login from Frankfurt at 02:13 IST, 41 min after a login from Pune,
followed by a Rs 4.8L NEFT to a beneficiary added 6 minutes earlier").

---

## Actor ID reference
| Scenario | ID | Type |
|---|---|---|
| S1 | `cust_0001` | customer |
| S2 | `cust_0002` | customer |
| S3 | `cust_0003` | customer |
| S4 | `sys_001` | internal system |
| S5 | `cust_0005` | customer |
