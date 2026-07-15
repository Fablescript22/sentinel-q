"""Synthetic data generator for SENTINEL-Q.

Produces data/cyber_events.csv and data/transactions.csv with 5 labeled
attack scenarios embedded (documented in data/scenarios.md).

RANDOM_SEED = 42 everywhere -> byte-identical output on every run.
"""
import os
import random
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from faker import Faker

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)
Faker.seed(RANDOM_SEED)
fake = Faker()

IST = timezone(timedelta(hours=5, minutes=30))
WINDOW_END = datetime(2026, 7, 12, 23, 59, 59, tzinfo=IST)
WINDOW_START = WINDOW_END - timedelta(days=30)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

NUM_CUSTOMERS = 500
NUM_SYSTEMS = 40

CUSTOMERS = [f"cust_{i:04d}" for i in range(1, NUM_CUSTOMERS + 1)]
SYSTEMS = [f"sys_{i:03d}" for i in range(1, NUM_SYSTEMS + 1)]

# --- scenario actors (see data/scenarios.md) --------------------------------
S1_CUSTOMER = "cust_0001"  # account takeover
S2_CUSTOMER = "cust_0002"  # credential stuffing
S3_CUSTOMER = "cust_0003"  # dormant burst
S4_SYSTEM = "sys_001"      # HNDL exfiltration (cyber CSV only)
S5_CUSTOMER = "cust_0005"  # impossible travel

# S3 is dormant: it gets NO background activity anywhere in the window.
DORMANT_CUSTOMERS = {S3_CUSTOMER}

KEY_EXCHANGE_CHOICES = [
    "ECDHE-P256", "ECDH-P384", "RSA-2048", "TLS1.0-RSA", "RSA-1024", "ML-KEM-768",
]
KEY_EXCHANGE_WEIGHTS = [0.40, 0.25, 0.20, 0.05, 0.05, 0.05]

# Weighted heavily towards India, with a long tail of other countries so
# occasional foreign logins look plausible rather than purely scenario noise.
COUNTRIES = ["IN"] * 85 + ["US", "GB", "SG", "AE", "DE", "NG", "RU", "CN"]

EVENT_TYPES = ["login", "vpn", "tls_session", "file_transfer"]
EVENT_TYPE_WEIGHTS = [0.35, 0.15, 0.35, 0.15]

CHANNELS = ["UPI", "NEFT", "RTGS", "IMPS"]
CHANNEL_WEIGHTS = [0.55, 0.15, 0.05, 0.25]

SYSTEM_EVENT_TYPES = ["tls_session", "file_transfer", "vpn"]
SYSTEM_EVENT_WEIGHTS = [0.50, 0.35, 0.15]


def random_ts():
    span = (WINDOW_END - WINDOW_START).total_seconds()
    return WINDOW_START + timedelta(seconds=random.uniform(0, span))


def amount_for_channel(channel):
    if channel == "UPI":
        return round(random.uniform(50, 5000), 2)
    if channel == "IMPS":
        return round(random.uniform(500, 200000), 2)
    if channel == "NEFT":
        return round(random.uniform(1000, 1000000), 2)
    return round(random.uniform(200000, 10000000), 2)  # RTGS


def device_pool(n=3):
    return [fake.hexify(text="dev_^^^^^^^^", upper=True) for _ in range(n)]


def beneficiary_pool(n=5):
    return [fake.bothify(text="ben_########") for _ in range(n)]


def beneficiary_added_dates(beneficiaries):
    return {b: WINDOW_START - timedelta(days=random.randint(30, 400)) for b in beneficiaries}


cyber_rows = []
txn_rows = []
system_baseline_bytes = {}

# --- background cyber events: customers -------------------------------------
for cust in CUSTOMERS:
    devices = device_pool()
    if cust in DORMANT_CUSTOMERS:
        continue  # S3 stays silent until its scripted burst
    n_events = random.randint(8, 18)
    for _ in range(n_events):
        event_type = random.choices(EVENT_TYPES, weights=EVENT_TYPE_WEIGHTS)[0]
        is_transfer_like = event_type in ("file_transfer", "tls_session")
        bytes_out = int(np.random.lognormal(mean=9 if is_transfer_like else 6, sigma=1 if is_transfer_like else 0.5))
        success = random.random() > 0.03 if event_type == "login" else True
        cyber_rows.append({
            "ts": random_ts(),
            "customer_id": cust,
            "event_type": event_type,
            "src_country": random.choice(COUNTRIES),
            "device_id": random.choice(devices),
            "bytes_out": bytes_out,
            "key_exchange": random.choices(KEY_EXCHANGE_CHOICES, weights=KEY_EXCHANGE_WEIGHTS)[0],
            "success": success,
        })

# --- background cyber events: internal systems -------------------------------
for sys_id in SYSTEMS:
    baseline_bytes = 50000.0 if sys_id == S4_SYSTEM else random.uniform(20000, 80000)
    system_baseline_bytes[sys_id] = baseline_bytes
    n_events = random.randint(25, 45)
    for _ in range(n_events):
        bytes_out = max(1000, int(np.random.normal(baseline_bytes, baseline_bytes * 0.15)))
        cyber_rows.append({
            "ts": random_ts(),
            "customer_id": sys_id,
            "event_type": random.choices(SYSTEM_EVENT_TYPES, weights=SYSTEM_EVENT_WEIGHTS)[0],
            "src_country": "IN",
            "device_id": f"dev_{sys_id}",
            "bytes_out": bytes_out,
            "key_exchange": random.choices(KEY_EXCHANGE_CHOICES, weights=KEY_EXCHANGE_WEIGHTS)[0],
            "success": True,
        })

# --- background transactions -------------------------------------------------
beneficiary_data = {}
for cust in CUSTOMERS:
    benefs = beneficiary_pool()
    added = beneficiary_added_dates(benefs)
    beneficiary_data[cust] = (benefs, added)
    if cust in DORMANT_CUSTOMERS:
        continue  # S3 stays silent until its scripted burst
    n_txns = random.randint(5, 15)
    for _ in range(n_txns):
        channel = random.choices(CHANNELS, weights=CHANNEL_WEIGHTS)[0]
        benef = random.choice(benefs)
        txn_rows.append({
            "ts": random_ts(),
            "customer_id": cust,
            "channel": channel,
            "amount_inr": amount_for_channel(channel),
            "beneficiary_id": benef,
            "beneficiary_added_ts": added[benef],
        })

# =============================================================================
# Scenario 1 -- account takeover: foreign login + new beneficiary + large
# transfer, all within 60 minutes.
# =============================================================================
s1_login_ts = datetime(2026, 6, 25, 2, 10, 0, tzinfo=IST)
s1_benef_added_ts = datetime(2026, 6, 25, 2, 32, 0, tzinfo=IST)
s1_txn_ts = datetime(2026, 6, 25, 2, 55, 0, tzinfo=IST)  # 45 min after login
s1_benef_id = "ben_S1NEWBEN"

cyber_rows.append({
    "ts": s1_login_ts, "customer_id": S1_CUSTOMER, "event_type": "login",
    "src_country": "NG", "device_id": "dev_S1_ATTACKER", "bytes_out": 2200,
    "key_exchange": "ECDHE-P256", "success": True,
})
txn_rows.append({
    "ts": s1_txn_ts, "customer_id": S1_CUSTOMER, "channel": "NEFT",
    "amount_inr": 725000.00, "beneficiary_id": s1_benef_id,
    "beneficiary_added_ts": s1_benef_added_ts,
})

# =============================================================================
# Scenario 2 -- credential stuffing: 20+ failed logins, then a success, then
# rapid small transfers.
# =============================================================================
s2_start = datetime(2026, 6, 18, 3, 0, 0, tzinfo=IST)
s2_benefs, s2_added = beneficiary_data[S2_CUSTOMER]

for i in range(21):  # 21 failed logins
    cyber_rows.append({
        "ts": s2_start + timedelta(seconds=30 * i), "customer_id": S2_CUSTOMER,
        "event_type": "login", "src_country": "IN", "device_id": "dev_S2_ATTACKER",
        "bytes_out": 1800, "key_exchange": "ECDHE-P256", "success": False,
    })
s2_success_ts = s2_start + timedelta(seconds=30 * 21)
cyber_rows.append({
    "ts": s2_success_ts, "customer_id": S2_CUSTOMER, "event_type": "login",
    "src_country": "IN", "device_id": "dev_S2_ATTACKER", "bytes_out": 1800,
    "key_exchange": "ECDHE-P256", "success": True,
})
for i in range(5):  # rapid small transfers
    txn_rows.append({
        "ts": s2_success_ts + timedelta(minutes=1 + i), "customer_id": S2_CUSTOMER,
        "channel": "UPI", "amount_inr": round(500 + i * 137.50, 2),
        "beneficiary_id": s2_benefs[i % len(s2_benefs)],
        "beneficiary_added_ts": s2_added[s2_benefs[i % len(s2_benefs)]],
    })

# =============================================================================
# Scenario 3 -- dormant burst: silent for the whole window, then a sudden
# login followed by a max-amount transfer.
# =============================================================================
s3_login_ts = datetime(2026, 7, 10, 22, 0, 0, tzinfo=IST)
s3_txn_ts = datetime(2026, 7, 10, 22, 12, 0, tzinfo=IST)
s3_benefs, s3_added = beneficiary_data[S3_CUSTOMER]

cyber_rows.append({
    "ts": s3_login_ts, "customer_id": S3_CUSTOMER, "event_type": "login",
    "src_country": "IN", "device_id": "dev_S3_USUAL", "bytes_out": 2000,
    "key_exchange": "ECDHE-P256", "success": True,
})
txn_rows.append({
    "ts": s3_txn_ts, "customer_id": S3_CUSTOMER, "channel": "RTGS",
    "amount_inr": 10000000.00, "beneficiary_id": s3_benefs[0],
    "beneficiary_added_ts": s3_added[s3_benefs[0]],
})

# =============================================================================
# Scenario 4 -- HNDL exfiltration: an internal system using weak/legacy
# key exchange AND bytes_out ~10x its own baseline, in the same event.
# =============================================================================
s4_ts = datetime(2026, 7, 2, 4, 0, 0, tzinfo=IST)
cyber_rows.append({
    "ts": s4_ts, "customer_id": S4_SYSTEM, "event_type": "file_transfer",
    "src_country": "IN", "device_id": f"dev_{S4_SYSTEM}",
    "bytes_out": int(system_baseline_bytes[S4_SYSTEM] * 10),
    "key_exchange": "RSA-1024", "success": True,
})

# =============================================================================
# Scenario 5 -- impossible travel: logins from India then Germany 41 minutes
# apart, followed by a transfer to a beneficiary added minutes earlier.
# (This is the exact scenario illustrated in CONTRACTS.md's alerts.json example.)
# =============================================================================
s5_login_in_ts = datetime(2026, 6, 29, 1, 32, 0, tzinfo=IST)   # "Pune"
s5_login_de_ts = datetime(2026, 6, 29, 2, 13, 0, tzinfo=IST)   # "Frankfurt", 41 min later
s5_benef_added_ts = datetime(2026, 6, 29, 2, 14, 0, tzinfo=IST)
s5_txn_ts = datetime(2026, 6, 29, 2, 20, 0, tzinfo=IST)        # 6 min after beneficiary added
s5_benef_id = "ben_S5NEWBEN"

cyber_rows.append({
    "ts": s5_login_in_ts, "customer_id": S5_CUSTOMER, "event_type": "login",
    "src_country": "IN", "device_id": "dev_S5_PUNE", "bytes_out": 2100,
    "key_exchange": "ECDHE-P256", "success": True,
})
cyber_rows.append({
    "ts": s5_login_de_ts, "customer_id": S5_CUSTOMER, "event_type": "login",
    "src_country": "DE", "device_id": "dev_S5_FRANKFURT", "bytes_out": 2100,
    "key_exchange": "ECDHE-P256", "success": True,
})
txn_rows.append({
    "ts": s5_txn_ts, "customer_id": S5_CUSTOMER, "channel": "NEFT",
    "amount_inr": 480000.00, "beneficiary_id": s5_benef_id,
    "beneficiary_added_ts": s5_benef_added_ts,
})

# =============================================================================
# assemble + write
# =============================================================================
os.makedirs(DATA_DIR, exist_ok=True)

cyber_rows.sort(key=lambda r: r["ts"])
for i, row in enumerate(cyber_rows, start=1):
    row["event_id"] = f"evt_{i:06d}"
    row["ts"] = row["ts"].isoformat()

txn_rows.sort(key=lambda r: r["ts"])
for i, row in enumerate(txn_rows, start=1):
    row["txn_id"] = f"txn_{i:06d}"
    row["ts"] = row["ts"].isoformat()
    row["beneficiary_added_ts"] = row["beneficiary_added_ts"].isoformat()

cyber_cols = ["event_id", "ts", "customer_id", "event_type", "src_country",
              "device_id", "bytes_out", "key_exchange", "success"]
txn_cols = ["txn_id", "ts", "customer_id", "channel", "amount_inr",
            "beneficiary_id", "beneficiary_added_ts"]

cyber_df = pd.DataFrame(cyber_rows)[cyber_cols]
txn_df = pd.DataFrame(txn_rows)[txn_cols]

cyber_df.to_csv(os.path.join(DATA_DIR, "cyber_events.csv"), index=False)
txn_df.to_csv(os.path.join(DATA_DIR, "transactions.csv"), index=False)

print(f"wrote {len(cyber_df)} cyber events -> data/cyber_events.csv")
print(f"wrote {len(txn_df)} transactions -> data/transactions.csv")
