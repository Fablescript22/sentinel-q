"""Tests for generate_data.py.

Run: python tests/test_data.py
Must print: DATA OK
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CYBER_CSV = DATA_DIR / "cyber_events.csv"
TXN_CSV = DATA_DIR / "transactions.csv"
SCENARIOS_MD = DATA_DIR / "scenarios.md"

SCENARIO_ID_RE = re.compile(r"\bcust_\d{4}\b|\bsys_\d{3}\b")


def run_generator():
    result = subprocess.run(
        [sys.executable, "generate_data.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"generate_data.py exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    run_generator()

    assert CYBER_CSV.exists() and CYBER_CSV.stat().st_size > 0, \
        "data/cyber_events.csv missing or empty"
    assert TXN_CSV.exists() and TXN_CSV.stat().st_size > 0, \
        "data/transactions.csv missing or empty"
    assert SCENARIOS_MD.exists(), "data/scenarios.md missing"

    scenario_text = SCENARIOS_MD.read_text()
    scenario_ids = set(SCENARIO_ID_RE.findall(scenario_text))
    assert len(scenario_ids) == 5, (
        f"expected 5 scenario ids in scenarios.md, found {len(scenario_ids)}: {scenario_ids}"
    )

    cyber_text = CYBER_CSV.read_text()
    txn_text = TXN_CSV.read_text()
    for sid in scenario_ids:
        assert sid in cyber_text or sid in txn_text, \
            f"scenario id {sid} (from scenarios.md) not found in generated data"

    hash1_cyber = sha256(CYBER_CSV)
    hash1_txn = sha256(TXN_CSV)

    run_generator()

    hash2_cyber = sha256(CYBER_CSV)
    hash2_txn = sha256(TXN_CSV)

    assert hash1_cyber == hash2_cyber, "cyber_events.csv is not byte-identical across runs"
    assert hash1_txn == hash2_txn, "transactions.csv is not byte-identical across runs"

    print("DATA OK")


if __name__ == "__main__":
    main()
