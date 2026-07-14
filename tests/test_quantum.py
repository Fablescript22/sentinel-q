"""Tests for crypto_agility.py per CLAUDE.md INVARIANTS 2 and 3.

Run: python tests/test_quantum.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto_agility import classify, hndl_context, PQC_READY, QUANTUM_VULNERABLE, CRITICAL


def test_tier_classification():
    cases = [
        ("ML-KEM-768", PQC_READY),
        ("ML-KEM-1024", PQC_READY),
        ("ECDH-P256", QUANTUM_VULNERABLE),
        ("ECDHE-RSA-AES256-GCM", QUANTUM_VULNERABLE),
        ("RSA-2048", CRITICAL),
        ("TLS1.0", CRITICAL),
    ]
    for key_exchange, expected_tier in cases:
        result = classify(key_exchange)
        assert result["tier"] == expected_tier, (
            f"classify({key_exchange!r}) tier={result['tier']!r}, expected {expected_tier!r}"
        )
        assert isinstance(result["reason"], str) and result["reason"], (
            f"classify({key_exchange!r}) missing plain-English reason"
        )

    # unknown/empty also fold into CRITICAL
    for key_exchange in ("", "TLS1.1", "totally-unknown-kex"):
        result = classify(key_exchange)
        assert result["tier"] == CRITICAL, (
            f"classify({key_exchange!r}) tier={result['tier']!r}, expected {CRITICAL!r}"
        )


def test_hndl_context_requires_both_crypto_and_exfiltration():
    # CRITICAL tier + normal bytes -> False (crypto posture alone is never an alert)
    assert hndl_context(CRITICAL, bytes_out=1000, baseline_bytes=1000) is False

    # CRITICAL tier + 10x bytes -> True (vulnerable crypto AND exfil-shaped)
    assert hndl_context(CRITICAL, bytes_out=10000, baseline_bytes=1000) is True

    # PQC-READY tier + 10x bytes -> False (safe crypto, no HNDL risk regardless of traffic)
    assert hndl_context(PQC_READY, bytes_out=10000, baseline_bytes=1000) is False

    # QUANTUM-VULNERABLE tier + 10x bytes -> True
    assert hndl_context(QUANTUM_VULNERABLE, bytes_out=10000, baseline_bytes=1000) is True

    # QUANTUM-VULNERABLE tier + normal bytes -> False
    assert hndl_context(QUANTUM_VULNERABLE, bytes_out=1200, baseline_bytes=1000) is False


if __name__ == "__main__":
    test_tier_classification()
    test_hndl_context_requires_both_crypto_and_exfiltration()
    print("QUANTUM OK")
