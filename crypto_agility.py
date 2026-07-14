"""Quantum crypto-agility tier classifier.

Classifies a TLS/key-exchange identifier into a quantum-exposure tier and
decides whether that exposure, combined with exfiltration-shaped traffic,
warrants an HNDL ("harvest now, decrypt later") flag.

Per CLAUDE.md INVARIANT 2: crypto posture alone is NEVER an alert. HNDL
requires vulnerable/critical crypto AND exfiltration-shaped behaviour
together — see hndl_context().

Per CLAUDE.md INVARIANT 3: this module never claims to detect quantum
computers. It only classifies known cryptographic exposure ("quantum
exposure"), stdlib only.
"""

PQC_READY = "PQC-READY"
QUANTUM_VULNERABLE = "QUANTUM-VULNERABLE"
CRITICAL = "CRITICAL"

# Exfiltration-shaped threshold: bytes_out > 5x baseline. Team decision
#  2026-07-13, recorded in DECISIONS.md — not mandated by CLAUDE.md.
HNDL_EXFIL_MULTIPLIER = 5


def _normalize(key_exchange):
    ke = (key_exchange or "").strip()
    norm = ke.upper().replace(" ", "").replace("TLSV", "TLS")
    return ke, norm


def classify(key_exchange: str) -> dict:
    """Classify a key-exchange/protocol identifier into a quantum-exposure tier.

    Tiering:
      ML-KEM-* (FIPS 203)      -> PQC-READY
      ECDH-* / ECDHE-*         -> QUANTUM-VULNERABLE
      RSA-*, TLS1.0/1.1,
      unknown/empty            -> CRITICAL

    Returns {"tier": str, "reason": str} where reason is one plain-English
    sentence explaining the classification.
    """
    original, norm = _normalize(key_exchange)

    if norm.startswith("ML-KEM"):
        return {
            "tier": PQC_READY,
            "reason": (
                f"{original} is a NIST FIPS 203 (ML-KEM) post-quantum key "
                "exchange, so it is not considered breakable by a "
                "sufficiently capable quantum computer."
            ),
        }

    if norm.startswith("ECDH"):
        return {
            "tier": QUANTUM_VULNERABLE,
            "reason": (
                f"{original} relies on elliptic-curve Diffie-Hellman, whose "
                "security a sufficiently capable quantum computer is "
                "expected to break via Shor's algorithm."
            ),
        }

    if norm.startswith("RSA"):
        return {
            "tier": CRITICAL,
            "reason": (
                f"{original} relies on RSA, which offers no forward secrecy "
                "against a sufficiently capable quantum computer and is "
                "considered critically exposed."
            ),
        }

    if norm.startswith("TLS1.0") or norm.startswith("TLS1.1"):
        return {
            "tier": CRITICAL,
            "reason": (
                f"{original} uses a deprecated TLS version with no "
                "quantum-resistant key exchange available, so it is "
                "considered critically exposed."
            ),
        }

    return {
        "tier": CRITICAL,
        "reason": (
            f"'{original}' is not a recognized quantum-safe key exchange, "
            "so it is treated as critically exposed by default."
        ),
    }


def hndl_context(tier: str, bytes_out: float, baseline_bytes: float) -> bool:
    """Decide whether a quantum-exposed endpoint's traffic looks like harvesting.

    Per CLAUDE.md INVARIANT 2: crypto posture alone must NEVER return True.
    Returns True only when BOTH hold:
      1. tier is CRITICAL or QUANTUM-VULNERABLE, AND
      2. bytes_out is exfiltration-shaped (> 5x baseline_bytes).
    """
    if tier not in (CRITICAL, QUANTUM_VULNERABLE):
        return False

    if baseline_bytes <= 0:
        return False

    return bytes_out > HNDL_EXFIL_MULTIPLIER * baseline_bytes
