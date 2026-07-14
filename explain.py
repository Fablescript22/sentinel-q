"""Z-score explanations, per CLAUDE.md INVARIANT 4: IsolationForest SCORES,
z-scores EXPLAIN — never conflate. This module never scores or predicts,
it only turns already-computed z-scores into plain-English sentences.

Pure function, stdlib only.
"""

# Known feature-name -> human subject overrides. Anything not listed falls
# back to a generic derivation from the feature name (see _subject_for).
KNOWN_SUBJECTS = {
    "amount_zscore": "Amount",
    "login_velocity_zscore": "Login velocity",
    "txn_hour_zscore": "Transaction hour",
    "distance_km_per_min_zscore": "Implied travel speed",
}

_SUFFIXES = ("_zscore", "_z_score", "_z")


def _subject_for(feature: str) -> str:
    if feature in KNOWN_SUBJECTS:
        return KNOWN_SUBJECTS[feature]

    base = feature
    for suffix in _SUFFIXES:
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break

    base = base.replace("_", " ").strip()
    return base[:1].upper() + base[1:] if base else "Value"


def feature_labels(features: dict) -> list:
    """Turn {feature_name: z_score} into plain-English explanation strings.

    Example: {"amount_zscore": 4.2} ->
      ["Amount is 4.2 standard deviations above this customer's historical average."]
    """
    labels = []
    for feature, z_score in features.items():
        subject = _subject_for(feature)
        direction = "above" if z_score >= 0 else "below"
        magnitude = abs(z_score)
        labels.append(
            f"{subject} is {magnitude:.1f} standard deviations {direction} "
            "this customer's historical average."
        )
    return labels
