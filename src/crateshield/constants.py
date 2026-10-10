"""Central constants for classification labels, score thresholds, and evaluation bands.

Single source of truth for prompt generation, response parsing, and benchmark evaluation.
"""
from __future__ import annotations

# Canonical classification labels
LABEL_BENIGN = "BENIGN"
LABEL_SUSPICIOUS = "SUSPICIOUS"
LABEL_MALICIOUS = "MALICIOUS"
VALID_CLASSIFICATIONS = {LABEL_MALICIOUS, LABEL_SUSPICIOUS, LABEL_BENIGN}

# Score thresholds (paper and benchmark single source of truth)
# < 0.25: BENIGN ("low probability")
# [0.25, 0.50): SUSPICIOUS ("possibly malicious / manual review")
# >= 0.50: MALICIOUS ("likely or high probability malicious / block")
BENIGN_SCORE_CEILING = 0.25
SUSPICIOUS_SCORE_FLOOR = 0.25
MALWARE_SCORE_THRESHOLD = 0.50

# Confidence thresholds
CONFIDENCE_HIGH_THRESHOLD = 0.75
CONFIDENCE_MEDIUM_THRESHOLD = 0.40

# Actions
ACTION_PASS = "Pass"
ACTION_MANUAL_REVIEW = "Manual review"
ACTION_BLOCK = "Block"

# Placement descriptions matching harness/inject_v2.py routing code
PLACEMENT_DESCRIPTIONS = {
    "P1": "Injected into build.rs (within or called from main)",
    "P2": "Injected into primary library module (src/lib.rs)",
    "P3": "Injected into secondary module across src/**/*.rs (falls back to src/lib.rs if single-file)",
    "P4": "Injected into library module (src/lib.rs macro expansion or library entry)",
    "P5": "Injected into build.rs (build script helper or build.rs fallback)",
}

def score_to_label(score: float | None) -> str:
    """Converts numeric malware score to canonical classification label."""
    if score is None:
        return LABEL_BENIGN
    if score >= MALWARE_SCORE_THRESHOLD:
        return LABEL_MALICIOUS
    if score >= SUSPICIOUS_SCORE_FLOOR:
        return LABEL_SUSPICIOUS
    return LABEL_BENIGN
