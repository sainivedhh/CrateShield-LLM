"""Parses LLM JSON responses defensively -- LLM output is not guaranteed
well-formed even with response_format=json_object.

Zahan et al. (ICSE 2025, Sec. VII-B4) report that models emit JSON about 99%
of the time but still produce schema violations (missing/extra keys) and
syntax errors (stray commas, prepended chatter, truncated text), and needed a
custom sloppy parser. `extract_json_object` is that: it tolerates fences,
leading/trailing prose, trailing commas and a JSON list wrapping one object.

Scores follow the paper's separation of concerns: malware intent, security
risk (vulnerability, not malice) and obfuscation are scored independently,
each in [0, 1], alongside a numeric confidence.
"""
from __future__ import annotations

import json
import logging
import re

from crateshield.config import MALWARE_SCORE_THRESHOLD, RECONCILE_SCORES, SUSPICIOUS_SCORE_FLOOR

logger = logging.getLogger(__name__)

VALID_CLASSIFICATIONS = {"MALICIOUS", "SUSPICIOUS", "BENIGN"}
VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}

_TRAILING_COMMA = re.compile(r",\s*([}\]])")


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 2:
            text = parts[1]
            if text.lstrip().lower().startswith("json"):
                text = text.lstrip()[4:]
    return text.strip()


def extract_json_object(response_text: str) -> dict | None:
    """Best-effort extraction of one JSON object from model output; None if
    nothing usable is found."""
    if not response_text:
        return None
    candidates = [_strip_fences(response_text)]
    first, last = response_text.find("{"), response_text.rfind("}")
    if first != -1 and last > first:
        candidates.append(response_text[first:last + 1])
    for cand in candidates:
        for variant in (cand, _TRAILING_COMMA.sub(r"\1", cand)):
            try:
                obj = json.loads(variant)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, list):
                obj = next((x for x in obj if isinstance(x, dict)), None)
            if isinstance(obj, dict):
                return obj
    return None


def coerce_score(value) -> float | None:
    """Score in [0,1] or None. Accepts numbers and numeric strings; clamps."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != f:  # NaN
        return None
    return max(0.0, min(1.0, f))


def first_score(obj: dict, *keys: str) -> float | None:
    for k in keys:
        if k in obj:
            s = coerce_score(obj[k])
            if s is not None:
                return s
    return None


def _confidence_label(raw, score: float | None) -> str:
    if isinstance(raw, str) and raw.upper() in VALID_CONFIDENCE:
        return raw.upper()
    if score is None:
        score = coerce_score(raw)  # model put a number in "confidence"
    if score is None:
        return "LOW"
    return "HIGH" if score >= 0.75 else "MEDIUM" if score >= 0.4 else "LOW"


def score_label_consistent(label: str, malware_score: float | None) -> bool | None:
    """Does the categorical verdict agree with the malware score? None if there
    is no score. Mirrors the paper's scale: <0.25 low, [0.25,0.5) possible,
    [0.5,0.75) likely, >=0.75 high."""
    if malware_score is None:
        return None
    if label == "BENIGN":
        return malware_score < SUSPICIOUS_SCORE_FLOOR
    if label == "SUSPICIOUS":
        return SUSPICIOUS_SCORE_FLOOR <= malware_score < 0.75
    return malware_score >= MALWARE_SCORE_THRESHOLD  # MALICIOUS


def parse_llm_response(response_text: str, reconcile: bool | None = None) -> dict:
    reconcile = RECONCILE_SCORES if reconcile is None else reconcile
    result = extract_json_object(response_text)
    if result is None:
        logger.error("Failed to parse LLM response as JSON. Raw: %s", (response_text or "")[:500])
        return {
            "classification": "SUSPICIOUS", "confidence": "LOW",
            "reasoning": "LLM response was not valid JSON and could not be parsed.",
            "primary_signals": [], "retrieved_evidence_used": [],
            "recommended_action": "Manual review",
            "malware_score": None, "security_risk_score": None, "obfuscation_score": None,
            "confidence_score": None, "flagged_by_score": None, "score_label_consistent": None,
            "parse_error": True,
        }

    llm_label = str(result.get("classification", "SUSPICIOUS")).upper()
    if llm_label not in VALID_CLASSIFICATIONS:
        logger.warning("Unexpected classification value %r, defaulting to SUSPICIOUS", llm_label)
        llm_label = "SUSPICIOUS"

    malware = first_score(result, "malware_score", "malware")
    risk = first_score(result, "security_risk_score", "securityRisk", "security_risk")
    obf = first_score(result, "obfuscation_score", "obfuscated", "obfuscation")
    conf_score = first_score(result, "confidence_score")
    if conf_score is None and not isinstance(result.get("confidence"), str):
        conf_score = coerce_score(result.get("confidence"))
    confidence = _confidence_label(result.get("confidence"), conf_score)

    consistent = score_label_consistent(llm_label, malware)
    label = llm_label
    reconciled = False
    # Paper Sec. VI-B3: models sometimes describe clearly bad behaviour yet
    # assign a low score/label. Never let a mismatch silently under-report:
    # a BENIGN verdict with a non-trivial malware score is escalated for review.
    if reconcile and llm_label == "BENIGN" and malware is not None and malware >= SUSPICIOUS_SCORE_FLOOR:
        label, reconciled = "SUSPICIOUS", True

    return {
        "classification": label,
        "llm_classification": llm_label,
        "reconciled": reconciled,
        "confidence": confidence,
        "reasoning": result.get("reasoning", result.get("analysis", "")),
        "primary_signals": result.get("primary_signals", []),
        "retrieved_evidence_used": result.get("retrieved_evidence_used", []),
        "recommended_action": result.get("recommended_action", "Manual review"),
        "malware_score": malware,
        "security_risk_score": risk,
        "obfuscation_score": obf,
        "confidence_score": conf_score,
        "flagged_by_score": None if malware is None else malware >= MALWARE_SCORE_THRESHOLD,
        "score_label_consistent": consistent,
        "parse_error": False,
    }
