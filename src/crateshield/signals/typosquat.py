"""Signal 4 — typosquatting scorer.

Levenshtein edit distance against a top-N popular-crate list. A high score
combined with low edit distance against a widely-used crate is a strong
impersonation signal (see the CrateDepression / rustdecimal case).
"""
from __future__ import annotations

from crateshield.config import TYPOSQUAT_EDIT_DISTANCE_THRESHOLD, TYPOSQUAT_SCORE_THRESHOLD


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def typosquat_score(name: str, target: str) -> float:
    dist = levenshtein(name.lower(), target.lower())
    max_len = max(len(name), len(target), 1)
    return 1 - (dist / max_len)


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_")


def analyze_typosquatting(name: str, top_crates: list[dict]) -> dict:
    """top_crates: [{"name": ..., "rank": int}, ...] sorted by popularity."""
    best = {"score": 0.0, "target": None, "edit_distance": None, "target_rank": None}
    norm_name = _normalize(name)

    for entry in top_crates:
        target = entry["name"]
        if _normalize(target) == norm_name:
            continue  # exact match, not a typosquat of itself
        score = typosquat_score(norm_name, _normalize(target))
        dist = levenshtein(norm_name, _normalize(target))
        if score > best["score"]:
            best = {"score": round(score, 3), "target": target,
                     "edit_distance": dist, "target_rank": entry.get("rank")}

    best["flagged"] = (
        best["score"] >= TYPOSQUAT_SCORE_THRESHOLD
        and best["edit_distance"] is not None
        and best["edit_distance"] <= TYPOSQUAT_EDIT_DISTANCE_THRESHOLD
    )
    return best
