"""Realism Review Ingestion and Analysis Script (Phase 4).

Ingests human ratings from review/realism_kit_v3.csv.
If ratings are blank, outputs status: pending (per Hard Rule / Phase 4).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REVIEW_CSV_PATH = ROOT / "review" / "realism_kit_v3.csv"
KEY_JSON_PATH = ROOT / "review" / "realism_kit_v3_key.json"


def ingest_realism_ratings() -> dict[str, Any]:
    if not REVIEW_CSV_PATH.exists():
        return {
            "status": "not_generated",
            "message": "Realism kit CSV not found.",
            "completed_reviews": 0,
        }

    with open(REVIEW_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    r1_plausible = [r["reviewer1_plausible_1_to_5"].strip() for r in rows if r["reviewer1_plausible_1_to_5"].strip()]
    r2_plausible = [r["reviewer2_plausible_1_to_5"].strip() for r in rows if r["reviewer2_plausible_1_to_5"].strip()]

    total = len(rows)
    completed = min(len(r1_plausible), len(r2_plausible))

    if completed == 0:
        return {
            "status": "pending",
            "message": "Realism review ratings are pending human reviewer assessment (no fabricated ratings).",
            "total_hunks": total,
            "completed_reviews": 0,
            "mean_plausibility": None,
        }

    # If completed ratings are provided
    scores = [float(x) for x in r1_plausible[:completed]]
    return {
        "status": "completed",
        "total_hunks": total,
        "completed_reviews": completed,
        "mean_plausibility": round(sum(scores) / len(scores), 2),
    }


if __name__ == "__main__":
    res = ingest_realism_ratings()
    print(f"Realism Status: {res['status']}")
    print(f"Details: {res.get('message', res)}")