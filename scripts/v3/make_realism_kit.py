"""Blinded Realism Kit Generator for Benchmark v3 (Phase 4).

Extracts 60 random hunks (balanced across generators, ladder levels,
malicious and lookalike twins) for blinded human review.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[2]
BENCH_V3 = ROOT / "data" / "bench_v3"
MANIFEST_PATH = BENCH_V3 / "manifest.json"
CORPUS_DIR = BENCH_V3 / "corpus_private"
REVIEW_DIR = ROOT / "review"
REVIEW_CSV_PATH = REVIEW_DIR / "realism_kit_v3.csv"
KEY_JSON_PATH = REVIEW_DIR / "realism_kit_v3_key.json"


def make_realism_kit(n_samples: int = 60, seed: int = 42) -> Path:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found at {MANIFEST_PATH}")

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Filter to modified twins (malicious and lookalike_benign)
    candidates = [
        s for s in manifest.get("samples", [])
        if s.get("twin_type") in ("malicious", "lookalike_benign") and s.get("hunk_line_ranges")
    ]

    rng = random.Random(seed)
    rng.shuffle(candidates)
    selected = candidates[:n_samples]

    rows = []
    key_records = []

    for idx, s in enumerate(selected):
        hunk_id = f"HUNK_{idx + 1:03d}"
        s_id = s["sample_id"]
        carrier = s["carrier"]
        carrier_file = CORPUS_DIR / s_id / carrier
        
        hunk_text = ""
        if carrier_file.exists():
            lines = carrier_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            ranges = s.get("hunk_line_ranges", [])
            if ranges:
                start_l, end_l = ranges[0]
                # Include 2 lines of context around hunk
                ctx_start = max(0, start_l - 3)
                ctx_end = min(len(lines), end_l + 2)
                hunk_text = "\n".join(lines[ctx_start:ctx_end])

        rows.append({
            "hunk_id": hunk_id,
            "carrier_type": Path(carrier).name,
            "code_snippet": hunk_text,
            "reviewer1_plausible_1_to_5": "",
            "reviewer1_looks_malicious_yn": "",
            "reviewer1_notes": "",
            "reviewer2_plausible_1_to_5": "",
            "reviewer2_looks_malicious_yn": "",
            "reviewer2_notes": "",
        })

        key_records.append({
            "hunk_id": hunk_id,
            "sample_id": s_id,
            "twin_type": s["twin_type"],
            "family": s["family"],
            "ladder_level": s["ladder_level"],
            "generator": s["generator"],
            "host_style": s["host_style"],
        })

    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "hunk_id", "carrier_type", "code_snippet",
        "reviewer1_plausible_1_to_5", "reviewer1_looks_malicious_yn", "reviewer1_notes",
        "reviewer2_plausible_1_to_5", "reviewer2_looks_malicious_yn", "reviewer2_notes",
    ]

    with open(REVIEW_CSV_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with open(KEY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(key_records, f, indent=2)

    print(f"Generated blinded realism kit: {REVIEW_CSV_PATH} ({len(rows)} hunks)")
    print(f"Generated secret unblinding key: {KEY_JSON_PATH}")
    return REVIEW_CSV_PATH


if __name__ == "__main__":
    make_realism_kit()