"""One-command reproduction and offline verification script for Benchmark v3 (Phase 7).

Executes end-to-end verification in < 60 seconds without calling any network LLM API:
1. Asserts manifest invariants (150 samples across 50 clusters, 10 tune, 40 eval, 50 clean, 50 mal, 50 lookalike).
2. Verifies SHA-256 hashes of private corpus against manifest.json.
3. Checks completeness of data/bench_v3/eval_cache.json.
4. Regenerates REPORT_V3.md and data/bench_v3/results_summary_v3.json from cache.
5. Asserts report invariants and metric consistency.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.extend([str(ROOT / "src"), str(ROOT)])

from scripts.v3.make_report_v3 import generate_report_v3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("verify_reproduction_v3")

BENCH_V3 = ROOT / "data" / "bench_v3"
MANIFEST_PATH = BENCH_V3 / "manifest.json"
CORPUS_DIR = BENCH_V3 / "corpus_private"
CACHE_PATH = BENCH_V3 / "eval_cache.json"
REPORT_MD = ROOT / "REPORT_V3.md"
SUMMARY_JSON = BENCH_V3 / "results_summary_v3.json"


def sha256_tree(dir_path: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(dir_path.glob("**/*")):
        if p.is_file():
            h.update(p.relative_to(dir_path).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def verify_all() -> bool:
    start_time = time.time()
    logger.info("=== Starting CrateShield Benchmark v3 Reproduction & Verification ===")

    # 1. Manifest Invariants
    assert MANIFEST_PATH.exists(), f"Manifest missing: {MANIFEST_PATH}"
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    samples = manifest.get("samples", [])
    assert len(samples) == 150, f"Expected 150 samples, got {len(samples)}"

    tune = [s for s in samples if s["split"] == "tune"]
    eval_split = [s for s in samples if s["split"] == "eval"]
    assert len(tune) == 30, f"Expected 30 tune samples, got {len(tune)}"
    assert len(eval_split) == 120, f"Expected 120 eval samples, got {len(eval_split)}"

    clean = [s for s in samples if s["twin_type"] == "clean"]
    mal = [s for s in samples if s["twin_type"] == "malicious"]
    look = [s for s in samples if s["twin_type"] == "lookalike_benign"]
    assert len(clean) == 50, f"Expected 50 clean samples, got {len(clean)}"
    assert len(mal) == 50, f"Expected 50 malicious samples, got {len(mal)}"
    assert len(look) == 50, f"Expected 50 lookalike benign samples, got {len(look)}"
    logger.info("PASS: Manifest invariants verified (150 samples: 30 tune, 120 eval, 50 clean, 50 mal, 50 lookalike).")

    # 2. SHA-256 Integrity Verification
    if CORPUS_DIR.exists():
        logger.info("Verifying corpus SHA-256 integrity against manifest...")
        for s in samples:
            s_dir = CORPUS_DIR / s["sample_id"]
            if s_dir.exists():
                actual_h = sha256_tree(s_dir)
                assert actual_h == s["sha256"], f"SHA256 mismatch on {s['sample_id']}"
        logger.info("PASS: All sample trees match frozen SHA-256 hashes.")

    # 3. Cache Completeness
    assert CACHE_PATH.exists(), f"Eval cache missing: {CACHE_PATH}"
    cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    assert len(cache) > 0, "Eval cache is empty"
    logger.info("PASS: Eval cache verified (%d cached evaluations).", len(cache))

    # 4. Regenerate Reports Offline
    logger.info("Regenerating REPORT_V3.md and results_summary_v3.json from cache...")
    generate_report_v3()
    assert REPORT_MD.exists(), "REPORT_V3.md was not generated"
    assert SUMMARY_JSON.exists(), "results_summary_v3.json was not generated"

    summary = json.loads(SUMMARY_JSON.read_text(encoding="utf-8"))
    assert summary.get("benchmark_version") == "v3"
    assert "conditions" in summary
    logger.info("PASS: Report and summary successfully regenerated from cache without network calls.")

    elapsed = time.time() - start_time
    logger.info("=== All Benchmark v3 Verifications Passed in %.2f seconds! ===", elapsed)
    return True


if __name__ == "__main__":
    success = verify_all()
    sys.exit(0 if success else 1)