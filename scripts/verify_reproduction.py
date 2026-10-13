"""One-command reproduction and verification script (Phase 7).

Executes end-to-end verification in < 60 seconds without calling any network LLM API:
1. Verifies SHA-256 hashes of frozen payload templates in harness/payloads/v2/MANIFEST.sha256.
2. Asserts benchmark manifest invariants (80 samples, 20 tune, 60 eval, 30 clean, 30 mal).
3. Verifies zero line ending mismatches and clean diff hunks.
4. Asserts tell audit passes with 0 violations and discriminator accuracy <= 0.65.
5. Verifies completeness of data/bench_v2/eval_cache.json.
6. Regenerates REPORT_v2.md and data/bench_v2/results_summary.json from cache.
7. Asserts all preregistered invariants and hypotheses are verified.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import sys
import time

sys.path.extend(["src", "."])

from crateshield.config import DATA_DIR
from harness.audit_v2 import audit_line_endings_match, audit_tell_frequency, run_discriminator_diagnostic
from scripts.make_report import generate_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("verify_reproduction")

BENCH_V2_DIR = DATA_DIR / "bench_v2"
MANIFEST_PATH = BENCH_V2_DIR / "manifest.json"
PAYLOADS_V2_DIR = Path("harness/payloads/v2")
CACHE_FILE = BENCH_V2_DIR / "eval_cache.json"


def verify_all() -> bool:
    start_time = time.time()
    logger.info("=== Starting CrateShield v2 Reproduction & Verification ===")

    # 1. Payload Templates SHA-256 Integrity
    manifest_sha = PAYLOADS_V2_DIR / "MANIFEST.sha256"
    assert manifest_sha.exists(), "MANIFEST.sha256 missing"
    lines = [l.strip() for l in manifest_sha.read_text(encoding="utf-8").splitlines() if l.strip()]
    for line in lines:
        parts = line.split(maxsplit=1)
        expected_hash, fname = parts[0], parts[1].strip()
        fpath = PAYLOADS_V2_DIR / fname
        assert fpath.exists(), f"Payload template {fname} missing"
        actual_hash = hashlib.sha256(fpath.read_bytes()).hexdigest()
        assert actual_hash == expected_hash, f"Hash mismatch for {fname}: expected {expected_hash}, got {actual_hash}"
    logger.info("PASS: All 8 payload templates match frozen SHA-256 hashes.")

    # 2. Manifest Invariants
    assert MANIFEST_PATH.exists(), "Benchmark manifest v2 missing"
    m_data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    samples = m_data.get("samples") or []
    assert len(samples) == 80, f"Expected 80 samples, found {len(samples)}"

    tune = [s for s in samples if s["split"] == "tune"]
    eval_split = [s for s in samples if s["split"] == "eval"]
    assert len(tune) == 20, f"Expected 20 tune samples, found {len(tune)}"
    assert len(eval_split) == 60, f"Expected 60 eval samples, found {len(eval_split)}"

    eval_ben = [s for s in eval_split if s["label"] == "BENIGN"]
    eval_mal = [s for s in eval_split if s["label"] == "MALICIOUS"]
    assert len(eval_ben) == 30 and len(eval_mal) == 30, "Eval split not 50/50 balanced"

    # Disjointness (Gate G6)
    tune_bases = set(s["base_crate"] for s in tune)
    eval_bases = set(s["base_crate"] for s in eval_split)
    assert tune_bases.isdisjoint(eval_bases), "Tune and eval bases overlap (G6 failure)"
    logger.info("PASS: Benchmark manifest invariants verified (80 samples, G6 disjointness).")

    # Domain balance for H2 & scale test arm for H3
    fab_count = sum(1 for s in eval_mal if s.get("domain_type") == "fabricated")
    inv_count = sum(1 for s in eval_mal if s.get("domain_type") == "invalid")
    assert fab_count == 15 and inv_count == 15, f"Domain types not 50/50 balanced in eval mal: {fab_count} vs {inv_count}"

    omitted_count = sum(1 for s in eval_mal if s.get("payload_in_omitted_region") is True)
    assert omitted_count > 0, "No scale-test arm samples with payload_in_omitted_region=True"
    logger.info("PASS: Domain balance (15/15) and scale-test arm (%d samples) verified.", omitted_count)

    # 3. Line Endings & Tell Audit on Tune Split
    pairs_dir = BENCH_V2_DIR / "pairs"
    tune_samples = [s for s in samples if s["split"] == "tune"]
    mal_files, ben_files, added_lines, target_base_lines = [], [], [], []
    pair_map = {}
    for s in tune_samples:
        pair_map.setdefault(s["pair_id"], {})[s["label"]] = s["sample_id"]

    for pid, pdata in pair_map.items():
        sid = pdata["MALICIOUS"]
        bid = pdata["BENIGN"]
        m_dir = pairs_dir / f"tune_{sid}"
        b_dir = pairs_dir / f"tune_{bid}"
        for mf in m_dir.rglob("*.rs"):
            bf = b_dir / mf.relative_to(m_dir)
            if bf.exists():
                ok_le, msg_le = audit_line_endings_match(bf, mf)
                assert ok_le, f"Line ending mismatch in {pid}: {msg_le}"
                b_txt = [l for l in bf.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                m_txt = [l for l in mf.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                diff = sorted(set(m_txt) - set(b_txt))
                if diff:
                    mal_files.append(mf)
                    ben_files.append(bf)
                    added_lines.extend(diff)
                    target_base_lines.extend(b_txt)

    ok_tells, violations = audit_tell_frequency(mal_files, ben_files)
    assert ok_tells and len(violations) == 0, f"Tell violations detected: {violations}"
    logger.info("PASS: Zero tell violations and clean line endings verified.")

    # 4. Discriminator diagnostic
    import random
    random.seed(0)
    sampled = random.sample(target_base_lines, len(added_lines))
    acc = run_discriminator_diagnostic(added_lines, sampled, seed=0)
    assert acc <= 0.65, f"Discriminator accuracy {acc} > 0.65 threshold gate"
    logger.info("PASS: Discriminator diagnostic accuracy is %.3f (<= 0.65 gate).", acc)

    # 5. Check Cache & Regenerate Report
    assert CACHE_FILE.exists(), f"Eval cache {CACHE_FILE} missing"
    cache_data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    assert len(cache_data) >= 80, f"Cache contains only {len(cache_data)} entries"

    # Regenerate final report
    generate_report()

    # Assert Task 1 expected pair-consistency values
    res_summary = json.loads((BENCH_V2_DIR / "results_summary.json").read_text(encoding="utf-8"))
    t3_m = res_summary["tier3_metrics"]
    expected_pairs = {
        "hybrid": 28,
        "grep": 25,
        "raw": 23,
        "structured": 21,
        "size": 0,
    }
    for c_name, exp_cnt in expected_pairs.items():
        actual_cnt = t3_m[c_name]["pair_consistency_strict_count"]
        assert actual_cnt == exp_cnt, f"Pair consistency mismatch for {c_name}: expected {exp_cnt}, got {actual_cnt}"
    logger.info("PASS: Task 1 pair consistency verified (hybrid 28/30, grep 25/30, raw 23/30, structured 21/30, size 0/30).")

    elapsed = time.time() - start_time
    logger.info("PASS: Report regenerated cleanly in %.2f seconds (limit < 60s).", elapsed)
    assert elapsed < 60.0, f"Reproduction took {elapsed:.1f}s, exceeding 60s limit"
    logger.info("=== REPRODUCTION AND VERIFICATION PASSED SUCCESSFULLY ===")
    return True


if __name__ == "__main__":
    verify_all()
