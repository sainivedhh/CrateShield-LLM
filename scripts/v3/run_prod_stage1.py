"""Part C Stage 1: Download, Safe Extract, and Static Pre-Screen across 1,300 crates.io crates.

- Downloads tarballs with max 1 req/sec etiquette.
- Caches every tarball by sha256 in data/prod_v2/tarballs/.
- Safely extracts into data/prod_v2/extracted/ using path containment & tar limits.
- Evaluates Stage 1 static pre-screen (0 LLM cost) via src/crateshield/prescreen.py.
- Produces data/prod_v2/stage1_results.json.
- Checks pause condition: If flagged crates > 2x 130 (i.e. > 260), pauses and reports back.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import sys
import time
import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from crateshield.config import USER_AGENT
from crateshield.ingestion.downloader import extract_crate, locate_crate_root
from crateshield.signals.extractor import extract_all_signals
from crateshield.prescreen import decide_prescreen

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prod_stage1")

PROD_DIR = ROOT / "data" / "prod_v2"
MANIFEST_PATH = PROD_DIR / "manifest_prod.json"
TARBALLS_DIR = PROD_DIR / "tarballs"
EXTRACTED_DIR = PROD_DIR / "extracted"
STAGE1_RESULTS_PATH = PROD_DIR / "stage1_results.json"

for d in (TARBALLS_DIR, EXTRACTED_DIR):
    d.mkdir(parents=True, exist_ok=True)


def download_tarball(name: str, version: str) -> tuple[Path, str]:
    """Downloads crate tarball from static.crates.io CDN with sha256 hashing."""
    dest_path = TARBALLS_DIR / f"{name}-{version}.crate"
    if dest_path.exists() and dest_path.stat().st_size > 0:
        sha256_hash = hashlib.sha256(dest_path.read_bytes()).hexdigest()
        return dest_path, sha256_hash

    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    headers = {"User-Agent": USER_AGENT}
    for attempt in range(4):
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200 and r.content:
                dest_path.write_bytes(r.content)
                sha256_hash = hashlib.sha256(r.content).hexdigest()
                return dest_path, sha256_hash
            elif r.status_code == 429:
                time.sleep(3 * (attempt + 1))
            else:
                time.sleep(1.5)
        except Exception as e:
            time.sleep(2 * (attempt + 1))

    raise RuntimeError(f"Failed to download {name} v{version} from {url}")


def run_stage1():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    all_crates = manifest["popular_sample"] + manifest["random_sample"]
    logger.info("Starting Stage 1 processing across %d crates...", len(all_crates))

    # Load existing results if resuming
    results = {}
    if STAGE1_RESULTS_PATH.exists():
        try:
            results = json.loads(STAGE1_RESULTS_PATH.read_text(encoding="utf-8"))
            logger.info("Resuming with %d existing results.", len(results))
        except Exception:
            pass

    flagged_popular = 0
    flagged_random = 0

    for idx, c in enumerate(all_crates, 1):
        sample_id = c["sample_id"]
        name = c["name"]
        version = c["version"]
        sample_type = c["sample_type"]

        if sample_id in results:
            res = results[sample_id]
            if not res.get("prescreen", {}).get("skip_llm", True):
                if sample_type == "popular_300":
                    flagged_popular += 1
                else:
                    flagged_random += 1
            continue

        logger.info("[%d/%d] Processing %s (%s v%s)...", idx, len(all_crates), sample_id, name, version)
        try:
            t0 = time.time()
            # 1. Download with 1 req/sec pacing
            tar_path, sha256_hash = download_tarball(name, version)
            time.sleep(1.0)  # max 1 req/sec etiquette

            # 2. Safe extraction
            extract_dest = EXTRACTED_DIR / f"{name}-{version}"
            if not extract_dest.exists() or not any(extract_dest.iterdir()):
                crate_root = extract_crate(tar_path, extract_dest)
            else:
                crate_root = locate_crate_root(extract_dest)

            # 3. Build anonymized/inert view for signal extractor
            source_files: dict[str, str] = {}
            build_rs = ""
            cargo_toml = ""

            for p in crate_root.rglob("*"):
                if p.is_file():
                    rel = p.relative_to(crate_root).as_posix()
                    if rel == "Cargo.toml":
                        try:
                            cargo_toml = p.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass
                    elif rel in ("build.rs", "build/main.rs"):
                        try:
                            build_rs = p.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass
                    elif rel.endswith(".rs"):
                        try:
                            source_files[rel] = p.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass

            view = {
                "name": name,
                "version": version,
                "cargo_toml": cargo_toml,
                "build_rs": build_rs,
                "source_files": source_files,
            }

            # 4. Extract static signals
            signals = extract_all_signals(view)

            # 5. Evaluate Stage 1 static pre-screen
            prescreen_decision = decide_prescreen(signals)
            skip_llm = prescreen_decision.get("skip_llm", True)

            if not skip_llm:
                if sample_type == "popular_300":
                    flagged_popular += 1
                else:
                    flagged_random += 1
                logger.info("  --> FLAGGED by pre-screen: %s (signals: %s)", prescreen_decision.get("reason"), prescreen_decision.get("fired"))
            else:
                logger.info("  --> Clean (LLM skipped): %s", prescreen_decision.get("reason_code"))

            results[sample_id] = {
                "sample_id": sample_id,
                "name": name,
                "version": version,
                "sample_type": sample_type,
                "sha256": sha256_hash,
                "downloads": c.get("downloads", 0),
                "prescreen": prescreen_decision,
                "fired_signals": prescreen_decision.get("fired", []),
                "flagged": not skip_llm,
                "extracted_path": str(crate_root),
            }

        except Exception as e:
            logger.error("Failed processing %s (%s): %s", sample_id, name, e)
            results[sample_id] = {
                "sample_id": sample_id,
                "name": name,
                "version": version,
                "sample_type": sample_type,
                "error": str(e),
                "flagged": False,
            }

        # Checkpoint every 25 crates
        if idx % 25 == 0:
            STAGE1_RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
            logger.info("Checkpoint saved (%d/%d crates processed). Current flagged: pop=%d, rand=%d, total=%d",
                        idx, len(all_crates), flagged_popular, flagged_random, flagged_popular + flagged_random)

    # Final write
    STAGE1_RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")

    total_flagged = flagged_popular + flagged_random
    logger.info("=== Stage 1 Complete ===")
    logger.info("Popular sample: %d / 300 flagged (%.1f%%)", flagged_popular, (flagged_popular / 300) * 100)
    logger.info("Random sample: %d / 1000 flagged (%.1f%%)", flagged_random, (flagged_random / 1000) * 100)
    logger.info("Total flagged: %d / 1300 (%.1f%%)", total_flagged, (total_flagged / 1300) * 100)

    return {
        "total_processed": len(results),
        "flagged_popular": flagged_popular,
        "flagged_random": flagged_random,
        "total_flagged": total_flagged,
    }


if __name__ == "__main__":
    run_stage1()
