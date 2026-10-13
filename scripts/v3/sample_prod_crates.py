"""Sample 1,300 crates from crates.io for Part C.

1,000 random (crate, latest-non-yanked-version) pairs (fixed seed=42).
300 download-weighted (popular) (crate, latest-non-yanked-version) pairs.
Strictly excludes all crates in rustsec, ossf, and benchmark v1/v2/v3.
Documented frame date: 2026-10-11.
Respects crates.io API pagination rules (page <= 100).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import random
import string
import sys
import time
import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.v3.build_exclusions import get_all_excluded_crates

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sample_prod")

USER_AGENT = "crateshield-research/1.0 (contact: paulazad@gmail.com)"
PROD_DIR = ROOT / "data" / "prod_v2"
PROD_DIR.mkdir(parents=True, exist_ok=True)
MANIFEST_PATH = PROD_DIR / "manifest_prod.json"


def fetch_api(params: dict) -> list[dict]:
    url = "https://crates.io/api/v1/crates"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    for attempt in range(4):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=20)
            if r.status_code == 200:
                return r.json().get("crates", [])
            elif r.status_code == 429:
                time.sleep(4 * (attempt + 1))
            else:
                logger.warning("crates.io returned status %d on params %s", r.status_code, params)
                time.sleep(1.5)
        except Exception as e:
            logger.warning("Error on params %s: %s", params, e)
            time.sleep(2 * (attempt + 1))
    return []


def build_prod_sample(seed: int = 42) -> dict:
    if MANIFEST_PATH.exists():
        try:
            existing = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            if len(existing.get("random_sample", [])) == 1000 and len(existing.get("popular_sample", [])) == 300:
                logger.info("Existing valid manifest with 1,300 crates found at %s", MANIFEST_PATH)
                return existing
        except Exception:
            pass

    excluded = get_all_excluded_crates()
    logger.info("Loaded %d excluded crate identifiers.", len(excluded))

    # 1. Collect 300 popular crates
    popular_crates: list[dict] = []
    seen_names: set[str] = set()

    logger.info("Sampling 300 download-weighted (popular) crates...")
    for page in range(1, 10):
        if len(popular_crates) >= 300:
            break
        crates = fetch_api({"page": page, "per_page": 100, "sort": "downloads"})
        time.sleep(1.0)  # max 1 req/sec etiquette
        for c in crates:
            name = c.get("name", "").strip()
            ver = c.get("max_stable_version") or c.get("max_version")
            yanked = c.get("yanked", False)
            if not name or not ver or yanked:
                continue
            norm = name.lower()
            if norm in excluded or norm.replace("-", "_") in excluded or norm.replace("_", "-") in excluded:
                continue
            if norm in seen_names:
                continue
            seen_names.add(norm)
            popular_crates.append({
                "sample_id": f"prod_pop_{len(popular_crates)+1:04d}",
                "name": name,
                "version": ver,
                "downloads": c.get("downloads", 0),
                "description": c.get("description") or "",
                "sample_type": "popular_300",
            })
            if len(popular_crates) >= 300:
                break

    logger.info("Successfully collected %d popular crates.", len(popular_crates))

    # 2. Collect 1,000 random crates across the ecosystem
    random_crates: list[dict] = []
    rng = random.Random(seed)

    # Strategy: query across all 26 letters of the alphabet + numeric, pages 1 to 5
    # Then query sort=recent-updates and sort=recently-added
    query_batches: list[dict] = []
    for letter in string.ascii_lowercase:
        for p in range(1, 4):
            query_batches.append({"letter": letter, "page": p, "per_page": 100})
    for p in range(1, 15):
        query_batches.append({"sort": "recent-updates", "page": p, "per_page": 100})
    for p in range(1, 15):
        query_batches.append({"sort": "recently-added", "page": p, "per_page": 100})

    rng.shuffle(query_batches)

    logger.info("Sampling 1,000 random crates across alphabetical and recent distributions (seed=%d)...", seed)
    for q in query_batches:
        if len(random_crates) >= 1000:
            break
        crates = fetch_api(q)
        time.sleep(1.0)  # max 1 req/sec etiquette
        if not crates:
            continue
        rng.shuffle(crates)
        for c in crates:
            name = c.get("name", "").strip()
            ver = c.get("max_stable_version") or c.get("max_version")
            yanked = c.get("yanked", False)
            if not name or not ver or yanked:
                continue
            norm = name.lower()
            if norm in excluded or norm.replace("-", "_") in excluded or norm.replace("_", "-") in excluded:
                continue
            if norm in seen_names:
                continue
            seen_names.add(norm)
            random_crates.append({
                "sample_id": f"prod_rand_{len(random_crates)+1:04d}",
                "name": name,
                "version": ver,
                "downloads": c.get("downloads", 0),
                "description": c.get("description") or "",
                "sample_type": "random_1000",
            })
            if len(random_crates) >= 1000:
                break
        logger.info("Random crates collected: %d/1000", len(random_crates))

    manifest_data = {
        "frame_date": "2026-10-11",
        "random_seed": seed,
        "total_crates": len(popular_crates) + len(random_crates),
        "popular_count": len(popular_crates),
        "random_count": len(random_crates),
        "popular_sample": popular_crates,
        "random_sample": random_crates,
    }

    MANIFEST_PATH.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    logger.info("Saved prod manifest with %d crates to %s", manifest_data["total_crates"], MANIFEST_PATH)
    return manifest_data


if __name__ == "__main__":
    build_prod_sample()
