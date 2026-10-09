"""Dataset fetcher utility.

Downloads missing raw .crate tarballs into data/raw/ from crates.io CDN by crate name and version.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import sys
import requests

sys.path.extend(["src", "."])

from crateshield.config import DATA_DIR, RAW_DIR, USER_AGENT

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("fetch_data")


def fetch_crate(name: str, version: str, expected_sha256: str | None = None) -> Path:
    """Downloads a .crate tarball to data/raw/ if not already present."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = RAW_DIR / f"{name}-{version}.crate"

    if dest_path.exists():
        if expected_sha256:
            actual = hashlib.sha256(dest_path.read_bytes()).hexdigest()
            if actual == expected_sha256:
                logger.info("Crate %s v%s already present and verified.", name, version)
                return dest_path
        else:
            logger.info("Crate %s v%s already present.", name, version)
            return dest_path

    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    logger.info("Fetching %s v%s from %s...", name, version, url)
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
    resp.raise_for_status()

    if expected_sha256:
        actual = hashlib.sha256(resp.content).hexdigest()
        if actual != expected_sha256:
            raise ValueError(f"Checksum mismatch for {name} v{version}: expected {expected_sha256}, got {actual}")

    dest_path.write_bytes(resp.content)
    logger.info("Saved %s (%d bytes)", dest_path.name, len(resp.content))
    return dest_path


def fetch_all_manifest_crates(manifest_path: Path | None = None) -> None:
    path = manifest_path or (DATA_DIR / "bench_v2" / "manifest.json")
    if not path.exists():
        logger.warning("Manifest not found at %s", path)
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data.get("samples") or data.get("records") or []
    seen = set()
    for s in samples:
        crate_name = s.get("base_crate")
        version = s.get("base_version")
        if crate_name and version and (crate_name, version) not in seen:
            seen.add((crate_name, version))
            try:
                fetch_crate(crate_name, version)
            except Exception as e:
                logger.warning("Failed to fetch %s v%s: %s", crate_name, version, e)


if __name__ == "__main__":
    fetch_all_manifest_crates()
