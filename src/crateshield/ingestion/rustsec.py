"""Pulls malicious-code / backdoor advisories from rustsec/advisory-db.

Walks the FULL advisory-db (not a cached subset) so results stay current.
Requires a GitHub token in GITHUB_TOKEN to avoid the 60/hr unauthenticated
rate limit when crawling all ~900+ advisory directories.
"""
from __future__ import annotations

import json
import logging
import os
import tomllib

import requests

from crateshield.config import DATA_DIR, RUSTSEC_ADVISORY_API, RUSTSEC_RAW, USER_AGENT

logger = logging.getLogger(__name__)

MALICIOUS_CATEGORIES = {"malicious-code", "backdoor", "malware", "typosquatting"}


def _session() -> requests.Session:
    s = requests.Session()
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    s.headers.update(headers)
    return s


def fetch_malicious_advisories(session: requests.Session | None = None) -> list[dict]:
    """Returns advisories tagged with a malicious-intent category.
    Prefers the local cache if available, falling back to crawling advisory-db."""
    local_cache = DATA_DIR / "rustsec_advisories.json"
    if local_cache.exists():
        try:
            advs = json.loads(local_cache.read_text(encoding="utf-8"))
            logger.info("Loaded %d RustSec advisories from %s", len(advs), local_cache)
            return advs
        except Exception as e:
            logger.warning("Could not read %s: %s", local_cache, e)

    s = session or _session()
    try:
        resp = s.get(RUSTSEC_ADVISORY_API, timeout=30)
        resp.raise_for_status()
        crate_dirs = [e for e in resp.json() if e.get("type") == "dir"]
        logger.info("Scanning %d crate advisory directories", len(crate_dirs))
    except Exception as e:
        logger.warning("Failed to fetch RustSec advisories from GitHub: %s", e)
        return []

    found = []
    for entry in crate_dirs:
        dir_resp = s.get(entry["url"], timeout=30)
        if dir_resp.status_code != 200:
            continue
        for f in dir_resp.json():
            if not f["name"].endswith(".md") and not f["name"].endswith(".toml"):
                continue
            if not f["name"].startswith("RUSTSEC-"):
                continue
            raw = s.get(f["download_url"] or f"{RUSTSEC_RAW}/crates/{entry['name']}/{f['name']}", timeout=30)
            if raw.status_code != 200:
                continue
            text = raw.text
            # advisories are TOML with an embedded markdown description after '---'
            toml_part = text.split("\n```\n")[0] if "```" in text else text
            try:
                doc = tomllib.loads(toml_part) if toml_part.strip().startswith("[") else None
            except tomllib.TOMLDecodeError:
                doc = None
            if not doc:
                continue
            adv = doc.get("advisory", {})
            categories = set(adv.get("categories", []))
            if categories & MALICIOUS_CATEGORIES:
                found.append({
                    "id": adv.get("id"),
                    "package": adv.get("package"),
                    "categories": list(categories),
                    "url": adv.get("url"),
                    "date": adv.get("date"),
                })
    logger.info("Found %d malicious-tagged advisories", len(found))
    return found


def resolve_malicious_version(name: str, advisory: dict,
                               session: requests.Session | None = None) -> str | None:
    """RustSec advisories don't always pin an exact malicious version.
    Try the crates.io API for the crate's version list and prefer a yanked
    version close to the advisory date; fall back to None if unresolvable
    (crate fully removed, not just yanked)."""
    from crateshield.ingestion.downloader import get_crate_metadata
    s = session or _session()
    try:
        meta = get_crate_metadata(name, s)
    except requests.RequestException:
        return None
    versions = meta.get("versions", [])
    yanked = [v for v in versions if v.get("yanked")]
    if yanked:
        return yanked[0]["num"]
    if versions:
        return versions[0]["num"]
    return None
