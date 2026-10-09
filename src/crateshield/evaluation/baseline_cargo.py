"""Condition C — cargo-audit baseline. Known-CVE matching only, expected
near-zero recall on novel/undisclosed malware by design; this motivates
the need for the LLM-based approach, it isn't meant to win."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_ADVISORIES_CACHE: list[dict] | None = None


def run_cargo_audit(name: str, version: str) -> dict:
    """Checks whether name@version has a KNOWN, PUBLISHED RustSec advisory
    (which is what cargo-audit actually does — it matches Cargo.lock
    entries against the advisory database, it does not analyze code)."""
    global _ADVISORIES_CACHE
    if _ADVISORIES_CACHE is None:
        # crawl once per process: fetch_malicious_advisories walks ~900 GitHub
        # directories, far too slow to repeat for every dataset entry
        from crateshield.ingestion.rustsec import fetch_malicious_advisories
        _ADVISORIES_CACHE = fetch_malicious_advisories()
    norm = lambda n: (n or "").lower().replace("-", "_")  # noqa: E731
    match = next((a for a in _ADVISORIES_CACHE if norm(a.get("package")) == norm(name)), None)

    if match:
        return {
            "classification": "MALICIOUS", "confidence": "HIGH",
            "reasoning": f"Matched published advisory {match.get('id')}",
            "primary_signals": ["published_advisory"], "recommended_action": "Block",
        }
    return {
        "classification": "BENIGN", "confidence": "LOW",
        "reasoning": "No matching published RustSec advisory found. "
                     "cargo-audit cannot detect undisclosed/novel malicious crates "
                     "by design — this is a known-CVE matcher, not a behavioral detector.",
        "primary_signals": [], "recommended_action": "Pass",
    }
