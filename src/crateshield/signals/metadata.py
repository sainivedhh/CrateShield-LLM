"""Signal 8 -- registry metadata and version-number anomalies.

Zahan et al. observed that their LLMs flagged dependency-confusion style
packages largely from metadata: abnormal version numbers, install-time
hooks, maintainer details. The extractor previously read crates.io metadata
from the top level of the API response, but crates.io nests it under
"crate", so publish date / downloads / keywords were always empty. This
module reads both shapes and adds a version-anomaly check.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from crateshield.config import HIGH_MAJOR_VERSION_THRESHOLD


def analyze_version(version: str | None) -> dict:
    m = re.match(r"\s*v?(\d+)\.", version or "")
    major = int(m.group(1)) if m else None
    high = bool(major is not None and major >= HIGH_MAJOR_VERSION_THRESHOLD)
    out = {"version": version, "major": major, "high_major_version": high}
    if high:
        out["note"] = (f"major version {major} >= {HIGH_MAJOR_VERSION_THRESHOLD}: a pattern used by "
                       "dependency-confusion placeholders, but some legitimate crates (e.g. rustc-ap-*) "
                       "also use very high majors -- weigh with crate age and downloads")
    return out


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def analyze_metadata(version: str | None, metadata: dict | None) -> dict:
    if not metadata:
        return {}
    crate = metadata.get("crate") if isinstance(metadata.get("crate"), dict) else metadata
    kws = metadata.get("keywords") if isinstance(metadata.get("keywords"), list) else crate.get("keywords", [])
    keywords = [k.get("keyword") if isinstance(k, dict) else k for k in (kws or [])]
    versions_meta = metadata.get("versions") if isinstance(metadata.get("versions"), list) else []
    created = _parse_dt(crate.get("created_at"))
    age_days = (datetime.now(timezone.utc) - created).days if created else None
    this = next((v for v in versions_meta if isinstance(v, dict) and v.get("num") == version), None)
    return {
        "publish_date": crate.get("created_at"),
        "age_days": age_days,
        "description": crate.get("description"),
        "keywords": [k for k in keywords if k],
        "downloads": crate.get("downloads"),
        "num_versions": len(versions_meta) or crate.get("num_versions"),
        "version_yanked": None if this is None else bool(this.get("yanked")),
    }
