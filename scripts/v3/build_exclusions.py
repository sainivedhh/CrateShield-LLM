"""Exclusion set builder for Part C.

Collects all crate names to exclude from Part C sampling:
1. data/rustsec_advisories.json
2. data/ossf/ crates
3. Crate names from v1, v2, v3 benchmarks (manifests and pairs)
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def get_all_excluded_crates() -> set[str]:
    excluded: set[str] = set()

    # 1. RustSec advisories
    rustsec_path = ROOT / "data" / "rustsec_advisories.json"
    if rustsec_path.exists():
        try:
            advs = json.loads(rustsec_path.read_text(encoding="utf-8"))
            if isinstance(advs, list):
                for a in advs:
                    if isinstance(a, dict) and "crate" in a:
                        excluded.add(a["crate"].strip().lower())
                    elif isinstance(a, str):
                        excluded.add(a.strip().lower())
            elif isinstance(advs, dict):
                for k in advs.keys():
                    excluded.add(k.strip().lower())
        except Exception:
            pass

    # 2. OSSF
    ossf_dir = ROOT / "data" / "ossf"
    if ossf_dir.exists():
        for p in ossf_dir.rglob("*.json"):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                pkg = d.get("package", {}).get("name")
                if pkg:
                    excluded.add(pkg.strip().lower())
            except Exception:
                pass

    # 3. Benchmark v1, v2, v3 manifests
    for bench in ("bench_v1", "bench_v2", "bench_v3"):
        manifest_path = ROOT / "data" / bench / "manifest.json"
        if manifest_path.exists():
            try:
                m = json.loads(manifest_path.read_text(encoding="utf-8"))
                samples = m.get("samples") or m.get("pairs") or m.get("records") or []
                for s in samples:
                    for field in ("crate_name", "base_crate", "cluster_id", "sample_id", "name"):
                        val = s.get(field)
                        if val and isinstance(val, str):
                            # clean up sample prefixes
                            name = val.split("_")[0] if "_" in val else val
                            excluded.add(val.strip().lower())
                            excluded.add(name.strip().lower())
            except Exception:
                pass

    # Normalize '-' and '_' interchangeable forms
    normalized_excluded = set(excluded)
    for c in list(excluded):
        normalized_excluded.add(c.replace("-", "_"))
        normalized_excluded.add(c.replace("_", "-"))

    return normalized_excluded


if __name__ == "__main__":
    ex = get_all_excluded_crates()
    print(f"Total excluded crate identifiers: {len(ex)}")
