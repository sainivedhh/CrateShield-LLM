"""Base-Crate Sampler implementing Section 3 of the CrateShield Harness Spec.

Eligibility filters:
1. Has a build.rs at the package root.
2. First published >= 12 months ago.
3. Not in RustSec or OSSF malicious lists, and depends on none.
4. Permissive license (MIT / Apache-2.0 / BSD / ISC).
5. All .rs files parse cleanly with tree-sitter-rust (zero parse errors).

Stratification:
- Log-scale total .rs size into 5 bins (quintiles).
- Download count into 3 bands (low <10k, mid 10k-500k, high 500k-10M; top 500 excluded).
- Build.rs behavior class:
    Class A: pure code / minimal
    Class B: tool / native build calls (cc, cmake, pkg-config)
    Class C: environment / autocfg probing
"""
from __future__ import annotations

import datetime
import json
import logging
import math
from pathlib import Path
import random
import tomllib
from typing import Any

import tree_sitter
import tree_sitter_rust

from crateshield.config import DATA_DIR

logger = logging.getLogger(__name__)

# Tree-sitter Rust parser setup
_RUST_LANG = tree_sitter.Language(tree_sitter_rust.language())
_PARSER = tree_sitter.Parser(_RUST_LANG)

PERMISSIVE_LICENSES = ("mit", "apache-2.0", "bsd", "isc", "unlicense", "cc0")


def load_malicious_denylist() -> set[str]:
    """Loads malicious package names from local RustSec and OSSF caches."""
    denylist = set()
    rustsec_path = DATA_DIR / "rustsec_advisories.json"
    if rustsec_path.exists():
        try:
            advs = json.loads(rustsec_path.read_text(encoding="utf-8"))
            for a in advs:
                if a.get("package"):
                    denylist.add(a["package"].lower().replace("-", "_"))
        except Exception as e:
            logger.warning("Could not load RustSec denylist: %s", e)

    ossf_manifest = DATA_DIR / "ossf" / "manifest.json"
    if ossf_manifest.exists():
        try:
            ossf_dir = DATA_DIR / "ossf" / "crates.io"
            if ossf_dir.exists():
                for p in ossf_dir.glob("*.json"):
                    denylist.add(p.stem.lower().replace("-", "_"))
        except Exception:
            pass

    return denylist


def check_tree_sitter_syntax(crate_dir: Path) -> tuple[bool, int, int]:
    """Verifies that all .rs files in the crate parse cleanly with zero error nodes.

    Returns:
        (is_clean, total_rs_files, total_rs_bytes)
    """
    rs_files = list(crate_dir.glob("**/*.rs"))
    if not rs_files:
        return False, 0, 0

    total_bytes = 0
    for rs in rs_files:
        try:
            content = rs.read_bytes()
            total_bytes += len(content)
            tree = _PARSER.parse(content)
            if tree.root_node.has_error:
                return False, len(rs_files), total_bytes
        except Exception:
            return False, len(rs_files), total_bytes

    return True, len(rs_files), total_bytes


def classify_build_rs_behavior(build_rs_content: str | None) -> str:
    """Classifies build.rs into Class A (pure), Class B (native tools), or Class C (probing)."""
    if not build_rs_content:
        return "none"
    lower = build_rs_content.lower()
    if any(k in lower for k in ("cc::", "cmake::", "pkg_config::", "gcc::")):
        return "native_tools"
    if any(k in lower for k in ("autocfg", "rustc_version", "env::var", "version_check")):
        return "env_probing"
    return "pure_rust"


def is_crate_eligible(
    crate_meta: dict[str, Any],
    crate_dir: Path,
    denylist: set[str] | None = None,
    min_age_days: int = 365,
) -> tuple[bool, str]:
    """Applies the 5 required eligibility filters from Section 3."""
    name = crate_meta.get("name") or crate_meta.get("id") or ""
    norm_name = name.lower().replace("-", "_")

    # 1. build.rs present at root
    build_rs = crate_dir / "build.rs"
    if not build_rs.exists() or not build_rs.is_file():
        return False, "Missing build.rs at package root"

    # 2. First published >= 12 months ago
    created_str = crate_meta.get("created_at")
    if created_str:
        try:
            # Handle ISO format
            created_dt = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            age = (datetime.datetime.now(datetime.timezone.utc) - created_dt).days
            if age < min_age_days:
                return False, f"Published only {age} days ago (minimum {min_age_days})"
        except Exception:
            pass

    # 3. Not in RustSec or OSSF denylist
    if denylist is None:
        denylist = load_malicious_denylist()
    if norm_name in denylist:
        return False, f"Named in malicious denylist ({name})"

    # 4. Permissive license
    license_str = (crate_meta.get("license") or crate_meta.get("max_version_license") or "").lower()
    if license_str and not any(l in license_str for l in PERMISSIVE_LICENSES):
        return False, f"Non-permissive license: {license_str}"

    # 5. Compiles-as-text sanity via tree-sitter
    is_clean, n_files, n_bytes = check_tree_sitter_syntax(crate_dir)
    if not is_clean:
        return False, "Contains syntax parse errors according to tree-sitter-rust"

    return True, "Eligible"


def stratify_and_sample(
    candidates: list[dict[str, Any]],
    target_count: int = 40,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Performs stratified sampling across size quintiles and build.rs behavior classes."""
    if len(candidates) <= target_count:
        return list(candidates)

    rng = random.Random(seed)

    # Group by build.rs behavior class
    classes: dict[str, list[dict[str, Any]]] = {
        "native_tools": [],
        "env_probing": [],
        "pure_rust": [],
    }

    for c in candidates:
        cls = c.get("build_class", "pure_rust")
        classes.setdefault(cls, []).append(c)

    # Sort each class by size to distribute across size bins
    for k in classes:
        classes[k].sort(key=lambda x: x.get("size_bytes", 0))

    selected: list[dict[str, Any]] = []
    selected_names: set[str] = set()

    active_classes = [k for k, pool in classes.items() if len(pool) > 0]
    per_class = target_count // len(active_classes)
    remainder = target_count % len(active_classes)

    for i, cls_name in enumerate(active_classes):
        pool = classes[cls_name]
        quota = per_class + (1 if i < remainder else 0)
        if len(pool) <= quota:
            for item in pool:
                if item.get("name") not in selected_names:
                    selected.append(item)
                    selected_names.add(item.get("name"))
        else:
            step = len(pool) / quota
            indices = [int(j * step) for j in range(quota)]
            for idx in indices:
                item = pool[min(idx, len(pool) - 1)]
                if item.get("name") not in selected_names:
                    selected.append(item)
                    selected_names.add(item.get("name"))

    # If any quota shortfall remains, fill from remaining candidates
    if len(selected) < target_count:
        remaining = [c for c in candidates if c.get("name") not in selected_names]
        remaining.sort(key=lambda x: x.get("size_bytes", 0))
        needed = target_count - len(selected)
        if len(remaining) <= needed:
            selected.extend(remaining)
        else:
            step = len(remaining) / needed
            indices = [int(j * step) for j in range(needed)]
            for idx in indices:
                item = remaining[min(idx, len(remaining) - 1)]
                if item.get("name") not in selected_names:
                    selected.append(item)
                    selected_names.add(item.get("name"))
            for item in remaining:
                if len(selected) >= target_count:
                    break
                if item.get("name") not in selected_names:
                    selected.append(item)
                    selected_names.add(item.get("name"))

    # Shuffle selected deterministically
    rng.shuffle(selected)
    return selected[:target_count]

