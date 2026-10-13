"""Signal 3 — proc-macro detector.

Procedural macros execute inside the compiler at build time and can inject
arbitrary code into the compiled binary, or exfiltrate source being
compiled. A proc-macro crate importing std::net/std::process is unusual
enough to flag.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

SUSPICIOUS_IMPORTS = ["std::process", "std::net", "std::fs::write", "reqwest", "ureq"]


def _is_proc_macro(cargo_toml: str | None) -> bool:
    """Real TOML parsing, not text regex -- a regex over raw text matches
    inside comments too (e.g. `# proc-macro = true`), which is a false
    positive a real TOML parser cannot produce."""
    if not cargo_toml:
        return False
    try:
        import tomllib
        doc = tomllib.loads(cargo_toml)
    except Exception:
        logger.warning("Could not parse Cargo.toml for proc-macro detection; "
                        "falling back to regex (may false-positive on comments)")
        return bool(re.search(r"\[lib\][^\[]*proc-macro\s*=\s*true", cargo_toml, re.DOTALL))
    return bool(doc.get("lib", {}).get("proc-macro") is True)


def analyze_proc_macro(cargo_toml: str | None, source_files: dict[str, str]) -> dict:
    if not _is_proc_macro(cargo_toml):
        return {"is_proc_macro": False}

    suspicious_found = []
    for _, content in source_files.items():
        for imp in SUSPICIOUS_IMPORTS:
            if imp in content:
                suspicious_found.append(imp)

    return {
        "is_proc_macro": True,
        "proc_macro_suspicious_imports": sorted(set(suspicious_found)),
    }
