"""Signal 9 -- how much analyzable code is actually there.

Zahan et al. found their weaker model hallucinated malicious verdicts for
near-empty files (173 false positives from placeholder content). Knowing a
crate is (almost) empty lets the pipeline avoid asking an LLM to invent a
story about nothing."""
from __future__ import annotations

import re

_COMMENT_OR_BLANK = re.compile(r"^\s*(//.*)?$")


def _meaningful_lines(text: str | None) -> int:
    if not text:
        return 0
    return sum(1 for ln in text.splitlines() if not _COMMENT_OR_BLANK.match(ln))


meaningful_lines = _meaningful_lines


def summarize_content(preprocessed: dict) -> dict:
    src = preprocessed.get("source_files") or {}
    build = preprocessed.get("build_rs")
    n_src = sum(_meaningful_lines(c) for c in src.values())
    n_build = _meaningful_lines(build)
    return {
        "rust_files": len(src),
        "has_build_script": bool(build),
        "meaningful_lines": n_src + n_build,
        "meaningful_lines_build_script": n_build,
        "total_bytes": sum(len(c.encode("utf-8", "replace")) for c in src.values())
                       + len((build or "").encode("utf-8", "replace")),
    }
