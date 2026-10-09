"""Packs a crate's raw files into one prompt under a character budget.

Replaces the old blind `raw_source[:20000]` slice, which silently dropped
everything after the first 20k characters. This version keeps a fixed
priority order (manifest, build script, then library files shallowest and
smallest first so more files fit), never cuts silently, and reports exactly
which files were included, partially included or left out, so an ablation
can state how much of each crate the baseline actually saw.
"""
from __future__ import annotations


def _ordered_source_paths(source_files: dict[str, str]) -> list[str]:
    def key(path: str):
        base = path.rsplit("/", 1)[-1]
        entry = 0 if base in ("lib.rs", "main.rs") else 1
        return (entry, path.count("/"), len(source_files[path]), path)
    return sorted(source_files, key=key)


def pack_source(preprocessed: dict, budget_chars: int) -> dict:
    parts: list[str] = []
    included: list[str] = []
    partial: list[str] = []
    omitted: list[str] = []
    used = 0

    items: list[tuple[str, str]] = []
    if preprocessed.get("cargo_toml"):
        items.append(("Cargo.toml", preprocessed["cargo_toml"]))
    if preprocessed.get("build_rs"):
        items.append((preprocessed.get("build_script_path") or "build.rs", preprocessed["build_rs"]))
    src = preprocessed.get("source_files") or {}
    for p in _ordered_source_paths(src):
        items.append((p, src[p]))

    for label, content in items:
        header = f"\n\n===== {label} =====\n"
        room = budget_chars - used - len(header)
        if room < 200:
            omitted.append(label)
            continue
        body = content if len(content) <= room else content[:room]
        if len(content) > room:
            partial.append(f"{label} ({room}/{len(content)} chars)")
        parts.append(header + body)
        included.append(label)
        used += len(header) + len(body)

    note = None
    if partial or omitted:
        note = (f"input was limited to about {budget_chars} characters; "
                f"{len(omitted)} file(s) were omitted and {len(partial)} truncated, so absence of "
                "evidence in what you see is not evidence of absence")
    return {"text": "".join(parts).lstrip("\n"), "included": included, "partial": partial,
            "omitted": omitted, "truncation_note": note, "total_files": len(items)}
