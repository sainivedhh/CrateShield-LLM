"""Anonymized model-visible view builder for CrateShield Evaluation Harness.

Enforces Section 7 of the spec:
- Neutral crate id: crate_<8 hex of salted hash>
- Cargo.toml: scrub name, authors, repository, homepage, documentation,
  description, keywords, categories, readme, license-file.
- Source code: scrub crate name, author/repo strings, benchmark tags from
  file paths, module paths, doc comments, and string literals.
- Version: pass derived flags, not raw misleading version strings.
- Typosquat & metadata: compute offline from real name; pass derived
  numerical/boolean features only, never the target crate name.
- Negative controls: build name-only and metadata-only views.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
import tomllib


SALT_DEFAULT = "crateshield-v1"

# Cargo.toml metadata fields that must be scrubbed from model view
SCRUB_MANIFEST_FIELDS = (
    "name", "authors", "repository", "homepage", "documentation",
    "description", "keywords", "categories", "readme", "license-file"
)

# Common label leak words to clean from source comments/fixtures
FORBIDDEN_LEAK_WORDS = (
    "cratebench", "defanged", "exfil", "payload", "c2"
)


def compute_view_id(name: str, salt: str = SALT_DEFAULT) -> str:
    """Generates deterministic neutral identifier: crate_<8 hex>."""
    raw = f"{name.strip().lower()}:{salt}".encode("utf-8")
    return f"crate_{hashlib.sha256(raw).hexdigest()[:8]}"


def scrub_cargo_toml(content: str, view_id: str, real_name: str | None = None) -> str:
    """Removes identifying metadata fields and replaces the package name."""
    lines = content.splitlines()
    cleaned_lines: list[str] = []
    in_package_section = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_package_section = (stripped == "[package]")
            if real_name:
                line = _replace_name_variants(line, real_name, view_id)
            cleaned_lines.append(line)
            continue

        if in_package_section:
            # Check if this line is an identifying field
            matched_field = False
            for field in SCRUB_MANIFEST_FIELDS:
                if re.match(rf"^{field}\s*=", stripped):
                    matched_field = True
                    if field == "name":
                        cleaned_lines.append(f'name = "{view_id}"')
                    break
            if not matched_field:
                # Replace real_name occurrences if any remain in comments
                if real_name:
                    line = _replace_name_variants(line, real_name, view_id)
                cleaned_lines.append(line)
        else:
            if real_name:
                line = _replace_name_variants(line, real_name, view_id)
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def _replace_name_variants(text: str, real_name: str, view_id: str) -> str:
    """Replaces real crate name, hyphen/underscore variations, and benchmark prefix."""
    if not real_name or len(real_name) < 2:
        return text

    variants = {
        real_name,
        real_name.replace("-", "_"),
        real_name.replace("_", "-"),
    }
    for var in sorted(variants, key=len, reverse=True):
        # First replace prefix forms like tokio_ or tokio-
        pattern_prefixed = re.compile(rf"(?i)\b{re.escape(var)}[-_]")
        text = pattern_prefixed.sub(f"{view_id}_", text)
        # Then replace standalone words
        pattern_word = re.compile(rf"(?i)\b{re.escape(var)}\b")
        text = pattern_word.sub(view_id, text)

    # Scrub benchmark artifacts like cratebench- or cratebench_
    text = re.sub(r"(?i)cratebench[-_]?", "pkg-", text)
    return text


def scrub_source_code(content: str, real_name: str, view_id: str,
                      extra_scrub_terms: list[str] | None = None) -> str:
    """Scrubs crate name, author/repo strings, and benchmark leak tokens from source."""
    scrubbed = _replace_name_variants(content, real_name, view_id)

    if extra_scrub_terms:
        for term in extra_scrub_terms:
            if term and len(term) > 2:
                pattern = re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
                scrubbed = pattern.sub("anon_entity", scrubbed)

    return scrubbed


def derive_version_flags(version_str: str | None) -> dict[str, bool]:
    """Computes derived version flags without passing raw suspicious strings."""
    if not version_str:
        return {"high_major": False, "pre_1_0": False, "is_prerelease": False}
    
    parts = version_str.strip().split(".")
    major = 0
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        pass

    return {
        "high_major": major >= 99,
        "pre_1_0": major == 0,
        "is_prerelease": "-" in version_str,
    }


def compute_derived_typosquat_features(real_name: str, top_crates: list[dict] | None = None) -> dict:
    """Computes typosquat features offline from real name; returns derived numbers only.
    NEVER leaks the nearest crate's name into the view.
    """
    if top_crates is None:
        from crateshield.config import TOP_CRATES_PATH
        if TOP_CRATES_PATH.exists():
            try:
                top_crates = json.loads(TOP_CRATES_PATH.read_text(encoding="utf-8"))
            except Exception:
                top_crates = []
        else:
            top_crates = []

    from crateshield.signals.typosquat import analyze_typosquatting
    res = analyze_typosquatting(real_name, top_crates or [])
    return {
        "is_typosquat_suspect": res.get("flagged", False),
        "min_edit_distance": res.get("edit_distance"),
        "similarity_score": res.get("score", 0.0),
        "nearest_rank": res.get("target_rank"),
    }


def build_anonymized_view(preprocessed: dict, metadata: dict | None = None,
                          salt: str = SALT_DEFAULT,
                          top_crates: list[str] | None = None) -> dict:
    """Builds a strictly anonymized, model-visible view of a crate.

    Args:
        preprocessed: Raw preprocessed crate dict (name, version, cargo_toml, build_rs, source_files).
        metadata: Optional live/cached crates.io metadata for offline feature derivation.
        salt: Hash salt for ID generation.
        top_crates: Optional list of top crates for typosquatting calculation.

    Returns:
        Dictionary representing the anonymized view.
    """
    real_name = preprocessed.get("name", "")
    real_version = preprocessed.get("version", "")
    view_id = compute_view_id(real_name, salt=salt)

    # Gather extra author/repo strings from Cargo.toml or metadata to scrub
    extra_scrub_terms: list[str] = []
    if metadata and isinstance(metadata, dict):
        crate_meta = metadata.get("crate", {})
        if crate_meta.get("repository"):
            repo_parts = crate_meta["repository"].split("/")
            extra_scrub_terms.extend([p for p in repo_parts if len(p) > 2])

    # 1. Scrub Cargo.toml
    orig_cargo = preprocessed.get("cargo_toml") or ""
    cargo_toml = scrub_cargo_toml(orig_cargo, view_id, real_name=real_name)

    # 2. Scrub build.rs
    orig_build = preprocessed.get("build_rs")
    build_rs = scrub_source_code(orig_build, real_name, view_id, extra_scrub_terms) if orig_build else None

    # 3. Scrub source files & paths
    source_files: dict[str, str] = {}
    orig_sources = preprocessed.get("source_files") or {}
    for path, code in orig_sources.items():
        clean_path = _replace_name_variants(path, real_name, view_id)
        if len(real_name) > 2:
            clean_path = re.sub(re.escape(real_name), view_id, clean_path, flags=re.IGNORECASE)
        clean_code = scrub_source_code(code, real_name, view_id, extra_scrub_terms)
        source_files[clean_path] = clean_code

    # 4. Derived version and typosquat features
    version_flags = derive_version_flags(real_version)
    typosquat_features = compute_derived_typosquat_features(real_name, top_crates=top_crates)

    # 5. Compute view text content hash for provenance
    all_view_text = (cargo_toml or "") + (build_rs or "") + "".join(source_files.values())
    view_hash = hashlib.sha256(all_view_text.encode("utf-8")).hexdigest()

    return {
        "view_id": view_id,
        "original_name": real_name,       # KEEP INTERNAL; NOT SEEN BY LLM
        "original_version": real_version, # KEEP INTERNAL; NOT SEEN BY LLM
        "name": view_id,                  # Model-visible name
        "version": "1.0.0",               # Standardized neutral semver
        "version_flags": version_flags,
        "cargo_toml": cargo_toml,
        "build_rs": build_rs,
        "build_script_path": preprocessed.get("build_script_path"),
        "source_files": source_files,
        "derived_features": {
            "typosquat": typosquat_features,
            "version_flags": version_flags,
        },
        "view_hash": view_hash,
    }


def build_negative_control_views(view: dict) -> dict[str, dict]:
    """Builds negative control views (name-only and metadata-only) per Section 7."""
    name_only = {
        "name": view["view_id"],
        "version": "1.0.0",
        "version_flags": view["version_flags"],
        "cargo_toml": f'[package]\nname = "{view["view_id"]}"\nversion = "1.0.0"\n',
        "build_rs": None,
        "build_script_path": None,
        "source_files": {},
        "derived_features": view["derived_features"],
    }

    metadata_only = {
        "name": view["view_id"],
        "version": "1.0.0",
        "version_flags": view["version_flags"],
        "cargo_toml": view["cargo_toml"],
        "build_rs": None,
        "build_script_path": None,
        "source_files": {},
        "derived_features": view["derived_features"],
    }

    return {
        "name_only": name_only,
        "metadata_only": metadata_only,
    }
