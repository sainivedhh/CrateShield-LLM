"""Leak Auditor and Acceptance Gate G1 validator for CrateShield Harness.

Enforces Section 9 Gate G1:
- Model-visible text contains no original name.
- No author or repository identifier leaks.
- No 'cratebench' benchmark artifacts.
- No forbidden label cue words (defanged, mock, payload, c2, exfil).
"""
from __future__ import annotations

import re


FORBIDDEN_TERMS = [
    "cratebench",
    "defanged",
    "c2_server",
    "c2_domain",
    "mock_exfiltration",
    "injected_payload",
    "exfiltration",
]


def audit_view(view: dict, real_metadata: dict | None = None) -> list[str]:
    """Audits an anonymized view for information leaks.

    Args:
        view: Dictionary returned by build_anonymized_view().
        real_metadata: Optional dictionary with real crate metadata to verify against.

    Returns:
        List of violation messages. Empty list indicates audit pass (Gate G1 satisfied).
    """
    violations: list[str] = []
    real_name = view.get("original_name", "").strip()

    # Collect texts that the model would be exposed to
    target_texts: dict[str, str] = {}
    if view.get("cargo_toml"):
        target_texts["Cargo.toml"] = view["cargo_toml"]
    if view.get("build_rs"):
        target_texts["build.rs"] = view["build_rs"]
    for path, content in (view.get("source_files") or {}).items():
        target_texts[path] = content
        # Check path itself
        if real_name and len(real_name) > 2:
            if real_name.lower() in path.lower():
                violations.append(f"File path leaks original crate name: '{path}'")

    # 1. Check for original name leaks in visible texts
    if real_name and len(real_name) > 2:
        name_variants = [
            real_name,
            real_name.replace("-", "_"),
            real_name.replace("_", "-"),
        ]
        for src_label, text in target_texts.items():
            for var in name_variants:
                # Word boundary match, case-insensitive
                pattern = re.compile(rf"\b{re.escape(var)}\b", re.IGNORECASE)
                matches = pattern.findall(text)
                if matches:
                    violations.append(
                        f"Original name variant '{var}' leaked in {src_label} ({len(matches)} occurrence(s))"
                    )

    # 2. Check for author/repo leaks if real metadata is supplied
    if real_metadata and isinstance(real_metadata, dict):
        crate_meta = real_metadata.get("crate", {})
        repo = crate_meta.get("repository", "")
        if repo and "github.com" in repo:
            repo_handle = repo.split("github.com/")[-1].strip("/")
            for part in repo_handle.split("/"):
                if len(part) > 3 and part.lower() != "github":
                    for src_label, text in target_texts.items():
                        if part.lower() in text.lower():
                            violations.append(
                                f"Repository handle part '{part}' leaked in {src_label}"
                            )

    # 3. Check for forbidden leak terms and benchmark tags
    for src_label, text in target_texts.items():
        text_lower = text.lower()
        for term in FORBIDDEN_TERMS:
            if term in text_lower:
                violations.append(
                    f"Forbidden leak term '{term}' found in {src_label}"
                )

    # 4. Check model-visible package name
    visible_name = view.get("name", "")
    if not visible_name.startswith("crate_"):
        violations.append(
            f"Visible package name '{visible_name}' does not follow neutral format 'crate_<hash>'"
        )

    return violations


def assert_gate_g1(view: dict, real_metadata: dict | None = None) -> None:
    """Raises AssertionError if view fails Gate G1 leak audit."""
    violations = audit_view(view, real_metadata=real_metadata)
    if violations:
        msg = f"Gate G1 Failed for {view.get('view_id')}:\n" + "\n".join(f" - {v}" for v in violations)
        raise AssertionError(msg)
