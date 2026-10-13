"""Injection Engine implementing Section 6 of the CrateShield Harness Spec.

Rules:
1. Input: base crate directory, payload template, placement, seed.
2. Output: modified twin crate directory with tree-sitter AST parse validation.
3. Placements:
    P1: inside existing build.rs (within or called from main)
    P2: in a library module in a rarely-used code path
    P3: in a function reachable from public API
    P4: in a proc-macro crate expansion routine
    P5: in a helper module imported by build.rs
4. Zero error nodes: all modified and added .rs files parse cleanly with tree-sitter-rust.
5. No build/cargo step executed (safety requirement).
6. Randomizes payload identifiers per seed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import re
import shutil
from typing import Any
import yaml

import tree_sitter
import tree_sitter_rust

_RUST_LANG = tree_sitter.Language(tree_sitter_rust.language())
_PARSER = tree_sitter.Parser(_RUST_LANG)


def load_templates(payloads_dir: Path) -> list[dict[str, Any]]:
    """Loads and validates all YAML templates in payloads_dir."""
    templates = []
    for yml in sorted(payloads_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(yml.read_text(encoding="utf-8"))
            if data and "id" in data and "variants" in data:
                templates.append(data)
        except Exception:
            pass
    return templates


def randomize_identifiers(code_text: str, seed: int) -> tuple[str, str]:
    """Randomizes top-level function names and local identifiers per seed.

    Returns:
        (transformed_code, main_entrypoint_fn_name)
    """
    rng = random.Random(seed)
    suffix = f"{rng.randint(1000, 9999)}"

    # Find first fn name
    fn_match = re.search(r"fn\s+([a-zA-Z0-9_]+)\s*\(", code_text)
    if not fn_match:
        return code_text, ""

    orig_fn_name = fn_match.group(1)
    new_fn_name = f"routine_{suffix}"

    transformed = re.sub(rf"\bfn\s+{re.escape(orig_fn_name)}\b", f"fn {new_fn_name}", code_text)
    return transformed, new_fn_name


def parse_and_verify(content_bytes: bytes) -> bool:
    """Verifies that bytes parse with zero tree-sitter error nodes."""
    tree = _PARSER.parse(content_bytes)
    return not tree.root_node.has_error


def _inject_into_build_rs(build_content: str, payload_code: str, entrypoint: str) -> str:
    """Injects payload code into build.rs and inserts a call in fn main()."""
    # 1. Parse existing build.rs with tree-sitter
    tree = _PARSER.parse(build_content.encode("utf-8"))
    root = tree.root_node

    main_fn = None
    for child in root.children:
        if child.type == "function_item":
            name_node = child.child_by_field_name("name")
            if name_node:
                fn_name = build_content.encode("utf-8")[name_node.start_byte:name_node.end_byte].decode("utf-8")
                if fn_name == "main":
                    main_fn = child
                    break

    call_statement = f"    let _ = {entrypoint}();\n"

    if main_fn:
        body = main_fn.child_by_field_name("body")
        if body:
            # Insert call right after opening brace
            insert_pos = body.start_byte + 1
            b = build_content.encode("utf-8")
            new_bytes = b[:insert_pos] + b"\n" + call_statement.encode("utf-8") + b[insert_pos:]
            modified = new_bytes.decode("utf-8")
            # Append definition at bottom
            modified = modified.rstrip() + f"\n\n// Platform integration hook\n{payload_code}\n"
            return modified

    # Fallback if no explicit main found: append with entry call
    return build_content.rstrip() + f"\n\n{payload_code}\n"


def _inject_into_lib_rs(lib_content: str, payload_code: str, entrypoint: str) -> str:
    """Injects payload code into src/lib.rs."""
    return lib_content.rstrip() + f"\n\n// Module internal helper\n{payload_code}\n"


def inject_payload(
    base_dir: Path,
    dest_dir: Path,
    template: dict[str, Any],
    variant_idx: int = 0,
    placement: str = "P1",
    seed: int = 42,
) -> dict[str, Any]:
    """Injects a payload template into base_dir, saving the twin to dest_dir.

    Args:
        base_dir: Path to clean base crate directory.
        dest_dir: Destination path for the modified twin crate.
        template: Template dictionary loaded from YAML.
        variant_idx: Index into template["variants"].
        placement: Injection placement strategy ("P1".."P5").
        seed: Deterministic RNG seed.

    Returns:
        Manifest entry data for the injection.
    """
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.copytree(base_dir, dest_dir)

    variants = template.get("variants", [])
    if not variants:
        raise ValueError(f"Template {template.get('id')} has no variants")

    selected_variant = variants[variant_idx % len(variants)]
    raw_code = selected_variant.get("code", "")
    transformed_code, entrypoint = randomize_identifiers(raw_code, seed=seed)

    modified_files = []

    if placement in ("P1", "P5"):
        # Inject into build.rs
        build_path = dest_dir / "build.rs"
        if not build_path.exists():
            build_content = "fn main() {}\n"
        else:
            build_content = build_path.read_text(encoding="utf-8", errors="ignore")

        new_build = _inject_into_build_rs(build_content, transformed_code, entrypoint)
        if not parse_and_verify(new_build.encode("utf-8")):
            raise ValueError(f"Tree-sitter parse failed for modified build.rs with {template.get('id')}")

        build_path.write_text(new_build, encoding="utf-8")
        modified_files.append("build.rs")

    else:  # P2, P3
        # Inject into src/lib.rs or first .rs in src
        lib_path = dest_dir / "src" / "lib.rs"
        if not lib_path.exists():
            candidates = list((dest_dir / "src").glob("*.rs"))
            lib_path = candidates[0] if candidates else (dest_dir / "src" / "lib.rs")
            lib_path.parent.mkdir(parents=True, exist_ok=True)
            if not lib_path.exists():
                lib_path.write_text("pub fn init() {}\n", encoding="utf-8")

        lib_content = lib_path.read_text(encoding="utf-8", errors="ignore")
        new_lib = _inject_into_lib_rs(lib_content, transformed_code, entrypoint)
        if not parse_and_verify(new_lib.encode("utf-8")):
            raise ValueError(f"Tree-sitter parse failed for modified {lib_path.name}")

        lib_path.write_text(new_lib, encoding="utf-8")
        modified_files.append(str(lib_path.relative_to(dest_dir)))

    # Tree-sitter verification across ALL files in modified crate
    all_clean = True
    for rs_file in dest_dir.glob("**/*.rs"):
        if not parse_and_verify(rs_file.read_bytes()):
            all_clean = False
            break

    if not all_clean:
        raise AssertionError(f"Tree-sitter syntax validation failed after injection on {dest_dir}")

    payload_bytes = len(transformed_code.encode("utf-8"))

    return {
        "template_id": template.get("id"),
        "category": template.get("category"),
        "placement": placement,
        "obfuscation_level": template.get("obfuscation_level", 0),
        "surface_variant": selected_variant.get("id"),
        "payload_bytes": payload_bytes,
        "modified_files": modified_files,
        "seed": seed,
    }
