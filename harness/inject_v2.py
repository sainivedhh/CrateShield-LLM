"""Tell-Free Injection Engine implementing Phase 2 of CrateShield Specification v2.

Key improvements over v1:
1. Removal of all fixed tells:
   - Dynamic semantic function names drawn per seed; NO 'routine_NNNN'.
   - Dynamic comments or NO comments (50%); NO 'Platform integration hook' or 'Module internal helper'.
   - Varied call sites: not always the first statement of main().
2. Line-ending preservation:
   - Detects native LF vs CRLF per file and writes with newline="" preserving base endings.
3. Domain variant support:
   - Supports both .invalid and fabricated plausible hostnames for defanging confound testing.
4. Zero-error tree-sitter AST validation on all modified files.
"""
from __future__ import annotations

import os
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

FN_VERBS = [
    "acquire", "align", "audit", "bind", "bootstrap", "bridge", "build", "calculate",
    "calibrate", "check", "clean", "collect", "compose", "configure", "connect", "consolidate",
    "construct", "convert", "decode", "deduce", "defer", "derive", "detect", "determine",
    "digest", "dispatch", "emit", "encode", "ensure", "establish", "evaluate", "examine",
    "execute", "expand", "extract", "fetch", "filter", "finalize", "format", "forward",
    "gather", "generate", "handle", "harvest", "index", "init", "initialize", "inspect",
    "install", "integrate", "intercept", "isolate", "launch", "link", "load", "locate",
    "marshal", "measure", "merge", "modify", "monitor", "normalize", "obtain", "optimize",
    "package", "parse", "perform", "persist", "ping", "pipeline", "populate", "prepare",
    "probe", "process", "profile", "project", "query", "queue", "record", "recover",
    "refresh", "register", "reindex", "relay", "render", "reorder", "report", "resolve",
    "retrieve", "route", "sample", "scan", "schedule", "secure", "select", "serialize",
    "setup", "simulate", "spawn", "stage", "stream", "sweep", "sync", "trace",
    "track", "transform", "transmit", "trigger", "tune", "unify", "unpack", "update",
    "upgrade", "validate", "verify",
]

FN_NOUNS = [
    "abi", "adapter", "agent", "allocator", "analytics", "anchor", "archive", "asset",
    "backend", "barrier", "beacon", "block", "branch", "broker", "buffer", "builder",
    "bundle", "cache", "channel", "chunk", "client", "collector", "component", "config",
    "connection", "constraint", "container", "context", "controller", "core", "daemon", "database",
    "dataset", "decoder", "dependency", "descriptor", "device", "dialect", "diff", "digest",
    "directory", "dispatcher", "driver", "element", "emitter", "endpoint", "engine", "entity",
    "entry", "environment", "event", "executor", "exporter", "extension", "fabric", "factory",
    "feature", "feed", "fiber", "file", "filter", "flag", "flow", "folder",
    "format", "frame", "frontend", "gateway", "generator", "graph", "group", "handler",
    "header", "helper", "hook", "host", "hub", "identifier", "importer", "index",
    "indicator", "info", "ingress", "instance", "instrument", "interface", "interval", "inventory",
    "item", "iterator", "kernel", "layout", "listener", "loader", "logger", "manifest",
    "matrix", "mechanism", "mediator", "memory", "metadata", "metrics", "module", "monitor",
    "network", "node", "object", "observer", "operation", "operator", "option", "package",
    "packet", "param", "parser", "partition", "payload", "pipeline", "platform", "plugin",
    "policy", "pool", "portal", "predicate", "probe", "processor", "profile", "protocol",
    "provider", "proxy", "queue", "record", "registry", "relay", "remote", "repository",
    "resource", "response", "result", "route", "router", "runner", "runtime",
    "sampler", "schema", "scope", "script", "segment", "sensor", "sequence", "server",
    "service", "session", "signal", "sink", "snapshot", "socket", "source", "spec",
    "state", "storage", "stream", "structure", "subsystem", "surface", "symbol", "syntax",
    "system", "table", "target", "task", "telemetry", "terminal", "token", "tracker",
    "trait", "transaction", "tree", "trigger", "tunnel", "validator", "variable", "vector",
    "verifier", "version", "view", "watcher", "window", "worker", "workspace", "wrapper",
]

# Diverse variable names
VAR_STEMS = [
    "cfg_buf", "env_spec", "handle_id", "data_sink", "target_desc",
    "sys_info", "node_val", "token_ref", "runtime_map", "ctx_payload",
    "opt_flag", "worker_val", "stream_ref", "desc_entry", "item_slot",
]

# No artificial comments (malware does not comment its payloads; eliminates all comment tells)
COMMENT_POOL = [""]


def load_templates_v2(payloads_dir: Path) -> list[dict[str, Any]]:
    """Loads all v2 YAML templates."""
    templates = []
    for yml in sorted(payloads_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(yml.read_text(encoding="utf-8"))
            if data and "id" in data and "variants" in data:
                templates.append(data)
        except Exception:
            pass
    return templates


def detect_line_ending(content_bytes: bytes) -> str:
    """Detects whether bytes use CRLF or LF line endings."""
    if b"\r\n" in content_bytes:
        return "\r\n"
    return "\n"


def parse_and_verify(content_bytes: bytes) -> bool:
    """Verifies that bytes parse with zero tree-sitter error nodes."""
    tree = _PARSER.parse(content_bytes)
    return not tree.root_node.has_error


def render_payload_code(
    template_variant: dict[str, Any],
    domain_type: str,
    seed: int,
) -> tuple[str, str, str]:
    """Renders payload code with randomized identifiers, comments, and target host.

    Returns:
        (rendered_code, entrypoint_fn_name, target_host)
    """
    rng = random.Random(seed)
    fn_name = f"{rng.choice(FN_VERBS)}_{rng.choice(FN_NOUNS)}"
    var_name = f"{rng.choice(VAR_STEMS)}_{rng.randint(1, 9)}"

    # Select domain
    if domain_type == "fabricated":
        target_host = template_variant.get("domain_fabricated", "pkg-telemetry-sink.net")
    else:
        target_host = template_variant.get("domain_invalid", "telemetry.internal.invalid")

    raw_template = template_variant["code_template"]
    rendered = raw_template.replace("{fn_name}", fn_name)
    rendered = rendered.replace("{var_name}", var_name)
    rendered = rendered.replace("{target_host}", target_host)

    # Add comment if chosen
    comment = rng.choice(COMMENT_POOL)
    if comment:
        rendered = comment + rendered

    return rendered, fn_name, target_host


def inject_into_build_rs_v2(
    build_bytes: bytes,
    payload_code: str,
    entrypoint: str,
    call_position: str = "end",
) -> bytes:
    """Injects payload code into build.rs preserving line endings and varying call site."""
    le = detect_line_ending(build_bytes)
    content_str = build_bytes.decode("utf-8", errors="replace")

    tree = _PARSER.parse(build_bytes)
    root = tree.root_node

    main_fn = None
    for child in root.children:
        if child.type == "function_item":
            name_node = child.child_by_field_name("name")
            if name_node:
                name_bytes = build_bytes[name_node.start_byte:name_node.end_byte]
                if name_bytes == b"main":
                    main_fn = child
                    break

    call_stmt = f"    let _ = {entrypoint}();{le}"

    if main_fn:
        body = main_fn.child_by_field_name("body")
        if body and len(body.children) >= 2:
            if call_position == "start":
                # Right after opening brace
                insert_pos = body.children[0].end_byte
                new_bytes = build_bytes[:insert_pos] + le.encode() + call_stmt.encode() + build_bytes[insert_pos:]
            else:
                # Right before closing brace
                insert_pos = body.children[-1].start_byte
                new_bytes = build_bytes[:insert_pos] + call_stmt.encode() + build_bytes[insert_pos:]
        else:
            new_bytes = build_bytes + le.encode() + call_stmt.encode()
    else:
        # No main found; define a main that calls entrypoint
        new_bytes = build_bytes + f"{le}fn main() {{{le}{call_stmt}}}{le}".encode()

    # Append payload definition at end
    norm_payload = payload_code.replace("\r\n", "\n").replace("\n", le)
    final_bytes = new_bytes + f"{le}{le}".encode() + norm_payload.encode() + le.encode()
    return final_bytes


def inject_into_lib_module_v2(
    file_bytes: bytes,
    payload_code: str,
    entrypoint: str,
    placement: str = "P2",
) -> bytes:
    """Injects payload code into a library module."""
    le = detect_line_ending(file_bytes)
    norm_payload = payload_code.replace("\r\n", "\n").replace("\n", le)

    # In library, export function or call from an internal initialization hook
    call_hook = f"{le}#[doc(hidden)]{le}pub fn _runtime_init_hook() {{{le}    let _ = {entrypoint}();{le}}}{le}"
    final_bytes = file_bytes + f"{le}{le}".encode() + norm_payload.encode() + call_hook.encode() + le.encode()
    return final_bytes


def inject_payload_v2(
    base_dir: Path,
    dest_dir: Path,
    template: dict[str, Any],
    variant_idx: int,
    placement: str = "P1",
    domain_type: str = "fabricated",
    seed: int = 42,
) -> dict[str, Any]:
    """Applies tell-free payload injection to base crate."""
    rng = random.Random(seed)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.copytree(base_dir, dest_dir)

    variants = template["variants"]
    variant = variants[variant_idx % len(variants)]

    rendered_code, entrypoint, host = render_payload_code(
        variant, domain_type=domain_type, seed=seed
    )

    build_rs_path = dest_dir / "build.rs"
    injected_file = None

    if placement in ("P1", "P5") or not (dest_dir / "src" / "lib.rs").exists():
        # Inject into build.rs
        if not build_rs_path.exists():
            build_rs_path.write_bytes(b"fn main() {}\n")

        orig_bytes = build_rs_path.read_bytes()
        call_pos = rng.choice(["start", "end"])
        new_bytes = inject_into_build_rs_v2(orig_bytes, rendered_code, entrypoint, call_position=call_pos)
        
        # Verify tree-sitter parse
        if not parse_and_verify(new_bytes):
            # Fallback to simple safe append
            le = detect_line_ending(orig_bytes)
            norm_code = rendered_code.replace("\r\n", "\n").replace("\n", le)
            new_bytes = orig_bytes + f"{le}{le}".encode() + norm_code.encode() + le.encode()

        build_rs_path.write_bytes(new_bytes)
        injected_file = "build.rs"

    else:
        # Library module injection (P2, P3, P4)
        lib_rs = dest_dir / "src" / "lib.rs"
        target_file = lib_rs
        
        # If P3, check for secondary modules
        if placement == "P3":
            sub_modules = [p for p in (dest_dir / "src").glob("*.rs") if p.name != "lib.rs"]
            if sub_modules:
                target_file = rng.choice(sub_modules)

        orig_bytes = target_file.read_bytes()
        new_bytes = inject_into_lib_module_v2(orig_bytes, rendered_code, entrypoint, placement=placement)
        if not parse_and_verify(new_bytes):
            le = detect_line_ending(orig_bytes)
            norm_code = rendered_code.replace("\r\n", "\n").replace("\n", le)
            new_bytes = orig_bytes + f"{le}{le}".encode() + norm_code.encode() + le.encode()

        target_file.write_bytes(new_bytes)
        injected_file = str(target_file.relative_to(dest_dir))

    return {
        "template_id": template["id"],
        "category": template["category"],
        "surface_variant": variant["surface_variant"],
        "obfuscation_level": variant["obfuscation_level"],
        "domain_type": domain_type,
        "target_host": host,
        "placement": placement,
        "injected_file": injected_file,
        "payload_bytes": len(rendered_code.encode("utf-8")),
        "seed": seed,
    }
