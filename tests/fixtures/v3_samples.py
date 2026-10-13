"""Self-contained fixture that builds minimal, Gate-G1-valid benchmark-v3
sample crates in a caller-provided temporary directory so the v3 unit tests
do not depend on the private corpus at data/bench_v3/corpus_private/.

A valid sample crate needs:
  - a Cargo.toml with a [package] section
  - (optionally) .rs source files

The view builder scrubs the original crate name, so any name works here; the
model-visible name becomes crate_<hash>. The corpus is gitignored and never
stored, so nothing secret is created or committed by these tests.
"""
from __future__ import annotations

import json
from pathlib import Path


def _minimal_cargo_toml(name: str, version: str = "1.0.0") -> str:
    return (
        f"[package]\n"
        f'name = "{name}"\n'
        f"version = \"{version}\"\n"
        f"description = \"a dependency of a dependency\"\n"
        f"license = \"MIT OR Apache-2.0\"\n"
        "\n"
        "[dependencies]\n"
    )


def _minimal_lib_rs() -> str:
    return (
        "#[allow(clippy::needless_return)]\n"
        "/// A benign utility function. This is placeholder library code.\n"
        "/// No network access, no file I/O, no unsafe blocks.\n"
        "pub fn add(a: i32, b: i32) -> i32 {\n"
        "    let sum = a + b;\n"
        "    return sum;\n"
        "}\n"
    )


def create_minimal_sample(parent: Path, sample_id: str, cluster_id: str,
                          version: str = "1.0.0", source_chars: int = 0) -> Path:
    """Creates a minimal, parseable sample crate under `parent/sample_id`.

    Args:
        parent: The corpus parent directory (e.g. tmp_path / "corpus_private").
        sample_id: Directory name for the sample (e.g. "s3_0035_malicious").
        cluster_id: The crate name that appears in Cargo.toml; will be scrubbed
            by the view builder before the model sees it.
        version: Cargo.toml version.
        source_chars: Number of filler lines of benign Rust source to add to
            src/lib.rs. Used to trigger context-limit branches.
    """
    sample_dir = parent / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "Cargo.toml").write_text(
        _minimal_cargo_toml(cluster_id, version), encoding="utf-8"
    )
    lib_dir = sample_dir / "src"
    lib_dir.mkdir(exist_ok=True)
    if source_chars > 0:
        # Generate a huge benign file. We loop until the final byte count
        # reaches at least `source_chars`, so the context-limit branch is
        # guaranteed to trigger.
        lines = ["/// Auto-generated benign filler code for benchmark evaluation."]
        base = "pub fn filler_{i:05d}(x: i32) -> i32 {{ let y = x + {i}; y }}"
        while True:
            content = "\n".join(lines)
            if len(content) >= source_chars:
                break
            i = len(lines) - 1
            lines.append(base.format(i=i))
        (lib_dir / "lib.rs").write_text("\n".join(lines), encoding="utf-8")
    else:
        (lib_dir / "lib.rs").write_text(_minimal_lib_rs(), encoding="utf-8")
    return sample_dir


def build_manifest_with_samples(parent: Path, sample_ids: list[str],
                                cluster_ids: list[str]) -> dict:
    """Builds a minimal manifest.json mirroring the structure under
    data/bench_v3/manifest.json so verify-style checks that read the manifest
    can run without the private corpus.

    Returns the manifest dict for convenient reuse.
    """
    samples = []
    for sample_id, cluster_id in zip(sample_ids, cluster_ids):
        create_minimal_sample(parent, sample_id, cluster_id)
        samples.append({
            "sample_id": sample_id,
            "pair_id": "pair_01",
            "cluster_id": cluster_id,
            "split": "eval",
            "twin_type": "malicious",
            "label": "MALICIOUS",
            "family": "F1",
            "seen_or_heldout": "SEEN",
            "ladder_level": "L1",
            "sha256": "0" * 64,  # Not verified by unit tests; corpus is ephemeral
        })
    manifest = {
        "version": "3",
        "samples": samples,
        "tune_clusters": [],
        "eval_clusters": [c["cluster_id"] for c in samples],
    }
    manifest_path = parent / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
