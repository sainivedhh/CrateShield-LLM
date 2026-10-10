"""Reviewer corpus packaging script for Benchmark v3 (Hard Rule 8).

Packs data/bench_v3/corpus_private into a verified reviewer archive
after verifying all sample SHA256 hashes against manifest.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]
BENCH_V3 = ROOT / "data" / "bench_v3"
CORPUS_DIR = BENCH_V3 / "corpus_private"
MANIFEST_PATH = BENCH_V3 / "manifest.json"


def sha256_tree(dir_path: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(dir_path.glob("**/*")):
        if p.is_file():
            h.update(p.relative_to(dir_path).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def pack_corpus(output_path: Path | None = None) -> Path:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found at {MANIFEST_PATH}")
    if not CORPUS_DIR.exists():
        raise FileNotFoundError(f"Private corpus directory not found at {CORPUS_DIR}")

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    samples = manifest.get("samples", [])
    print(f"Verifying {len(samples)} samples against manifest SHA256 hashes...")

    mismatches = []
    for s in samples:
        s_id = s["sample_id"]
        s_dir = CORPUS_DIR / s_id
        if not s_dir.exists():
            mismatches.append(f"Missing sample directory: {s_id}")
            continue
        actual_hash = sha256_tree(s_dir)
        expected_hash = s.get("sha256")
        if actual_hash != expected_hash:
            mismatches.append(f"Hash mismatch on {s_id}: expected {expected_hash}, got {actual_hash}")

    if mismatches:
        raise ValueError("Corpus verification failed:\n" + "\n".join(mismatches[:5]))

    print(f"All {len(samples)} samples verified successfully.")

    if output_path is None:
        output_path = BENCH_V3 / "crateshield_v3_reviewer_corpus.tar.gz"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_path, "w:gz") as tar:
        tar.add(CORPUS_DIR, arcname="corpus_v3")

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"Created reviewer archive: {output_path} ({size_mb:.2f} MB)")
    return output_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pack verified v3 reviewer corpus")
    parser.add_argument("--output", type=Path, default=None, help="Output archive path")
    args = parser.parse_args()
    pack_corpus(args.output)