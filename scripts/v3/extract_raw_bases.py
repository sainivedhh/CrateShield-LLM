import sys, os, tarfile, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from harness.sampler import check_tree_sitter_syntax, classify_build_rs_behavior

raw_dir = Path("data/raw")
dest_dir = Path("data/bench_v3/base_candidates")
dest_dir.mkdir(parents=True, exist_ok=True)

crates_to_extract = [
    "anyhow-1.0.89.crate", "base64-0.22.1.crate", "bitflags-2.6.0.crate",
    "bytes-1.7.1.crate", "chrono-0.4.38.crate", "clap-4.5.18.crate",
    "futures-0.3.30.crate", "hashbrown-0.14.5.crate", "hex-0.4.3.crate",
    "hyper-1.4.1.crate", "indexmap-2.5.0.crate", "itertools-0.13.0.crate",
    "libloading-0.8.5.crate", "log-0.4.22.crate", "memmap2-0.9.5.crate",
    "mio-1.0.2.crate", "once_cell-1.19.0.crate", "pkg-config-0.3.30.crate",
    "quote-1.0.37.crate", "rand-0.8.5.crate", "regex-1.10.6.crate",
    "smallvec-1.13.2.crate", "tempfile-3.12.0.crate", "thiserror-1.0.64.crate",
    "tracing-0.1.40.crate", "url-2.5.2.crate", "uuid-1.10.0.crate",
    "walkdir-2.5.0.crate", "crossbeam-channel-0.5.13.crate", "crossbeam-epoch-0.9.18.crate",
    "sha2-0.10.8.crate", "syn-2.0.77.crate", "cc-1.1.21.crate"
]

extracted_valid = []
for fname in crates_to_extract:
    tar_path = raw_dir / fname
    if not tar_path.exists():
        continue
    stem = fname.replace(".crate", "")
    target = dest_dir / stem
    if not target.exists():
        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=dest_dir)
        except Exception as e:
            print(f"Failed to extract {fname}: {e}")
            continue
            
    # Check tree-sitter
    clean, n_files, n_bytes = check_tree_sitter_syntax(target)
    if clean:
        b_rs = target / "build.rs"
        b_class = "none"
        if b_rs.exists():
            b_class = classify_build_rs_behavior(b_rs.read_text(encoding="utf-8", errors="ignore"))
        crate_name = stem.rsplit("-", 1)[0]
        ver = stem.rsplit("-", 1)[1] if "-" in stem else "1.0.0"
        extracted_valid.append({
            "name": crate_name,
            "version": ver,
            "root": str(target),
            "build_class": b_class,
            "size_bytes": n_bytes,
            "rs_count": n_files,
        })
    else:
        print(f"Syntax error in {stem}")

print(f"Extracted and validated {len(extracted_valid)} crates from data/raw")
with open("data/bench_v3/extracted_raw_bases.json", "w", encoding="utf-8") as f:
    json.dump(extracted_valid, f, indent=2)