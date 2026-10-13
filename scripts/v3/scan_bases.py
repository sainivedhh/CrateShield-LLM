import sys, os, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from harness.sampler import is_crate_eligible, classify_build_rs_behavior, load_malicious_denylist

with open("data/bench_v1/manifest.json") as f:
    v1_bases = {s.get("base_crate") for s in json.load(f)["samples"] if s.get("base_crate")}
with open("data/bench_v2/manifest.json") as f:
    v2_bases = {s.get("base_crate") for s in json.load(f)["samples"] if s.get("base_crate")}
used = v1_bases | v2_bases
denylist = load_malicious_denylist()

cand_dir = Path("data/bench_v1/base_candidates")
valid_bases = []

for d in sorted(cand_dir.iterdir()):
    if not d.is_dir(): continue
    crate_name = d.name.rsplit("-", 1)[0]
    ver = d.name.rsplit("-", 1)[1] if "-" in d.name else "1.0.0"
    if crate_name in used or crate_name in denylist: continue
    
    build_rs = d / "build.rs"
    if not build_rs.exists():
        sub = [p for p in d.iterdir() if p.is_dir() and (p / "build.rs").exists()]
        if sub: build_rs = sub[0] / "build.rs"
        else: continue
    root = build_rs.parent
    
    rs_files = list(root.glob("**/*.rs"))
    ok, reason = is_crate_eligible({"name": crate_name}, root, denylist, min_age_days=0)
    if ok:
        b_class = classify_build_rs_behavior(build_rs.read_text(encoding="utf-8", errors="ignore"))
        sz = sum(f.stat().st_size for f in rs_files)
        valid_bases.append({
            "name": crate_name,
            "version": ver,
            "root": str(root),
            "build_class": b_class,
            "size_bytes": sz,
            "rs_count": len(rs_files)
        })

print(f"Total valid fresh base crates: {len(valid_bases)}")
for b in valid_bases:
    print(f"{b['name']} ({b['version']}): {b['size_bytes']} bytes, {b['rs_count']} rs files, {b['build_class']}")

with open("data/bench_v3/candidate_bases.json", "w", encoding="utf-8") as f:
    json.dump(valid_bases, f, indent=2)
print("Saved data/bench_v3/candidate_bases.json")