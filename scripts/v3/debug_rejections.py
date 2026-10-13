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

for d in sorted(cand_dir.iterdir()):
    if not d.is_dir(): continue
    crate_name = d.name.rsplit("-", 1)[0]
    if crate_name in used or crate_name in denylist: continue
    
    build_rs = d / "build.rs"
    if not build_rs.exists():
        sub = [p for p in d.iterdir() if p.is_dir() and (p / "build.rs").exists()]
        if sub: build_rs = sub[0] / "build.rs"
        else: continue
    root = build_rs.parent
    
    ok, reason = is_crate_eligible({"name": crate_name}, root, denylist, min_age_days=0)
    if not ok:
        print(f"Rejected {crate_name}: {reason}")