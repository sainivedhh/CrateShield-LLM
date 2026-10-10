import json
from pathlib import Path

with open("data/bench_v3/candidate_bases.json") as f:
    cand_17 = json.load(f)

with open("data/bench_v3/extracted_raw_bases.json") as f:
    raw_30 = json.load(f)

all_bases = {}
for b in cand_17:
    all_bases[b["name"]] = b

for b in raw_30:
    if b["name"] not in all_bases:
        all_bases[b["name"]] = b

# Let's add bindgen, rust_decimal, semver from extracted if needed to hit 50
extracted_dir = Path("data/extracted")
extras = ["bindgen-0.69.4", "rust_decimal-1.36.0", "semver-1.0.23"]
for ex in extras:
    p = extracted_dir / ex
    if p.exists():
        crate_name = ex.rsplit("-", 1)[0]
        if crate_name not in all_bases:
            all_bases[crate_name] = {
                "name": crate_name,
                "version": ex.rsplit("-", 1)[1],
                "root": str(p),
                "build_class": "env_probing",
                "size_bytes": sum(f.stat().st_size for f in p.glob("**/*.rs")),
                "rs_count": len(list(p.glob("**/*.rs")))
            }

base_list = list(all_bases.values())
print(f"Total available distinct base crates: {len(base_list)}")

# Sort by size
base_list.sort(key=lambda x: x["size_bytes"])
print(f"Smallest: {base_list[0]['name']} ({base_list[0]['size_bytes']} bytes)")
print(f"Median: {base_list[len(base_list)//2]['name']} ({base_list[len(base_list)//2]['size_bytes']} bytes)")
print(f"Largest: {base_list[-1]['name']} ({base_list[-1]['size_bytes']} bytes)")

# Save exactly 50 bases
selected_50 = base_list[:50]
with open("data/bench_v3/selected_50_bases.json", "w", encoding="utf-8") as f:
    json.dump(selected_50, f, indent=2)
print("Saved 50 selected bases to data/bench_v3/selected_50_bases.json")