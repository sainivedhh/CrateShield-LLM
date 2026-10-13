import json
from pathlib import Path

s1 = json.load(open('data/prod_v2/stage1_results.json', encoding='utf-8'))
s2 = json.load(open('data/prod_v2/stage2_results.json', encoding='utf-8'))

crates_to_check = [
    'prod_pop_0138', 'prod_pop_0086', 'prod_pop_0272',
    'prod_rand_0224', 'prod_rand_0401', 'prod_rand_0560',
    'prod_rand_0281', 'prod_rand_0879', 'prod_rand_0948', 'prod_rand_0994'
]

for sid in crates_to_check:
    c1 = s1[sid]
    c2 = s2[sid]
    name = c1["name"]
    ver = c1["version"]
    cohort = c1["sample_type"]
    signals = c1.get("fired_signals", [])
    clf = c2.get("classification", {})
    verdict = clf.get("verdict")
    score = clf.get("malware_score")
    reasoning = clf.get("reasoning", "")
    print(f"[{cohort}] {sid} | {name} v{ver} | {verdict} (score={score}) | signals={signals}")
