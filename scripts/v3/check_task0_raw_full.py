import json

def check_task0():
    with open('data/bench_v3/eval_cache.json', 'r', encoding='utf-8') as f:
        cache = json.load(f)

    with open('data/bench_v3/manifest.json', 'r', encoding='utf-8') as f:
        manifest = json.load(f)

    manifest_by_id = {s['sample_id']: s for s in manifest['samples']}

    rf_entries = {}
    for entry in cache.values():
        if (entry.get('condition') == 'raw_full' and 
            entry.get('model') == 'gemini-3.5-flash-lite' and 
            entry.get('split') == 'eval' and 
            entry.get('repeat', 0) == 0):
            rf_entries[entry['sample_id']] = entry

    print(f"Total raw_full eval entries: {len(rf_entries)}")
    exceeds = [e for e in rf_entries.values() if e.get('finish_reason') == 'exceeds_context' or e.get('exceeds_context') is True]
    print(f"Total exceeds_context=True: {len(exceeds)}")

    for e in sorted(exceeds, key=lambda x: x['sample_id']):
        s = manifest_by_id[e['sample_id']]
        classification = e.get('classification', {})
        cls_val = classification.get('classification') or classification.get('verdict')
        is_dry = e.get('dry_run', False)
        lvl = s.get('ladder_level')
        if not str(lvl).startswith('L'):
            lvl = f"L{lvl}"
        print(f"{e['sample_id']}: crate={s.get('crate_name')}, twin_type={s.get('twin_type')}, ladder={lvl}, cls={cls_val}, chars={e.get('total_chars', 'N/A')}, dry_run={is_dry}")

    mal_samples = [s for s in manifest['samples'] if s['split'] == 'eval' and s['twin_type'] == 'malicious']
    print(f"\nTotal malicious eval samples: {len(mal_samples)}")

    # Breakdown (a): All 40 malicious samples
    correct_a = 0
    by_ladder_a = {f"L{i}": [0, 0] for i in range(5)}
    for s in mal_samples:
        lvl = s.get('ladder_level')
        if not str(lvl).startswith('L'):
            lvl = f"L{lvl}"
        by_ladder_a[lvl][1] += 1
        e = rf_entries.get(s['sample_id'])
        if e:
            cls_val = e.get('classification', {}).get('classification') or e.get('classification', {}).get('verdict')
            if cls_val == 'MALICIOUS':
                correct_a += 1
                by_ladder_a[lvl][0] += 1

    print("\n--- Breakdown (a) All 40 malicious (current computed) ---")
    print(f"Overall Recall: {correct_a}/{len(mal_samples)} = {correct_a/len(mal_samples):.1%}")
    for lvl in sorted(by_ladder_a.keys()):
        c, t = by_ladder_a[lvl]
        print(f"{lvl}: {c}/{t} ({c/t:.1%})")
    l2_4_c = sum(by_ladder_a[f'L{i}'][0] for i in (2,3,4))
    l2_4_t = sum(by_ladder_a[f'L{i}'][1] for i in (2,3,4))
    print(f"L2-L4 pooled: {l2_4_c}/{l2_4_t} ({l2_4_c/l2_4_t:.1%})")

    # Breakdown (b): Excluding exceeds_context
    testable_b = [s for s in mal_samples if not (rf_entries.get(s['sample_id'], {}).get('finish_reason') == 'exceeds_context' or rf_entries.get(s['sample_id'], {}).get('exceeds_context') is True)]
    correct_b = 0
    by_ladder_b = {f"L{i}": [0, 0] for i in range(5)}
    for s in testable_b:
        lvl = s.get('ladder_level')
        if not str(lvl).startswith('L'):
            lvl = f"L{lvl}"
        by_ladder_b[lvl][1] += 1
        e = rf_entries.get(s['sample_id'])
        if e:
            cls_val = e.get('classification', {}).get('classification') or e.get('classification', {}).get('verdict')
            if cls_val == 'MALICIOUS':
                correct_b += 1
                by_ladder_b[lvl][0] += 1

    print("\n--- Breakdown (b) Excluding exceeds_context (N=35 testable) ---")
    print(f"Overall Recall: {correct_b}/{len(testable_b)} = {correct_b/len(testable_b):.1%}")
    for lvl in sorted(by_ladder_b.keys()):
        c, t = by_ladder_b[lvl]
        print(f"{lvl}: {c}/{t} ({c/t:.1%})")
    l2_4_c_b = sum(by_ladder_b[f'L{i}'][0] for i in (2,3,4))
    l2_4_t_b = sum(by_ladder_b[f'L{i}'][1] for i in (2,3,4))
    print(f"L2-L4 pooled: {l2_4_c_b}/{l2_4_t_b} ({l2_4_c_b/l2_4_t_b:.1%})")

if __name__ == '__main__':
    check_task0()
