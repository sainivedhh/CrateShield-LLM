import json
import subprocess

commits = subprocess.check_output(
    ['git', 'log', '--format=%H', '--', 'data/bench_v3/eval_cache.json'],
    encoding='utf-8'
).splitlines()

print(f"Total commits touching eval_cache.json: {len(commits)}")
for c in commits:
    try:
        data = subprocess.check_output(
            ['git', 'show', f'{c}:data/bench_v3/eval_cache.json'],
            encoding='utf-8'
        )
        d = json.loads(data)
        q_entries = [v for v in d.values() if 'qwen' in str(v.get('model'))]
        q_conds = {}
        for q in q_entries:
            cond = q.get('condition')
            dr = q.get('dry_run')
            fr = q.get('finish_reason')
            is_live = (not dr) and (fr != 'dry_run')
            q_conds.setdefault(cond, []).append(is_live)
        summary = {k: f"{len(v)} total, {sum(v)} live" for k, v in q_conds.items()}
        msg = subprocess.check_output(['git', 'log', '-1', '--format=%s', c], encoding='utf-8').strip()
        print(f"{c[:7]} | {msg[:50]:<50} | {summary}")
    except Exception as e:
        print(f"{c[:7]} | error: {e}")
