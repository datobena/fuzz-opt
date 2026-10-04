#!/usr/bin/env python3
"""Final analysis for the per-trial-optimizer campaign (online-24h-c1).

Answers, in order:
  1. Did the optimizer speed the target up?   (replay-gate folds, per optimizer)
  2. Did that convert into fuzzing work?      (execs, matched run_time)
  3. Did THAT convert into coverage or bugs?  (edges, crashes)

The distinction between 2 and 3 is the point. b1..b6 could report only a single
optimizer draw; this reports ten, so every number below carries a real spread.
"""
import json, os, sys, statistics as st

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from lib import stats_util

EXP = "online-24h-c2-libxml2"
KEY = 'libxml2-arvo-1972'
R = f'/home/sefcom/fuzz-opt/results/{EXP}/{KEY}'
TRIALS = f'{R}/optimized/online/trials'


def fuzzer_stats(arm, t):
    f = f'{R}/{arm}/trial_{t:02d}/afl_out/default/fuzzer_stats'
    if not os.path.exists(f):
        return None
    d = {}
    for line in open(f):
        if ':' in line:
            k, _, v = line.partition(':')
            d[k.strip()] = v.strip()
    return d


def col(arm, key):
    out = []
    for t in range(10):
        d = fuzzer_stats(arm, t)
        if d and key in d:
            out.append(float(d[key]))
    return out


def compare(label, key, higher_better=True):
    b, o = col('baseline', key), col('optimized', key)
    if not b or not o:
        return
    mb, mo = st.median(b), st.median(o)
    ratio = (mo / mb) if mb else float('nan')
    try:
        # stats_util is written for time-to-bug (lower=better); these metrics are
        # higher=better, so ask for "greater" and swap the A12 args.
        p = stats_util.mann_whitney_u(o, b, alternative='greater')[1]
        a12 = stats_util.vargha_delaney_a12(b, o)
    except Exception:
        p, a12 = float('nan'), float('nan')
    print(f"  {label:<12} base {mb:>14,.0f} | opt {mo:>14,.0f} | "
          f"{ratio:6.3f}x | p={p:<10.3g} A12={a12:.2f}")


print("=" * 86)
print(f"FINAL ANALYSIS — {EXP}")
prov = json.load(open(f'{R}/optimized/online/campaign_provenance.json'))
print(f"  -O level {prov['build_opt_level']} | design {json.dumps(prov['design'])}")
print(f"  model {prov['optimizer'].get('model')} (pinned={prov['optimizer'].get('model_pinned')})")
print("=" * 86)

# ---- 1. optimizer rounds -------------------------------------------------
print("\n[1] OPTIMIZER ROUNDS (replay gate, threshold 1.02x)")
per_round, cum = {}, {}
for t in range(10):
    c, n = 1.0, 0
    for it in range(1, 12):
        f = f'{TRIALS}/trial_{t:02d}/iter_{it:02d}/round_provenance.json'
        if not os.path.exists(f):
            continue
        d = json.load(open(f))
        per_round.setdefault(it, []).append(d)
        if d['outcome'] == 'kept' and d['speedup']:
            c *= d['speedup']
            n += 1
    cum[t] = (c, n)

for it in sorted(per_round):
    rows = per_round[it]
    kept = [r for r in rows if r['outcome'] == 'kept']
    sp = [r['speedup'] for r in kept if r['speedup']]
    oc = {}
    for r in rows:
        oc[r['outcome']] = oc.get(r['outcome'], 0) + 1
    med = f"{st.median(sp):.4f}x" if sp else "n/a"
    print(f"  round {it}: {len(rows):2d} reported | kept {len(kept):2d} | median {med:>9} | {oc}")

print("\n  cumulative speedup per optimizer (product of kept folds):")
for t, (c, n) in sorted(cum.items(), key=lambda kv: kv[1][0]):
    print(f"    trial_{t:02d}  {c:.4f}x  ({n} folds)")
v = [c for c, _ in cum.values()]
print(f"\n    median {st.median(v):.4f}x  mean {st.mean(v):.4f}x  "
      f"min {min(v):.4f}x  max {max(v):.4f}x  stdev {st.stdev(v):.4f}")

# bug survival across every kept fold
survived = sum(1 for rows in per_round.values() for r in rows
               if r['outcome'] == 'kept' and r['poc_reproduces'] == 'yes')
kept_total = sum(1 for rows in per_round.values() for r in rows if r['outcome'] == 'kept')
print(f"\n  bug survival: {survived}/{kept_total} kept folds still reproduce the PoC")

# ---- 2 & 3. what it bought ----------------------------------------------
print("\n[2/3] LIVE FUZZING OUTCOME (10 v 10, matched run_time)")
for lab, key in (('run_time', 'run_time'), ('EXECS', 'execs_done'),
                 ('EDGES', 'edges_found'), ('corpus', 'corpus_count'),
                 ('CRASHES', 'saved_crashes')):
    compare(lab, key)

rt_b, rt_o = col('baseline', 'run_time'), col('optimized', 'run_time')
if rt_b and rt_o:
    print(f"\n  run_time handicap: optimized fuzzed {st.median(rt_b)-st.median(rt_o):.0f}s "
          f"LESS than baseline (hot-swap downtime), so throughput gains are net of that.")

ex_b, ex_o = col('baseline', 'execs_done'), col('optimized', 'execs_done')
ed_b, ed_o = col('baseline', 'edges_found'), col('optimized', 'edges_found')
if ex_b and ed_b:
    print(f"\n  CONVERSION: {st.median(ex_o)/st.median(ex_b):.2f}x executions "
          f"-> {st.median(ed_o)/st.median(ed_b):.3f}x edges")
