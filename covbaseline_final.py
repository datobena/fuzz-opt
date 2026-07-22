#!/usr/bin/env python3
"""Total coverage of each variant's ACCUMULATED corpus, on the BASELINE binary.

Mounts each trial's corpus dir read-only (no copy — the container runs as root)
and replays it on the baseline binary with -runs=0, so baseline/aggr8h/mut8h are
measured on the SAME instrumentation. Answers "what would these accumulated
inputs give us on the baseline program". Mean cov/ft per variant.
"""
import json, os, re, subprocess, threading, queue, statistics, collections

ROOT = "local_pinned"
RUNNER = "gcr.io/oss-fuzz-base/base-runner"
VAR = ["baseline", "aggr8h", "mut8h"]
TARGETS = {"selinux": ("selinux-CVE-2021-36085", "secilc-fuzzer"),
           "libavc":  ("libavc-arvo-16505", "avc_dec_fuzzer")}
COV = re.compile(r"cov:\s*(\d+)\s+ft:\s*(\d+)")
POOL = queue.Queue()
for c in range(10):
    POOL.put(c)


def replay(target, corpus_dir):
    tgt = TARGETS[target][1]
    binp = os.path.abspath(f"results/aggr-8h/{TARGETS[target][0]}/baseline/bin")
    core = POOL.get()
    try:
        cmd = ["docker", "run", "--rm", "--cpuset-cpus", str(core),
               "-v", f"{binp}:/out:ro", "-v", f"{os.path.abspath(corpus_dir)}:/corpus:ro",
               RUNNER, "/bin/bash", "-lc",
               f"export ASAN_OPTIONS=detect_leaks=0; /out/{tgt} /corpus -runs=0 "
               "-detect_leaks=0 -rss_limit_mb=8192 -print_final_stats=1 2>&1"]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=1800)
    finally:
        POOL.put(core)
    cov = ft = None
    for m in COV.finditer(r.stdout + r.stderr):
        cov, ft = int(m[1]), int(m[2])
    return cov, ft


def main():
    results = json.load(open(f"{ROOT}/results.json"))
    out = {}
    wlock = threading.Lock()
    def work(t, v, tr):
        cd = f"{ROOT}/{t}/{v}/trial_{tr:02d}/corpus"
        if not os.path.isdir(cd):
            return
        cov, ft = replay(t, cd)
        n = len([f for f in os.listdir(cd) if os.path.isfile(os.path.join(cd, f))])
        with wlock:
            out[(t, v, tr)] = (cov, ft, n)
            json.dump({f"{a}/{b}/{c}": out[(a, b, c)] for (a, b, c) in out},
                      open(f"{ROOT}/covbaseline_final.json", "w"), indent=2)   # incremental
        print(f"  {t}/{v}/trial_{tr:02d}: {n} inputs -> baseline cov={cov} ft={ft}", flush=True)
    ths = []
    for r in results:
        if r["target"] not in TARGETS:
            continue
        th = threading.Thread(target=work, args=(r["target"], r["variant"], r["trial"]))
        th.start(); ths.append(th)
    for th in ths:
        th.join()

    print("\n=== TOTAL accumulated-corpus coverage ON BASELINE BINARY (mean across trials) ===")
    print(f"{'target':9s} {'variant':9s} {'n_trials':>8s} {'meanCov':>9s} {'meanFt':>9s} {'meanCorpus':>11s}")
    agg = {}
    for t in TARGETS:
        for v in VAR:
            rows = [out[(t, v, tr)] for (tt, vv, tr) in out if (tt, vv) == (t, v)]
            rows = [r for r in rows if r[0] is not None]
            if not rows:
                continue
            mc = statistics.mean(r[0] for r in rows); mf = statistics.mean(r[1] for r in rows)
            mn = statistics.mean(r[2] for r in rows)
            sc = statistics.pstdev([r[0] for r in rows]) if len(rows) > 1 else 0
            agg[(t, v)] = (mc, mf, mn, len(rows), sc)
            print(f"{t:9s} {v:9s} {len(rows):>8d} {mc:>9.0f} {mf:>9.0f} {mn:>11.0f}")
        b = agg.get((t, "baseline"))
        if b:
            for v in ("aggr8h", "mut8h"):
                a = agg.get((t, v))
                if a:
                    print(f"           {v} cov vs baseline: {a[0]/b[0]:.3f}x  "
                          f"(baseline sd={b[4]:.0f})")
    json.dump({f"{t}/{v}/{tr}": out[(t, v, tr)] for (t, v, tr) in out},
              open(f"{ROOT}/covbaseline_final.json", "w"), indent=2)


if __name__ == "__main__":
    main()
