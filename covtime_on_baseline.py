#!/usr/bin/env python3
"""Coverage of each variant's ACCUMULATED corpus, measured on the BASELINE binary.

The `cov:`/`ft:` libFuzzer prints are on each variant's OWN instrumented binary,
which folding changes -> not comparable. Fair method: for each variant, take the
inputs it had discovered by time T (ctime-ordered prefix of its corpus) and
replay them on the *baseline* binary (-runs=0), counting baseline edges/features.
Common yardstick, so baseline vs aggr8h vs mut8h coverage is apples-to-apples.
Aggregated as mean across trials per variant; one plot + table per target.
"""
import glob, json, os, re, shutil, subprocess, tempfile, threading, queue, statistics, collections
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = "local_pinned"
RUNNER = "gcr.io/oss-fuzz-base/base-runner"
CKPT = [300, 900, 1800, 3600, 7200, 14400, 28800]
LBL = {300:"5m",900:"15m",1800:"30m",3600:"1h",7200:"2h",14400:"4h",28800:"8h"}
VAR = ["baseline", "aggr8h", "mut8h"]
COLORS = {"baseline":"#1f77b4","aggr8h":"#d62728","mut8h":"#2ca02c"}
TARGETS = {
    "selinux": ("selinux-CVE-2021-36085", "secilc-fuzzer"),
    "libavc":  ("libavc-arvo-16505", "avc_dec_fuzzer"),
}
COV = re.compile(r"cov:\s*(\d+)\s+ft:\s*(\d+)")
POOL = queue.Queue()
for c in range(8):            # modest concurrency; main fuzzing run still holds cores 0-19
    POOL.put(c)


def baseline_bin(target):
    return os.path.abspath(f"results/aggr-8h/{TARGETS[target][0]}/baseline/bin")


def replay(target, prefix_dir):
    tgt = TARGETS[target][1]
    core = POOL.get()
    try:
        cmd = ["docker","run","--rm","--cpuset-cpus",str(core),
               "-v",f"{baseline_bin(target)}:/out:ro","-v",f"{os.path.abspath(prefix_dir)}:/corpus:ro",
               RUNNER,"/bin/bash","-lc",
               f"export ASAN_OPTIONS=detect_leaks=0; /out/{tgt} /corpus -runs=0 "
               "-detect_leaks=0 -rss_limit_mb=8192 -print_final_stats=1 2>&1"]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=1200)
    finally:
        POOL.put(core)
    cov = ft = None
    for m in COV.finditer(r.stdout + r.stderr):
        cov, ft = int(m[1]), int(m[2])           # last cov: line = final
    return cov, ft


def trial_prefixes(corpus_dir):
    """files sorted by ctime, with time relative to earliest (t0)."""
    fs = [f for f in glob.glob(corpus_dir+"/*") if os.path.isfile(f)]
    if not fs: return None
    fs.sort(key=lambda f: os.stat(f).st_ctime)
    t0 = os.stat(fs[0]).st_ctime
    return [(os.stat(f).st_ctime - t0, f) for f in fs]


def measure_trial(target, variant, tr, out):
    rel = trial_prefixes(f"{ROOT}/{target}/{variant}/trial_{tr:02d}/corpus")
    if not rel: return
    row = {}
    for T in CKPT:
        files = [f for (t, f) in rel if t <= T]
        if not files:
            continue
        with tempfile.TemporaryDirectory(dir=ROOT) as pd:
            for i, f in enumerate(files):
                shutil.copy(f, os.path.join(pd, f"u{i:06d}"))   # copy prefix (files are root-owned)
            cov, ft = replay(target, pd)
        row[T] = (cov, ft)
    out[(target, variant, tr)] = row
    print(f"  {target}/{variant}/trial_{tr:02d}: " +
          " ".join(f"{LBL[T]}={row[T][0]}" for T in CKPT if T in row), flush=True)


def main():
    results = json.load(open(f"{ROOT}/results.json"))
    done = [(r["target"], r["variant"], r["trial"]) for r in results]
    out = {}
    threads = []
    for (t, v, tr) in done:
        if t not in TARGETS: continue
        th = threading.Thread(target=measure_trial, args=(t, v, tr, out))
        th.start(); threads.append(th)
    for th in threads: th.join()

    agg = collections.defaultdict(dict)
    for target in TARGETS:
        print(f"\n################ {target}: coverage of accumulated inputs ON BASELINE BINARY ################")
        print(f"{'checkpoint':10s} | " + " | ".join(f"{v:^16s}" for v in VAR))
        print(f"{'':10s} | " + " | ".join(f"{'cov':>7s} {'ft':>8s}" for v in VAR))
        for T in CKPT:
            cells = []
            for v in VAR:
                vals = [out[(target,v,tr)][T] for (tt,vv,tr) in done
                        if (tt,vv)==(target,v) and (target,v,tr) in out and T in out[(target,v,tr)]]
                if not vals: cells.append(f"{'-':>7s} {'-':>8s}"); continue
                mc = statistics.mean(c for c,_ in vals); mf = statistics.mean(f for _,f in vals)
                agg[(target,v)][T] = (mc, mf, len(vals))
                cells.append(f"{mc:>7.0f} {mf:>8.0f}")
            print(f"{LBL[T]:10s} | " + " | ".join(cells))
        # plot
        plt.figure(figsize=(9,5.5))
        for v in VAR:
            pts = [(T/3600, agg[(target,v)][T][0]) for T in CKPT if T in agg[(target,v)]]
            if pts:
                xs,ys = zip(*pts)
                plt.plot(xs, ys, "o-", color=COLORS[v], label=v)
        plt.xlabel("time (h)"); plt.ylabel("baseline-binary edges (cov) from accumulated corpus")
        plt.title(f"{target}: coverage of each variant's corpus, replayed on the BASELINE binary")
        plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
        outp = f"{ROOT}/covbaseline_{target}.png"; plt.savefig(outp, dpi=110); plt.close()
        print(f"wrote {outp}")
    json.dump({f"{t}/{v}": {str(T): agg[(t,v)][T] for T in agg[(t,v)]} for (t,v) in agg},
              open(f"{ROOT}/covbaseline.json","w"), indent=2)


if __name__ == "__main__":
    main()
