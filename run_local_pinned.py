#!/usr/bin/env python3
"""CPU-pinned LOCAL phase-3 to remove k8s node/load noise.

For each target (selinux, libavc) run 3 binaries — baseline, aggr8h-optimized,
mut8h-optimized — 10 trials each. Every trial is pinned to a DEDICATED physical
core (logical CPUs 0-19; their HT siblings 20-39 are left idle), starts from the
SAME corpus with the SAME per-trial seed (1337 + trial*1000), and runs the exact
k8s fuzzer command. Scored with lib/crash_classify (real crashes only,
signature-agnostic). Records crashing-input hash + exec/s so we can see if the
same seed finds the same input across variants and whether wall-clock TTB is now
stable.

  python3 run_local_pinned.py [--duration 28800] [--trials 10] [--targets selinux libavc]
"""
import argparse, json, os, re, shutil, subprocess, threading, queue, time, zipfile, collections, statistics
from pathlib import Path

import config
from lib import crash_classify as cc

RUNNER = "gcr.io/oss-fuzz-base/base-runner"
RSS = config.PHASE3_K8S_RSS_LIMIT_MB               # 8192, matching the k8s runs
PHYS_CORES = list(range(20))                        # one logical CPU per physical core

TARGETS = {
    "selinux": {"key": "selinux-CVE-2021-36085", "target": "secilc-fuzzer",
                "corpus_zip": "secilc-fuzzer_seed_corpus.zip"},   # identical across builds
    "libavc":  {"key": "libavc-arvo-16505", "target": "avc_dec_fuzzer",
                "corpus_zip": None},                              # cold start (matches k8s)
}
# variant label -> (experiment, bin subdir). baseline is byte-identical between
# the two experiments (same sha), so aggr-8h's baseline stands in for "the baseline".
VARIANTS = {
    "baseline": ("aggr-8h", "baseline"),
    "aggr8h":   ("aggr-8h", "optimized"),
    "mut8h":    ("mut-8h",  "optimized"),
}


def bin_dir(target, variant):
    exp, sub = VARIANTS[variant]
    return (Path("results") / exp / TARGETS[target]["key"] / sub / "bin").absolute()


def prep_corpus(target, dest):
    dest.mkdir(parents=True, exist_ok=True)
    z = TARGETS[target]["corpus_zip"]
    if not z:
        return  # cold start
    src = bin_dir(target, "baseline") / z
    with zipfile.ZipFile(src) as zf:
        for m in zf.namelist():
            if m.endswith("/"):
                continue
            (dest / os.path.basename(m)).write_bytes(zf.read(m))


def run_one(target, variant, trial, core, outroot, duration):
    tdir = outroot / target / variant / f"trial_{trial:02d}"
    if tdir.exists():
        shutil.rmtree(tdir)
    corpus, crashes = tdir / "corpus", tdir / "crashes"
    tdir.mkdir(parents=True); crashes.mkdir()
    prep_corpus(target, corpus)
    seed = config.BASE_SEED + trial * config.SEED_MULTIPLIER
    tgt = TARGETS[target]["target"]
    inner = (
        "export ASAN_OPTIONS=detect_leaks=0; export UBSAN_OPTIONS=print_stacktrace=1; "
        f"/out/{tgt} /corpus -seed={seed} -verbosity=1 -print_corpus_stats=1 "
        f"-print_funcs=1 -report_slow_units=10 -malloc_limit_mb={RSS} -detect_leaks=0 "
        f"-max_total_time={duration} -print_final_stats=1 -rss_limit_mb={RSS} "
        "-artifact_prefix=/crashes/"
    )
    cmd = ["docker", "run", "--rm", "--cpuset-cpus", str(core),
           "-v", f"{bin_dir(target, variant)}:/out:ro",
           "-v", f"{corpus.absolute()}:/corpus",
           "-v", f"{crashes.absolute()}:/crashes",
           RUNNER, "/bin/bash", "-lc", inner]
    start = time.time()
    with (tdir / "fuzz.log").open("w") as log:
        subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
    # collect crash artifacts (timestamp = mtime - start, type by prefix)
    cts = []
    for f in sorted(crashes.iterdir()):
        if not f.is_file():
            continue
        n = f.name
        ctype = ("oom" if n.startswith("oom-") else "timeout" if n.startswith("timeout-")
                 else "crash" if n.startswith("crash-") else "unknown")
        cts.append({"timestamp_s": max(0.0, round(f.stat().st_mtime - start, 2)),
                    "artifact": n, "crash_type": ctype})
    blob = (tdir / "fuzz.log").read_text(errors="replace")
    m = re.search(r"stat::average_exec_per_sec:\s*(\d+)", blob)
    execs = int(m.group(1)) if m else None
    ttb = cc.trial_time_to_bug(cts, duration)
    first = min((c for c in cts if cc.is_target_bug_find(c, duration)),
                key=lambda c: c["timestamp_s"], default=None)
    rec = {"target": target, "variant": variant, "trial": trial, "seed": seed, "cpu": core,
           "crash_times": cts, "max_total_time": duration, "avg_exec_s": execs,
           "found_bug": ttb is not None, "ttb_s": ttb,
           "crash_input": first["artifact"] if first else None,
           "wall_s": round(time.time() - start, 1)}
    json.dump(rec, (tdir / "result.json").open("w"), indent=2)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=28800)
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--targets", nargs="+", default=["selinux", "libavc"])
    a = ap.parse_args()

    outroot = Path("local_pinned")
    outroot.mkdir(exist_ok=True)
    subprocess.run(["docker", "pull", RUNNER], capture_output=True)  # ensure present

    # interleave so variants/targets are balanced across the first wave
    jobs = [(t, v, tr) for tr in range(a.trials) for v in VARIANTS for t in a.targets]
    print(f"[local-pinned] {len(jobs)} trials, {len(PHYS_CORES)} cores, "
          f"dur={a.duration}s, targets={a.targets}", flush=True)

    core_q = queue.Queue()
    for c in PHYS_CORES:
        core_q.put(c)
    results, lock, done = [], threading.Lock(), [0]

    def worker(job):
        t, v, tr = job
        core = core_q.get()
        try:
            rec = run_one(t, v, tr, core, outroot, a.duration)
        finally:
            core_q.put(core)
        with lock:
            results.append(rec)
            done[0] += 1
            print(f"[{done[0]:2d}/{len(jobs)}] {t}/{v}/trial_{tr:02d} cpu{core} "
                  f"found={rec['found_bug']} ttb={rec['ttb_s']} exec/s={rec['avg_exec_s']} "
                  f"wall={rec['wall_s']}s", flush=True)
            json.dump(results, (outroot / "results.json").open("w"), indent=2)

    threads = [threading.Thread(target=worker, args=(j,)) for j in jobs]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    # summary
    print("\n=== SUMMARY (real crashes, signature-agnostic) ===")
    g = collections.defaultdict(list)
    for r in results:
        g[(r["target"], r["variant"])].append(r)
    for t in a.targets:
        for v in VARIANTS:
            rr = g.get((t, v), [])
            ttbs = [r["ttb_s"] for r in rr if r["ttb_s"] is not None]
            mean = f"{statistics.mean(ttbs)/3600:.2f}h" if ttbs else "-"
            sd = f"{statistics.pstdev(ttbs)/3600:.2f}h" if len(ttbs) > 1 else "-"
            xs = [r["avg_exec_s"] for r in rr if r["avg_exec_s"]]
            print(f"  {t:8s} {v:9s} found {len(ttbs)}/{len(rr)}  meanTTB={mean} sd={sd}  "
                  f"exec/s[min-max]={min(xs) if xs else '-'}-{max(xs) if xs else '-'}")
    print(f"\nwrote {outroot/'results.json'}")


if __name__ == "__main__":
    main()
