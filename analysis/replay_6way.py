#!/usr/bin/env python3
"""Replay 3 selinux binaries on 2 corpora (6 runs) and report replay times.

Binaries:  baseline (vulnerable), kube-2 optimized, new-kube-1 optimized.
Corpora:   A = replay corpus (13,548, sanitized/clean) ; B = trial seed corpus
           (13,843, contains the crasher -> binaries SEGV on read).

Same method as the benchmark replay metric: run `<target> <corpus> -runs=0`
(replay each unit once, no mutation), pinned to one CPU, inside base-runner,
median of REPEATS. Timing is measured INSIDE the container (excludes docker
startup) via integer nanoseconds.
"""
import concurrent.futures
import json
import re
import statistics
import subprocess

BENCH = "/home/sefcom/asu/project/test/benchmark"
RUNNER = "gcr.io/oss-fuzz-base/base-runner"
TGT = "secilc-fuzzer"
REPEATS = 3

BINS = [
    ("baseline",           f"{BENCH}/results/new-kube-1/selinux-CVE-2021-36085/baseline/bin", 3),
    ("kube2-optimized",    f"{BENCH}/results/kube-2/selinux-CVE-2021-36085/optimized/bin", 4),
    ("newkube1-optimized", f"{BENCH}/results/new-kube-1/selinux-CVE-2021-36085/optimized/bin", 5),
]
CORPORA = [
    # both CLEAN replay corpora (no crasher). kube-2's is the evolving corpus its
    # 2.15x was measured on (1775); new-kube-1's is the fixed corpus (13548).
    ("kube2_replay_1775", f"{BENCH}/results/kube-2/selinux-CVE-2021-36085/optimized/source_diff/profiles/evolving_corpus"),
    ("newkube1_replay_13548", f"{BENCH}/results/poff-selinux-2/selinux-CVE-2021-36085/optimized/source_diff/profiles/fixed_corpus"),
]

INNER = (
    'start=$(date +%s%N); '
    f'/out/{TGT} /corpus -runs=0 -seed=1337 -rss_limit_mb=4096 -malloc_limit_mb=4096 '
    '-detect_leaks=0 -print_final_stats=1 >/tmp/o 2>&1; '
    'rc=$?; end=$(date +%s%N); '
    'echo "ELAPSED_MS=$(( (end - start) / 1000000 )) RC=$rc"; '
    'grep -aoE "Done [0-9]+ runs|number_of_executed_units: *[0-9]+|'
    'ERROR: AddressSanitizer: [a-zA-Z-]+" /tmp/o | tail -3'
)


def run_one(out_dir, corpus_dir, cpu):
    cmd = ["docker", "run", "--rm", f"--cpuset-cpus={cpu}",
           "-v", f"{out_dir}:/out:ro", "-v", f"{corpus_dir}:/corpus:ro",
           "--entrypoint", "bash", RUNNER, "-c", INNER]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=3600)
        out = p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return {"ms": None, "rc": "timeout", "crashed": False, "units": None}
    ms = rc = units = None
    crashed = "AddressSanitizer:" in out
    m = re.search(r"ELAPSED_MS=(\d+) RC=(\d+)", out)
    if m:
        ms, rc = int(m.group(1)), int(m.group(2))
    mu = re.search(r"number_of_executed_units: *(\d+)", out)
    md = re.search(r"Done (\d+) runs", out)
    if mu:
        units = int(mu.group(1))
    elif md:
        units = int(md.group(1))
    return {"ms": ms, "rc": rc, "crashed": crashed, "units": units}


def do_bin(spec, cdir, cname):
    name, bdir, cpu = spec
    runs = []
    for r in range(REPEATS):
        res = run_one(bdir, cdir, cpu)
        runs.append(res)
        print(f"[{cname}] {name} rep{r}: {res['ms']}ms rc={res['rc']} "
              f"crashed={res['crashed']} units={res['units']}", flush=True)
    good = [x["ms"] for x in runs if x["ms"] is not None]
    return name, {"median_s": round(statistics.median(good) / 1000.0, 2) if good else None,
                  "all_ms": [x["ms"] for x in runs],
                  "crashed": any(x["crashed"] for x in runs),
                  "units": next((x["units"] for x in runs if x["units"] is not None), None)}


def main():
    results = {}
    for cname, cdir in CORPORA:
        print(f"\n===== corpus {cname} =====", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(do_bin, spec, cdir, cname) for spec in BINS]
            for f in concurrent.futures.as_completed(futs):
                name, data = f.result()
                results.setdefault(cname, {})[name] = data
        json.dump(results, open(f"{BENCH}/replay_6way.json", "w"), indent=2)

    print("\n\n================ 6-WAY REPLAY TIMES (median, clean) ================", flush=True)
    print(f"{'binary':20} {'kube-2 corpus (1775)':>22} {'new-kube-1 corpus (13548)':>26}")
    for name, _, _ in BINS:
        k = results.get("kube2_replay_1775", {}).get(name, {})
        n = results.get("newkube1_replay_13548", {}).get(name, {})
        kcol = f"{k.get('median_s')}s ({k.get('units')}u)"
        ncol = f"{n.get('median_s')}s ({n.get('units')}u)"
        print(f"{name:20} {kcol:>22} {ncol:>26}", flush=True)
    # speedups vs baseline, per corpus
    print("\n-- speedup vs baseline (per corpus) --", flush=True)
    for cname in ("kube2_replay_1775", "newkube1_replay_13548"):
        base = results.get(cname, {}).get("baseline", {}).get("median_s")
        if not base:
            continue
        parts = []
        for name in ("kube2-optimized", "newkube1-optimized"):
            m = results.get(cname, {}).get(name, {}).get("median_s")
            if m:
                parts.append(f"{name} {base/m:.2f}x")
        print(f"  {cname}: baseline={base}s  " + "  ".join(parts), flush=True)
    print("\nwrote replay_6way.json", flush=True)


if __name__ == "__main__":
    main()
