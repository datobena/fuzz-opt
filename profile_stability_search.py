#!/usr/bin/env python3
"""Find how many corpus mutations are needed before the perf profile stops moving.

Motivation
----------
The ``profile-once-fuzz-folds`` optimizer profiles the baseline once, on a fixed
corpus, and hands the agent a ranked hotspot list. If that corpus is too small
the ranking is noise; past some size the profile converges and adding more inputs
barely changes it. This tool finds that size N* per project, so we can (a) give
the agent trustworthy numbers and (b) compare N* across projects.

What it measures
----------------
Given a large POOL of fuzzer-produced inputs (the "mutations"), it treats the
profile of the *whole* pool as the reference, then asks: for a random subset of
size N, how far is its profile from the reference? Instability(N) falls as N
grows. N* is the smallest N whose instability is at or below a threshold epsilon
and stays there. A geometric ladder brackets the crossing; a binary search then
refines the exact integer N* (this is the "binary search" of the request).

The profile is produced with the SAME perf/afl-showmap replay the real pipeline
uses (``replay_fuzzer_profile.py``), so what we characterise is exactly the
profile the agent would receive.

Distance metric
---------------
Profiles are compared as *distributions of self-time over the target's own
functions* (perf ``--no-children`` rows whose DSO is the fuzz target). We
renormalise to a distribution and use total-variation distance
(``0.5 * sum|p-q|``, range [0,1]); a value of 0.10 means 10% of self-time shifted
between functions. Sanitizer/instrumentation symbols (``__asan*`` etc.) are
excluded by default because the agent cannot fold them -- the actionable hotspots
are project functions. Top-K overlap and Spearman rank correlation are reported
alongside for interpretability.

This tool profiles only; it never builds or trusts an agent edit. Profiling runs
in the perf-preinstalled image (``--perf-image``) so no per-run apt install is
needed.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ---------------------------------------------------------------------------
# perf profiling (mirrors sandbox/broker replay + skill replay_fuzzer_profile)
# ---------------------------------------------------------------------------

# Symbols that live in the target DSO but are runtime/instrumentation, not
# project code the optimizer can act on. Excluded from the hotspot distribution
# by default.
_RUNTIME_PREFIXES = (
    "__asan", "__lsan", "__msan", "__ubsan", "__tsan", "__sanitizer",
    "__interceptor", "___interceptor", "__cmplog", "_afl", "__afl",
    "asan.", "ubsan", "__sancov", "sancov.",
)

# flat.txt row:  "   8.31%  cmd   dso   [.] symbol (may contain spaces)"
_FLAT_RE = re.compile(
    r"^\s*([0-9]+\.[0-9]+)%\s+(\S+)\s+(\S+)\s+\[([.k])\]\s+(.*\S)\s*$"
)


def _is_runtime(sym: str) -> bool:
    return any(sym.startswith(p) for p in _RUNTIME_PREFIXES)


def parse_flat(flat_text: str, fuzz_target: str, *, project_only: bool) -> dict[str, float]:
    """Return {function: self_time_pct} for rows in the target's own DSO.

    ``project_only`` drops sanitizer/instrumentation symbols. Percentages are the
    raw perf overhead (share of ALL samples), not yet renormalised.
    """
    out: dict[str, float] = {}
    for line in flat_text.splitlines():
        m = _FLAT_RE.match(line)
        if not m:
            continue
        pct, _cmd, dso, kind, sym = m.groups()
        if kind != "." or dso != fuzz_target:
            continue
        if project_only and _is_runtime(sym):
            continue
        out[sym] = out.get(sym, 0.0) + float(pct)
    return out


def _replay_loop(fuzz_target: str, min_sec: int) -> str:
    """The afl-showmap replay loop, run under perf until min_sec of samples."""
    return (
        f"end=$(( $(date +%s) + {int(min_sec)} )); "
        'while [ "$(date +%s)" -lt "$end" ]; do '
        f"/out/afl-showmap -C -i /corpus -o /dev/null -t 5000+ -m none "
        f"-- /out/{fuzz_target} >/dev/null 2>&1 || true; "
        "done"
    )


def profile_corpus(
    *, out_dir: str, corpus_dir: str, fuzz_target: str, perf_image: str,
    cpu: int, min_sec: int, extra_libs: str = "", freq: int = 997, timeout: int = 1800,
) -> tuple[str, dict, str]:
    """Perf-profile the target replaying corpus_dir. Returns (flat_text, meta, log).

    Raises RuntimeError if perf produced no usable flat.txt.

    IMPORTANT: ``perf_image`` must ship a perf that MATCHES THE HOST KERNEL. A perf
    that is older than the kernel (e.g. the 20.04 base-runner's perf 5.4 under a
    6.8 kernel) records the afl-showmap parent but NOT its exec'd forkserver
    children, so every profile comes back ~75% afl-showmap and 0% target -- a
    silent, total failure. We use a 24.04 image (perf 6.8) and supply the target's
    own C++/unwind libs via ``extra_libs`` (LD_LIBRARY_PATH), since the target was
    built against the 20.04 prework runtime.
    """
    art = Path(tempfile.mkdtemp(prefix="stab-art-"))
    replay = _replay_loop(fuzz_target, min_sec)
    script = (
        "set -uo pipefail; "
        "PERF_BIN=$(find /usr/lib -path '*/linux-tools*' -name perf | sort | head -n 1); "
        'test -n "$PERF_BIN"; rc=0; '
        f'"$PERF_BIN" record -g --call-graph dwarf -F {freq} '
        "-o /artifacts/perf.data -- "
        f"/bin/bash -c '{replay}' > /artifacts/run.log 2>&1 || rc=$?; "
        'if [ "$rc" -eq 0 ]; then '
        '"$PERF_BIN" report --stdio --no-children -g none --percent-limit 0.5 '
        "-i /artifacts/perf.data > /artifacts/flat.txt 2>>/artifacts/run.log || rc=$?; "
        'fi; chmod -R a+r /artifacts 2>/dev/null || true; exit $rc'
    )
    cmd = [
        "docker", "run", "--rm", "--name", f"stab-{os.getpid()}-{uuid.uuid4().hex[:8]}",
        "--cpuset-cpus", str(cpu), "--memory", "4g", "--shm-size", "2g", "--privileged",
        "-e", "ASAN_OPTIONS=symbolize=0:detect_leaks=0:abort_on_error=0",
        "-e", "UBSAN_OPTIONS=symbolize=0",
        "-e", "AFL_NO_AFFINITY=1", "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
        "-v", f"{Path(out_dir).resolve()}:/out:ro",
        "-v", f"{Path(corpus_dir).resolve()}:/corpus:ro",
        "-v", f"{art.resolve()}:/artifacts",
    ]
    if extra_libs:
        cmd += ["-v", f"{Path(extra_libs).resolve()}:/extra:ro", "-e", "LD_LIBRARY_PATH=/extra"]
    cmd += [perf_image, "/bin/bash", "-lc", script]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        flat_path = art / "flat.txt"
        log = ((r.stdout or "") + (r.stderr or ""))[-2000:]
        if r.returncode != 0 or not flat_path.exists() or flat_path.stat().st_size == 0:
            runlog = (art / "run.log").read_text(errors="replace")[-1500:] if (art / "run.log").exists() else ""
            raise RuntimeError(f"perf failed (rc={r.returncode}):\n{log}\n--- run.log ---\n{runlog}")
        flat_text = flat_path.read_text(errors="replace")
        return flat_text, {"rc": r.returncode}, log
    finally:
        shutil.rmtree(art, ignore_errors=True)


# ---------------------------------------------------------------------------
# distance metrics between two profiles
# ---------------------------------------------------------------------------

def _renorm(profile: dict[str, float]) -> dict[str, float]:
    total = sum(profile.values())
    if total <= 0:
        return {}
    return {k: v / total for k, v in profile.items()}


def tv_distance(a: dict[str, float], b: dict[str, float]) -> float:
    """Total-variation distance of two renormalised profiles, range [0,1]."""
    pa, pb = _renorm(a), _renorm(b)
    keys = set(pa) | set(pb)
    return 0.5 * sum(abs(pa.get(k, 0.0) - pb.get(k, 0.0)) for k in keys)


def topk_overlap(a: dict[str, float], b: dict[str, float], k: int) -> float:
    ta = {kk for kk, _ in sorted(a.items(), key=lambda x: -x[1])[:k]}
    tb = {kk for kk, _ in sorted(b.items(), key=lambda x: -x[1])[:k]}
    if not ta and not tb:
        return 1.0
    return len(ta & tb) / max(1, min(k, len(ta | tb)))


def spearman(a: dict[str, float], b: dict[str, float]) -> float | None:
    """Spearman rank correlation over functions present in both profiles."""
    common = sorted(set(a) & set(b))
    n = len(common)
    if n < 3:
        return None

    def ranks(vals):
        order = sorted(range(len(vals)), key=lambda i: -vals[i])
        rk = [0.0] * len(vals)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and vals[order[j + 1]] == vals[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1
            for t in range(i, j + 1):
                rk[order[t]] = avg
            i = j + 1
        return rk

    ra = ranks([a[k] for k in common])
    rb = ranks([b[k] for k in common])
    d2 = sum((ra[i] - rb[i]) ** 2 for i in range(n))
    return 1 - (6 * d2) / (n * (n * n - 1))


# ---------------------------------------------------------------------------
# the search
# ---------------------------------------------------------------------------

def geometric_ladder(pool_size: int) -> list[int]:
    ns, n = [], 1
    while n < pool_size:
        ns.append(n)
        n *= 2
    ns.append(pool_size)
    return ns


def _materialize(picks, exec_budget, dst):
    """Write `picks` cycled up to `exec_budget` files into dst.

    Replicating the N distinct inputs to a fixed execution count keeps a single
    afl-showmap pass long regardless of N, so afl-showmap startup is amortized and
    the profile reflects the N inputs' code paths -- not a sampling artifact of how
    fast a tiny corpus finishes. Instability(N) then measures input DIVERSITY, the
    thing we care about, rather than replay-loop overhead.
    """
    n = max(1, exec_budget)
    i = 0
    while i < n:
        for f in picks:
            shutil.copy(f, dst / f"c{i:07d}")
            i += 1
            if i >= n:
                break


def profile_subset(files, k, seed, ctx, cpu):
    """Profile a random k-file subset (replicated to the exec budget)."""
    rng = random.Random(seed)
    pick = rng.sample(files, k) if k < len(files) else list(files)
    sub = Path(tempfile.mkdtemp(prefix="stab-sub-"))
    try:
        _materialize(pick, ctx["exec_budget"], sub)
        flat, _meta, _log = profile_corpus(
            out_dir=ctx["out_dir"], corpus_dir=str(sub), fuzz_target=ctx["fuzz_target"],
            perf_image=ctx["perf_image"], cpu=cpu, min_sec=ctx["min_sec"],
            extra_libs=ctx["extra_libs"],
        )
        return parse_flat(flat, ctx["fuzz_target"], project_only=True)
    finally:
        shutil.rmtree(sub, ignore_errors=True)


def instability_at(n, files, ref, ctx, repeats, cpus, base_seed):
    """Median TV-distance-to-reference over `repeats` random n-subsets (parallel)."""
    dists, overlaps, rhos = [], [], []
    with ThreadPoolExecutor(max_workers=len(cpus)) as ex:
        futs = [
            ex.submit(profile_subset, files, n, base_seed + 1000 * r + n, ctx, cpus[r % len(cpus)])
            for r in range(repeats)
        ]
        profs = [f.result() for f in futs]
    for p in profs:
        dists.append(tv_distance(p, ref))
        overlaps.append(topk_overlap(p, ref, ctx["topk"]))
        rr = spearman(p, ref)
        if rr is not None:
            rhos.append(rr)
    return {
        "n": n,
        "tv_median": statistics.median(dists),
        "tv_all": [round(d, 4) for d in dists],
        "topk_overlap_median": statistics.median(overlaps),
        "spearman_median": round(statistics.median(rhos), 4) if rhos else None,
    }


def run_search(ctx, files, ref, *, epsilon, repeats, cpus, base_seed):
    pool = len(files)
    ladder = geometric_ladder(pool)
    print(f"[{ctx['project']}] pool={pool}  ladder={ladder}  eps={epsilon}", flush=True)
    curve = []
    for n in ladder:
        t0 = time.time()
        row = instability_at(n, files, ref, ctx, repeats, cpus, base_seed)
        row["secs"] = round(time.time() - t0, 1)
        curve.append(row)
        print(f"  N={n:<6d} TV={row['tv_median']:.3f}  top{ctx['topk']}ovl="
              f"{row['topk_overlap_median']:.2f}  rho={row['spearman_median']}  "
              f"({row['secs']}s)", flush=True)

    # First ladder point at/below epsilon that also stays below for the rest.
    stable_from = None
    for i, row in enumerate(curve):
        if row["tv_median"] <= epsilon and all(r["tv_median"] <= epsilon for r in curve[i:]):
            stable_from = i
            break

    refined = None
    if stable_from is not None and stable_from > 0:
        lo, hi = curve[stable_from - 1]["n"], curve[stable_from]["n"]
        print(f"  bracket [{lo},{hi}] -> binary search", flush=True)
        while hi - lo > max(1, lo // 8):          # refine to ~12% resolution
            mid = (lo + hi) // 2
            row = instability_at(mid, files, ref, ctx, repeats, cpus, base_seed)
            print(f"    mid N={mid:<6d} TV={row['tv_median']:.3f}", flush=True)
            curve.append({**row, "secs": None, "refine": True})
            if row["tv_median"] <= epsilon:
                hi = mid
            else:
                lo = mid
        refined = hi
    n_star = refined if refined is not None else (curve[stable_from]["n"] if stable_from is not None else None)
    return {"pool": pool, "ladder": ladder, "epsilon": epsilon, "repeats": repeats,
            "curve": sorted(curve, key=lambda r: r["n"]), "n_star": n_star}


def make_plot(results: dict, out_png: str):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:                                    # noqa: BLE001
        print(f"(plot skipped: {e})")
        return
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for proj, res in results.items():
        pts = [(r["n"], r["tv_median"]) for r in res["curve"] if not r.get("refine")]
        pts.sort()
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        line, = ax.plot(xs, ys, marker="o", label=f"{proj} (N*={res['n_star']})")
        if res["n_star"]:
            ax.axvline(res["n_star"], color=line.get_color(), ls=":", alpha=0.5)
    eps = next(iter(results.values()))["epsilon"]
    ax.axhline(eps, color="grey", ls="--", label=f"epsilon={eps}")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("corpus size N (number of mutations, log2)")
    ax.set_ylabel("profile instability  (TV distance to full-pool profile)")
    ax.set_title("Profile stability vs. corpus size")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_png, dpi=130)
    print(f"wrote {out_png}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="label for output")
    ap.add_argument("--out-dir", required=True, help="/out dir with the built target")
    ap.add_argument("--pool-dir", required=True, help="dir of fuzzer-produced inputs (the mutation pool)")
    ap.add_argument("--fuzz-target", required=True)
    ap.add_argument("--perf-image", default="stability/perf24",
                    help="image with a perf MATCHING the host kernel (see profile_corpus)")
    ap.add_argument("--extra-libs", default="",
                    help="host dir of the target's runtime libs (libc++/unwind/python) "
                         "mounted at /extra with LD_LIBRARY_PATH; needed when perf-image "
                         "differs from the build image")
    ap.add_argument("--exec-budget", type=int, default=8000,
                    help="replicate each N-subset up to this many files so one afl-showmap "
                         "pass is long enough to amortize startup")
    ap.add_argument("--epsilon", type=float, default=0.10, help="TV-distance stability threshold")
    ap.add_argument("--repeats", type=int, default=4, help="random subsets averaged per N")
    ap.add_argument("--min-sec", type=int, default=20, help="perf sampling seconds per profile")
    ap.add_argument("--ref-min-sec", type=int, default=45, help="perf seconds for the reference profile")
    ap.add_argument("--topk", type=int, default=10)
    ap.add_argument("--cpus", default="2,3,4", help="comma-separated cpuset ids for parallel profiling")
    ap.add_argument("--seed", type=int, default=20260929)
    ap.add_argument("--out-json", default="")
    args = ap.parse_args()

    files = sorted(str(p) for p in Path(args.pool_dir).iterdir() if p.is_file())
    if len(files) < 8:
        print(f"pool too small ({len(files)} files); need >=8", file=sys.stderr)
        return 2
    cpus = [int(c) for c in args.cpus.split(",") if c.strip()]
    ctx = {"project": args.project, "out_dir": args.out_dir, "fuzz_target": args.fuzz_target,
           "perf_image": args.perf_image, "min_sec": args.min_sec, "topk": args.topk,
           "extra_libs": args.extra_libs, "exec_budget": args.exec_budget}

    print(f"[{args.project}] reference profile on full pool ({len(files)} distinct files)...", flush=True)
    ref_sub = Path(tempfile.mkdtemp(prefix="stab-ref-"))
    try:
        _materialize(files, args.exec_budget, ref_sub)
        ref_flat, _m, _l = profile_corpus(
            out_dir=args.out_dir, corpus_dir=str(ref_sub), fuzz_target=args.fuzz_target,
            perf_image=args.perf_image, cpu=cpus[0], min_sec=args.ref_min_sec,
            extra_libs=args.extra_libs)
    finally:
        shutil.rmtree(ref_sub, ignore_errors=True)
    ref = parse_flat(ref_flat, args.fuzz_target, project_only=True)
    if not ref:
        print("reference profile has 0 project functions -- perf is not sampling the "
              "target (kernel/perf mismatch?). Aborting.", file=sys.stderr)
        return 3
    top = sorted(ref.items(), key=lambda x: -x[1])[:args.topk]
    print(f"  reference top-{args.topk} project functions:")
    for name, pct in top:
        print(f"    {pct:6.2f}%  {name[:80]}")

    res = run_search(ctx, files, ref, epsilon=args.epsilon, repeats=args.repeats,
                     cpus=cpus, base_seed=args.seed)
    res["reference_top"] = [(n, round(p, 3)) for n, p in top]
    res["fuzz_target"] = args.fuzz_target
    print(f"\n[{args.project}] N* (mutations for a stable profile) = {res['n_star']}  "
          f"(pool={res['pool']}, eps={args.epsilon})")

    out_json = args.out_json or f"profile_stability_{args.project}.json"
    Path(out_json).write_text(json.dumps({args.project: res}, indent=2))
    print(f"wrote {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
