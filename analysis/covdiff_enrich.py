#!/usr/bin/env python3
"""Enrich the per-trial coverage summary with replay speedup + time-to-bug averages
(from the new-kube-1-rerun phase-4 results), without re-running the replays.

Reads:
  covdiff_pertrial/results_pertrial.json        (per-trial cov aggregate)
  results/new-kube-1-rerun/report/results.json  (replay_speedup + TTB mean stats)
Writes/overwrites:
  covdiff_pertrial/summary.txt                  (now with replay + TTB avg columns)
  covdiff_pertrial/results_pertrial.json         (aggregate gets replay/ttb fields)
"""
import json
from pathlib import Path

OUT = Path("covdiff_pertrial")
cd = json.load(open(OUT / "results_pertrial.json"))
agg = cd["aggregate"]
def _bare(name):  # "libxml2-arvo-1972" -> "libxml2"; "selinux" -> "selinux"
    return name.split("-arvo-")[0].split("-CVE-")[0]


ph4 = {_bare(e["project"]): e for e in
       json.load(open("results/new-kube-1-rerun/report/results.json"))}

PROJECTS = ["assimp", "libavc", "libxml2", "selinux", "wolfssl"]


def ttb_mean_h(stats, found):
    if not stats or not found:      # no crashes -> TTB not meaningful
        return None
    m = stats.get("mean")
    return None if m is None else m / 3600.0


# attach replay + TTB to each project's aggregate
for p in PROJECTS:
    e = ph4.get(p, {})
    bmean = ttb_mean_h(e.get("baseline_stats"), e.get("baseline_found_bug"))
    omean = ttb_mean_h(e.get("optimized_stats"), e.get("optimized_found_bug"))
    agg.setdefault(p, {})["phase4"] = {
        "replay_speedup": e.get("replay_speedup"),
        "ttb_base_mean_h": round(bmean, 2) if bmean is not None else None,
        "ttb_opt_mean_h": round(omean, 2) if omean is not None else None,
        "ttb_mean_speedup": round(bmean / omean, 3) if (bmean and omean) else None,
        "baseline_found_bug": e.get("baseline_found_bug"),
        "optimized_found_bug": e.get("optimized_found_bug"),
    }

cd["aggregate"] = agg
json.dump(cd, open(OUT / "results_pertrial.json", "w"), indent=2)

L = []
L.append("PER-TRIAL coverage on the BASELINE binary (mean across trials) + replay/TTB (phase-4)")
L.append("")
L.append("Coverage (each trial's corpus replayed separately on the baseline binary):")
L.append(f"{'project':10s} {'variant':9s} {'trials':>6s} {'cov_mean':>9s} "
         f"{'cov_min':>7s} {'cov_max':>7s} {'cov_sd':>7s} {'files_mean':>10s} {'bytes_mean':>12s}")
for p in PROJECTS:
    for variant in ("baseline", "optimized"):
        a = agg.get(p, {}).get(variant)
        if not a or not a["cov"]:
            continue
        L.append(f"{p:10s} {variant:9s} {a['trials']:>6d} {a['cov']['mean']:>9.1f} "
                 f"{a['cov']['min']:>7d} {a['cov']['max']:>7d} {a['cov']['stdev']:>7.1f} "
                 f"{a['files']['mean']:>10.1f} {a['bytes']['mean']:>12.0f}")

L.append("")
L.append("Per-project summary (cov ratio + replay speedup + time-to-bug averages):")
L.append(f"{'project':10s} {'cov_opt/base':>12s} {'replay_x':>9s} "
         f"{'ttb_base_h':>11s} {'ttb_opt_h':>10s} {'ttb_avg_x':>10s} {'bug b/o':>9s}")
for p in PROJECTS:
    a = agg.get(p, {})
    b, o, f4 = a.get("baseline"), a.get("optimized"), a.get("phase4", {})
    covr = (f"{o['cov']['mean']/b['cov']['mean']:.4f}"
            if b and o and b["cov"] and o["cov"] and b["cov"]["mean"] else "n/a")
    rx = f"{f4['replay_speedup']:.2f}" if f4.get("replay_speedup") is not None else "n/a"
    tb = f"{f4['ttb_base_mean_h']:.2f}" if f4.get("ttb_base_mean_h") is not None else "n/f"
    to = f"{f4['ttb_opt_mean_h']:.2f}" if f4.get("ttb_opt_mean_h") is not None else "n/f"
    tx = f"{f4['ttb_mean_speedup']:.2f}" if f4.get("ttb_mean_speedup") is not None else "n/f"
    bg = f"{f4.get('baseline_found_bug')}/{f4.get('optimized_found_bug')}"
    L.append(f"{p:10s} {covr:>12s} {rx:>9s} {tb:>11s} {to:>10s} {tx:>10s} {bg:>9s}")
L.append("")
L.append("(ttb_*_h = mean time-to-bug in hours over crashing trials; ttb_avg_x = base/opt mean;")
L.append(" n/f = bug not found in any trial; replay_x = phase-4 frozen-corpus replay speedup.)")

out = "\n".join(L)
print(out)
(OUT / "summary.txt").write_text(out + "\n")
print(f"\nwrote {OUT/'summary.txt'} and updated {OUT/'results_pertrial.json'}")
