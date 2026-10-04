#!/usr/bin/env python3
"""PER-TRIAL coverage diff (vs the earlier pooled/union covdiff).

For each of the 5 optimized projects (new-kube-1-rerun), replay EACH trial's corpus
SEPARATELY on the BASELINE binary and record per-trial: edge cov, features (ft),
executed units, corpus file count, corpus bytes. Then report per-variant AVERAGES
(mean/min/max/stdev). Baseline-generated corpora come from new-kube-1-rerun; the
optimized-generated corpora from nk1-covgen. Both replayed on the baseline binary.

Outputs:
  covdiff_pertrial/results_pertrial.json   (every per-trial row + per-variant aggregate)
  covdiff_pertrial/summary.txt             (readable table)

  Step 1: python3 tools/run_covdiff_pertrial.py --pull     (pull each per-trial corpus zip)
  Step 2: python3 tools/run_covdiff_pertrial.py --replay   (replay each on baseline binary)
  Both:   python3 tools/run_covdiff_pertrial.py --pull --replay
"""
import argparse, json, os, re, statistics, subprocess, time, zipfile
from pathlib import Path

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
import phase3_k8s as p3

# Experiments are env-configurable so the same tooling serves other runs (e.g.
# mut-8h, where BOTH variants live in the same experiment): set COVTIME_SRC_EXP and
# COVTIME_OPT_EXP to the same id, and COVTIME_PROJECTS to the subset.
SRC_EXP  = os.environ.get("COVTIME_SRC_EXP", "new-kube-1-rerun")  # baseline corpora + binaries
OPT_EXP  = os.environ.get("COVTIME_OPT_EXP", "nk1-covgen")        # optimized corpora
ART      = "/artifacts/bena/phase3-kube"
RUNNER   = "gcr.io/oss-fuzz-base/base-runner"
_projenv = os.environ.get("COVTIME_PROJECTS", "").split()
PROJECTS = set(_projenv) if _projenv else {"libxml2", "wolfssl", "libavc", "assimp", "selinux"}
OUT      = Path(os.environ.get("COVTIME_PULL_DIR", "covdiff_pertrial"))
NS       = config.PHASE3_K8S_NAMESPACE
POD      = "covdiff-pertrial-pod"


def _sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", **kw)


def manifest():
    return [e for e in json.load(open(f"manifest_{SRC_EXP}.json"))
            if e["project"] in PROJECTS]


# --- Step 1: pull each per-trial corpus zip (NOT merged) -----------------------
def pull():
    OUT.mkdir(exist_ok=True)
    spec = {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD},
        "spec": {"restartPolicy": "Never",
                 "containers": [{"name": "c", "image": "busybox:1.36",
                                 "command": ["sh", "-c", "sleep 3600"],
                                 "volumeMounts": [{"name": "a", "mountPath": "/artifacts"}]}],
                 "volumes": [{"name": "a", "persistentVolumeClaim": {"claimName": "nfs"}}]},
    }
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        json.dump(spec, f); path = f.name
    _sh(["kubectl", *p3._ns_args(NS), "delete", "pod", POD, "--ignore-not-found"])
    _sh(["kubectl", *p3._ns_args(NS), "apply", "-f", path])
    _sh(["kubectl", *p3._ns_args(NS), "wait", "--for=condition=Ready",
         f"pod/{POD}", "--timeout=120s"])

    for e in manifest():
        p = e["project"]
        for exp, variant in ((SRC_EXP, "baseline"), (OPT_EXP, "optimized")):
            base = f"{ART}/{exp}/{p}/{variant}"
            r = _sh(["kubectl", *p3._ns_args(NS), "exec", POD, "--", "sh", "-c",
                     f"find {base} -name 'corpus-*.zip' 2>/dev/null"])
            zips = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            for z in zips:
                bn = os.path.basename(z)                 # corpus-<trial>-<suffix>.zip
                dst = OUT / p / variant / bn
                dst.parent.mkdir(parents=True, exist_ok=True)
                src = f"{NS}/{POD}:{z}" if NS else f"{POD}:{z}"
                _sh(["kubectl", *p3._ns_args(NS), "cp", src, str(dst)])
                cdir = OUT / p / variant / bn[:-4]        # strip .zip -> per-trial dir
                cdir.mkdir(exist_ok=True)
                try:
                    with zipfile.ZipFile(dst) as zf:
                        zf.extractall(cdir)
                except Exception as ex:
                    print(f"    WARN unzip {dst}: {ex}")
            print(f"  pulled {p}/{variant}: {len(zips)} per-trial corpora")
    _sh(["kubectl", *p3._ns_args(NS), "delete", "pod", POD, "--wait=false",
         "--ignore-not-found"])


# --- Step 2: replay each trial corpus on the baseline binary -------------------
def _cov(out_dir: Path, corpus: Path, target: str) -> dict:
    cmd = ["docker", "run", "--rm", "--privileged",
           "-v", f"{out_dir.absolute()}:/out:ro",
           "-v", f"{corpus.absolute()}:/corpus:ro", RUNNER, "/bin/bash", "-lc",
           ("export ASAN_OPTIONS=detect_leaks=0; "
            f"exec /out/{target} /corpus -runs=0 -detect_leaks=0 "
            "-rss_limit_mb=4096 -print_final_stats=1")]
    r = _sh(cmd)
    blob = r.stdout + r.stderr
    cov = ft = units = None
    for m in re.finditer(r"cov:\s*(\d+)\s+ft:\s*(\d+)", blob):
        cov, ft = int(m.group(1)), int(m.group(2))
    mu = re.search(r"stat::number_of_executed_units:\s*(\d+)", blob)
    if mu:
        units = int(mu.group(1))
    return {"cov": cov, "ft": ft, "executed_units": units}


def _stat(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return None
    return {"mean": round(statistics.mean(vals), 2), "min": min(vals), "max": max(vals),
            "stdev": round(statistics.pstdev(vals), 2) if len(vals) > 1 else 0.0,
            "n": len(vals)}


def replay():
    rows = []
    for e in manifest():
        p, cve, ft = e["project"], e["cve"], e.get("fuzz_target", "")
        bin_dir = Path(config.RESULTS_DIR) / SRC_EXP / p3.cve_key(p, cve) / "baseline" / "bin"
        if not (bin_dir / ft).is_file():
            print(f"  SKIP {p}: baseline binary missing"); continue
        for variant in ("baseline", "optimized"):
            vdir = OUT / p / variant
            trials = sorted(d for d in vdir.glob("corpus-*") if d.is_dir()) if vdir.is_dir() else []
            for td in trials:
                files = [f for f in td.rglob("*") if f.is_file()]
                nfiles = len(files)
                nbytes = sum(f.stat().st_size for f in files)
                c = _cov(bin_dir, td, ft) if nfiles else {"cov": None, "ft": None, "executed_units": None}
                rows.append({"project": p, "variant": variant, "trial": td.name,
                             "files": nfiles, "bytes": nbytes, **c})
                print(f"  {p:10s} {variant:9s} {td.name:44s} files={nfiles:>6d} "
                      f"cov={c['cov']} ft={c['ft']}")

    agg = {}
    for p in sorted(PROJECTS):
        agg[p] = {}
        for variant in ("baseline", "optimized"):
            vr = [r for r in rows if r["project"] == p and r["variant"] == variant]
            if not vr:
                continue
            agg[p][variant] = {
                "trials": len(vr),
                "cov": _stat([r["cov"] for r in vr]),
                "ft": _stat([r["ft"] for r in vr]),
                "files": _stat([r["files"] for r in vr]),
                "bytes": _stat([r["bytes"] for r in vr]),
            }

    OUT.mkdir(exist_ok=True)
    json.dump({"description": "per-trial coverage of each trial corpus replayed on the "
               "BASELINE binary; baseline corpora from new-kube-1-rerun, optimized from "
               "nk1-covgen", "per_trial": rows, "aggregate": agg},
              open(OUT / "results_pertrial.json", "w"), indent=2)

    L = []
    L.append("PER-TRIAL coverage on the BASELINE binary (mean across trials)")
    L.append(f"{'project':10s} {'variant':9s} {'trials':>6s} {'cov_mean':>9s} "
             f"{'cov_min':>7s} {'cov_max':>7s} {'cov_sd':>7s} {'files_mean':>10s} {'bytes_mean':>12s}")
    for p in sorted(PROJECTS):
        for variant in ("baseline", "optimized"):
            a = agg.get(p, {}).get(variant)
            if not a or not a["cov"]:
                continue
            L.append(f"{p:10s} {variant:9s} {a['trials']:>6d} {a['cov']['mean']:>9.1f} "
                     f"{a['cov']['min']:>7d} {a['cov']['max']:>7d} {a['cov']['stdev']:>7.1f} "
                     f"{a['files']['mean']:>10.1f} {a['bytes']['mean']:>12.0f}")
        b = agg.get(p, {}).get("baseline"); o = agg.get(p, {}).get("optimized")
        if b and o and b["cov"] and o["cov"] and b["cov"]["mean"]:
            L.append(f"{'':10s} -> opt/base mean-cov ratio: "
                     f"{o['cov']['mean']/b['cov']['mean']:.4f}")
    out = "\n".join(L)
    print("\n" + out)
    (OUT / "summary.txt").write_text(out + "\n")
    print(f"\nwrote {OUT/'results_pertrial.json'} and {OUT/'summary.txt'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--replay", action="store_true")
    a = ap.parse_args()
    if not (a.pull or a.replay):
        ap.error("pass --pull and/or --replay")
    if a.pull:
        pull()
    if a.replay:
        replay()
