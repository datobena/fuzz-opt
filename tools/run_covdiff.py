#!/usr/bin/env python3
"""Differential coverage: does the OPTIMIZED-generated corpus cover less of the
BASELINE binary than the BASELINE-generated corpus?

For each of the 5 optimized projects, replays two corpora on the SAME (baseline)
binary and compares libFuzzer edge coverage:
  - baseline-generated corpus  = union of new-kube-1-rerun baseline trial corpora (NFS)
  - optimized-generated corpus = union of nk1-covgen optimized trial corpora (NFS)

If the optimized-generated corpus reaches fewer baseline edges, that quantifies the
bug-surface narrowing discussed for the algorithmic rewrites (selinux/libavc): the
optimized fuzzer had no coverage signal for code the optimization removed, so it
never produced inputs that exercise it on the baseline.

Run AFTER run_optcorpus_gen.py jobs finish.
  Step 1 (pull+merge on NFS, cp out):  python3 run_covdiff.py --pull
  Step 2 (replay on baseline binary):  python3 run_covdiff.py --replay
  Both:                                python3 run_covdiff.py --pull --replay
"""
import argparse, json, os, re, subprocess, sys, tempfile, zipfile
from pathlib import Path

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
import phase3_k8s as p3

SRC_EXP   = "new-kube-1-rerun"   # baseline corpora + baseline binaries
OPT_EXP   = "nk1-covgen"         # optimized corpora
ART_ROOT  = "/artifacts/bena/phase3-kube"
RUNNER    = "gcr.io/oss-fuzz-base/base-runner"
PROJECTS  = {"libxml2", "wolfssl", "libavc", "assimp", "selinux"}
OUT       = Path("covdiff")      # local working dir
NS        = config.PHASE3_K8S_NAMESPACE


def _sh(cmd, **kw):
    # errors="replace": replay output (ASan/crash text) can contain non-UTF-8
    # bytes; never let a decode error abort the run.
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", **kw)


def manifest():
    return [e for e in json.load(open(f"manifest_{SRC_EXP}.json"))
            if e["project"] in PROJECTS]


# --- Step 1: merge per-project corpora on NFS into single zips, cp them local ----
def pull():
    OUT.mkdir(exist_ok=True)
    # A pod that unions every trial corpus (dedup by content-hash filename) per
    # project/variant into one zip under the NFS covdiff/ scratch dir.
    script = f"""
set -e
ROOT={ART_ROOT}
OUT=$ROOT/covdiff-scratch
rm -rf $OUT; mkdir -p $OUT
merge() {{  # $1=exp $2=project $3=variant $4=outname
  u=$(mktemp -d)
  find $ROOT/$1/$2/$3 -name 'corpus-*.zip' 2>/dev/null | while read z; do
    unzip -o -q "$z" -d "$u" 2>/dev/null || true
  done
  n=$(find "$u" -type f | wc -l)
  (cd "$u" && zip -q -r -0 $OUT/$4.zip . 2>/dev/null) || true
  echo "$4: $n files"
  rm -rf "$u"
}}
"""
    for e in manifest():
        p = e["project"]
        script += f'merge {SRC_EXP} {p} baseline {p}-baseline\n'
        script += f'merge {OPT_EXP} {p} optimized {p}-optimized\n'
    script += "echo MERGE_DONE; sleep 600\n"

    pod = "covdiff-merge"
    spec = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": pod},
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "c", "image": "alpine:3.19",
                "command": ["sh", "-c", "apk add -q zip unzip >/dev/null 2>&1; " + script],
                "volumeMounts": [{"name": "artifacts", "mountPath": "/artifacts"}],
            }],
            "volumes": [{"name": "artifacts",
                         "persistentVolumeClaim": {"claimName": "nfs"}}],
        },
    }
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        json.dump(spec, f); path = f.name
    _sh(["kubectl", *p3._ns_args(NS), "delete", "pod", pod, "--ignore-not-found"])
    _sh(["kubectl", *p3._ns_args(NS), "apply", "-f", path])
    # wait for MERGE_DONE
    import time
    for _ in range(120):
        logs = _sh(["kubectl", *p3._ns_args(NS), "logs", pod]).stdout
        if "MERGE_DONE" in logs:
            print(logs.strip()); break
        time.sleep(10)
    # cp each merged zip out + unzip locally
    for e in manifest():
        p = e["project"]
        for variant in ("baseline", "optimized"):
            remote = f"{pod}:{ART_ROOT}/covdiff-scratch/{p}-{variant}.zip"
            dst = OUT / f"{p}-{variant}.zip"
            src = f"{NS}/{remote}" if NS else remote
            _sh(["kubectl", *p3._ns_args(NS), "cp", src, str(dst)])
            cdir = OUT / p / variant
            cdir.mkdir(parents=True, exist_ok=True)
            if dst.is_file():
                try:
                    with zipfile.ZipFile(dst) as zf: zf.extractall(cdir)
                except Exception as ex:
                    print(f"  WARN unzip {dst}: {ex}")
            n = sum(1 for _ in cdir.rglob("*") if _.is_file())
            print(f"  pulled {p}/{variant}: {n} files")
    _sh(["kubectl", *p3._ns_args(NS), "delete", "pod", pod, "--wait=false",
         "--ignore-not-found"])


# --- Step 2: replay each corpus on the BASELINE binary, parse cov/ft -------------
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
    # last "cov: X ft: Y" libFuzzer line wins (after whole corpus loaded)
    for m in re.finditer(r"cov:\s*(\d+)\s+ft:\s*(\d+)", blob):
        cov, ft = int(m.group(1)), int(m.group(2))
    mu = re.search(r"stat::number_of_executed_units:\s*(\d+)", blob)
    if mu: units = int(mu.group(1))
    return {"cov": cov, "ft": ft, "executed_units": units}


def replay():
    rows = []
    for e in manifest():
        p, cve, ft = e["project"], e["cve"], e.get("fuzz_target", "")
        bin_dir = Path(config.RESULTS_DIR) / SRC_EXP / p3.cve_key(p, cve) / "baseline" / "bin"
        if not (bin_dir / ft).is_file():
            print(f"  SKIP {p}: baseline binary missing"); continue
        bc = OUT / p / "baseline"
        oc = OUT / p / "optimized"
        try:
            rb = _cov(bin_dir, bc, ft) if any(bc.rglob("*")) else {"cov": None}
        except Exception as ex:
            print(f"  WARN {p} baseline-corpus replay failed: {ex}"); rb = {"cov": None}
        try:
            ro = _cov(bin_dir, oc, ft) if any(oc.rglob("*")) else {"cov": None}
        except Exception as ex:
            print(f"  WARN {p} optimized-corpus replay failed: {ex}"); ro = {"cov": None}
        nb = sum(1 for _ in bc.rglob("*") if _.is_file()) if bc.is_dir() else 0
        no = sum(1 for _ in oc.rglob("*") if _.is_file()) if oc.is_dir() else 0
        ratio = (ro["cov"] / rb["cov"]) if (rb.get("cov") and ro.get("cov")) else None
        rows.append({"project": p, "baseline_corpus_files": nb,
                     "optimized_corpus_files": no,
                     "cov_baseline_corpus": rb.get("cov"), "ft_baseline_corpus": rb.get("ft"),
                     "cov_optimized_corpus": ro.get("cov"), "ft_optimized_corpus": ro.get("ft"),
                     "opt_over_base_cov_ratio": ratio})
        print(f"  {p:12s} files b/o={nb}/{no}  cov(base corpus)={rb.get('cov')}  "
              f"cov(opt corpus)={ro.get('cov')}  ratio={ratio}")
    OUT.mkdir(exist_ok=True)
    json.dump(rows, open(OUT / "covdiff_results.json", "w"), indent=2)
    print(f"\nwrote {OUT/'covdiff_results.json'}")
    print("\n== Coverage on the BASELINE binary (edges) ==")
    print(f"{'project':12s} {'base-corpus cov':>16s} {'opt-corpus cov':>15s} {'opt/base':>9s}")
    for r in rows:
        rr = f"{r['opt_over_base_cov_ratio']:.3f}" if r['opt_over_base_cov_ratio'] else "n/a"
        print(f"{r['project']:12s} {str(r['cov_baseline_corpus']):>16s} "
              f"{str(r['cov_optimized_corpus']):>15s} {rr:>9s}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--replay", action="store_true")
    a = ap.parse_args()
    if not (a.pull or a.replay):
        ap.error("pass --pull and/or --replay")
    if a.pull: pull()
    if a.replay: replay()
