#!/usr/bin/env python3
"""Per-line execution counts for baseline vs optimized queues, on the BASELINE.

Fuzz Introspector shows, for one target, how many times each source line was
executed by a corpus. This does the same for both arms of a campaign and
aggregates over trials: cumulative (summed across trials) and average (mean per
trial), per source line.

Everything is measured on ONE binary: a coverage build of the pristine baseline
source. Each arm's accumulated AFL queue is replayed through it. So the question
answered is

    "what did each arm's corpus execute, in the ORIGINAL program?"

which is directly comparable between arms and between trials, because every
number refers to the same line of the same source. Measuring each arm on its own
binary would answer a different question and would not be comparable at all: the
folds insert, delete and move lines, so `parser.c:412` is a different line in
each optimized tree -- and with per-trial optimizers it differs between trials of
the same arm too. This mirrors what `coverage_growth.py` already does for edge
coverage, one level finer.

What this does NOT measure: how often the OPTIMIZED binary executes a line. That
is unobservable on a common instrument, by construction.

Why a separate build at all: the campaign's binaries are AFL+ASan builds whose
edge bitmap gives hit buckets, not counts. Execution counts need an llvm
source-based coverage build (-fprofile-instr-generate -fcoverage-mapping), which
OSS-Fuzz produces with SANITIZER=coverage.

Usage:
  python3 line_exec_counts.py --experiment online-24h-c2-libxml2 --trials 0
  python3 line_exec_counts.py --experiment online-24h-c2-libxml2 --jobs 4
  python3 line_exec_counts.py --experiment online-24h-c2-libxml2 --reuse
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("line_exec_counts")

RESULTS = Path(os.environ.get("BENCH_RESULTS", "/home/sefcom/fuzz-opt/results"))
# The coverage build and merged profiles are cached between runs; the build is a
# full project compile, so never redo one silently.
CACHE = Path(os.environ.get("LINE_COV_CACHE", "/home/sefcom/fuzz-opt/.linecov"))


def scope_cache(cve: str) -> Path:
    """Scope the cache to one target.

    Without this the coverage build, profiles and counts of every project share
    one directory, so `--reuse` on a second experiment silently measures the
    FIRST project's binary -- line numbers from the wrong program, reported
    without any error. Keyed by the campaign's cve dir, which is unique per
    target and per ARVO/FuzzBench id.
    """
    global CACHE
    CACHE = CACHE / cve
    return CACHE


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def discover(experiment: str) -> dict:
    """Locate the arms, trials and accumulated queues of a campaign."""
    root = RESULTS / experiment
    if not root.is_dir():
        raise SystemExit(f"no such experiment: {root}")
    cves = [d for d in sorted(root.iterdir()) if (d / "optimized").is_dir()]
    if not cves:
        raise SystemExit(f"no <cve>/optimized under {root}")
    cve = cves[0]

    def queues(arm: str) -> dict[int, Path]:
        out = {}
        for d in sorted((cve / arm).glob("trial_*")):
            q = d / "afl_out" / "default" / "queue"
            if q.is_dir() and any(q.iterdir()):
                out[int(d.name.split("_")[1])] = q
        return out

    info = {
        "experiment": experiment,
        "cve": cve.name,
        "root": cve,
        "baseline_queues": queues("baseline"),
        "optimized_queues": queues("optimized"),
    }
    prov = cve / "optimized" / "online" / "campaign_provenance.json"
    if prov.is_file():
        try:
            info["provenance"] = json.loads(prov.read_text())
        except ValueError:
            pass
    return info


def resolve_image(cve_name: str, override: str = "") -> str:
    """Pick the project image, exact match first, and never guess between several.

    Several ARVO ids of the same project are usually present at once (three
    libxml2 images, two harfbuzz, lcms vs little-cms). A substring match silently
    selects the wrong *version* of the project, producing a coverage build whose
    line numbers do not correspond to the campaign's source -- wrong numbers that
    look entirely plausible.
    """
    if override:
        return override
    out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                         capture_output=True, text=True).stdout
    images = [l.strip() for l in out.splitlines() if l.startswith("bench-aflpp/")]

    exact = f"bench-aflpp/{cve_name.lower()}:latest"
    if exact in images:
        return exact

    # Campaign dirs are "<project>-<suite>-<id>" where suite is arvo, fuzzbench
    # or CVE, and the image may use a DIFFERENT suite token for the same target
    # (mruby-fuzzbench-900026 is built as bench-aflpp/mruby-arvo-900026). So
    # split the suite off both sides and match on project plus id.
    def split_name(n: str) -> tuple[str, str]:
        m = re.match(r"^(.*?)-(?:arvo|fuzzbench|CVE)-(.+)$", n, re.I)
        return (m.group(1).lower(), m.group(2).lower()) if m else (n.lower(), "")

    project, ident = split_name(cve_name)
    parsed = [(i, *split_name(i.split("/", 1)[1].split(":")[0])) for i in images]

    if ident:
        byid = [i for i, pr, idd in parsed if pr == project and idd == ident]
        if len(byid) == 1:
            return byid[0]
    cands = [i for i, pr, _ in parsed if pr == project]
    if len(cands) == 1:
        return cands[0]
    if cands:
        raise SystemExit(
            f"{len(cands)} images match project {project!r} and none is named "
            f"{cve_name!r} exactly: {cands}. Pass --image to choose.")
    raise SystemExit(f"no bench-aflpp image for project {project!r}; pass --image")


# --------------------------------------------------------------------------- #
# Coverage build (once) + replay (per arm/trial)
# --------------------------------------------------------------------------- #
def _run(cmd, timeout, label):
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                       timeout=timeout)
    if r.returncode != 0:
        tail = ((r.stdout or "") + (r.stderr or ""))[-1500:]
        raise RuntimeError(f"{label} failed (rc={r.returncode}):\n{tail}")
    return r


def coverage_build(image: str, out: Path, cpu: str, timeout: int = 5400) -> None:
    """OSS-Fuzz `compile` with SANITIZER=coverage, on the image's pristine source.

    No source is mounted: this is deliberately the unmodified baseline program,
    the common instrument every arm is measured on.
    """
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm", "--privileged", "--ulimit", "core=0"]
    if cpu:
        cmd += ["--cpuset-cpus", cpu]
    cmd += [
        # Coverage builds are a libFuzzer-engine concept in OSS-Fuzz: `compile`
        # keys off SANITIZER=coverage to add -fprofile-instr-generate
        # -fcoverage-mapping, and the target then takes a corpus directory with
        # -runs=0, which is exactly the replay needed here.
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", "SANITIZER=coverage",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{out.resolve()}:/out",
        # `compile` runs as root, so hand /out back or the cache becomes
        # unremovable from the host and a later rm -rf fails halfway, leaving a
        # half-deleted build that still looks cached.
        "--entrypoint", "/bin/bash", image, "-lc",
        f"compile && chown -R {os.getuid()}:{os.getgid()} /out",
    ]
    _run(cmd, timeout, f"coverage build -> {out}")


def replay_for_profile(image: str, out: Path, queue: Path, prof: Path,
                       target: str, cpu: str, timeout: int = 7200,
                       chunk: int = 400) -> None:
    """Replay one accumulated queue through the baseline coverage binary."""
    prof.mkdir(parents=True, exist_ok=True)
    for stale in prof.glob("*.profraw"):
        stale.unlink()
    cmd = ["docker", "run", "--rm", "--privileged", "--ulimit", "core=0"]
    if cpu:
        cmd += ["--cpuset-cpus", cpu]
    cmd += [
        "-e", "LLVM_PROFILE_FILE=/prof/%m-%p.profraw",
        # A crashing or leaking input must not abort the replay: that would
        # silently truncate the corpus and undercount every later line.
        "-e", "ASAN_OPTIONS=detect_leaks=0:symbolize=0",
        "-v", f"{out.resolve()}:/out:ro",
        "-v", f"{queue.resolve()}:/queue:ro",
        "-v", f"{prof.resolve()}:/prof",
        "--entrypoint", "/bin/bash", image, "-lc",
        # Replay in CHUNKS of explicit files rather than handing libFuzzer the
        # whole directory. A queue from a bug-finding campaign contains inputs
        # that crash the target, and a hard crash skips LLVM's atexit profile
        # write -- one crashing input then costs the ENTIRE trial's counts
        # (observed on mruby: zero .profraw for every trial). Chunking confines
        # that loss to the rest of one batch, and `|| true` keeps the loop
        # going. %p in LLVM_PROFILE_FILE gives each batch its own file.
        #
        # The directory is also too large to pass as one argv (15k+ files hits
        # ARG_MAX), so xargs does the splitting either way.
        #
        # Cost of chunking: per-process one-time init is counted once per batch
        # instead of once per trial. At the default batch size that is amortised
        # over several hundred inputs; raise --chunk if a target's init is heavy.
        f"find /queue -type f -print0 | xargs -0 -r -n {chunk} "
        f"sh -c '\"$0\" \"$@\" -rss_limit_mb=4096 -timeout=25 "
        f">/dev/null 2>&1 || true' /out/{target}; "
        "n=$(ls /prof/*.profraw 2>/dev/null | wc -l); "
        'echo "profraw_batches=$n"; [ "$n" -gt 0 ]',
    ]
    r = _run(cmd, timeout, f"replay -> {prof}")
    logger.debug("%s", (r.stdout or "").strip().splitlines()[-1:])


def export_line_counts(image: str, out: Path, prof: Path, target: str,
                       timeout: int = 1800) -> dict[str, dict[int, int]]:
    """Merge profraws and export per-line execution counts.

    llvm-cov's export gives per-file `segments` of
    [line, col, count, hasCount, isRegionEntry, isGapRegion]. A line's count is
    the max over segments starting on it -- the rule `llvm-cov show` displays and
    what Introspector reports per line.
    """
    script = (
        "set -e; "
        "find /prof -name '*.profraw' > /prof/raw.list; "
        "llvm-profdata merge -sparse --input-files=/prof/raw.list "
        "-o /prof/merged.profdata; "
        f"llvm-cov export -instr-profile=/prof/merged.profdata /out/{target} "
        "> /prof/cov.json"
    )
    cmd = ["docker", "run", "--rm",
           "-v", f"{out.resolve()}:/out:ro",
           "-v", f"{prof.resolve()}:/prof",
           "--entrypoint", "/bin/bash", image, "-lc", script]
    _run(cmd, timeout, f"llvm-cov export <- {prof}")

    data = json.loads((prof / "cov.json").read_text())
    per_file: dict[str, dict[int, int]] = {}
    for export in data.get("data", []):
        for f in export.get("files", []):
            path, lines = f.get("filename", ""), {}
            for seg in f.get("segments", []):
                if len(seg) < 4 or not seg[3]:
                    continue
                line, count = int(seg[0]), int(seg[2])
                if count > lines.get(line, -1):
                    lines[line] = count
            if lines:
                per_file[path] = lines
    return per_file


def measure(image: str, arm: str, trial: int, queue: Path, build: Path,
            target: str, cpu: str, reuse: bool, chunk: int = 400) -> dict:
    """Replay one (arm, trial) queue through the shared baseline build."""
    tag = f"{arm}_trial_{trial:02d}"
    prof = CACHE / "prof" / tag
    counts_file = CACHE / "counts" / f"{tag}.json"
    counts_file.parent.mkdir(parents=True, exist_ok=True)
    n_files = sum(1 for _ in queue.iterdir())

    if reuse and counts_file.is_file():
        logger.info("%s: reusing cached counts", tag)
        return {"arm": arm, "trial": trial, "queue_files": n_files,
                "counts": {k: {int(n): c for n, c in v.items()}
                           for k, v in json.loads(counts_file.read_text()).items()}}

    logger.info("%s: replaying %d queue files", tag, n_files)
    replay_for_profile(image, build, queue, prof, target, cpu, chunk=chunk)
    counts = export_line_counts(image, build, prof, target)
    counts_file.write_text(json.dumps({k: {str(n): c for n, c in v.items()}
                                       for k, v in counts.items()}))
    return {"arm": arm, "trial": trial, "counts": counts, "queue_files": n_files}


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def aggregate(results: list[dict]) -> dict:
    """Cumulative (sum over trials) and average (mean over trials) per line.

    Safe to sum across trials and compare across arms: every count refers to the
    same line of the same baseline source.
    """
    by_arm: dict[str, list[dict]] = collections.defaultdict(list)
    for r in results:
        by_arm[r["arm"]].append(r)

    agg: dict = {}
    for arm, runs in by_arm.items():
        runs = sorted(runs, key=lambda r: r["trial"])
        order = [r["trial"] for r in runs]
        n = len(runs)
        # per_trial[path][line] = [count for each trial, in `order`]; a trial that
        # never executed the line contributes 0, which is what makes
        # trials_covered meaningful.
        per_trial: dict[str, dict[int, list[int]]] = collections.defaultdict(dict)
        for i, r in enumerate(runs):
            for path, lines in r["counts"].items():
                bucket = per_trial[path]
                for line, count in lines.items():
                    vec = bucket.get(line)
                    if vec is None:
                        vec = bucket[line] = [0] * n
                    vec[i] = count

        files = {}
        for path in sorted(per_trial):
            out = {}
            for line in sorted(per_trial[path]):
                vec = per_trial[path][line]
                cum = sum(vec)
                covered = sum(1 for v in vec if v > 0)
                out[str(line)] = {
                    "cumulative": cum,
                    # Mean over ALL trials in the arm, not only the ones that
                    # covered the line: "executions per trial" is the question,
                    # and dividing by the covering subset would overstate a line
                    # that only one trial ever reached.
                    "average": cum / n,
                    "trials_covered": covered,
                    "per_trial": vec,
                }
            files[path] = out

        agg[arm] = {
            "trials": order,
            "n_trials": n,
            "queue_files_total": sum(r["queue_files"] for r in runs),
            "files": files,
        }
    return agg


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def load_sources(build: Path, paths: set[str]) -> dict[str, list[str]]:
    """Source text from the coverage build's own /out/src copy.

    Using the compiled copy rather than a host tree guarantees the text lines up
    with the line numbers llvm-cov reported.
    """
    got: dict[str, list[str]] = {}
    for cov_path in paths:
        local = build / cov_path.lstrip("/")
        try:
            if local.is_file():
                got[cov_path] = local.read_text(errors="replace").splitlines()
        except OSError:
            continue
    return got


def write_report(agg: dict, info: dict, dest: Path, target: str, top: int) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "line_counts.json").write_text(json.dumps(
        {"experiment": info["experiment"], "cve": info["cve"], "target": target,
         "measured_on": "baseline coverage build (common instrument)",
         "provenance": info.get("provenance"), "arms": agg}, indent=2))

    out = []
    w = out.append
    w(f"Per-line execution counts — {info['experiment']} / {info['cve']}")
    prov = (info.get("provenance") or {}).get("optimizer") or {}
    if prov:
        w(f"optimizer: {prov.get('model')} (pinned={prov.get('model_pinned')}) "
          f"effort={prov.get('reasoning_effort')}")
    w("")
    w("Both arms replayed through ONE coverage build of the pristine baseline, so")
    w("every count refers to the same line of the same source and the arms are")
    w("directly comparable. This is what each arm's corpus executed IN THE")
    w("ORIGINAL program -- not how often the optimized binary ran a line.")
    w("")
    for arm, a in sorted(agg.items()):
        tot = sum(v["cumulative"] for f in a["files"].values() for v in f.values())
        nlines = sum(len(f) for f in a["files"].values())
        w(f"[{arm}] trials={a['n_trials']} {a['trials']}  "
          f"queue_files={a['queue_files_total']}  "
          f"lines_with_counts={nlines}  total_line_executions={tot:,}")
        hot = sorted(((v["cumulative"], v["average"], path, line)
                      for path, f in a["files"].items() for line, v in f.items()),
                     reverse=True)[:top]
        for cum, avg, path, line in hot:
            w(f"    {cum:>14,}  avg/trial {avg:>12,.0f}  {path}:{line}")
        w("")

    if len(agg) == 2:
        a, b = sorted(agg)
        w(f"Largest per-line differences ({b} minus {a}, cumulative):")
        diffs = []
        for path in set(agg[a]["files"]) | set(agg[b]["files"]):
            fa, fb = agg[a]["files"].get(path, {}), agg[b]["files"].get(path, {})
            for line in set(fa) | set(fb):
                va = fa.get(line, {}).get("cumulative", 0)
                vb = fb.get(line, {}).get("cumulative", 0)
                if va or vb:
                    diffs.append((vb - va, va, vb, path, line))
        diffs.sort(key=lambda d: -abs(d[0]))
        for d, va, vb, path, line in diffs[:top]:
            w(f"    {d:>+15,}   {a}={va:,}  {b}={vb:,}   {path}:{line}")
        w("")
    (dest / "line_counts.txt").write_text("\n".join(out))
    print("\n".join(out))


def write_html(agg: dict, info: dict, sources: dict, dest: Path, target: str,
               max_files: int) -> Path:
    import html as _html

    arms = sorted(agg)
    totals: dict[str, int] = collections.defaultdict(int)
    for arm in arms:
        for path, lines in agg[arm]["files"].items():
            totals[path] += sum(v["cumulative"] for v in lines.values())
    ranked = sorted(totals, key=lambda p: -totals[p])[:max_files]

    payload = {"arms": arms, "files": {}}
    for path in ranked:
        payload["files"][path] = {
            "arms": {a: agg[a]["files"].get(path, {}) for a in arms},
            "src": sources.get(path, []),
        }
    prov = (info.get("provenance") or {}).get("optimizer") or {}
    meta = {"experiment": info["experiment"], "cve": info["cve"], "target": target,
            "optimizer": prov,
            "arms": {a: {"trials": agg[a]["trials"], "n_trials": agg[a]["n_trials"],
                         "queue_files_total": agg[a]["queue_files_total"]}
                     for a in arms}}

    doc = """<!doctype html><meta charset="utf-8">
<title>Line execution counts — @@CVE@@</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#6b7280;--line:#e5e7eb;--up:#b91c1c;--dn:#047857;--note:#92400e;--notebg:#fef3c7}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#9aa0a6;--line:#2a2f3a;--up:#f87171;--dn:#34d399;--note:#fcd34d;--notebg:#3b2f0b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,sans-serif}
header{padding:13px 18px;border-bottom:1px solid var(--line)}
h1{margin:0 0 3px;font-size:17px}.sub{color:var(--mut);font-size:12.5px}
.note{background:var(--notebg);color:var(--note);padding:7px 18px;font-size:12.5px;border-bottom:1px solid var(--line)}
.wrap{display:flex;min-height:calc(100vh - 128px)}
nav{width:330px;min-width:220px;border-right:1px solid var(--line);overflow:auto;max-height:calc(100vh - 128px)}
nav .f{padding:7px 12px;border-bottom:1px solid var(--line);cursor:pointer;font-size:12.5px}
nav .f:hover{background:rgba(125,125,125,.12)}nav .f.sel{background:rgba(125,125,125,.2);font-weight:600}
nav .p{word-break:break-all}nav .n{color:var(--mut);font-variant-numeric:tabular-nums}
main{flex:1;overflow:auto;max-height:calc(100vh - 128px)}
.bar{padding:8px 14px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap;font-size:12.5px}
table{border-collapse:collapse;width:100%}
th{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);font-size:11px;color:var(--mut);text-align:right;padding:5px 8px;white-space:nowrap}
th.s{text-align:left}
td{padding:1px 8px;vertical-align:top;white-space:pre;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
td.ln{text-align:right;color:var(--mut);user-select:none;width:1%}
td.c{text-align:right;font-variant-numeric:tabular-nums;width:1%}
td.src{width:100%}
.up{color:var(--up)}.dn{color:var(--dn)}.z{color:var(--mut);opacity:.4}
@media(max-width:780px){.wrap{flex-direction:column}nav{width:auto;max-height:200px}}
</style>
<header><h1>Per-line execution counts — @@CVE@@</h1><div class="sub" id="meta"></div></header>
<div class="note">Both arms replayed through one coverage build of the <b>pristine baseline</b>.
Counts are what each arm's accumulated queue executed <b>in the original program</b> — directly
comparable. They are not how often the optimized binary ran a line.</div>
<div class="wrap"><nav id="nav"></nav><main>
<div class="bar">
  <label><input type="checkbox" id="only" checked> only executed lines</label>
  <label><input type="checkbox" id="diffonly"> only lines that differ</label>
  <span class="sub" id="fstat"></span>
</div>
<div id="code"></div></main></div>
<script>
const DATA=@@PAYLOAD@@, META=@@META@@, $=i=>document.getElementById(i);
const A=DATA.arms, paths=Object.keys(DATA.files);
$('meta').textContent=META.experiment+" · target "+META.target+" · "+
 A.map(a=>a+": "+META.arms[a].n_trials+" trials, "+META.arms[a].queue_files_total.toLocaleString()+" queue files").join("  ·  ")+
 (META.optimizer&&META.optimizer.model?"  ·  optimizer "+META.optimizer.model+" effort="+META.optimizer.reasoning_effort:"");
const tot=(p,a)=>{let t=0;const m=DATA.files[p].arms[a]||{};for(const k in m)t+=m[k].cumulative;return t};
let sel=paths[0];
function nav(){$('nav').innerHTML='';paths.forEach(p=>{const d=document.createElement('div');
 d.className='f';d.dataset.p=p;
 d.innerHTML='<div class="p">'+p.replace(/^.*\\/src\\//,'')+'</div><div class="n">'+
   A.map(a=>a[0]+': '+tot(p,a).toLocaleString()).join(' · ')+'</div>';
 d.onclick=()=>{sel=p;draw()};$('nav').appendChild(d)})}
function draw(){
 const F=DATA.files[sel], src=F.src;
 [...$('nav').children].forEach(c=>c.classList.toggle('sel',c.dataset.p===sel));
 if(!src||!src.length){$('code').innerHTML='<p style="padding:14px" class="sub">No source available for this file.</p>';return}
 let max=0;A.forEach(a=>{const m=F.arms[a]||{};for(const k in m)max=Math.max(max,m[k].cumulative)});
 const lg=Math.log10(max+1)||1, only=$('only').checked, dOnly=$('diffonly').checked;
 const esc=s=>s.replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));
 let h='<table><thead><tr><th>line</th>';
 A.forEach(a=>{h+='<th>'+a+' cum</th><th>'+a+' avg</th>'});
 if(A.length===2)h+='<th>&Delta;</th>';
 h+='<th class="s">source</th></tr></thead><tbody>';
 src.forEach((text,i)=>{
  const n=i+1, cs=A.map(a=>(F.arms[a]||{})[n]||null);
  const any=cs.some(c=>c&&c.cumulative>0);
  if(only&&!any)return;
  let d=null;
  if(A.length===2){const x=cs[0]?cs[0].cumulative:0,y=cs[1]?cs[1].cumulative:0;d=y-x}
  if(dOnly&&!d)return;
  h+='<tr><td class="ln">'+n+'</td>';
  cs.forEach(c=>{
   const v=c?c.cumulative:null;
   const heat=v?Math.min(.5,Math.log10(v+1)/lg*0.5):0;
   h+='<td class="c" style="'+(v?'background:rgba(220,70,40,'+heat.toFixed(3)+')':'')+'">'+
      (v===null?'':v.toLocaleString())+'</td>';
   h+='<td class="c '+(c?'':'z')+'">'+(c?Math.round(c.average).toLocaleString():'')+'</td>'});
  if(A.length===2)h+='<td class="c '+(d>0?'up':d<0?'dn':'z')+'">'+(d?(d>0?'+':'')+d.toLocaleString():'')+'</td>';
  h+='<td class="src">'+esc(text)+'</td></tr>'});
 h+='</tbody></table>';
 $('code').innerHTML=h;
 $('fstat').textContent=sel+' — '+A.map(a=>a+' '+tot(sel,a).toLocaleString()).join(' · ');
}
$('only').onchange=draw;$('diffonly').onchange=draw;nav();draw();
</script>"""
    for tok, val in (("@@CVE@@", _html.escape(info["cve"])),
                     ("@@PAYLOAD@@", json.dumps(payload)),
                     ("@@META@@", json.dumps(meta))):
        doc = doc.replace(tok, val)
    out = dest / "line_counts.html"
    out.write_text(doc)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--image", default="", help="override the project image")
    ap.add_argument("--target", default="", help="fuzz target (default: from provenance)")
    ap.add_argument("--arms", default="baseline,optimized")
    ap.add_argument("--trials", default="", help="comma list, e.g. 0,1,2 (default: all)")
    ap.add_argument("--jobs", type=int, default=2, help="concurrent replays")
    ap.add_argument("--cpus", default="", help="cpuset for each container, e.g. 20-29")
    ap.add_argument("--chunk", type=int, default=400,
                    help="queue files per replay process; smaller confines "
                         "the loss from a crashing input, larger amortises "
                         "per-process init (default 400)")
    ap.add_argument("--reuse", action="store_true", help="reuse cached build and counts")
    ap.add_argument("--top", type=int, default=25, help="hottest lines to print per arm")
    ap.add_argument("--no-html", action="store_true")
    ap.add_argument("--html-max-files", type=int, default=60)
    ap.add_argument("--out", default="", help="report dir (default: <results>/<exp>/line_counts)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    info = discover(args.experiment)
    image = resolve_image(info["cve"], args.image)
    scope_cache(info["cve"])

    # Projects can ship several fuzz targets (libxml2 has two), so prefer the
    # one the campaign recorded over anything inferred, and refuse rather than
    # pick when that is missing.
    target = args.target or (info.get("provenance") or {}).get("fuzz_target", "")
    if not target:
        raise SystemExit("campaign_provenance.json records no fuzz_target; pass --target")

    want = ([int(x) for x in args.trials.split(",") if x.strip() != ""]
            if args.trials else None)
    units = []
    for arm in [a.strip() for a in args.arms.split(",") if a.strip()]:
        for trial, q in sorted(info[f"{arm}_queues"].items()):
            if want is None or trial in want:
                units.append((arm, trial, q))
    if not units:
        raise SystemExit("nothing to measure (check --arms/--trials)")

    build = CACHE / "build" / "baseline"
    if not (args.reuse and (build / target).is_file()):
        logger.info("coverage build of pristine baseline (one build for all arms)")
        coverage_build(image, build, args.cpus)
    if not (build / target).is_file():
        raise SystemExit(f"coverage build produced no /out/{target}")
    logger.info("image=%s target=%s units=%d", image, target, len(units))

    results, failures = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = {ex.submit(measure, image, arm, trial, q, build, target,
                          args.cpus, args.reuse, args.chunk): (arm, trial)
                for arm, trial, q in units}
        for fut in concurrent.futures.as_completed(futs):
            arm, trial = futs[fut]
            try:
                results.append(fut.result())
            except Exception as exc:                      # noqa: BLE001
                logger.error("%s trial %d FAILED: %s", arm, trial, exc)
                failures.append((arm, trial, str(exc)))
    if not results:
        raise SystemExit("every unit failed; see errors above")

    dest = Path(args.out) if args.out else (RESULTS / args.experiment / "line_counts")
    agg = aggregate(results)
    write_report(agg, info, dest, target, args.top)
    if not args.no_html:
        paths = {p for a in agg.values() for p in a["files"]}
        htm = write_html(agg, info, load_sources(build, paths), dest, target,
                         args.html_max_files)
        logger.info("HTML report: %s", htm)
    if failures:
        (dest / "failures.json").write_text(json.dumps(failures, indent=2))
        logger.warning("%d unit(s) failed; see %s/failures.json", len(failures), dest)
    logger.info("wrote %s", dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
