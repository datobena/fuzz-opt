#!/usr/bin/env python3
"""Introspector-style interactive report: call paths, coverage, executions.

Builds the three views OSS-Fuzz Fuzz Introspector gives you, for BOTH arms of a
campaign at once:

  overview    reached vs unreached functions, region coverage, totals per arm
  functions   sortable table: per-function execution counts (cumulative and
              average per trial), region coverage, reachability
  call paths  the static call tree from LLVMFuzzerTestOneInput, each node
              annotated with how often it actually ran -- a node reachable but
              never executed is a fuzz blocker, which is the view Introspector
              is most used for
  source      per-line execution counts beside the source text

Everything is measured on ONE instrument: a coverage build of the pristine
baseline. Each arm's accumulated AFL queue is replayed through it, so every
number refers to the same line and the same function of the same source, and the
arms are directly comparable. See line_exec_counts.py for why that matters.

The call graph is STATIC, recovered from the binary's direct call instructions
(objdump). It therefore misses indirect/virtual calls and includes edges that
no input ever takes -- which is exactly why each node carries its measured
execution count: static reachability says what COULD run, the counts say what
DID.

Usage:
  python3 introspector.py --experiment online-24h-c2-libxml2 --trials 0 --reuse
  python3 introspector.py --experiment online-24h-c2-libxml2 --jobs 4
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import line_exec_counts as lec  # noqa: E402

logger = logging.getLogger("introspector")
ENTRY = "LLVMFuzzerTestOneInput"

_FUNC_RE = re.compile(r"^[0-9a-f]+ <(.+)>:$")
_CALL_RE = re.compile(
    r"^\s+[0-9a-f]+:\s+(?:call|jmp)\w*\s+[0-9a-f]+ <([^>+]+)(?:\+0x[0-9a-f]+)?>")


# --------------------------------------------------------------------------- #
# Static call graph
# --------------------------------------------------------------------------- #
def call_graph(binary: Path) -> dict[str, list[str]]:
    """Direct-call edges recovered from the binary's disassembly.

    Tail-call-optimised calls show up as `jmp <sym>`, so both are counted. PLT
    thunks are collapsed onto the symbol they forward to, otherwise every libc
    call would appear as a distinct `foo@plt` leaf.
    """
    out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(binary)],
                         capture_output=True, text=True, errors="replace").stdout
    edges: dict[str, set[str]] = collections.defaultdict(set)
    cur = None
    for line in out.splitlines():
        m = _FUNC_RE.match(line)
        if m:
            cur = m.group(1)
            continue
        c = _CALL_RE.match(line)
        if c and cur:
            target = c.group(1).replace("@plt", "")
            if target != cur:
                edges[cur].add(target)
    return {k: sorted(v) for k, v in edges.items()}


def reachable_from(edges: dict[str, list[str]], entry: str) -> set[str]:
    seen, stack = {entry}, [entry]
    while stack:
        for t in edges.get(stack.pop(), ()):
            if t not in seen:
                seen.add(t)
                stack.append(t)
    return seen


def demangle(names: list[str]) -> dict[str, str]:
    """Best-effort C++ demangling for display; identity if c++filt is missing."""
    mangled = [n for n in names if n.startswith("_Z")]
    if not mangled:
        return {}
    try:
        r = subprocess.run(["c++filt", "-n"], input="\n".join(mangled),
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return {}
        return dict(zip(mangled, r.stdout.splitlines()))
    except (OSError, subprocess.SubprocessError):
        return {}


# --------------------------------------------------------------------------- #
# Per-function coverage, read from the cov.json the replay already produced
# --------------------------------------------------------------------------- #
def function_counts(prof: Path) -> dict[str, dict]:
    """{function: {count, regions_total, regions_covered, file}} for one replay."""
    cov = prof / "cov.json"
    if not cov.is_file():
        return {}
    data = json.loads(cov.read_text())
    out: dict[str, dict] = {}
    for export in data.get("data", []):
        for fn in export.get("functions", []):
            name = fn.get("name", "")
            regions = fn.get("regions", [])
            covered = sum(1 for r in regions if len(r) > 4 and r[4] > 0)
            prev = out.get(name)
            rec = {
                "count": int(fn.get("count", 0)),
                "regions_total": len(regions),
                "regions_covered": covered,
                "file": (fn.get("filenames") or [""])[0],
            }
            # A name can appear more than once (inlined into several TUs); keep
            # the most-executed instance rather than an arbitrary one.
            if prev is None or rec["count"] > prev["count"]:
                out[name] = rec
    return out


def aggregate_functions(per_trial: list[tuple[str, int, dict]]) -> dict:
    """Cumulative and average per-function counts, per arm."""
    by_arm: dict[str, list[dict]] = collections.defaultdict(list)
    for arm, _trial, fns in per_trial:
        by_arm[arm].append(fns)
    agg: dict[str, dict] = {}
    for arm, runs in by_arm.items():
        n = len(runs)
        acc: dict[str, dict] = {}
        for fns in runs:
            for name, rec in fns.items():
                a = acc.setdefault(name, {"cumulative": 0, "regions_total": 0,
                                          "regions_covered": 0, "file": rec["file"],
                                          "trials_covered": 0, "per_trial": []})
                a["cumulative"] += rec["count"]
                a["per_trial"].append(rec["count"])
                if rec["count"] > 0:
                    a["trials_covered"] += 1
                a["regions_total"] = max(a["regions_total"], rec["regions_total"])
                a["regions_covered"] = max(a["regions_covered"], rec["regions_covered"])
        for a in acc.values():
            # Mean over every trial in the arm, including those that never
            # reached the function -- "executions per trial", not "per trial
            # that happened to reach it".
            a["average"] = a["cumulative"] / n
            a["n_trials"] = n
        agg[arm] = acc
    return agg


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def build_payload(fn_agg: dict, line_agg: dict, edges: dict, reach: set,
                  sources: dict, names_demangled: dict, max_files: int,
                  max_funcs: int) -> dict:
    arms = sorted(fn_agg)
    all_names = set()
    for arm in arms:
        all_names |= set(fn_agg[arm])
    # Keep what a reader can act on: anything reachable from the entry, or
    # anything that actually executed. Dropping the rest keeps the page small
    # without hiding a single line that ran.
    keep = {n for n in all_names
            if n in reach or any(fn_agg[a].get(n, {}).get("cumulative", 0)
                                 for a in arms)}
    ranked = sorted(keep, key=lambda n: -max(
        fn_agg[a].get(n, {}).get("cumulative", 0) for a in arms))[:max_funcs]
    keep = set(ranked)

    funcs = []
    for n in ranked:
        row = {"n": n, "d": names_demangled.get(n, n), "r": n in reach}
        for a in arms:
            rec = fn_agg[a].get(n)
            # [cumulative, average, regions_covered, regions_total,
            #  trials_covered, n_trials]
            row[a] = ([rec["cumulative"], round(rec["average"]),
                       rec["regions_covered"], rec["regions_total"],
                       rec.get("trials_covered", 0), rec.get("n_trials", 0)]
                      if rec else None)
            if rec and not row.get("f"):
                row["f"] = rec["file"]
        funcs.append(row)

    # Edges only among kept nodes, so the tree never dangles.
    cg = {s: [t for t in ts if t in keep] for s, ts in edges.items() if s in keep}

    line_files: dict[str, dict] = {}
    totals: dict[str, int] = collections.defaultdict(int)
    for arm in arms:
        for path, lines in line_agg[arm]["files"].items():
            totals[path] += sum(v["cumulative"] for v in lines.values())
    for path in sorted(totals, key=lambda p: -totals[p])[:max_files]:
        per_arm = {}
        for a in arms:
            n_tr = line_agg[a]["n_trials"]
            per_arm[a] = {ln: [v["cumulative"], round(v["average"]),
                               v.get("trials_covered", 0), n_tr]
                          for ln, v in line_agg[a]["files"].get(path, {}).items()}
        line_files[path] = {"arms": per_arm, "src": sources.get(path, [])}
    diff = coverage_diff(line_agg, arms) if len(arms) == 2 else None
    return {"arms": arms, "funcs": funcs, "cg": cg, "entry": ENTRY,
            "lines": line_files, "diff": diff}


def coverage_diff(line_agg: dict, arms: list[str], top: int = 400) -> dict:
    """Where the two arms' corpora differ, in coverage and in execution count.

    Coverage and execution are separate questions and a line can move on one
    without the other. `only_*` are lines one arm's corpus reached and the
    other's never did -- the coverage difference the optimization caused.
    `breadth` counts lines where the same line was covered by a different NUMBER
    of trials, which is the softer version of the same signal.
    """
    a, b = arms
    fa, fb = line_agg[a]["files"], line_agg[b]["files"]
    only_a, only_b, breadth, execs = [], [], [], []
    for path in set(fa) | set(fb):
        la, lb = fa.get(path, {}), fb.get(path, {})
        for ln in set(la) | set(lb):
            va, vb = la.get(ln), lb.get(ln)
            ca = va["cumulative"] if va else 0
            cb = vb["cumulative"] if vb else 0
            ta = va.get("trials_covered", 0) if va else 0
            tb = vb.get("trials_covered", 0) if vb else 0
            if ca > 0 and cb == 0:
                only_a.append([path, ln, ca, ta])
            elif cb > 0 and ca == 0:
                only_b.append([path, ln, cb, tb])
            elif ta != tb:
                breadth.append([path, ln, ta, tb, ca, cb])
            if ca or cb:
                execs.append([path, ln, ca, cb, cb - ca])
    only_a.sort(key=lambda r: -r[2]); only_b.sort(key=lambda r: -r[2])
    breadth.sort(key=lambda r: -abs(r[3] - r[2]))
    execs.sort(key=lambda r: -abs(r[4]))
    return {"a": a, "b": b,
            "n_only_a": len(only_a), "n_only_b": len(only_b),
            "n_breadth": len(breadth),
            "only_a": only_a[:top], "only_b": only_b[:top],
            "breadth": breadth[:top], "execs": execs[:top]}


HTML = r"""<!doctype html><meta charset="utf-8">
<title>@@TITLE@@</title>
<style>
:root{--bg:#fff;--fg:#17191c;--mut:#6b7280;--line:#e5e7eb;--card:#f8f9fb;--acc:#1d4ed8;
--up:#b91c1c;--dn:#047857;--warn:#92400e;--warnbg:#fef3c7;--cold:#9ca3af}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#9aa0a6;--line:#2a2f3a;
--card:#171a21;--acc:#7aa2f7;--up:#f87171;--dn:#34d399;--warn:#fcd34d;--warnbg:#3b2f0b;--cold:#6b7280}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:14px 18px 0}h1{margin:0 0 3px;font-size:18px}
.sub{color:var(--mut);font-size:12.5px}
.note{background:var(--warnbg);color:var(--warn);padding:7px 18px;font-size:12.5px;margin-top:10px}
nav.tabs{display:flex;gap:2px;padding:10px 18px 0;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tab{padding:7px 14px;border:1px solid var(--line);border-bottom:none;border-radius:7px 7px 0 0;
cursor:pointer;font-size:13px;background:var(--bg);color:var(--mut)}
.tab.on{background:var(--card);color:var(--fg);font-weight:600}
section{display:none;padding:14px 18px}section.on{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:12px 14px}
.card .k{color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:21px;font-weight:650;font-variant-numeric:tabular-nums;margin-top:3px}
.card .s{color:var(--mut);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);
text-align:right;padding:6px 9px;font-size:11px;color:var(--mut);cursor:pointer;white-space:nowrap}
th.l{text-align:left}th:hover{color:var(--fg)}
td{padding:3px 9px;border-bottom:1px solid var(--line);text-align:right;
font-variant-numeric:tabular-nums;white-space:nowrap}
td.l{text-align:left;white-space:normal;word-break:break-word;font:12px ui-monospace,Menlo,monospace}
.bar{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:10px;font-size:12.5px}
input[type=search]{padding:6px 9px;border:1px solid var(--line);border-radius:7px;
background:var(--bg);color:var(--fg);min-width:230px;font:13px system-ui}
.pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid var(--line)}
.hot{background:rgba(220,70,40,.16)}.cold{color:var(--cold)}
.up{color:var(--up)}.dn{color:var(--dn)}
ul.tree{list-style:none;margin:0;padding-left:16px}
ul.tree li{margin:1px 0}
.tw{cursor:pointer;user-select:none;font:12px ui-monospace,Menlo,monospace}
.tw .c{color:var(--mut);font-variant-numeric:tabular-nums}
.blocked{color:var(--cold)}
.srcwrap{display:flex;gap:0}
.flist{width:300px;min-width:180px;border-right:1px solid var(--line);overflow:auto;max-height:72vh}
.flist div{padding:6px 10px;border-bottom:1px solid var(--line);cursor:pointer;font-size:12px}
.flist div:hover{background:rgba(125,125,125,.12)}.flist div.sel{background:rgba(125,125,125,.2);font-weight:600}
.code{flex:1;overflow:auto;max-height:72vh}
.code td{border:none;padding:1px 8px;font:12px/1.45 ui-monospace,Menlo,monospace;white-space:pre}
.code td.src{text-align:left;width:100%}
@media(max-width:820px){.srcwrap{flex-direction:column}.flist{width:auto;max-height:190px}}
</style>
<header><h1>@@TITLE@@</h1><div class="sub" id="meta"></div></header>
<div class="note">All numbers measured on <b>one</b> coverage build of the pristine baseline, with each
arm's accumulated queue replayed through it — so both arms refer to the same line and the same
function. Call edges are <b>static</b> (direct calls recovered from the binary): they say what
<i>could</i> run; the counts say what <i>did</i>.</div>
<nav class="tabs">
  <div class="tab on" data-t="ov">Overview</div>
  <div class="tab" data-t="fn">Functions</div>
  <div class="tab" data-t="cp">Call paths</div>
  <div class="tab" data-t="cd">Coverage diff</div>
  <div class="tab" data-t="src">Source</div>
</nav>
<section id="ov" class="on"><div class="cards" id="cards"></div>
  <div class="sub">Reachability is from <code>@@ENTRY@@</code> over static direct-call edges.
  "Blocked" means statically reachable but never executed by that arm's corpus — the frontier
  Introspector calls a fuzz blocker.</div></section>
<section id="fn">
  <div class="bar"><input type="search" id="q" placeholder="filter functions or files…">
    <label><input type="checkbox" id="onlyreach"> only reachable</label>
    <label><input type="checkbox" id="onlyblocked"> only blocked (never executed)</label>
    <span class="sub" id="fnstat"></span></div>
  <div style="overflow:auto;max-height:74vh"><table id="ftab"></table></div></section>
<section id="cp">
  <div class="bar"><label>depth <select id="depth"></select></label>
    <label><input type="checkbox" id="hideblocked"> hide blocked subtrees</label>
    <span class="sub">click a node to expand · counts are cumulative</span></div>
  <div id="tree" style="overflow:auto;max-height:74vh"></div></section>
<section id="cd">
  <div class="cards" id="dcards"></div>
  <div class="bar"><label>view <select id="dview">
    <option value="execs">biggest execution deltas</option>
    <option value="only_b">covered only by optimized</option>
    <option value="only_a">covered only by baseline</option>
    <option value="breadth">covered by a different number of trials</option>
  </select></label><span class="sub" id="dstat"></span></div>
  <div style="overflow:auto;max-height:70vh"><table id="dtab"></table></div></section>
<section id="src"><div class="srcwrap"><div class="flist" id="flist"></div>
  <div class="code" id="code"></div></div></section>
<script>
const D=@@PAYLOAD@@, M=@@META@@, $=i=>document.getElementById(i);
const A=D.arms, FN=new Map(D.funcs.map(f=>[f.n,f])), fmt=n=>n==null?'':n.toLocaleString();
$('meta').textContent=M.experiment+" · "+M.cve+" · target "+M.target+" · "+
 A.map(a=>a+": "+M.arms[a].n_trials+" trials, "+M.arms[a].queue_files_total.toLocaleString()+" queue files").join("  ·  ")+
 (M.optimizer&&M.optimizer.model?"  ·  optimizer "+M.optimizer.model+" effort="+M.optimizer.reasoning_effort:"");
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
 document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===t));
 document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id===t.dataset.t));});

/* ---------- overview ---------- */
(function(){let h='';
 A.forEach(a=>{
  let ex=0,reach=0,blocked=0,tot=0,rc=0,rt=0;
  D.funcs.forEach(f=>{const v=f[a];if(f.r)reach++;
   if(v){tot+=v[0];rc+=v[2];rt+=v[3];if(v[0]>0)ex++;else if(f.r)blocked++}else if(f.r)blocked++});
  h+='<div class="card"><div class="k">'+a+'</div><div class="v">'+tot.toLocaleString()+
     '</div><div class="s">function executions · '+ex.toLocaleString()+' functions ran</div></div>';
  h+='<div class="card"><div class="k">'+a+' blocked</div><div class="v">'+blocked.toLocaleString()+
     '</div><div class="s">reachable but never executed of '+reach.toLocaleString()+
     ' reachable · regions '+(rt?Math.round(100*rc/rt):0)+'%</div></div>';});
 $('cards').innerHTML=h})();

/* ---------- functions ---------- */
let sortKey=A[0], sortDir=-1;
function ftab(){
 const q=$('q').value.toLowerCase(), oR=$('onlyreach').checked, oB=$('onlyblocked').checked;
 let rows=D.funcs.filter(f=>{
  if(oR&&!f.r)return false;
  if(oB&&!(f.r&&!A.some(a=>f[a]&&f[a][0]>0)))return false;
  if(q&&!(f.d.toLowerCase().includes(q)||(f.f||'').toLowerCase().includes(q)))return false;
  return true});
 rows.sort((x,y)=>{
  const g=f=>sortKey==='name'?f.d:(f[sortKey]?f[sortKey][0]:-1);
  const a=g(x),b=g(y);return (a<b?-1:a>b?1:0)*sortDir});
 let h='<thead><tr><th class="l" data-k="name">function</th>';
 A.forEach(a=>{h+='<th data-k="'+a+'">'+a+' cum</th><th>'+a+' avg</th><th>'+a+' trials</th><th>'+a+' regions</th>'});
 if(A.length===2)h+='<th>&Delta;</th>';
 h+='<th class="l">file</th></tr></thead><tbody>';
 rows.slice(0,3000).forEach(f=>{
  h+='<tr><td class="l">'+(f.r?'':'<span class="pill cold">unreached</span> ')+f.d+'</td>';
  A.forEach(a=>{const v=f[a];
   h+='<td class="'+(v&&v[0]>0?'hot':'cold')+'">'+(v?fmt(v[0]):'')+'</td>'+
      '<td class="cold">'+(v?fmt(v[1]):'')+'</td>'+
      '<td class="'+(v&&v[5]&&v[4]===v[5]?'':'cold')+'">'+(v&&v[5]?v[4]+'/'+v[5]:'')+'</td>'+
      '<td class="cold">'+(v&&v[3]?v[2]+'/'+v[3]:'')+'</td>'});
  if(A.length===2){const x=f[A[0]]?f[A[0]][0]:0,y=f[A[1]]?f[A[1]][0]:0,d=y-x;
   h+='<td class="'+(d>0?'up':d<0?'dn':'cold')+'">'+(d?(d>0?'+':'')+fmt(d):'')+'</td>'}
  h+='<td class="l cold">'+((f.f||'').replace(/^.*\/src\//,''))+'</td></tr>'});
 h+='</tbody>';
 $('ftab').innerHTML=h;
 $('fnstat').textContent=rows.length.toLocaleString()+' functions'+(rows.length>3000?' (showing 3000)':'');
 $('ftab').querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{
  const k=th.dataset.k; sortDir=(k===sortKey)?-sortDir:-1; sortKey=k; ftab()});
}
$('q').oninput=ftab;$('onlyreach').onchange=ftab;$('onlyblocked').onchange=ftab;ftab();

/* ---------- call paths ---------- */
for(let i=1;i<=6;i++){const o=document.createElement('option');o.value=i;o.textContent=i;
 if(i===3)o.selected=true;$('depth').appendChild(o)}
function node(name,depth,maxd,seen){
 const f=FN.get(name), ran=f&&A.some(a=>f[a]&&f[a][0]>0);
 if($('hideblocked').checked&&f&&f.r&&!ran)return '';
 const kids=(D.cg[name]||[]);
 const label=(f?f.d:name);
 const counts=A.map(a=>{const v=f&&f[a];return a[0]+':'+(v?fmt(v[0]):'0')}).join('  ');
 const cls=ran?'':'blocked';
 const open=depth<maxd&&kids.length&&!seen.has(name);
 let h='<li><span class="tw '+cls+'" data-n="'+encodeURIComponent(name)+'">'+
   (kids.length?(open?'▾ ':'▸ '):'&nbsp;&nbsp;')+label+
   ' <span class="c">['+counts+']</span></span>';
 if(open){const s=new Set(seen);s.add(name);
  h+='<ul class="tree">'+kids.map(k=>node(k,depth+1,maxd,s)).join('')+'</ul>'}
 h+='</li>';return h}
function tree(){const d=+$('depth').value;
 $('tree').innerHTML='<ul class="tree">'+node(D.entry,0,d,new Set())+'</ul>';
 $('tree').querySelectorAll('.tw').forEach(s=>s.onclick=e=>{
  e.stopPropagation();const li=s.parentElement;
  const sub=li.querySelector('ul');
  if(sub){sub.remove();s.innerHTML=s.innerHTML.replace('▾','▸');return}
  const n=decodeURIComponent(s.dataset.n), kids=D.cg[n]||[];
  if(!kids.length)return;
  const ul=document.createElement('ul');ul.className='tree';
  ul.innerHTML=kids.map(k=>node(k,0,0,new Set([n]))).join('');
  li.appendChild(ul);s.innerHTML=s.innerHTML.replace('▸','▾');
  ul.querySelectorAll('.tw').forEach(x=>x.onclick=s.onclick)})}
$('depth').onchange=tree;$('hideblocked').onchange=tree;tree();

/* ---------- source ---------- */
const paths=Object.keys(D.lines);let sel=paths[0];
function flist(){$('flist').innerHTML='';paths.forEach(p=>{const d=document.createElement('div');
 d.dataset.p=p;const t=a=>{let s=0;const m=D.lines[p].arms[a]||{};for(const k in m)s+=m[k][0];return s};
 d.innerHTML='<div>'+p.replace(/^.*\/src\//,'')+'</div><div class="sub">'+
   A.map(a=>a[0]+': '+t(a).toLocaleString()).join(' · ')+'</div>';
 d.onclick=()=>{sel=p;srcview()};$('flist').appendChild(d)})}
function srcview(){
 const F=D.lines[sel];
 [...$('flist').children].forEach(c=>c.classList.toggle('sel',c.dataset.p===sel));
 if(!F.src.length){$('code').innerHTML='<p class="sub" style="padding:12px">No source available.</p>';return}
 let max=0;A.forEach(a=>{const m=F.arms[a]||{};for(const k in m)max=Math.max(max,m[k][0])});
 const lg=Math.log10(max+1)||1, esc=s=>s.replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));
 let h='<table><thead><tr><th>line</th>';
 A.forEach(a=>{h+='<th>'+a+' cum</th><th>'+a+' avg</th><th>'+a+' trials</th>'});
 if(A.length===2)h+='<th>&Delta;</th>';
 h+='<th class="l">source</th></tr></thead><tbody>';
 F.src.forEach((text,i)=>{const n=i+1, cs=A.map(a=>(F.arms[a]||{})[n]||null);
  if(!cs.some(c=>c&&c[0]>0))return;
  h+='<tr><td class="cold">'+n+'</td>';
  cs.forEach(c=>{const v=c?c[0]:null;
   const ht=v?Math.min(.5,Math.log10(v+1)/lg*.5):0;
   h+='<td style="'+(v?'background:rgba(220,70,40,'+ht.toFixed(3)+')':'')+'">'+fmt(v)+'</td>'+
      '<td class="cold">'+(c?fmt(c[1]):'')+'</td>'+
      '<td class="'+(c&&c[3]&&c[2]===c[3]?'':'cold')+'">'+(c&&c[3]?c[2]+'/'+c[3]:'')+'</td>'});
  if(A.length===2){const x=cs[0]?cs[0][0]:0,y=cs[1]?cs[1][0]:0,d=y-x;
   h+='<td class="'+(d>0?'up':d<0?'dn':'cold')+'">'+(d?(d>0?'+':'')+fmt(d):'')+'</td>'}
  h+='<td class="src">'+esc(text)+'</td></tr>'});
 $('code').innerHTML=h+'</tbody></table>'}
flist();srcview();

/* ---------- coverage diff ---------- */
(function(){
 const X=D.diff; if(!X){$('cd').innerHTML='<p class="sub">Needs both arms.</p>';return}
 const short=p=>p.replace(/^.*\/src\//,'');
 $('dcards').innerHTML=
  '<div class="card"><div class="k">covered only by '+X.b+'</div><div class="v dn">'+
   X.n_only_b.toLocaleString()+'</div><div class="s">lines the '+X.b+
   ' corpus reached and '+X.a+' never did</div></div>'+
  '<div class="card"><div class="k">covered only by '+X.a+'</div><div class="v up">'+
   X.n_only_a.toLocaleString()+'</div><div class="s">lines lost — reached by '+X.a+
   ' but not by '+X.b+'</div></div>'+
  '<div class="card"><div class="k">different trial breadth</div><div class="v">'+
   X.n_breadth.toLocaleString()+'</div><div class="s">covered by both, but by a different'+
   ' number of trials</div></div>';
 function dtab(){
  const v=$('dview').value, rows=X[v]||[];
  let h='<thead><tr><th class="l">file</th><th>line</th>';
  if(v==='execs')h+='<th>'+X.a+'</th><th>'+X.b+'</th><th>&Delta;</th>';
  else if(v==='breadth')h+='<th>'+X.a+' trials</th><th>'+X.b+' trials</th><th>'+X.a+'</th><th>'+X.b+'</th>';
  else h+='<th>executions</th><th>trials</th>';
  h+='</tr></thead><tbody>';
  rows.forEach(r=>{
   h+='<tr><td class="l cold">'+short(r[0])+'</td><td>'+r[1]+'</td>';
   if(v==='execs'){h+='<td>'+fmt(r[2])+'</td><td>'+fmt(r[3])+'</td><td class="'+
     (r[4]>0?'up':r[4]<0?'dn':'cold')+'">'+(r[4]>0?'+':'')+fmt(r[4])+'</td>'}
   else if(v==='breadth'){h+='<td>'+r[2]+'</td><td>'+r[3]+'</td><td class="cold">'+
     fmt(r[4])+'</td><td class="cold">'+fmt(r[5])+'</td>'}
   else{h+='<td>'+fmt(r[2])+'</td><td class="cold">'+r[3]+'</td>'}
   h+='</tr>'});
  $('dtab').innerHTML=h+'</tbody>';
  $('dstat').textContent='showing '+rows.length.toLocaleString()+' of '+
    (v==='only_a'?X.n_only_a:v==='only_b'?X.n_only_b:v==='breadth'?X.n_breadth:rows.length).toLocaleString();
 }
 $('dview').onchange=dtab;dtab();
})();
</script>"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--image", default="")
    ap.add_argument("--target", default="")
    ap.add_argument("--arms", default="baseline,optimized")
    ap.add_argument("--trials", default="")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--cpus", default="")
    ap.add_argument("--chunk", type=int, default=400,
                    help="queue files per replay process; smaller confines "
                         "the loss from a crashing input, larger amortises "
                         "per-process init (default 400)")
    ap.add_argument("--reuse", action="store_true")
    ap.add_argument("--max-files", type=int, default=40)
    ap.add_argument("--max-funcs", type=int, default=4000)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    info = lec.discover(args.experiment)
    image = lec.resolve_image(info["cve"], args.image)
    lec.scope_cache(info["cve"])
    target = args.target or (info.get("provenance") or {}).get("fuzz_target", "")
    if not target:
        raise SystemExit("no fuzz_target in provenance; pass --target")

    want = ([int(x) for x in args.trials.split(",") if x.strip() != ""]
            if args.trials else None)
    units = []
    for arm in [a.strip() for a in args.arms.split(",") if a.strip()]:
        for trial, q in sorted(info[f"{arm}_queues"].items()):
            if want is None or trial in want:
                units.append((arm, trial, q))
    if not units:
        raise SystemExit("nothing to measure")

    build = lec.CACHE / "build" / "baseline"
    if not (args.reuse and (build / target).is_file()):
        logger.info("coverage build of pristine baseline")
        lec.coverage_build(image, build, args.cpus)
    if not (build / target).is_file():
        raise SystemExit(f"no /out/{target} in the coverage build")

    results, per_trial_fns = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = {ex.submit(lec.measure, image, arm, trial, q, build, target,
                          args.cpus, args.reuse, args.chunk): (arm, trial) for arm, trial, q in units}
        for fut in concurrent.futures.as_completed(futs):
            arm, trial = futs[fut]
            try:
                results.append(fut.result())
            except Exception as exc:                      # noqa: BLE001
                logger.error("%s trial %d FAILED: %s", arm, trial, exc)
    if not results:
        raise SystemExit("every unit failed")
    for r in results:
        per_trial_fns.append((r["arm"], r["trial"],
                              function_counts(lec.CACHE / "prof" /
                                              f"{r['arm']}_trial_{r['trial']:02d}")))

    logger.info("recovering static call graph")
    edges = call_graph(build / target)
    reach = reachable_from(edges, ENTRY)
    logger.info("call graph: %d nodes with edges, %d reachable from %s",
                len(edges), len(reach), ENTRY)

    line_agg = lec.aggregate(results)
    fn_agg = aggregate_functions(per_trial_fns)
    names = sorted({n for a in fn_agg.values() for n in a} | set(edges) |
                   {t for ts in edges.values() for t in ts})
    payload = build_payload(fn_agg, line_agg, edges, reach,
                            lec.load_sources(build, {p for a in line_agg.values()
                                                     for p in a["files"]}),
                            demangle(names), args.max_files, args.max_funcs)

    prov = (info.get("provenance") or {}).get("optimizer") or {}
    meta = {"experiment": info["experiment"], "cve": info["cve"], "target": target,
            "optimizer": prov,
            "arms": {a: {"trials": line_agg[a]["trials"],
                         "n_trials": line_agg[a]["n_trials"],
                         "queue_files_total": line_agg[a]["queue_files_total"]}
                     for a in sorted(line_agg)}}

    dest = Path(args.out) if args.out else (lec.RESULTS / args.experiment / "introspector")
    dest.mkdir(parents=True, exist_ok=True)
    doc = HTML
    for tok, val in (("@@TITLE@@", f"Fuzz introspection — {info['cve']}"),
                     ("@@ENTRY@@", ENTRY),
                     ("@@PAYLOAD@@", json.dumps(payload, separators=(",", ":"))),
                     ("@@META@@", json.dumps(meta))):
        doc = doc.replace(tok, val)
    page = dest / "index.html"
    page.write_text(doc)
    (dest / "data.json").write_text(json.dumps(
        {"meta": meta, "functions": fn_agg, "reachable": sorted(reach),
         "call_edges": edges}, indent=2))
    logger.info("wrote %s (%.1f MB)", page, page.stat().st_size / 1e6)
    print(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
