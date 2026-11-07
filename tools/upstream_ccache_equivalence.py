#!/usr/bin/env python3
"""ccache equivalence test for ONE upstream (bench-upstream/...) target.

The upstream analogue of tools/fb_ccache_equivalence.py: a project may use ccache
for its optimized-arm upstream rebuilds only after this passes. Every build goes
through the production path (prework.prework_build.rebuild_with_prework_image);
uncached builds run with CCACHE_DISABLE=1, cached ones with the backend-clang
wrappers and a per-build copy of the cache. ONE `compile` per build (no cmplog,
no dictionary). Builds:

  P0  pristine, no cache, ONE core (timed reference)
  P0' pristine, no cache, multi-core: P0 vs P0' shows whether the build is
      reproducible and, if not, where its noise is (fb_ccache.noise_model)
  C0  pristine, cold cache, multi-core                                     = P0
  W0  pristine, warm cache (copy of the cache after C0), ONE core, timed   = P0
  PC  new fold_ helper in a compiled .c/.cc + calls, no cache, multi-core
  WC  same tree, warm cache copy, ONE core, timed                          = PC
  PH  new static __inline__ fold_ helper in a header several compiled files
      include (+ calls from one includer), no cache, multi-core
  WH  same tree, warm cache copy, ONE core, timed                          = PH

Each pair compares sha256 of every ELF harness in /out (the sets must match and
contain the fuzz target). Every cached build must have used ccache (statslog
shows hits/misses; a missing log counts as unused) and every warm build must
show hits. Verdicts:

  pass               every pair byte-identical
  pass_noise_masked  some pair differs only inside noise regions learned from
                     P0 vs P0' (strings / non-loaded sections); a difference in
                     loaded code is never masked
  fail               anything else (incl. a cached build that did not use ccache)

Writes <work>/report.json and <work>/report.txt. Exit 0 on pass / pass_noise_masked.

  python3 tools/upstream_ccache_equivalence.py --project <p> \\
      --src <root>/source_tree/src/<p> --work <scratch>/eq/<p> \\
      --cpuset 40-58 --one-core 59 [--parallel]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from prework import fb_ccache_probe as probe  # noqa: E402
from prework import upstream_ccache as uc  # noqa: E402
from prework.fb_ccache import sha256_file  # noqa: E402

MARKER = ".upstream_ccache_equivalence"
VCS_DIRS = (".git", ".hg", ".svn", ".bzr")
STATSLOG_NAME = "statslog"   # prework_build.UPSTREAM_CCACHE_STATSLOG basename
NEEDED_PAIRS = ("P0_vs_C0", "P0_vs_W0", "PC_vs_WC", "PH_vs_WH")
CACHED = ("C0", "W0", "WC", "WH")
WARM = ("W0", "WC", "WH")
MANIFEST = REPO / "data" / "manifests" / "manifest_upstream.json"


class EqError(RuntimeError):
    pass


# ------------------------------------------------------- pure comparison logic

def harness_files(out_dir: str | os.PathLike) -> dict[str, Path]:
    """{name: path} of the ELF files directly in /out (the harnesses)."""
    res: dict[str, Path] = {}
    d = Path(out_dir)
    if not d.is_dir():
        return res
    for p in sorted(d.iterdir()):
        try:
            if p.is_file() and not p.is_symlink():
                with open(p, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        res[p.name] = p
        except OSError:
            continue
    return res


def learn_noise(p0_out, p1_out) -> dict[str, dict]:
    """{harness: noise model} from two plain /out dirs of the same tree."""
    a, b = harness_files(p0_out), harness_files(p1_out)
    return {n: uc.upstream_noise_model(a[n], b[n]) for n in a if n in b}


def compare_outs(x_out, y_out, noise: dict[str, dict] | None = None) -> dict:
    """Compare every harness of two /out dirs (sha256, then noise masking).

    {"status": identical|masked|differs, "files": {name: per-file result},
     "only_in_x": [...], "only_in_y": [...]}. Plain-vs-plain (noise=None for
    P0 vs P0') never masks."""
    x, y = harness_files(x_out), harness_files(y_out)
    res: dict = {"files": {}, "only_in_x": sorted(set(x) - set(y)),
                 "only_in_y": sorted(set(y) - set(x))}
    status = "identical"
    if res["only_in_x"] or res["only_in_y"] or not x:
        status = "differs"
    for n in sorted(set(x) & set(y)):
        if sha256_file(x[n]) == sha256_file(y[n]):
            r = {"status": "identical"}
        elif noise is None:
            r = {"status": "differs", "why": "plain comparison, no masking"}
        else:
            r = uc.upstream_masked_compare(x[n], y[n], noise.get(n))
        res["files"][n] = r
        if r["status"] == "differs":
            status = "differs"
        elif r["status"] == "masked" and status == "identical":
            status = "masked"
    res["status"] = status
    return res


def statslog_for(cache_dir: str | os.PathLike) -> dict:
    """parse_stats of the build's statslog under the (host) cache dir; a missing
    log is unused (never a crash)."""
    p = Path(cache_dir) / STATSLOG_NAME
    if not p.is_file():
        return uc.parse_stats(None)
    return uc.parse_stats(p)


def decide_verdict(pairs: dict[str, dict], stats: dict[str, dict | None],
                   noise: dict[str, dict] | None = None,
                   p0_vs_p0prime: dict | None = None) -> dict:
    """Pure verdict. ``pairs``: name -> compare_outs() result (NEEDED_PAIRS);
    ``stats``: build label -> parse_stats() result (None/absent = ccache unused);
    ``noise``: harness -> noise model; ``p0_vs_p0prime``: compare_outs result.

    Returns {"verdict": pass|pass_noise_masked|fail, "pass": bool, "problems": [...],
    "masked": [...]}."""
    problems = [f"{k}: missing" for k in NEEDED_PAIRS if k not in pairs]
    problems += [f"{k}: differs" for k in NEEDED_PAIRS
                 if k in pairs and pairs[k].get("status") not in ("identical", "masked")]
    if p0_vs_p0prime and p0_vs_p0prime.get("status") != "identical":
        for n, m in (noise or {}).items():
            if not m.get("deterministic") and not m.get("ok"):
                problems.append(f"P0 vs P0' {n}: non-deterministic and not maskable: "
                                f"{m.get('why')}")
        if p0_vs_p0prime.get("only_in_x") or p0_vs_p0prime.get("only_in_y"):
            problems.append("P0 vs P0': harness sets differ")
    for lbl in CACHED:
        st = stats.get(lbl) if stats else None
        if not (st and st.get("used")):
            problems.append(f"{lbl}: ccache not used (no hits/misses in statslog)")
        elif lbl in WARM and not st.get("hits"):
            problems.append(f"{lbl}: warm build shows no cache hits")
    masked = sorted({f"{n}: {s}" for k in NEEDED_PAIRS
                     for n, f in ((pairs.get(k) or {}).get("files") or {}).items()
                     for s in f.get("masked", [])})
    any_masked = any((pairs.get(k) or {}).get("status") == "masked" for k in NEEDED_PAIRS)
    verdict = "fail" if problems else "pass_noise_masked" if any_masked else "pass"
    return {"verdict": verdict, "pass": verdict != "fail", "problems": problems,
            "masked": masked}


# ------------------------------------------------------------ orchestration

def parse_cpus(spec: str) -> list[int]:
    out: list[int] = []
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out += list(range(int(lo), int(hi) + 1))
        elif part:
            out.append(int(part))
    return sorted(dict.fromkeys(out))


def cpus_str(cpus: list[int]) -> str:
    return ",".join(str(c) for c in cpus)


def split_pool(pool: list[int], n: int) -> list[list[int]]:
    if n <= 0 or len(pool) < n:
        raise EqError(f"need at least {n} cores in the pool, have {len(pool)}")
    k, r = divmod(len(pool), n)
    out, i = [], 0
    for j in range(n):
        m = k + (1 if j < r else 0)
        out.append(pool[i:i + m])
        i += m
    return out


def resolve_entry(project: str, manifest: str | os.PathLike = MANIFEST) -> dict:
    entries = [e for e in json.loads(Path(manifest).read_text())
               if e.get("project") == project]
    if not entries:
        raise EqError(f"no upstream manifest entry for project {project!r}")
    asan = [e for e in entries if e.get("sanitizer") == "address"]
    if not asan:
        raise EqError(f"{project}: no address-sanitizer manifest entry")
    return asan[0]


class Runner:
    def __init__(self, a):
        self.a = a
        self.work = Path(a.work).absolute()
        self.entry = resolve_entry(a.project)
        self.target = a.fuzz_target or self.entry.get("fuzz_target")
        self.builds: dict[str, dict] = {}
        self.pairs: dict[str, dict] = {}
        self.notes: list[str] = []
        self.edits: dict[str, dict] = {}
        self.noise: dict[str, dict] = {}
        self.stats: dict[str, dict] = {}
        self.one_core = str(a.one_core)
        self.pool = [c for c in parse_cpus(a.cpuset) if c != int(a.one_core)]
        if not self.pool:
            raise EqError("--cpuset has no core besides --one-core")

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    def image(self) -> str:
        from prework.prework_build import prework_image_for
        return prework_image_for(self.entry)

    def prepare_work(self):
        from prework.prework_build import restore_ownership
        w = self.work
        if w.exists() and any(w.iterdir()):
            only_reports = {x.name for x in w.iterdir()} <= {"report.json", "report.txt"}
            if not (w / MARKER).exists() and not only_reports:
                raise EqError(f"--work {w} is not empty and was not made by this tool; "
                              "refusing to delete it")
            restore_ownership(self.image(), [str(w)])
            shutil.rmtree(w)
        w.mkdir(parents=True, exist_ok=True)
        (w / MARKER).write_text("made by tools/upstream_ccache_equivalence.py\n")
        for d in ("trees", "out", "cache", "logs"):
            (w / d).mkdir()

    def make_tree(self, label: str) -> Path:
        """Copy of --src at trees/<label>/source_tree/src/<project> (the layout
        vcs_dir_for expects), with the original tree's set-aside VCS dirs linked
        beside it so the staged build restores the same .git dirs."""
        from prework.prework_build import vcs_dir_for
        root = self.work / "trees" / label / "source_tree"
        dest = root / "src" / self.a.project
        shutil.copytree(Path(self.a.src).absolute(), dest, symlinks=True,
                        ignore=shutil.ignore_patterns(*VCS_DIRS))
        vcs = vcs_dir_for(self.a.src)
        if vcs is not None:
            (root / "vcs").symlink_to(vcs)
        return dest

    def build(self, label: str, tree: Path, *, cpus: str, cache: Path | None = None) -> dict:
        from prework.prework_build import rebuild_with_prework_image, restore_ownership
        out = self.work / "out" / label
        if out.exists():
            restore_ownership(self.image(), [str(out)])
            shutil.rmtree(out)
        out.mkdir(parents=True)
        log_path = self.work / "logs" / f"{label}.log"
        print(f"[{time.strftime('%H:%M:%S')}] build {label} on cpus {cpus}"
              f"{' with cache ' + cache.name if cache else ''} ...", flush=True)
        t0 = time.time()
        ok, log = rebuild_with_prework_image(
            entry=self.entry, source_dir=str(tree), out_dir=str(out), cpu=cpus,
            capture_log=True, timeout=self.a.timeout,
            ccache_dir=str(cache) if cache else None)
        wall = time.time() - t0
        log_path.write_text(log)
        rec = {"label": label, "ok": bool(ok), "cpus": cpus, "wall_s": round(wall, 1),
               "cache": cache.name if cache else None, "log": str(log_path),
               "out": str(out), "harnesses": {n: sha256_file(p)
                                              for n, p in harness_files(out).items()}}
        if cache is not None:
            restore_ownership(self.image(), [str(cache)])
            st = statslog_for(cache)
            rec["ccache"] = uc.slim_stats(st)
            self.stats[label] = st
        self.builds[label] = rec
        print(f"    {label}: ok={ok} wall={wall:.1f}s ccache={rec.get('ccache')}", flush=True)
        if not ok:
            print("    log tail:\n" + "\n".join(log.splitlines()[-15:]), flush=True)
        return rec

    def warm_copy(self, label: str) -> Path:
        from prework.fb_ccache import seed_cache
        dest = self.work / "cache" / label
        seed_cache(self.work / "cache" / "warm_template", dest)
        (dest / STATSLOG_NAME).unlink(missing_ok=True)
        return dest

    def compare(self, name: str, a: str, b: str, *, masked: bool = True) -> dict:
        ra, rb = self.builds.get(a), self.builds.get(b)
        if not (ra and rb and ra["ok"] and rb["ok"]):
            res = {"status": "differs", "files": {}, "error": f"{a} or {b} did not build"}
        else:
            res = compare_outs(ra["out"], rb["out"], self.noise if masked else None)
            if self.target not in res["files"]:
                res["status"] = "differs"
                res["error"] = f"fuzz target {self.target} not in both /out dirs"
        res.update(a=a, b=b)
        self.pairs[name] = res
        print(f"    {name}: {a} vs {b} -> {res['status']}", flush=True)
        return res

    # ---- fold variants (no audit build: candidates come from a source scan)
    def _sources(self, tree: Path) -> list[Path]:
        out = []
        for p in tree.rglob("*"):
            if p.suffix.lower() in (".c", ".cc", ".cpp", ".cxx") and p.is_file() \
                    and not p.is_symlink() and not any(v in p.parts for v in VCS_DIRS):
                out.append(p)
        rel = probe.rank_sources([str(p.relative_to(tree)) for p in out])
        return [tree / r for r in rel]

    def _helper_reached(self, out: Path, helper: str) -> bool:
        return any(probe.helper_in_binary(p, helper) for p in harness_files(out).values())

    def pick_c_variant(self, cpus: str):
        src = Path(self.a.src).absolute()
        tried = 0
        for cand in self._sources(src):
            text = cand.read_text(errors="surrogateescape")
            edited = probe.add_c_fold(text)
            if edited is None:
                continue
            if tried >= self.a.max_candidates:
                break
            tried += 1
            rel = cand.relative_to(src)
            tree = self.make_tree(f"foldc_{tried}")
            (tree / rel).write_text(edited[0], errors="surrogateescape")
            rec = self.build("PC", tree, cpus=cpus)
            if not rec["ok"]:
                self.note(f"fold-in-.c candidate {rel}: plain build failed; next")
                continue
            info = {"file": str(rel), **edited[1], "tree": str(tree)}
            if self._helper_reached(Path(rec["out"]), probe.C_HELPER):
                return tree, info
            self.note(f"fold-in-.c candidate {rel}: {probe.C_HELPER} not in any /out "
                      "harness; next")
        self.note(f"no usable fold-in-.c variant ({tried} tried)")
        return None

    def pick_h_variant(self, cpus: str):
        src = Path(self.a.src).absolute()
        cands = probe.header_candidates(src, self._sources(src))
        tried, fallback = 0, None
        for header, includers in cands:
            new_h = probe.add_header_fold(header.read_text(errors="surrogateescape"))
            if new_h is None:
                continue
            if tried >= self.a.max_candidates:
                break
            tried += 1
            tree = self.make_tree(f"foldh_{tried}")
            hrel = header.relative_to(src)
            (tree / hrel).write_text(new_h, errors="surrogateescape")
            info = {"header": str(hrel), "includers": len(includers),
                    "helper": probe.H_HELPER, "caller": None}
            for inc in includers:
                if probe.is_harness(str(inc.relative_to(src)), None):
                    continue
                call = probe.add_h_call(inc.read_text(errors="surrogateescape"))
                if call:
                    irel = inc.relative_to(src)
                    (tree / irel).write_text(call[0], errors="surrogateescape")
                    info["caller"] = {"file": str(irel), "call_lines": call[1]["call_lines"]}
                    break
            rec = self.build("PH", tree, cpus=cpus)
            if not rec["ok"]:
                self.note(f"fold-in-header candidate {hrel}: plain build failed; next")
                continue
            info["in_harness"] = self._helper_reached(Path(rec["out"]), probe.H_HELPER)
            if info["in_harness"]:
                return tree, info
            self.note(f"fold-in-header candidate {hrel}: helper not in any harness; next")
            if fallback is None:
                fallback = (tree, info)
        if fallback is not None:
            tree, info = fallback
            self.build("PH", tree, cpus=cpus)
            self.note(f"fold-in-header: no candidate reached a harness; using "
                      f"{info['header']} (checks only that its includers miss)")
            return tree, info
        self.note(f"no usable fold-in-header variant ({len(cands)} candidates, {tried} tried)")
        return None

    # ---- main flow
    def run(self) -> dict:
        a = self.a
        if not Path(a.src).is_dir():
            raise EqError(f"--src {a.src} is not a directory")
        if not self.target:
            raise EqError("cannot find fuzz_target (pass --fuzz-target)")
        self.prepare_work()
        pristine = self.make_tree("pristine")
        pool = cpus_str(self.pool)
        c0_cache = self.work / "cache" / "C0"
        c0_cache.mkdir()
        results: dict[str, object] = {}

        if a.parallel:
            chunks = [cpus_str(c) for c in split_pool(self.pool, 4)]
            with ThreadPoolExecutor(max_workers=5) as ex:
                futs = [ex.submit(self.build, "P0", pristine, cpus=self.one_core),
                        ex.submit(self.build, "P0prime", pristine, cpus=chunks[0]),
                        ex.submit(self.build, "C0", pristine, cpus=chunks[1],
                                  cache=c0_cache)]
                fc = ex.submit(self.pick_c_variant, chunks[2])
                fh = ex.submit(self.pick_h_variant, chunks[3])
                for f in futs:
                    f.result()
                results["c"], results["h"] = fc.result(), fh.result()
            self.note("parallel: P0 was timed while other builds ran on other cores")
        else:
            self.build("P0", pristine, cpus=self.one_core)
            self.build("P0prime", pristine, cpus=pool)
            self.build("C0", pristine, cpus=pool, cache=c0_cache)
        if not self.builds["P0"]["ok"]:
            raise EqError("pristine build P0 failed; see " + self.builds["P0"]["log"])
        p0, p1 = self.builds["P0"], self.builds.get("P0prime")
        if p1 and p1["ok"]:
            self.noise = learn_noise(p0["out"], p1["out"])
        self.compare("P0_vs_P0prime", "P0", "P0prime", masked=False)
        self.compare("P0_vs_C0", "P0", "C0")
        shutil.copytree(c0_cache, self.work / "cache" / "warm_template", symlinks=False)

        if a.parallel:
            cv, hv = results["c"], results["h"]
            cores = [self.one_core] + [str(c) for c in self.pool[:2]]
            jobs = [("W0", pristine)] + ([("WC", cv[0])] if cv else []) + \
                   ([("WH", hv[0])] if hv else [])
            with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
                fs = [ex.submit(self.build, lbl, tree, cpus=cores[i],
                                cache=self.warm_copy(lbl))
                      for i, (lbl, tree) in enumerate(jobs)]
                for f in fs:
                    f.result()
            if len(jobs) > 1:
                self.note("parallel: W0/WC/WH were timed at the same time on cores "
                          + ", ".join(cores[:len(jobs)]))
        else:
            self.build("W0", pristine, cpus=self.one_core, cache=self.warm_copy("W0"))
            cv = self.pick_c_variant(pool)
            if cv:
                self.build("WC", cv[0], cpus=self.one_core, cache=self.warm_copy("WC"))
            hv = self.pick_h_variant(pool)
            if hv:
                self.build("WH", hv[0], cpus=self.one_core, cache=self.warm_copy("WH"))
        self.compare("P0_vs_W0", "P0", "W0")
        if cv:
            self.edits["c"] = cv[1]
            self.compare("PC_vs_WC", "PC", "WC")
        if hv:
            self.edits["h"] = hv[1]
            self.compare("PH_vs_WH", "PH", "WH")
        return self.finish()

    def finish(self) -> dict:
        d = decide_verdict(self.pairs, self.stats, self.noise,
                           self.pairs.get("P0_vs_P0prime"))
        timing = {}
        p0 = (self.builds.get("P0") or {}).get("wall_s")
        for lbl in ("P0", "W0", "WC", "WH"):
            b = self.builds.get(lbl)
            if b:
                t = {"wall_s": b["wall_s"], "cpus": b["cpus"]}
                for k in ("hits", "misses"):
                    t[k] = (b.get("ccache") or {}).get(k)
                if p0 and lbl != "P0":
                    t["speedup_vs_P0"] = round(p0 / max(b["wall_s"], 0.1), 2)
                timing[lbl] = t
        return {"project": self.a.project, "image": self.image(),
                "fuzz_target": self.target, "src": str(Path(self.a.src).absolute()),
                **d, "pairs": self.pairs,
                "noise": {n: {k: v for k, v in m.items() if k != "regions"}
                          for n, m in self.noise.items()},
                "builds": self.builds, "edits": self.edits, "timing_one_core": timing,
                "notes": self.notes, "cpuset": self.a.cpuset,
                "one_core": self.a.one_core, "parallel": bool(self.a.parallel)}


def text_report(rep: dict) -> str:
    L = [f"upstream ccache equivalence: {rep['project']}  ->  {rep['verdict'].upper()}",
         f"image {rep.get('image')}, target {rep.get('fuzz_target')}"]
    for k, p in rep.get("pairs", {}).items():
        st = p.get("status")
        L.append(f"  {k:16s} {st}"
                 + ("" if st != "differs" else
                    " " + (p.get("error") or ", ".join(
                        f"{n}: {f.get('why')}" for n, f in p.get("files", {}).items()
                        if f.get("status") == "differs")
                        or f"sets differ: {p.get('only_in_x')} / {p.get('only_in_y')}")))
    for s in rep.get("masked", [])[:20]:
        L.append(f"  masked: {s!r}")
    e = rep.get("edits", {})
    if "c" in e:
        L.append(f"  fold in .c: {e['c']['file']} ({len(e['c']['call_lines'])} call sites)")
    if "h" in e:
        c = e["h"].get("caller")
        L.append(f"  fold in header: {e['h']['header']} (included by {e['h']['includers']}; "
                 f"called from {c['file'] if c else 'nowhere'}; in harness: "
                 f"{e['h'].get('in_harness')})")
    L.append("  one-core build times (s):")
    for lbl, t in rep.get("timing_one_core", {}).items():
        L.append(f"    {lbl:3s} cpu {t.get('cpus')} wall {t['wall_s']:>8}"
                 + (f"  hits {t['hits']} misses {t['misses']}" if t.get("hits") is not None else "")
                 + (f"  speedup {t['speedup_vs_P0']}x" if t.get("speedup_vs_P0") else ""))
    L += [f"  PROBLEM: {p}" for p in rep.get("problems", [])]
    L += [f"  note: {n}" for n in rep.get("notes", [])]
    if rep.get("error"):
        L.append(f"  ERROR: {rep['error']}")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project", required=True, help="upstream project (manifest_upstream.json)")
    ap.add_argument("--src", required=True, help="extracted project source tree")
    ap.add_argument("--work", required=True, help="scratch dir (created; wiped on rerun)")
    ap.add_argument("--cpuset", required=True, help="cores for multi-core builds")
    ap.add_argument("--one-core", required=True, help="single core for timed builds")
    ap.add_argument("--parallel", action="store_true")
    ap.add_argument("--fuzz-target", help="override the manifest fuzz_target")
    ap.add_argument("--timeout", type=int, default=6 * 3600, help="per build, seconds")
    ap.add_argument("--max-candidates", type=int, default=3,
                    help="files to try per fold variant before giving up")
    a = ap.parse_args(argv)
    if not str(a.one_core).isdigit():
        ap.error("--one-core must be a single CPU number")
    if a.parallel and len([c for c in parse_cpus(a.cpuset) if c != int(a.one_core)]) < 4:
        ap.error("--parallel needs at least 4 cores in --cpuset besides --one-core")
    r = None
    try:
        r = Runner(a)
        rep = r.run()
    except (EqError, OSError) as e:
        rep = {"project": a.project, "image": None,
               "fuzz_target": getattr(r, "target", None), "pass": False,
               "verdict": "fail", "error": str(e), "problems": [str(e)],
               "pairs": getattr(r, "pairs", {}), "builds": getattr(r, "builds", {}),
               "edits": getattr(r, "edits", {}), "notes": getattr(r, "notes", []),
               "timing_one_core": {}}
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    (work / "report.json").write_text(json.dumps(rep, indent=1, default=str))
    txt = text_report(rep)
    (work / "report.txt").write_text(txt)
    print(txt, end="")
    print(f"report: {work / 'report.json'}")
    return 0 if rep.get("pass") else 1


if __name__ == "__main__":
    sys.exit(main())
