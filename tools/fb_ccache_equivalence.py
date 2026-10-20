#!/usr/bin/env python3
"""ccache equivalence test for ONE FuzzBench target (fuzzbench-parity-ccache, section 5).

A target may use ccache for its optimized-arm rebuilds (main AND cmplog build) only
after this passes. Every build marked "cache" below caches BOTH halves (as production
does); P0 and P0' are fully uncached. It builds, through the production command
(prework.fuzzbench_image.fuzzbench_build_command):

  A0  audit build (FB_AUDIT_CC_LOG), multi-core: picks the files to edit; not compared
  P0  pristine, no cache, ONE core (timed reference)
  P0' pristine, no cache, multi-core: always built; P0 vs P0' shows whether the build
      is reproducible and, if not, where its noise is (see fb_ccache.noise_model)
  C0  pristine, cold cache, multi-core                                     = P0
  W0  pristine, warm cache (copy of the cache after C0), ONE core, timed   = P0
  PC  new fold_ helper in a compiled .c/.cc + calls, no cache, multi-core; only a
      file whose helper symbol ends up in the MAIN fuzz binary counts
  WC  same tree, warm cache copy, ONE core, timed                          = PC
  PH  new static __inline__ fold_ helper in a header several compiled files
      include (+ calls from one includer), no cache, multi-core
  WH  same tree, warm cache copy, ONE core, timed                          = PH

Each pair compares sha256 of /out/<t> and /out/cmplog/<t> and the sorted unique set of
/out/afl++.dict entries. Every cached build must report ccache in use for both
halves. One-core times and hit rates are reported per half (main / cmplog), and
__cmplog_* hook call sites are counted in P0 and W0 (cmplog: many, main: none).
Verdicts:

  pass               every pair byte-identical
  pass_noise_masked  some pair differs, but P0 != P0' and, for every differing
                     binary, sizes are equal and every differing byte lies inside a
                     noise region learned from P0 vs P0' (a NUL-terminated printable
                     string, or a 16-byte block inside a non-loaded section such as
                     .debug_line); dict sets equal. Differences in loaded code (a
                     build race) are never masked.
  fail               anything else (incl. a cached build that did not use ccache)

--parallel runs independent builds at the same time on disjoint core subsets of
--cpuset (P0 alone on --one-core; W0/WC/WH each alone on its own core).
Writes <work>/report.json and <work>/report.txt. Exit 0 on pass / pass_noise_masked.

  python3 tools/fb_ccache_equivalence.py --dir zlib_zlib_uncompress_fuzzer \\
      --src <validate>/<dir>/source_tree/src/zlib --work <scratch>/eq/zlib \\
      --cpuset 40-58 --one-core 59 [--parallel]

The image must have ccache at /opt/fb_ccache/ccache and none on PATH (rebuild it with
`python3 -m prework.fuzzbench_image --dir <dir> --cpuset <yours>`).
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from prework import fb_ccache, fb_ccache_probe as probe  # noqa: E402
from prework.fuzzbench_image import (  # noqa: E402
    BENCHMARKS_DIR, fuzzbench_build_command, fuzzbench_image_tag,
)

MARKER = ".fb_ccache_equivalence"
VCS_DIRS = (".git", ".hg", ".svn", ".bzr")
AUDIT_REL = "fb_audit_cc.jsonl"
_CONTAINERS: set[str] = set()
_LOCK = threading.Lock()
NEEDED_PAIRS = ("P0_vs_C0", "P0_vs_W0", "PC_vs_WC", "PH_vs_WH")


class EqError(RuntimeError):
    pass


# --------------------------------------------------------------- docker helpers

def _cleanup_containers() -> None:
    for name in list(_CONTAINERS):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        _CONTAINERS.discard(name)


def _on_signal(signum, _frame):
    _cleanup_containers()
    raise SystemExit(128 + signum)


def chown_back(image: str, paths: list[Path], cpuset: str) -> None:
    """Hand root-owned build output back to this user (pinned to our cpuset)."""
    if os.geteuid() == 0:
        return
    paths = [p for p in paths if p.exists()]
    if not paths:
        return
    mounts = []
    for i, p in enumerate(paths):
        mounts += ["-v", f"{p.absolute()}:/fix{i}"]
    r = subprocess.run(
        ["docker", "run", "--rm", "--cpuset-cpus", cpuset, *mounts,
         "--entrypoint", "chown", image, "-R", f"{os.getuid()}:{os.getgid()}",
         *[f"/fix{i}" for i in range(len(paths))]],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise EqError(f"could not restore ownership of {paths}: {r.stderr[-300:]}")


def image_has_ccache(image: str, cpuset: str) -> str:
    """ccache version at /opt/fb_ccache/ccache; refuse an image where a build system
    could find a ccache on its own (round-1 images had /usr/bin/ccache)."""
    r = subprocess.run(
        ["docker", "run", "--rm", "--cpuset-cpus", cpuset, "--entrypoint", "/bin/sh",
         image, "-c", f"{fb_ccache.CONTAINER_CCACHE_BIN} --version | head -1; "
                      "echo PATH_CCACHE=$(command -v ccache); ls -d /usr/lib/ccache 2>/dev/null; true"],
        capture_output=True, text=True)
    if r.returncode != 0 or "ccache version" not in r.stdout:
        raise EqError(f"{image} has no {fb_ccache.CONTAINER_CCACHE_BIN}; rebuild it: "
                      f"python3 -m prework.fuzzbench_image --dir <dir> --cpuset {cpuset}")
    if not re.search(r"^PATH_CCACHE=$", r.stdout, re.MULTILINE) or "/usr/lib/ccache" in r.stdout:
        raise EqError(f"{image} has a ccache on PATH (build systems auto-detect it); "
                      "rebuild the image")
    return r.stdout.splitlines()[0].strip()


def parse_cpus(spec: str) -> list[int]:
    out: list[int] = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out += list(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return sorted(dict.fromkeys(out))


def cpus_str(cpus: list[int]) -> str:
    return ",".join(str(c) for c in cpus)


def split_pool(pool: list[int], n: int) -> list[list[int]]:
    """n disjoint, contiguous, near-equal chunks (each non-empty)."""
    if n <= 0 or len(pool) < n:
        raise EqError(f"need at least {n} cores in the pool, have {len(pool)}")
    k, r = divmod(len(pool), n)
    out, i = [], 0
    for j in range(n):
        m = k + (1 if j < r else 0)
        out.append(pool[i:i + m])
        i += m
    return out


# --------------------------------------------------------------- the test

class Runner:
    def __init__(self, a):
        self.a = a
        self.work = Path(a.work).absolute()
        self.image = a.image or fuzzbench_image_tag(a.dir)
        self.name = Path(a.src).absolute().name
        self.target = a.fuzz_target or _fuzz_target(a.dir)
        self.builds: dict[str, dict] = {}
        self.pairs: dict[str, dict] = {}
        self.notes: list[str] = []
        self.edits: dict[str, dict] = {}
        self.noise: dict[str, dict] = {}
        self.one_core = str(a.one_core)
        self.pool = [c for c in parse_cpus(a.cpuset) if c != int(a.one_core)]
        if not self.pool:
            raise EqError("--cpuset has no core besides --one-core")

    def note(self, msg: str) -> None:
        with _LOCK:
            self.notes.append(msg)

    # ---- setup
    def prepare_work(self):
        w = self.work
        if w.exists() and any(w.iterdir()):
            only_reports = {x.name for x in w.iterdir()} <= {"report.json", "report.txt"}
            if not (w / MARKER).exists() and not only_reports:
                raise EqError(f"--work {w} is not empty and was not made by this tool; "
                              "refusing to delete it")
            chown_back(self.image, [w], self.a.cpuset)
            shutil.rmtree(w)
        w.mkdir(parents=True, exist_ok=True)
        (w / MARKER).write_text("made by tools/fb_ccache_equivalence.py\n")
        for d in ("trees", "out", "cache", "logs"):
            (w / d).mkdir()

    def make_tree(self, label: str) -> Path:
        dest = self.work / "trees" / label / self.name
        shutil.copytree(Path(self.a.src).absolute(), dest, symlinks=True,
                        ignore=shutil.ignore_patterns(*VCS_DIRS))
        return dest

    # ---- one build
    def build(self, label: str, tree: Path, *, cpus: str, cache: Path | None = None,
              audit: bool = False) -> dict:
        out = self.work / "out" / label
        if out.exists():
            chown_back(self.image, [out], cpus)
            shutil.rmtree(out)
        out.mkdir(parents=True)
        cname = f"fbcc-eq-{os.getpid()}-{label.lower().replace(chr(39), 'p')}"
        extra = ["--name", cname, "--ulimit", "core=0"]
        if cache is not None:
            extra += ["-e", "FB_CCACHE_FORCE=1"]   # this tool only: bypass the list
        if audit:
            extra += ["-e", f"FB_AUDIT_CC_LOG=/out/{AUDIT_REL}"]
        cmd = fuzzbench_build_command(image=self.image, source_dir=str(tree),
                                      out_dir=str(out), cpu=cpus, extra_docker_args=extra,
                                      ccache_dir=str(cache) if cache else None)
        log_path = self.work / "logs" / f"{label}.log"
        print(f"[{time.strftime('%H:%M:%S')}] build {label} on cpus {cpus}"
              f"{' with cache ' + cache.name if cache else ''} ...", flush=True)
        with _LOCK:
            _CONTAINERS.add(cname)
        t0 = time.time()
        try:
            with open(log_path, "w") as log:
                log.write("$ " + " ".join(cmd) + "\n")
                log.flush()
                r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                                   timeout=self.a.timeout)
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = 124
        finally:
            subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
            with _LOCK:
                _CONTAINERS.discard(cname)
        wall = time.time() - t0
        chown_back(self.image, [out] + ([cache] if cache else []), cpus)
        text = log_path.read_text(errors="replace")
        rec = {"label": label, "rc": rc, "ok": rc == 0, "cpus": cpus,
               "wall_s": round(wall, 1), "cache": cache.name if cache else None,
               "timings": fb_ccache.parse_build_timings(text),
               "ccache": _short_stats(fb_ccache.parse_stats(text)),
               "log": str(log_path), "out": str(out),
               "fingerprint": fb_ccache.out_fingerprint(out, self.target)}
        with _LOCK:
            self.builds[label] = rec
        print(f"    {label}: rc={rc} wall={wall:.1f}s cmplog={rec['timings'].get('/out/cmplog')} "
              f"ccache={rec['ccache']}", flush=True)
        if rc != 0:
            tail = "\n".join(text.splitlines()[-15:])
            print(f"    build {label} FAILED; log tail:\n{tail}", flush=True)
        return rec

    def learn_noise(self) -> None:
        """Noise regions of main and cmplog from the two plain builds P0 / P0'."""
        p0, p1 = self.builds.get("P0"), self.builds.get("P0prime")
        if not (p0 and p1 and p0["ok"] and p1["ok"]):
            return
        self.noise.update(fb_ccache.noise_models(p0["out"], p1["out"], self.target))

    def count_hooks(self) -> None:
        """__cmplog_* call sites in P0 / W0 main and cmplog binaries: proves the
        cached cmplog build still has its hooks and the cached main build none
        (main and cmplog objects never share a cache entry)."""
        for lbl in ("P0", "W0"):
            b = self.builds.get(lbl)
            if not (b and b["ok"]):
                continue
            b["cmplog_hook_sites"] = {
                part: fb_ccache.cmplog_hook_sites(Path(b["out"]) / rel)
                for part, rel in (("main", self.target),
                                  ("cmplog", f"cmplog/{self.target}"))}

    def compare(self, name: str, a: str, b: str) -> dict:
        ra, rb = self.builds.get(a), self.builds.get(b)
        if not (ra and rb and ra["ok"] and rb["ok"]):
            res = {"identical": False, "status": "differs",
                   "error": f"{a} or {b} did not build"}
        elif name == "P0_vs_P0prime":
            res = fb_ccache.compare_outs(ra["out"], rb["out"], self.target)
            res["status"] = "identical" if res["identical"] else "differs"
        else:
            res = fb_ccache.compare_outs_masked(ra["out"], rb["out"], self.target,
                                                self.noise)
        res.update(a=a, b=b)
        with _LOCK:
            self.pairs[name] = res
        print(f"    {name}: {a} vs {b} -> {res['status']}"
              + ("" if res["status"] != "differs"
                 else " " + str(res.get("parts") or res.get("error"))), flush=True)
        return res

    def warm_copy(self, label: str) -> Path:
        dest = self.work / "cache" / label
        fb_ccache.seed_cache(self.work / "cache" / "warm_template", dest)
        return dest

    # ---- fold variants
    def _host(self, cpath: str) -> Path:
        return Path(self.a.src).absolute() / os.path.relpath(cpath, f"/src/{self.name}")

    def _texts(self, cpaths) -> dict[str, str]:
        out = {}
        for c in cpaths:
            try:
                out[c] = self._host(c).read_text(errors="surrogateescape")
            except OSError:
                continue
        return out

    def pick_c_variant(self, audit_recs, symbols, cpus: str) -> tuple[Path, dict] | None:
        compiled = probe.compiled_sources(audit_recs, src_root=f"/src/{self.name}")
        texts = self._texts(compiled)
        linked = probe.link_line_sources(audit_recs, target=self.target,
                                         src_root=f"/src/{self.name}")
        ranked = probe.rank_candidates(compiled, texts=texts, symbols=symbols,
                                       linked=linked)
        harness = sum(1 for c in compiled if probe.is_harness(c, texts.get(c)))
        tried = editable = 0
        for cpath, score in ranked:
            rel = os.path.relpath(cpath, f"/src/{self.name}")
            edited = probe.add_c_fold(texts[cpath])
            if edited is None:
                continue
            editable += 1
            if tried >= self.a.max_candidates:
                break
            tried += 1
            tree = self.make_tree(f"foldc_{tried}")
            (tree / rel).write_text(edited[0], errors="surrogateescape")
            rec = self.build("PC", tree, cpus=cpus)
            info = {"file": rel, **edited[1], "tree": str(tree), "symbol_score": score,
                    "on_link_line": cpath in linked}
            if not rec["ok"]:
                self.note(f"fold-in-.c candidate {rel}: plain build failed; next")
                continue
            if not probe.helper_in_binary(Path(rec["out"]) / self.target, probe.C_HELPER):
                self.note(f"fold-in-.c candidate {rel}: {probe.C_HELPER} is not in the "
                          f"main binary (object not linked into {self.target}); next")
                continue
            return tree, info
        self.note(f"no usable fold-in-.c variant: {len(compiled)} compiled project "
                  f"sources, {harness} harness file(s) excluded, {editable} with an "
                  f"insertable function body, {tried} tried"
                  + (" (see the candidate notes)" if tried else ""))
        return None

    def pick_h_variant(self, audit_recs, symbols, cpus: str) -> tuple[Path, dict] | None:
        src = Path(self.a.src).absolute()
        compiled_c = probe.compiled_sources(audit_recs, src_root=f"/src/{self.name}")
        texts = self._texts(compiled_c)
        compiled = [self._host(p) for p in compiled_c]
        cands = probe.header_candidates(src, compiled)
        linked = probe.link_line_sources(audit_recs, target=self.target,
                                         src_root=f"/src/{self.name}")
        tried = 0
        fallback = None
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
            inc_c = [f"/src/{self.name}/{i.relative_to(src)}" for i in includers]
            for cpath, _score in probe.rank_candidates(inc_c, texts=texts,
                                                       symbols=symbols, linked=linked):
                call = probe.add_h_call(texts[cpath])
                if call:
                    irel = os.path.relpath(cpath, f"/src/{self.name}")
                    (tree / irel).write_text(call[0], errors="surrogateescape")
                    info["caller"] = {"file": irel, "call_lines": call[1]["call_lines"]}
                    break
            rec = self.build("PH", tree, cpus=cpus)
            if not rec["ok"]:
                self.note(f"fold-in-header candidate {hrel}: plain build failed; next")
                continue
            info["in_main_binary"] = probe.helper_in_binary(
                Path(rec["out"]) / self.target, probe.H_HELPER)
            if info["in_main_binary"]:
                return tree, info
            self.note(f"fold-in-header candidate {hrel}: {probe.H_HELPER} not in the "
                      "main binary; next")
            if fallback is None:
                fallback = (tree, info, dict(rec))
        if fallback is not None:
            # No header reached the target: keep the first one that built (every
            # includer must still miss), rebuilt so out/PH is that tree.
            tree, info, _rec = fallback
            self.build("PH", tree, cpus=cpus)
            self.note(f"fold-in-header: no candidate reached the main binary; using "
                      f"{info['header']} (checks only that its includers miss)")
            return tree, info
        self.note(f"no usable fold-in-header variant: {len(cands)} project header(s) "
                  f"included by >= 2 compiled files, {tried} tried"
                  + ("" if tried else " (none had a recognisable include guard)"))
        return None

    # ---- main flow
    def run(self) -> dict:
        a = self.a
        if not Path(a.src).is_dir():
            raise EqError(f"--src {a.src} is not a directory")
        if not self.target:
            raise EqError("cannot find fuzz_target (pass --fuzz-target)")
        ccache_version = image_has_ccache(self.image, a.cpuset)
        self.prepare_work()
        pristine = self.make_tree("pristine")
        pool = cpus_str(self.pool)

        a0 = self.build("A0", pristine, cpus=pool, audit=True)
        if not a0["ok"]:
            raise EqError("audit build A0 failed; see " + a0["log"])
        audit_file = Path(a0["out"]) / AUDIT_REL
        shutil.copy2(audit_file, self.work / "audit_cc.jsonl")
        audit_recs = probe.load_audit(audit_file)
        symbols = probe.binary_symbols(Path(a0["out"]) / self.target)
        c0_cache = self.work / "cache" / "C0"
        c0_cache.mkdir()
        results: dict[str, object] = {}

        def c0_job(cpus):
            self.build("C0", pristine, cpus=cpus, cache=c0_cache)

        if a.parallel:
            # P0 alone on --one-core; four multi-core jobs on disjoint pool chunks.
            chunks = [cpus_str(c) for c in split_pool(self.pool, 4)]
            with ThreadPoolExecutor(max_workers=5) as ex:
                futs = [ex.submit(self.build, "P0", pristine, cpus=self.one_core),
                        ex.submit(self.build, "P0prime", pristine, cpus=chunks[0]),
                        ex.submit(c0_job, chunks[1])]
                fc = ex.submit(self.pick_c_variant, audit_recs, symbols, chunks[2])
                fh = ex.submit(self.pick_h_variant, audit_recs, symbols, chunks[3])
                for f in futs:
                    f.result()
                results["c"], results["h"] = fc.result(), fh.result()
            self.note("parallel: P0 was timed while other builds ran on other cores")
        else:
            self.build("P0", pristine, cpus=self.one_core)
            self.build("P0prime", pristine, cpus=pool)
            c0_job(pool)
        if not self.builds["P0"]["ok"]:
            raise EqError("pristine build P0 failed; see " + self.builds["P0"]["log"])
        self.learn_noise()
        self.compare("P0_vs_P0prime", "P0", "P0prime")
        self.compare("P0_vs_C0", "P0", "C0")
        shutil.copytree(c0_cache, self.work / "cache" / "warm_template", symlinks=False)

        if a.parallel:
            cv, hv = results["c"], results["h"]
            # W0/WC/WH: each alone on its own core, nothing else running.
            cores = [self.one_core] + [str(c) for c in self.pool[:2]]
            jobs = [("W0", pristine)]
            if cv:
                jobs.append(("WC", cv[0]))
            if hv:
                jobs.append(("WH", hv[0]))
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
            cv = self.pick_c_variant(audit_recs, symbols, pool)
            if cv:
                self.build("WC", cv[0], cpus=self.one_core, cache=self.warm_copy("WC"))
            hv = self.pick_h_variant(audit_recs, symbols, pool)
            if hv:
                self.build("WH", hv[0], cpus=self.one_core, cache=self.warm_copy("WH"))
        self.compare("P0_vs_W0", "P0", "W0")
        if cv:
            self.edits["c"] = cv[1]
            self.compare("PC_vs_WC", "PC", "WC")
        if hv:
            self.edits["h"] = hv[1]
            if not hv[1].get("in_main_binary"):
                self.note("header fold did not reach the main binary; the header test "
                          "still checks that every includer misses")
            self.compare("PH_vs_WH", "PH", "WH")
        self.count_hooks()
        return self.verdict(ccache_version)

    def verdict(self, ccache_version: str) -> dict:
        problems = [f"{k}: missing" for k in NEEDED_PAIRS if k not in self.pairs]
        problems += [f"{k}: differs" for k in NEEDED_PAIRS
                     if k in self.pairs and self.pairs[k].get("status") == "differs"]
        det = self.pairs.get("P0_vs_P0prime", {})
        if det and det.get("status") != "identical":
            if not det.get("parts", {}).get("dict_set", True):
                problems.append("P0 vs P0': dict sets differ (non-deterministic "
                                "dictionary)")
            for part, m in self.noise.items():
                if not m.get("deterministic") and not m.get("ok"):
                    problems.append(f"P0 vs P0' {part}: non-deterministic and not "
                                    f"maskable: {m.get('why')}")
        for lbl in ("C0", "W0", "WC", "WH"):
            st = (self.builds.get(lbl) or {}).get("ccache") or {}
            if lbl not in self.builds:
                continue
            for half in ("main", "cmplog"):
                h = (st.get("builds") or {}).get(half)
                if not (h and h.get("enabled")):
                    problems.append(f"{lbl}: ccache not used for the {half} build "
                                    f"({(h or {}).get('reason') or st.get('reason')})")
            if st.get("compiler_check_failed"):
                problems.append(f"{lbl}: ccache compiler check failed "
                                f"{st['compiler_check_failed']}x")
        hooks = {lbl: (self.builds.get(lbl) or {}).get("cmplog_hook_sites") or {}
                 for lbl in ("P0", "W0")}
        if hooks["W0"]:
            if hooks["W0"].get("main"):
                problems.append(f"W0 main binary has {hooks['W0']['main']} cmplog hook "
                                "call sites (main reused cmplog objects?)")
            if hooks["P0"].get("cmplog") and \
                    hooks["W0"].get("cmplog") != hooks["P0"].get("cmplog"):
                problems.append(f"W0 cmplog hook sites {hooks['W0'].get('cmplog')} != "
                                f"P0 {hooks['P0'].get('cmplog')}")
        masked = sorted({s for k in NEEDED_PAIRS
                         for part in ((self.pairs.get(k) or {}).get("masked_detail") or {}).values()
                         for s in part.get("masked", [])})
        any_masked = any((self.pairs.get(k) or {}).get("status") == "masked"
                         for k in NEEDED_PAIRS)
        verdict = ("fail" if problems else
                   "pass_noise_masked" if any_masked else "pass")
        p0t = self.builds.get("P0", {}).get("timings", {})
        timing = {}
        for lbl in ("P0", "W0", "WC", "WH"):
            b = self.builds.get(lbl)
            if not b:
                continue
            t = {"wall_s": b["wall_s"], "cpus": b["cpus"]}
            per = ((b.get("ccache") or {}).get("builds")) or {}
            for half, key in (("main", "/out"), ("cmplog", "/out/cmplog")):
                t[f"{half}_s"] = b["timings"].get(key)
                h = per.get(half) or {}
                t[f"{half}_hits"] = h.get("hits")
                t[f"{half}_misses"] = h.get("misses")
                t[f"{half}_hit_rate"] = h.get("hit_rate")
                if p0t.get(key) and t[f"{half}_s"]:
                    t[f"{half}_speedup_vs_P0"] = round(
                        p0t[key] / max(t[f"{half}_s"], 0.1), 2)
            if t.get("main_s") is not None and t.get("cmplog_s") is not None:
                t["both_s"] = round(t["main_s"] + t["cmplog_s"], 1)
                p0b = (p0t.get("/out") or 0) + (p0t.get("/out/cmplog") or 0)
                if p0b and lbl != "P0":
                    t["both_speedup_vs_P0"] = round(p0b / max(t["both_s"], 0.1), 2)
            timing[lbl] = t
        return {"dir": self.a.dir, "image": self.image, "fuzz_target": self.target,
                "src": str(Path(self.a.src).absolute()), "ccache_version": ccache_version,
                "verdict": verdict, "pass": verdict != "fail",
                "masked_noise": masked, "problems": problems, "pairs": _slim(self.pairs),
                "noise": _slim_noise(self.noise), "builds": self.builds,
                "edits": self.edits, "timing_one_core": timing, "notes": self.notes,
                "cpuset": self.a.cpuset, "one_core": self.a.one_core,
                "parallel": bool(self.a.parallel)}


def _short_stats(st):
    return fb_ccache.slim_stats(st) if st else None


def _slim(pairs):
    out = {}
    for k, v in pairs.items():
        out[k] = {kk: vv for kk, vv in v.items() if kk not in ("a", "b")} | {
            "a": v.get("a"), "b": v.get("b")}
    return out


def _slim_noise(noise):
    out = {}
    for part, m in noise.items():
        out[part] = {k: v for k, v in m.items() if k != "regions"}
        out[part]["regions"] = [{k: v for k, v in r.items() if k not in ("pre", "post", "skeleton", "core")}
                                for r in m.get("regions", [])[:50]]
    return out


def _fuzz_target(fb_dir: str) -> str | None:
    y = BENCHMARKS_DIR / fb_dir / "benchmark.yaml"
    try:
        m = re.search(r"^fuzz_target:\s*(\S+)", y.read_text(), re.MULTILINE)
    except OSError:
        return None
    return m.group(1).strip("'\"") if m else None


def text_report(rep: dict) -> str:
    v = rep.get("verdict") or ("pass" if rep.get("pass") else "fail")
    L = [f"ccache equivalence: {rep['dir']}  ->  {v.upper()}",
         f"image {rep['image']}, target {rep['fuzz_target']}, {rep.get('ccache_version')}"]
    for k, p in rep.get("pairs", {}).items():
        st = p.get("status") or ("identical" if p.get("identical") else "differs")
        if st == "identical":
            L.append(f"  {k:16s} identical (main, cmplog, dict set)")
        elif st == "masked":
            L.append(f"  {k:16s} equal after noise masking (dict set identical)")
        else:
            bad = [q for q, ok in (p.get("parts") or {}).items() if not ok]
            L.append(f"  {k:16s} DIFFERS: {', '.join(bad) or p.get('error')}")
            for part, d in (p.get("masked_detail") or {}).items():
                if d.get("status") == "differs":
                    L.append(f"      {part}: {d.get('why')}"
                             + (f"; e.g. {d['unmasked'][0]}" if d.get("unmasked") else ""))
            if p.get("dict_only_in_a") or p.get("dict_only_in_b"):
                L.append(f"      dict only in {p['a']}: {p.get('dict_only_in_a')}; "
                         f"only in {p['b']}: {p.get('dict_only_in_b')}")
    if rep.get("masked_noise"):
        L.append("  masked noise:")
        for s in rep["masked_noise"][:20]:
            L.append(f"    {s!r}")
    e = rep.get("edits", {})
    if "c" in e:
        L.append(f"  fold in .c: {e['c']['file']} ({len(e['c']['call_lines'])} call sites; "
                 f"helper in main binary; on link line: {e['c'].get('on_link_line')})")
    if "h" in e:
        c = e["h"].get("caller")
        L.append(f"  fold in header: {e['h']['header']} (included by {e['h']['includers']} "
                 f"compiled files; called from {c['file'] if c else 'nowhere'}; helper in "
                 f"main binary: {e['h'].get('in_main_binary')})")
    L.append("  one-core build times (s), per half:")
    for lbl, t in rep.get("timing_one_core", {}).items():
        L.append(f"    {lbl:3s} cpu {t.get('cpus')} wall {t['wall_s']:>8}"
                 + (f"  both {t['both_s']}" if t.get("both_s") is not None else "")
                 + (f" ({t['both_speedup_vs_P0']}x)" if t.get("both_speedup_vs_P0") else ""))
        for half in ("main", "cmplog"):
            L.append(f"        {half:6s} {t.get(f'{half}_s')}"
                     + (f"  hits {t[f'{half}_hits']} misses {t[f'{half}_misses']} "
                        f"rate {t[f'{half}_hit_rate']}"
                        if t.get(f"{half}_hits") is not None else "")
                     + (f"  speedup {t[f'{half}_speedup_vs_P0']}x"
                        if t.get(f"{half}_speedup_vs_P0") else ""))
    for lbl in ("P0", "W0"):
        h = (rep.get("builds", {}).get(lbl) or {}).get("cmplog_hook_sites")
        if h:
            L.append(f"  {lbl} __cmplog_* call sites: main {h.get('main')}, "
                     f"cmplog {h.get('cmplog')}")
    for p in rep.get("problems", []):
        L.append(f"  PROBLEM: {p}")
    for n in rep.get("notes", []):
        L.append(f"  note: {n}")
    if rep.get("error"):
        L.append(f"  ERROR: {rep['error']}")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", required=True, help="fuzzbench_dir (image fb-aflpp/<dir>)")
    ap.add_argument("--src", required=True,
                    help="extracted project source dir (its basename must be the dir "
                         "under $SRC, e.g. .../source_tree/src/zlib)")
    ap.add_argument("--work", required=True, help="scratch dir (created; wiped on rerun)")
    ap.add_argument("--cpuset", required=True,
                    help="cores for the multi-core builds (--one-core is excluded)")
    ap.add_argument("--one-core", required=True, help="single core for the timed builds")
    ap.add_argument("--parallel", action="store_true",
                    help="run independent builds at once on disjoint core subsets")
    ap.add_argument("--image", help="override fb-aflpp/<dir>")
    ap.add_argument("--fuzz-target", help="override benchmark.yaml fuzz_target")
    ap.add_argument("--timeout", type=int, default=6 * 3600, help="per build, seconds")
    ap.add_argument("--max-candidates", type=int, default=4,
                    help="files to try per fold variant before giving up")
    a = ap.parse_args(argv)
    if not re.fullmatch(r"\d+", str(a.one_core)):
        ap.error("--one-core must be a single CPU number")
    if a.parallel and len([c for c in parse_cpus(a.cpuset) if c != int(a.one_core)]) < 4:
        ap.error("--parallel needs at least 4 cores in --cpuset besides --one-core")

    atexit.register(_cleanup_containers)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    r = None
    try:
        r = Runner(a)
        rep = r.run()
    except (EqError, OSError, subprocess.SubprocessError) as e:
        rep = {"dir": a.dir, "image": getattr(r, "image", a.image),
               "fuzz_target": getattr(r, "target", None), "pass": False,
               "verdict": "fail", "error": str(e), "problems": [str(e)],
               "pairs": _slim(getattr(r, "pairs", {})), "builds": getattr(r, "builds", {}),
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
