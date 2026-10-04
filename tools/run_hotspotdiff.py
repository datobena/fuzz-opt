#!/usr/bin/env python3
"""Seed-vs-mutation hotspot-diff diagnostic.

Phase 2 optimizes a fuzz target for throughput by profiling ONLY the initial
seed corpus: it freezes the seeds into a fixed corpus and runs
``replay_fuzzer_profile.py`` (a deterministic libFuzzer ``-runs=0`` replay under
``perf``) to produce ``.../profiles/profile_once/flat.txt``, the self-time hotspot
list the optimizer folds against.

But during a REAL fuzzing campaign the inputs executed are not the seeds -- they
are the MUTATIONS the fuzzer generates from those seeds, which may exercise a
different set of hot functions. If the seed-corpus profile is not representative
of that mutation workload, the optimizer may be folding the wrong hotspots. This
tool measures the gap: it captures the mutations libFuzzer generates from the same
initial corpus into a saved corpus, then diffs a profile of that saved corpus
against a profile of the seed corpus -- both on the same baseline binary.

Flow
----
1. Seed profile: ``-runs=0`` replay of the initial corpus under perf.
2. Mutation capture: build a DIAGNOSTIC target with a custom-mutator shim
   (``mutation_dump_mutator.c``) linked in, fuzz it from the same initial corpus,
   and have the shim write EVERY mutation (regardless of coverage) to a corpus,
   capped at ``--mutation-cap``. Freeze that as the saved mutation corpus.
3. Mutation profile: ``-runs=0`` replay of the saved mutation corpus under perf.
Because each profile is a replay of the exact inputs it measures, profile ==
replay == corpus, and a later replay reuses the same saved mutation corpus.

Design notes
------------
* Both profiles run on the SAME (clean) baseline binary via the same replay
  profiler, so the two sides are directly comparable. The shim build is used ONLY
  to generate mutations, never to profile.
* The initial corpus defaults to the BUNDLED default seed corpus shipped with the
  target (``seed_corpus/build/``) -- the same corpus the phase-3 fuzzing campaign
  starts from -- NOT the accumulated GCS public corpus. Change with
  ``--corpus-source {bundled,fixed,merged,gcs}``.
* Capturing every mutation needs the shim linked into the target: libFuzzer only
  persists coverage-increasing inputs and has no flag to dump all mutations, and
  ``LLVMFuzzerCustomMutator`` is a static (weak) symbol that can't be LD_PRELOADed.
  The shim is injected as an object on the fuzz-target link line in build.sh
  (before ``$LIB_FUZZING_ENGINE``) during an OSS-Fuzz ``compile``.
* ``perf report`` is generated INSIDE the container (via replay_fuzzer_profile.py).
  Host-side reporting against a container-recorded ``perf.data`` yields raw
  addresses instead of symbols (``/out`` does not exist on the host).
* Both profiles surface libFuzzer engine + sanitizer + kernel/system-lib frames.
  ``is_noise_frame`` filters them so the diff compares TARGET-LIBRARY hotspots; the
  fuzzer-overhead share is itself reported as a separate metric.

Usage
-----
    python3 tools/run_hotspotdiff.py --experiment new-kube-1-rerun --projects selinux \
        --duration 120 --mutation-cap 50000 --seed 1337

Produces per target:
    hotspotdiff/<project>-<cve>/mutations/            (SAVED mutation corpus, reusable)
    hotspotdiff/<project>-<cve>/mutation/flat.txt     (profile of the saved corpus)
    hotspotdiff/<project>-<cve>/seed/flat.txt         (profile of the seed corpus)
    hotspotdiff/<project>-<cve>/hotspot_diff.{json,md}
    hotspotdiff/summary.md
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import time
import types
import zipfile
from pathlib import Path

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
import phase3_k8s as p3

RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"  # == replay_fuzzer_profile.RUNNER_IMAGE
OUT_DEFAULT = "hotspotdiff"


# --------------------------------------------------------------------------- #
# perf flat.txt parsing
# --------------------------------------------------------------------------- #
# A flat.txt row from ``perf report --stdio --no-children -g none`` looks like:
#     18.93%  secilc-fuzzer  secilc-fuzzer       [.] avtab_map
#      0.94%  secilc-fuzzer  [kernel.kallsyms]   [k] __irqentry_text_end
# Columns: Overhead  Command  Shared-Object  [.]|[k] Symbol. The command and DSO
# are single tokens (perf truncates the command to 15 chars); the symbol is
# everything after the map marker and MAY contain spaces (C++ signatures).
_FLAT_ROW = re.compile(
    r"^\s*(?P<pct>\d+\.\d+)%\s+"
    r"(?P<command>\S+)\s+"
    r"(?P<dso>\S+)\s+"
    r"\[(?P<kind>[.k])\]\s+"
    r"(?P<symbol>.+?)\s*$"
)


def parse_flat_text(text: str) -> list[dict]:
    """Parse perf flat.txt content into hotspot rows (comment/blank lines skipped)."""
    rows: list[dict] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _FLAT_ROW.match(line)
        if not m:
            continue
        rows.append({
            "pct": float(m.group("pct")),
            "command": m.group("command"),
            "dso": m.group("dso"),
            "kind": m.group("kind"),
            "symbol": m.group("symbol"),
        })
    return rows


def parse_flat(path: str | Path) -> list[dict]:
    return parse_flat_text(Path(path).read_text(errors="replace"))


# --------------------------------------------------------------------------- #
# frame filtering: drop libFuzzer engine + sanitizer + kernel/system-lib frames
# so the diff compares TARGET-LIBRARY hotspots. Mirrors the profiling skills'
# guidance (references/profile_guided_analysis.md) to filter out harness/driver
# and kernel/system-library frames.
# --------------------------------------------------------------------------- #
_NOISE_SYMBOL_RES = [re.compile(p) for p in (
    r"^fuzzer::",                       # all libFuzzer internals + mutation engine
    r"^__sanitizer",                    # __sanitizer_cov_* and __sanitizer::*
    r"^__asan", r"^__lsan", r"^__msan", r"^__ubsan", r"^__tsan",
    r"^__interceptor_",                 # sanitizer libc interceptors
    r"^(StartFuzzing|RunOneTest|LLVMFuzzerRunDriver|FuzzerDriver|ExecuteFilesOnyByOne)\b",
    r"^LLVMFuzzerTestOneInput$",        # harness/driver boundary (negligible self-time)
)]

_NOISE_DSOS = ("[kernel.kallsyms]", "[vdso]", "[unknown]", "[vsyscall]")
_NOISE_DSO_PREFIXES = (
    "libc-", "libc.so", "ld-", "libc++", "libstdc++", "libgcc",
    "libm-", "libm.so", "libpthread", "libdl-", "librt-", "ld-linux",
)


def is_noise_frame(row: dict) -> bool:
    """True if this hotspot is fuzzer/sanitizer/kernel/system-lib overhead."""
    if row.get("kind") == "k":
        return True
    dso = row.get("dso", "")
    if dso in _NOISE_DSOS or dso.startswith(_NOISE_DSO_PREFIXES):
        return True
    sym = row.get("symbol", "")
    return any(rx.match(sym) for rx in _NOISE_SYMBOL_RES)


def split_frames(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Partition rows into (library_frames, noise_frames)."""
    lib, noise = [], []
    for r in rows:
        (noise if is_noise_frame(r) else lib).append(r)
    return lib, noise


def overhead_share(rows: list[dict]) -> float:
    """Total self-time %% attributable to noise (fuzzer/sanitizer/kernel) frames."""
    return round(sum(r["pct"] for r in rows if is_noise_frame(r)), 2)


# --------------------------------------------------------------------------- #
# diff engine
# --------------------------------------------------------------------------- #
def _sym_map(rows: list[dict]) -> dict[str, float]:
    m: dict[str, float] = {}
    for r in rows:
        m[r["symbol"]] = m.get(r["symbol"], 0.0) + r["pct"]
    return m


def diff_profiles(
    seed_rows: list[dict],
    mut_rows: list[dict],
    *,
    delta_threshold: float = 0.5,
    top_n: int = 10,
) -> dict:
    """Diff two lists of (already noise-filtered) library hotspot rows.

    Returns ``{"rows": [...], "summary": {...}}`` where each row is
    ``{symbol, dso, seed_pct, mutation_pct, delta, ratio, category}`` and
    ``category`` is one of new/gone/grown/shrunk/stable.
    """
    seed = _sym_map(seed_rows)
    mut = _sym_map(mut_rows)
    dso: dict[str, str] = {}
    for r in seed_rows + mut_rows:
        dso.setdefault(r["symbol"], r.get("dso", ""))

    rows = []
    for s in set(seed) | set(mut):
        sp = seed.get(s, 0.0)
        mp = mut.get(s, 0.0)
        delta = round(mp - sp, 3)
        in_s, in_m = s in seed, s in mut
        if in_s and not in_m:
            cat = "gone"
        elif in_m and not in_s:
            cat = "new"
        elif abs(delta) < delta_threshold:
            cat = "stable"
        elif delta > 0:
            cat = "grown"
        else:
            cat = "shrunk"
        rows.append({
            "symbol": s,
            "dso": dso.get(s, ""),
            "seed_pct": round(sp, 3),
            "mutation_pct": round(mp, 3),
            "delta": delta,
            "ratio": round(mp / sp, 3) if sp > 0 else None,
            "category": cat,
        })
    rows.sort(key=lambda r: abs(r["delta"]), reverse=True)
    return {"rows": rows, "summary": _summary(rows, seed, mut, top_n)}


def _summary(rows, seed, mut, top_n) -> dict:
    top_seed = {s for s, _ in sorted(seed.items(), key=lambda kv: kv[1], reverse=True)[:top_n]}
    top_mut = {s for s, _ in sorted(mut.items(), key=lambda kv: kv[1], reverse=True)[:top_n]}
    inter = top_seed & top_mut
    union = top_seed | top_mut
    jaccard = round(len(inter) / len(union), 3) if union else 0.0

    new_rows = [r for r in rows if r["category"] == "new"]
    max_new = round(max((r["mutation_pct"] for r in new_rows), default=0.0), 2)
    representative = jaccard >= 0.7 and max_new < 5.0
    return {
        "top_n_overlap": {
            "n": top_n,
            "jaccard": jaccard,
            "shared": sorted(inter),
            "rank_preserved": len(inter),
        },
        "library_selftime_seed": round(sum(seed.values()), 2),
        "library_selftime_mutation": round(sum(mut.values()), 2),
        "new_sum": round(sum(r["mutation_pct"] for r in new_rows), 2),
        "gone_sum": round(sum(r["seed_pct"] for r in rows if r["category"] == "gone"), 2),
        "grown_sum": round(sum(r["delta"] for r in rows if r["category"] == "grown"), 2),
        "shrunk_sum": round(sum(-r["delta"] for r in rows if r["category"] == "shrunk"), 2),
        "max_new_pct": max_new,
        "representative": representative,
        "verdict": (
            "seed profile representative of mutation workload"
            if representative
            else "seed profile NOT representative -- mutation hotspots differ"
        ),
    }


# --------------------------------------------------------------------------- #
# mutation capture primitives live in mutation_capture.py (shared with phase 2)
# --------------------------------------------------------------------------- #
from mutation_capture import (  # noqa: E402
    SHIM_SRC_DEFAULT,
    _count_files,
    run_mutation_capture,
)


# --------------------------------------------------------------------------- #
# replay profiler: reuse the existing (in-container, symbol-resolving) tool.
# Used for BOTH the seed corpus and the saved mutation corpus, so each side is a
# -runs=0 replay of the exact inputs it profiles (profile == replay == corpus).
# --------------------------------------------------------------------------- #
def _load_skill_module(name: str):
    path = Path(config.PHASE2_SKILL_SCRIPTS_DIR) / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load skill module {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_replay_profile(
    *,
    out_dir: str | Path,
    corpus_dir: str | Path,
    artifact_dir: str | Path,
    fuzz_target: str,
    min_sample_seconds: int,
    seed: int,
    cpu: int,
    memory: str = "4g",
    shm_size: str = "2g",
) -> dict:
    """Perf-profile a deterministic ``-runs=0`` replay of ``corpus_dir`` on the
    binary in ``out_dir`` via replay_fuzzer_profile.py (reports in-container so
    symbols resolve). Writes ``<artifact_dir>/flat.txt`` + ``callgraph.txt``.
    """
    profiler = _load_skill_module("replay_fuzzer_profile")
    ns = types.SimpleNamespace(
        out_dir=str(out_dir),
        corpus_dir=str(corpus_dir),
        artifact_dir=str(artifact_dir),
        fuzz_target=fuzz_target,
        min_sample_seconds=int(min_sample_seconds),
        loop_timeout=1800,
        seed=int(seed),
        cpu=int(cpu),
        memory=memory,
        shm_size=shm_size,
    )
    profiler.run_replay_profile(ns)
    return {"mode": "replay", "min_sample_seconds": min_sample_seconds, "seed": seed,
            "corpus_dir": str(corpus_dir), "corpus_file_count": _count_files(corpus_dir)}


# --------------------------------------------------------------------------- #
# path resolution (mirrors run_covtime.py / run_covdiff_pertrial.py conventions)
# --------------------------------------------------------------------------- #
def _dir_has_files(directory: Path) -> bool:
    return directory.is_dir() and any(p.is_file() for p in directory.rglob("*"))


def _corpus_source_dir(base: Path, source: str) -> Path:
    """Map a --corpus-source choice to its on-disk directory under results/."""
    diff_dir = base / "optimized" / "source_diff" / "profiles"
    return {
        # DEFAULT: the seed corpus shipped with the target (the bundled
        # <target>_seed_corpus.zip), which is exactly what the phase-3 fuzzing
        # campaign starts from -- deliberately NOT the accumulated GCS public
        # corpus (which for a vulnerable target also carries fuzzing discoveries).
        "bundled": base / "seed_corpus" / "build",
        "fixed": diff_dir / "fixed_corpus",       # phase-2's GCS-derived frozen snapshot
        "merged": base / "seed_corpus" / "merged",  # gcs + bundled merged
        "gcs": base / "seed_corpus" / "gcs",       # GCS public ClusterFuzz corpus
    }[source]


def _extract_bundled_seed_corpus(base: Path, fuzz_target: str, dest: Path) -> Path | None:
    """Materialize the default bundled seed corpus from the shipped
    ``<target>_seed_corpus.zip`` when ``seed_corpus/build/`` was not populated."""
    for cand in (base / "baseline" / "bin" / f"{fuzz_target}_seed_corpus.zip",
                 base / "optimized" / "bin" / f"{fuzz_target}_seed_corpus.zip"):
        if cand.is_file():
            dest.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(cand) as zf:
                zf.extractall(dest)
            return dest if _dir_has_files(dest) else None
    return None


def resolve_paths(
    entry: dict,
    experiment: str,
    *,
    out_dir_override: str | None = None,
    corpus_override: str | None = None,
    seed_flat_override: str | None = None,
    corpus_source: str = "bundled",
) -> dict:
    key = p3.cve_key(entry["project"], entry["cve"])
    base = Path(config.RESULTS_DIR) / experiment / key
    diff_dir = base / "optimized" / "source_diff" / "profiles"

    baseline_out = Path(out_dir_override) if out_dir_override else base / "baseline" / "bin"
    corpus_dir = (Path(corpus_override) if corpus_override
                  else _corpus_source_dir(base, corpus_source))
    seed_flat = Path(seed_flat_override) if seed_flat_override else diff_dir / "profile_once" / "flat.txt"

    return {
        "key": key,
        "base": base,
        "fuzz_target": entry.get("fuzz_target", ""),
        "baseline_out": baseline_out,
        "corpus_dir": corpus_dir,
        "corpus_source": "override" if corpus_override else corpus_source,
        "seed_flat": seed_flat,
    }


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #
def render_markdown(diff: dict, meta: dict) -> str:
    s = diff["summary"]
    L = []
    L.append(f"# Hotspot Diff -- {meta.get('key', '?')}")
    L.append("")
    L.append("Seed-corpus profile vs. saved-mutation profile -- both are `-runs=0` "
             "replays on the baseline binary, so each profile is a replay of the exact "
             "inputs it measures. Library hotspots only (libFuzzer/sanitizer/kernel "
             "frames filtered).")
    L.append("")
    L.append("## Run")
    L.append("")
    L.append(f"- fuzz target: `{meta.get('fuzz_target', '?')}`")
    L.append(f"- baseline binary: `{meta.get('baseline_out', '?')}`")
    L.append(f"- initial corpus: `{meta.get('corpus_dir', '?')}` "
             f"({meta.get('seed_corpus_file_count', '?')} files, "
             f"source={meta.get('corpus_source', '?')})")
    L.append(f"- seed profile source: {meta.get('seed_source', '?')}")
    fs = meta.get("mutation_final_stats") or {}
    L.append(f"- saved mutation corpus: `{meta.get('mutation_corpus', '?')}` "
             f"({meta.get('mutation_corpus_count', '?')} inputs, "
             f"cap {meta.get('mutation_cap', '?')}, raw {meta.get('mutation_raw_count', '?')})")
    L.append(f"- generation: shim build `{meta.get('builder_image', '?')}`, "
             f"{meta.get('duration', '?')}s fuzz, seed={meta.get('seed', '?')}; "
             f"fuzzer execs {fs.get('executed_units', '?')}, "
             f"cov={fs.get('cov', '?')}, ft={fs.get('ft', '?')}")
    L.append("")
    L.append("## Summary")
    L.append("")
    ov = s["top_n_overlap"]
    L.append(f"- **verdict: {s['verdict']}**")
    L.append(f"- top-{ov['n']} hotspot overlap (Jaccard): **{ov['jaccard']}** "
             f"({ov['rank_preserved']} shared)")
    L.append(f"- library self-time captured: seed {s['library_selftime_seed']}%, "
             f"mutation {s['library_selftime_mutation']}%")
    L.append(f"- fuzzer/sanitizer overhead share: seed {meta.get('seed_overhead_pct', '?')}%, "
             f"mutation {meta.get('mutation_overhead_pct', '?')}%")
    L.append(f"- new-under-fuzzing self-time: {s['new_sum']}% (max single {s['max_new_pct']}%); "
             f"gone: {s['gone_sum']}%; grown: +{s['grown_sum']}%; shrunk: -{s['shrunk_sum']}%")
    L.append("")
    L.append("## Per-function (sorted by |delta|)")
    L.append("")
    L.append("| symbol | dso | seed% | mut% | delta | category |")
    L.append("|---|---|---:|---:|---:|---|")
    for r in diff["rows"]:
        L.append(f"| `{r['symbol']}` | {r['dso']} | {r['seed_pct']} | "
                 f"{r['mutation_pct']} | {r['delta']:+} | {r['category']} |")
    L.append("")
    return "\n".join(L)


def write_report(out_dir: str | Path, diff: dict, meta: dict) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hotspot_diff.json").write_text(
        json.dumps({"meta": meta, "diff": diff}, indent=2)
    )
    (out_dir / "hotspot_diff.md").write_text(render_markdown(diff, meta))
    print(f"  wrote {out_dir / 'hotspot_diff.json'} and {out_dir / 'hotspot_diff.md'}")


# --------------------------------------------------------------------------- #
# per-target orchestration
# --------------------------------------------------------------------------- #
def analyze_one(
    entry: dict,
    experiment: str,
    out_root: str | Path,
    args: argparse.Namespace,
    *,
    run_capture=run_mutation_capture,
    run_replay=run_replay_profile,
) -> dict | None:
    paths = resolve_paths(
        entry, experiment,
        out_dir_override=args.baseline_out_dir,
        corpus_override=args.corpus_dir,
        seed_flat_override=args.seed_flat,
        corpus_source=args.corpus_source,
    )
    key, target = paths["key"], paths["fuzz_target"]
    print(f"[{key}] target={target}")
    if not target:
        print(f"  SKIP {key}: no fuzz_target in manifest")
        return None
    if not (paths["baseline_out"] / target).is_file():
        print(f"  SKIP {key}: baseline binary missing at {paths['baseline_out'] / target}")
        return None

    out_dir = Path(out_root) / key

    # Resolve the initial corpus; if the bundled seed dir was never populated,
    # materialize it from the shipped <target>_seed_corpus.zip. Both the seed
    # profile and the mutation window start from this SAME corpus.
    corpus_dir = paths["corpus_dir"]
    if _count_files(corpus_dir) == 0 and not args.corpus_dir and paths["corpus_source"] == "bundled":
        extracted = _extract_bundled_seed_corpus(paths["base"], target, out_dir / "_bundled_seeds")
        if extracted:
            corpus_dir = extracted
            print(f"  materialized bundled seed corpus -> {corpus_dir} ({_count_files(corpus_dir)} files)")
    if _count_files(corpus_dir) == 0:
        print(f"  SKIP {key}: initial corpus empty at {corpus_dir} (source={paths['corpus_source']})")
        return None
    print(f"  initial corpus: {corpus_dir} "
          f"({_count_files(corpus_dir)} files, source={paths['corpus_source']})")

    # --- seed profile: -runs=0 replay of the initial corpus on baseline ------
    if args.use_existing_seed_profile:
        seed_flat = paths["seed_flat"]
        if not seed_flat.is_file():
            print(f"  SKIP {key}: existing seed profile missing at {seed_flat}")
            return None
        seed_source = f"existing:{seed_flat}"
    else:
        seed_art = out_dir / "seed"
        print(f"  seed profile: replay {corpus_dir} on baseline ...")
        run_replay(
            out_dir=paths["baseline_out"],
            corpus_dir=corpus_dir,
            artifact_dir=seed_art,
            fuzz_target=target,
            min_sample_seconds=args.min_sample_seconds,
            seed=args.seed,
            cpu=args.cpu,
        )
        seed_flat = seed_art / "flat.txt"
        seed_source = f"regenerated:{seed_flat}"

    # --- mutation: capture every mutation, freeze, then replay-profile it -----
    image = args.image or (
        f"gcr.io/oss-fuzz/{entry['local_id']}" if entry.get("local_id") else None
    )
    if entry.get("image"):
        image = entry["image"]  # explicit n132/arvo image wins
    if not image:
        print(f"  SKIP {key}: no builder image (need manifest 'image' or 'local_id') "
              f"for the shim build")
        return None
    print(f"  mutation capture: shim-build {image}, generate <= {args.mutation_cap} "
          f"mutations ({args.duration}s), freeze ...")
    frozen_dir, cap_meta = run_capture(
        image=image,
        shim_src=args.shim_src,
        gen_out_dir=out_dir / "mutgen",
        seed_corpus_dir=corpus_dir,
        work_corpus_dir=out_dir / "gen_corpus",
        mut_raw_dir=out_dir / "mutations_raw",
        frozen_dir=out_dir / "mutations",
        fuzz_target=target,
        duration=args.duration,
        seed=args.seed,
        cap=args.mutation_cap,
        every=args.mutation_every,
        reservoir=args.reservoir,
        guarantee_queue=args.guarantee_queue,
        queue_depth=args.queue_depth,
        ensure_one_queue_pass=args.ensure_one_queue_pass,
        cpu=args.cpu,
        sanitizer=args.sanitizer,
        reuse_build=not args.rebuild_shim,
    )
    print(f"  saved mutation corpus: {frozen_dir} ({cap_meta['frozen_count']} inputs)")
    mut_art = out_dir / "mutation"
    print(f"  mutation profile: replay saved mutation corpus on baseline ...")
    run_replay(
        out_dir=paths["baseline_out"],
        corpus_dir=frozen_dir,
        artifact_dir=mut_art,
        fuzz_target=target,
        min_sample_seconds=args.min_sample_seconds,
        seed=args.seed,
        cpu=args.cpu,
    )
    mut_flat = mut_art / "flat.txt"

    # --- parse, filter, diff -------------------------------------------------
    seed_rows_all = parse_flat(seed_flat)
    mut_rows_all = parse_flat(mut_flat)
    seed_lib, _ = split_frames(seed_rows_all)
    mut_lib, _ = split_frames(mut_rows_all)
    diff = diff_profiles(seed_lib, mut_lib,
                         delta_threshold=args.delta_threshold, top_n=args.top_n)

    meta = {
        "key": key,
        "experiment": experiment,
        "fuzz_target": target,
        "baseline_out": str(paths["baseline_out"]),
        "corpus_dir": str(corpus_dir),
        "corpus_source": paths["corpus_source"],
        "seed_corpus_file_count": _count_files(corpus_dir),
        "duration": args.duration,
        "seed": args.seed,
        "seed_source": seed_source,
        "seed_overhead_pct": overhead_share(seed_rows_all),
        "mutation_overhead_pct": overhead_share(mut_rows_all),
        "builder_image": image,
        "mutation_corpus": str(frozen_dir),
        "mutation_corpus_count": cap_meta.get("frozen_count"),
        "mutation_raw_count": cap_meta.get("raw_count"),
        "mutation_cap": cap_meta.get("cap"),
        "mutation_final_stats": cap_meta.get("final_stats", {}),
    }
    write_report(out_dir, diff, meta)
    return {"key": key, "summary": diff["summary"], "meta": meta}


def _write_rollup(out_root: Path, results: list[dict]) -> None:
    L = ["# Hotspot Diff -- summary", "",
         "| target | top-N overlap | mut overhead% | verdict |",
         "|---|---:|---:|---|"]
    for r in results:
        s = r["summary"]
        L.append(f"| {r['key']} | {s['top_n_overlap']['jaccard']} | "
                 f"{r['meta']['mutation_overhead_pct']} | {s['verdict']} |")
    out = "\n".join(L) + "\n"
    (out_root / "summary.md").write_text(out)
    print(f"\nwrote {out_root / 'summary.md'}")


def load_manifest(experiment: str) -> list[dict]:
    path = Path(f"manifest_{experiment}.json")
    if not path.exists():
        path = Path(config.MANIFEST_PATH)
    return json.load(open(path))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment", default="new-kube-1-rerun",
                    help="experiment id; reads manifest_<exp>.json under results/<exp>/")
    ap.add_argument("--projects", nargs="*", default=None,
                    help="subset of projects (default: all in manifest)")
    ap.add_argument("--duration", type=int, default=120,
                    help="mutation-generation fuzzing window in seconds (default 120); "
                         "capped early once --mutation-cap inputs are saved")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--cpu", type=int, default=max(config.RESERVED_CORES - 1, 0),
                    help="CPU to pin generation + both replay profiles to")
    ap.add_argument("--min-sample-seconds", type=int, default=120,
                    help="perf sample floor for each -runs=0 replay profile")
    ap.add_argument("--mutation-cap", type=int, default=50000,
                    help="max mutations to save into the corpus (default 50000)")
    ap.add_argument("--mutation-every", type=int, default=1,
                    help="pre-filter: consider 1 of every N mutations (default 1 = all)")
    ap.add_argument("--reservoir", dest="reservoir", action="store_true", default=True,
                    help="uniform reservoir sample over the whole run (default)")
    ap.add_argument("--prefix", dest="reservoir", action="store_false",
                    help="legacy first-N sampling (biased to the run's opening, early-exits)")
    ap.add_argument("--guarantee-queue", dest="guarantee_queue", action="store_true", default=True,
                    help="guarantee every seed is mutated >=1x (one pass, reserved) (default)")
    ap.add_argument("--no-guarantee-queue", dest="guarantee_queue", action="store_false",
                    help="skip the guaranteed seed-queue pass")
    ap.add_argument("--queue-depth", type=int, default=5,
                    help="mutations per seed in the guaranteed pass (libFuzzer mutate_depth=5)")
    ap.add_argument("--ensure-queue-pass", dest="ensure_one_queue_pass", action="store_true", default=True,
                    help="run for max(duration, time_for_one_queue) (default)")
    ap.add_argument("--no-ensure-queue-pass", dest="ensure_one_queue_pass", action="store_false",
                    help="use the fixed duration even if one queue pass takes longer")
    ap.add_argument("--sanitizer", default="address",
                    help="sanitizer for the shim generation build (default address)")
    ap.add_argument("--shim-src", default=SHIM_SRC_DEFAULT,
                    help="path to the custom-mutator shim C source")
    ap.add_argument("--image", default=None,
                    help="builder image override (default gcr.io/oss-fuzz/<local_id> "
                         "or the manifest 'image' field)")
    ap.add_argument("--rebuild-shim", action="store_true",
                    help="force rebuilding the shim target even if it already exists")
    ap.add_argument("--corpus-source", choices=["bundled", "fixed", "merged", "gcs"],
                    default="bundled",
                    help="initial corpus to profile+fuzz from (default: bundled = the "
                         "default seed corpus shipped with the target, i.e. what phase-3 "
                         "fuzzing starts from; NOT the GCS public corpus)")
    ap.add_argument("--use-existing-seed-profile", action="store_true",
                    help="read the pre-existing profile_once/flat.txt instead of "
                         "regenerating it (note: profile_once was built from the GCS "
                         "fixed_corpus, so it will not match --corpus-source bundled)")
    ap.add_argument("--out-root", default=OUT_DEFAULT)
    ap.add_argument("--delta-threshold", type=float, default=0.5,
                    help="min |seed-mut| self-time %% to count as grown/shrunk (else stable)")
    ap.add_argument("--top-n", type=int, default=10,
                    help="hotspot depth for the overlap metric")
    # single-target explicit overrides
    ap.add_argument("--baseline-out-dir", default=None)
    ap.add_argument("--corpus-dir", default=None)
    ap.add_argument("--seed-flat", default=None)
    args = ap.parse_args()

    entries = load_manifest(args.experiment)
    if args.projects:
        want = set(args.projects)
        entries = [e for e in entries if e["project"] in want]
    if not entries:
        ap.error("no matching manifest entries")

    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    results = []
    for e in entries:
        try:
            r = analyze_one(e, args.experiment, out_root, args)
        except Exception as exc:  # keep going across targets
            print(f"  ERROR {p3.cve_key(e['project'], e['cve'])}: {exc}")
            continue
        if r:
            results.append(r)

    if results:
        _write_rollup(out_root, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
