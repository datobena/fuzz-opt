import importlib.util
import json
import subprocess
import types
from pathlib import Path


def _load(name="run_hotspotdiff"):
    path = Path(__file__).resolve().parent.parent / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# Real selinux flat.txt rows (from profile_once) + a kernel frame + junk lines.
FLAT = (
    "# Overhead  Command  Shared Object  Symbol\n"
    "# ........  .......  .............  ......\n"
    "#\n"
    "    18.93%  secilc-fuzzer  secilc-fuzzer       [.] __sanitizer_cov_trace_cmp4\n"
    "    16.66%  secilc-fuzzer  secilc-fuzzer       [.] avtab_map\n"
    "    12.23%  secilc-fuzzer  secilc-fuzzer       [.] ebitmap_set_bit\n"
    "     2.23%  secilc-fuzzer  secilc-fuzzer       [.] fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool)\n"
    "     1.69%  secilc-fuzzer  secilc-fuzzer       [.] __asan::Allocator::Allocate\n"
    "     0.94%  secilc-fuzzer  [kernel.kallsyms]   [k] __irqentry_text_end\n"
    "     0.51%  secilc-fuzzer  libc-2.31.so        [.] __memmove_avx_unaligned\n"
    "\n"
    "WARNING: some junk line that must be ignored\n"
    "#\n"
)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def test_parse_flat_extracts_rows():
    m = _load()
    rows = m.parse_flat_text(FLAT)
    assert len(rows) == 7  # junk/comment/blank skipped
    assert rows[0] == {"pct": 18.93, "command": "secilc-fuzzer",
                       "dso": "secilc-fuzzer", "kind": ".",
                       "symbol": "__sanitizer_cov_trace_cmp4"}
    assert rows[1]["symbol"] == "avtab_map"
    # C++ signature with spaces preserved intact.
    assert rows[3]["symbol"].startswith("fuzzer::Fuzzer::RunOne(unsigned char")
    # kernel frame keeps its bracketed DSO and [k] kind.
    assert rows[5]["kind"] == "k" and rows[5]["dso"] == "[kernel.kallsyms]"


def test_parse_flat_reads_file(tmp_path):
    m = _load()
    p = tmp_path / "flat.txt"
    p.write_text(FLAT)
    assert len(m.parse_flat(p)) == 7


# --------------------------------------------------------------------------- #
# noise filter
# --------------------------------------------------------------------------- #
def test_is_noise_frame_filters_engine_sanitizer_kernel_syslib():
    m = _load()

    def f(sym, dso="target-fuzzer", kind="."):
        return m.is_noise_frame({"symbol": sym, "dso": dso, "kind": kind})

    assert f("fuzzer::Fuzzer::RunOne(...)")
    assert f("fuzzer::MutationDispatcher::Mutate")
    assert f("__sanitizer_cov_trace_cmp4")
    assert f("__sanitizer::StackDepotBase<x>::Put")
    assert f("__asan::Allocator::Allocate")
    assert f("__interceptor_memcpy")
    assert f("LLVMFuzzerTestOneInput")
    assert f("__irqentry_text_end", kind="k")                 # kernel by kind
    assert f("__memmove_avx_unaligned", dso="libc-2.31.so")   # system lib by DSO
    # real target hotspots are kept
    assert not f("avtab_map", dso="secilc-fuzzer")
    assert not f("ebitmap_set_bit", dso="secilc-fuzzer")
    # a genuine target function living in a .so shared library is NOT dropped
    assert not f("vips_foreign_load", dso="libvips.so.42")


def test_split_frames_and_overhead_share():
    m = _load()
    rows = m.parse_flat_text(FLAT)
    lib, noise = m.split_frames(rows)
    lib_syms = {r["symbol"] for r in lib}
    assert lib_syms == {"avtab_map", "ebitmap_set_bit"}
    # noise = the two sanitizer + fuzzer + asan + kernel + libc rows
    assert len(noise) == 5
    # overhead share = sum of the noise rows' pct
    assert m.overhead_share(rows) == round(18.93 + 2.23 + 1.69 + 0.94 + 0.51, 2)


# --------------------------------------------------------------------------- #
# diff engine
# --------------------------------------------------------------------------- #
def test_diff_profiles_categorizes_and_overlaps():
    m = _load()
    seed = [{"pct": 16.0, "symbol": "avtab_map", "dso": "t"},
            {"pct": 14.0, "symbol": "ebitmap_set_bit", "dso": "t"},
            {"pct": 3.0, "symbol": "only_seed", "dso": "t"},
            {"pct": 5.0, "symbol": "stable_fn", "dso": "t"}]
    mut = [{"pct": 10.0, "symbol": "avtab_map", "dso": "t"},        # shrunk -6
           {"pct": 20.0, "symbol": "ebitmap_set_bit", "dso": "t"},  # grown +6
           {"pct": 8.0, "symbol": "only_mut", "dso": "t"},          # new
           {"pct": 5.2, "symbol": "stable_fn", "dso": "t"}]         # stable (+0.2)
    d = m.diff_profiles(seed, mut, delta_threshold=0.5, top_n=10)
    by = {r["symbol"]: r for r in d["rows"]}
    assert by["avtab_map"]["category"] == "shrunk"
    assert by["ebitmap_set_bit"]["category"] == "grown"
    assert by["only_mut"]["category"] == "new"
    assert by["only_seed"]["category"] == "gone"
    assert by["stable_fn"]["category"] == "stable"
    # sorted by |delta| desc -> only_mut (new, delta=+8) leads, then the +/-6 rows
    assert d["rows"][0]["symbol"] == "only_mut"
    assert [abs(r["delta"]) for r in d["rows"][:3]] == [8.0, 6.0, 6.0]
    s = d["summary"]
    assert s["top_n_overlap"]["n"] == 10
    assert s["new_sum"] == 8.0
    assert s["gone_sum"] == 3.0


def test_diff_summary_verdict_representative_when_overlap_high():
    m = _load()
    rows = [{"pct": 10.0, "symbol": f"fn{i}", "dso": "t"} for i in range(5)]
    d = m.diff_profiles(rows, rows, delta_threshold=0.5, top_n=10)
    assert d["summary"]["top_n_overlap"]["jaccard"] == 1.0
    assert d["summary"]["representative"] is True
    assert "representative" in d["summary"]["verdict"]


def test_diff_summary_not_representative_when_new_hotspot_dominates():
    m = _load()
    seed = [{"pct": 40.0, "symbol": "a", "dso": "t"}]
    mut = [{"pct": 40.0, "symbol": "a", "dso": "t"},
           {"pct": 30.0, "symbol": "brand_new_hot", "dso": "t"}]
    d = m.diff_profiles(seed, mut, top_n=10)
    # a big brand-new fuzzing-only hotspot => seed profile not representative
    assert d["summary"]["representative"] is False
    assert d["summary"]["max_new_pct"] == 30.0


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #
def test_render_and_write_report_round_trip(tmp_path):
    m = _load()
    seed = [{"pct": 16.0, "symbol": "avtab_map", "dso": "t"}]
    mut = [{"pct": 10.0, "symbol": "avtab_map", "dso": "t"},
           {"pct": 8.0, "symbol": "only_mut", "dso": "t"}]
    diff = m.diff_profiles(seed, mut)
    meta = {"key": "selinux-CVE-2021-36085", "fuzz_target": "secilc-fuzzer",
            "mutation_overhead_pct": 40.0, "seed_overhead_pct": 30.0}
    md = m.render_markdown(diff, meta)
    assert "# Hotspot Diff -- selinux-CVE-2021-36085" in md
    assert "| `avtab_map` |" in md
    assert "verdict" in md.lower()

    m.write_report(tmp_path / "out", diff, meta)
    back = json.loads((tmp_path / "out" / "hotspot_diff.json").read_text())
    assert back["diff"]["summary"]["top_n_overlap"]["n"] == 10
    assert back["meta"]["key"] == "selinux-CVE-2021-36085"
    assert (tmp_path / "out" / "hotspot_diff.md").is_file()


# --------------------------------------------------------------------------- #
# path resolution + per-target orchestration
# --------------------------------------------------------------------------- #
def test_resolve_paths_corpus_source_defaults_to_bundled(tmp_path, monkeypatch):
    m = _load()
    monkeypatch.setattr(m.config, "RESULTS_DIR", str(tmp_path))
    entry = {"project": "selinux", "cve": "CVE-1", "fuzz_target": "secilc-fuzzer"}
    base = tmp_path / "exp" / "selinux-CVE-1"

    # DEFAULT = bundled: the default seed corpus shipped with the target, NOT gcs.
    p = m.resolve_paths(entry, "exp")
    assert p["key"] == "selinux-CVE-1"
    assert p["baseline_out"] == base / "baseline" / "bin"
    assert p["corpus_dir"] == base / "seed_corpus" / "build"
    assert p["corpus_source"] == "bundled"

    # Explicit sources map to their dirs.
    diff = base / "optimized" / "source_diff" / "profiles"
    assert m.resolve_paths(entry, "exp", corpus_source="fixed")["corpus_dir"] == diff / "fixed_corpus"
    assert m.resolve_paths(entry, "exp", corpus_source="merged")["corpus_dir"] == base / "seed_corpus" / "merged"
    assert m.resolve_paths(entry, "exp", corpus_source="gcs")["corpus_dir"] == base / "seed_corpus" / "gcs"

    # Explicit --corpus-dir override wins and is flagged as such.
    ov = m.resolve_paths(entry, "exp", corpus_override=str(tmp_path / "my"))
    assert ov["corpus_dir"] == tmp_path / "my" and ov["corpus_source"] == "override"


def test_extract_bundled_seed_corpus(tmp_path):
    import zipfile
    m = _load()
    base = tmp_path / "k"
    (base / "baseline" / "bin").mkdir(parents=True)
    zpath = base / "baseline" / "bin" / "t_seed_corpus.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("a", "x")
        z.writestr("b", "y")
    dest = tmp_path / "out" / "_bundled_seeds"
    got = m._extract_bundled_seed_corpus(base, "t", dest)
    assert got == dest and m._count_files(dest) == 2
    # missing zip -> None
    assert m._extract_bundled_seed_corpus(tmp_path / "nope", "t", tmp_path / "d2") is None


def _analyze_args(tmp_path, **over):
    ns = dict(
        baseline_out_dir=None, corpus_dir=None, seed_flat=None, corpus_source="bundled",
        use_existing_seed_profile=True, min_sample_seconds=120, seed=1337, cpu=3,
        duration=120, mutation_cap=50000, mutation_every=1, sanitizer="address",
        shim_src=str(tmp_path / "shim.c"), image=None, rebuild_shim=False,
        delta_threshold=0.5, top_n=10,
    )
    ns.update(over)
    return types.SimpleNamespace(**ns)


def test_analyze_one_captures_and_reports_with_fakes(tmp_path):
    m = _load()
    bind = tmp_path / "bin"
    bind.mkdir()
    (bind / "t").write_text("ELF")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "s0").write_text("x")
    seed_flat = tmp_path / "seed_flat.txt"
    seed_flat.write_text("    16.00%  t  t  [.] avtab_map\n")

    def fake_capture(**kw):
        frozen = Path(kw["frozen_dir"])
        frozen.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            (frozen / f"unit_{i:08d}").write_text(f"m{i}")
        return frozen, {"frozen_count": 3, "raw_count": 9, "cap": 50000,
                        "final_stats": {"executed_units": 999}}

    def fake_replay(**kw):
        art = Path(kw["artifact_dir"])
        art.mkdir(parents=True, exist_ok=True)
        (art / "flat.txt").write_text(
            "    10.00%  t  t  [.] avtab_map\n"
            "     8.00%  t  t  [.] only_mut\n"
            "    20.00%  t  t  [.] fuzzer::Fuzzer::RunOne\n"   # filtered out
        )
        return {"mode": "replay"}

    args = _analyze_args(tmp_path, baseline_out_dir=str(bind),
                         corpus_dir=str(corpus), seed_flat=str(seed_flat))
    entry = {"project": "demo", "cve": "CVE-1", "fuzz_target": "t", "local_id": 123}
    out_root = tmp_path / "hotspotdiff"
    res = m.analyze_one(entry, "exp", out_root, args,
                        run_capture=fake_capture, run_replay=fake_replay)
    assert res is not None and res["key"] == "demo-CVE-1"
    data = json.loads((out_root / "demo-CVE-1" / "hotspot_diff.json").read_text())
    cats = {r["symbol"]: r["category"] for r in data["diff"]["rows"]}
    assert cats["only_mut"] == "new"
    assert "fuzzer::Fuzzer::RunOne" not in cats               # noise filtered
    assert res["meta"]["mutation_overhead_pct"] == 20.0
    assert res["meta"]["mutation_corpus_count"] == 3          # saved corpus recorded
    assert data["meta"]["builder_image"] == "gcr.io/oss-fuzz/123"
    assert (out_root / "demo-CVE-1" / "hotspot_diff.md").is_file()


def test_analyze_one_skips_when_baseline_binary_missing(tmp_path, capsys):
    m = _load()
    args = _analyze_args(tmp_path, baseline_out_dir=str(tmp_path / "nope"))
    entry = {"project": "demo", "cve": "CVE-1", "fuzz_target": "t", "local_id": 1}
    res = m.analyze_one(entry, "exp", tmp_path / "out", args)
    assert res is None
    assert "SKIP" in capsys.readouterr().out


def test_analyze_one_skips_when_no_builder_image(tmp_path, capsys):
    m = _load()
    bind = tmp_path / "bin"; bind.mkdir(); (bind / "t").write_text("ELF")
    corpus = tmp_path / "corpus"; corpus.mkdir(); (corpus / "s0").write_text("x")
    seed_flat = tmp_path / "sf.txt"; seed_flat.write_text("  1.0%  t  t  [.] f\n")
    args = _analyze_args(tmp_path, baseline_out_dir=str(bind),
                         corpus_dir=str(corpus), seed_flat=str(seed_flat))
    entry = {"project": "demo", "cve": "CVE-1", "fuzz_target": "t"}  # no local_id/image
    res = m.analyze_one(entry, "exp", tmp_path / "out", args,
                        run_replay=lambda **k: {"mode": "replay"})
    assert res is None
    assert "no builder image" in capsys.readouterr().out
