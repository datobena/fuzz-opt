"""hotspot_table.py: target-source hotspot ranking from perf-script call chains.

Synthetic chains, leaf first, in the exact text format perf script emits with
``-F comm,pid,period,ip,sym,symoff,dso,dsoff`` (and ``-G`` for the sample-IP
pass). Every build-DSO function below has a start address; SRC is what
addr2line would say about it.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "profile-once-fuzz-folds" / "scripts"


def _load():
    spec = importlib.util.spec_from_file_location("hotspot_table", SCRIPTS / "hotspot_table.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ht = _load()
T = "/out/demo"
SO = "/out/lib/libproj-shared.so"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
CRT = "/src/llvm-project/compiler-rt/lib/asan"

# (dso, name) -> (start, file, line). Non-PIE vaddrs: ip - symoff.
FUNCS = {
    (T, "next_char"): (0x1000, "/src/proj/parser.c", 10),
    (T, "skip_blanks"): (0x2000, "/src/proj/parser.c", 50),
    (T, "str_dup"): (0x3000, "/src/proj/str.c", 5),
    (T, "parse_doc"): (0x3800, "/src/proj/parser.c", 400),
    (T, "lex_scan"): (0x3900, "/src/proj/scanner.l", 77),
    (T, "amalgam_fn"): (0x3A00, "/src/proj/bld/amalgam.c", 9000),
    (T, "LLVMFuzzerTestOneInput"): (0x4000, "/src/proj/fuzz/target.c", 3),
    (T, "fuzz_read_entity"): (0x5000, "/src/proj/fuzz/fuzz.c", 9),
    (T, "main"): (0x6000, "/afl/utils/aflpp_driver/aflpp_driver.c", 269),
    (T, "__asan_stack_malloc_2"): (0x7000, f"{CRT}/asan_fake_stack.cpp", 259),
    (T, "__interceptor_malloc"): (0x7100, f"{CRT}/asan_malloc_linux.cpp", 65),
    (T, "__asan::Allocator::Allocate(unsigned long, unsigned long, "
        "__sanitizer::BufferedStackTrace*, __asan::AllocType, bool)"):
        (0x7200, f"{CRT}/asan_allocator.cpp", 500),
    (T, "__sanitizer_cov_trace_pc_guard"):
        (0x7300, "llvm_mode/instrumentation/afl-compiler-rt.o.c", 1374),
    (T, "memcpy"): (0x7400, f"{CRT}/../sanitizer_common/sanitizer_common_interceptors.inc", 800),
    (T, "inflate_fast"): (0x8000, "/src/zlib/inffast.c", 50),
    (T, "std::__1::__tree<int>::find(int const&)"): (0x8100, "/usr/local/include/c++/v1/__tree", 2400),
    (T, "nodebug_fn"): (0x8200, None, None),
    (T, "asan.module_ctor"): (0x8300, "/src/proj/parser.c", 1),
    (T, "sancov.module_ctor_trace_pc_guard"): (0x8400, "/src/proj/str.c", 1),
    (T, "gen_writer"): (0x8500, "/src/proj/arch/GenAsmWriter.inc", 30),
    (SO, "link_config_parse"): (0x11000, "/src/proj/src/shared/conf.c", 120),
    (SO, "hashmap_get"): (0x12000, "/src/proj/src/basic/hashmap.c", 900),
}
SRC = {(d, s): (n, f, ln) for (d, n), (s, f, ln) in FUNCS.items()}


def fr(name, off=0x4, dso=T):
    start = FUNCS[(dso, name)][0]
    return f"\t{start + off:16x} {name}+0x{off:x} ({dso}+0x{start + off:x})\n"


def lib(sym, off=0x10, dso=LIBC, ip=0x7F0000001000):
    return f"\t{ip:16x} {sym}+0x{off:x} ({dso}+0x{off:x})\n"


def kern(ip=0xFFFFFFFFB4F01891):
    return f"\t{ip:16x} [unknown] ([kernel.kallsyms]+0x{ip:x})\n"


def sample(frames, period=1000, comm="demo", pid=27):
    return f"{comm} {pid:>8} {period:>10} \n" + "".join(frames) + "\n"


def ip_line(frame, period=1000, comm="demo", pid=27):
    return f"{comm} {pid:>8} {period:>10} {frame.strip()}\n"


class FakeElf:
    is_pie = False
    known = {"demo", "libproj-shared.so"}

    def __init__(self, path):
        self.path = str(path)
        if os.path.basename(self.path) not in self.known:
            raise ht.HotspotError(f"cannot read {path}")

    def symbol_addresses(self, names):
        return {n: FUNCS[(T, n)][0] for n in names if (T, n) in FUNCS}


def _fake_resolve(binary, addrs, **k):
    dso = SO if binary.endswith("libproj-shared.so") else T
    return {a: SRC[(dso, a)] for a in addrs if (dso, a) in SRC}


@pytest.fixture
def fake_binary(monkeypatch):
    monkeypatch.setattr(ht, "ElfInfo", FakeElf)
    monkeypatch.setattr(ht, "resolve_sources", _fake_resolve)


def build(tmp_path, text, ip_text=None, **kw):
    p = tmp_path / "perf_script.txt"
    p.write_text(text)
    if ip_text is not None:
        (tmp_path / "ip.txt").write_text(ip_text)
        kw["ip_script"] = tmp_path / "ip.txt"
    return ht.build_hotspot_table(perf_script=p, binary=tmp_path / "demo",
                                  fuzz_target="demo", out_dir=tmp_path / "out", **kw)


def row(res, name):
    return next(r for r in res["functions"] if r["function"] == name)


@pytest.fixture
def tree(tmp_path):
    """An editable tree named like the project dir, as the agent gets it."""
    t = tmp_path / "src" / "proj"
    for rel in ("parser.c", "str.c", "scanner.l", "fuzz/target.c", "fuzz/fuzz.c",
                "src/shared/conf.c", "src/basic/hashmap.c", "arch/GenAsmWriter.inc"):
        (t / rel).parent.mkdir(parents=True, exist_ok=True)
        (t / rel).write_text("")
    return t


# --- parsing ------------------------------------------------------------------
def test_frame_line_keeps_cpp_signatures_and_splits_offsets():
    line = ("\t          4adfae __sanitizer::InternalAlloc(unsigned long, __sanitizer::"
            "SizeClassAllocator32LocalCache<__sanitizer::SizeClassAllocator32<__sanitizer::AP32> >*,"
            " unsigned long)+0x4e (/out/xml+0xadfae)\n")
    ip, sym, symoff, dso, dsoff = ht.parse_frame_line(line)
    assert ip == 0x4ADFAE and symoff == 0x4E and dso == "/out/xml" and dsoff == 0xADFAE
    assert sym.startswith("__sanitizer::InternalAlloc(unsigned long") and sym.endswith("long)")
    ip, sym, symoff, dso, dsoff = ht.parse_frame_line(
        "\t    7df76c461a00 [unknown] (/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2+0x25a00)\n")
    assert sym == "[unknown]" and symoff is None and dso.endswith("ld-linux-x86-64.so.2")


def test_iter_samples_reads_headers_periods_and_chains():
    text = (sample([fr("next_char"), fr("parse_doc")], period=7, comm="my prog")
            + sample([kern()], period=3))
    got = list(ht.iter_samples(text.splitlines(keepends=True)))
    assert [p for p, _ in got] == [7, 3]
    assert len(got[0][1]) == 2 and len(got[1][1]) == 1


def test_build_dsos_are_the_target_and_shared_libraries_under_out():
    assert ht.is_build_dso("/out/demo", "demo")
    assert ht.is_build_dso("/out/src/shared/libsystemd-shared-255.so", "demo")
    assert not ht.is_build_dso("/out/afl-showmap", "demo")
    assert not ht.is_build_dso(LIBC, "demo")


# --- attribution ----------------------------------------------------------------
def test_sanitizer_leaf_is_credited_to_the_nearest_target_function(tmp_path, fake_binary):
    chain = [fr("__asan_stack_malloc_2"), fr("next_char"), fr("skip_blanks"),
             fr("LLVMFuzzerTestOneInput"), fr("main")]
    res = build(tmp_path, sample(chain, period=100))
    nc, sb = row(res, "next_char"), row(res, "skip_blanks")
    assert nc["samples"] == 1 and nc["sanitizer_pct"] == 100.0 and nc["caused_pct"] == 100.0
    assert sb["samples"] == 0 and sb["caused_pct"] == 0.0
    assert sb["inclusive_pct"] == 100.0 and nc["inclusive_pct"] == 100.0
    assert nc["file"] == "/src/proj/parser.c" and nc["line"] == 10


def test_allocator_sub_bucket_includes_kernel_work_under_malloc(tmp_path, fake_binary):
    alloc = [fr("__asan::Allocator::Allocate(unsigned long, unsigned long, "
                "__sanitizer::BufferedStackTrace*, __asan::AllocType, bool)"),
             fr("__interceptor_malloc"), fr("str_dup"), fr("parse_doc")]
    faulting = [kern(), fr("__interceptor_malloc"), fr("str_dup"), fr("parse_doc")]
    res = build(tmp_path, sample(alloc, 30) + sample(faulting, 10) + sample([fr("str_dup")], 60))
    sd = row(res, "str_dup")
    assert sd["samples"] == 3
    assert sd["allocator_pct"] == 40.0 and sd["self_pct"] == 60.0
    assert sd["kernel_pct"] == 0.0 and sd["sanitizer_pct"] == 0.0


def test_runtime_and_third_party_code_get_separate_columns(tmp_path, fake_binary):
    """std-library templates, vendored libraries outside the tree and code with
    no debug info are NOT sanitizer runtime."""
    text = (sample([fr("memcpy"), fr("parse_doc")], 10)                  # interceptor
            + sample([fr("__sanitizer_cov_trace_pc_guard"), fr("parse_doc")], 20)
            + sample([fr("std::__1::__tree<int>::find(int const&)"), fr("parse_doc")], 30)
            + sample([fr("inflate_fast"), fr("parse_doc")], 25)
            + sample([fr("nodebug_fn"), fr("parse_doc")], 15))
    pd = row(build(tmp_path, text), "parse_doc")
    assert pd["sanitizer_pct"] == 30.0 and pd["thirdparty_pct"] == 70.0


def test_libc_kernel_and_harness_leaves_get_their_own_columns(tmp_path, fake_binary):
    text = (sample([lib("memcpy"), fr("parse_doc")], 10)
            + sample([kern(), fr("parse_doc")], 20)
            + sample([fr("fuzz_read_entity"), fr("parse_doc")], 30)
            + sample([fr("__sanitizer_cov_trace_pc_guard"), fr("parse_doc")], 40))
    pd = row(build(tmp_path, text), "parse_doc")
    assert (pd["libc_pct"], pd["kernel_pct"], pd["other_pct"], pd["sanitizer_pct"]) == \
        (10.0, 20.0, 30.0, 40.0)
    assert pd["caused_pct"] == 100.0


def test_recursion_counts_once_for_inclusive(tmp_path, fake_binary):
    rec = [fr("next_char", 4), fr("next_char", 8), fr("next_char", 12), fr("parse_doc")]
    mutual = [fr("next_char"), fr("parse_doc"), fr("next_char"), fr("parse_doc", 0x20)]
    res = build(tmp_path, sample(rec, 50) + sample(mutual, 50))
    nc, pd = row(res, "next_char"), row(res, "parse_doc")
    assert nc["inclusive_samples"] == 2 and nc["inclusive_pct"] == 100.0
    assert pd["inclusive_samples"] == 2 and pd["inclusive_pct"] == 100.0
    assert nc["samples"] == 2 and nc["self_pct"] == 100.0


def test_truncated_chains_still_attribute_from_the_leaf(tmp_path, fake_binary):
    truncated = [fr("__sanitizer_cov_trace_pc_guard"), fr("skip_blanks")]
    no_target = [fr("__asan_stack_malloc_2"), fr("__sanitizer_cov_trace_pc_guard")]
    res = build(tmp_path, sample(truncated, 70) + sample(no_target, 30))
    assert row(res, "skip_blanks")["sanitizer_pct"] == 70.0
    out = res["totals"]["outside_target"]
    assert out["samples"] == 1 and out["by_class"]["sanitizer"]["pct"] == 30.0


def test_classification_excludes_harness_support_and_driver(tmp_path, fake_binary):
    text = (sample([fr("LLVMFuzzerTestOneInput"), fr("main")], 10)
            + sample([fr("fuzz_read_entity"), fr("LLVMFuzzerTestOneInput")], 10)
            + sample([fr("main")], 10)
            + sample([fr("inflate_fast"), fr("LLVMFuzzerTestOneInput")], 10)
            + sample([lib("showmap_run", dso="/out/afl-showmap")], 10, comm="afl-showmap")
            + sample([lib("[unknown]", dso="/usr/bin/bash")], 10, comm="bash")
            + sample([fr("next_char")], 40))
    res = build(tmp_path, text)
    assert {r["function"] for r in res["functions"]} == {"next_char"}
    out = res["totals"]["outside_target"]["by_class"]
    assert out["other"]["samples"] == 5
    assert out["thirdparty"]["samples"] == 1
    assert res["source_root"] == "/src/proj"
    assert "/src/proj/fuzz/target.c" in res["harness_files"]


# --- finding: project code in the build's own shared libraries ---------------------
def test_shared_libraries_of_the_build_produce_rows(tmp_path, fake_binary):
    chain = [fr("hashmap_get", dso=SO), fr("link_config_parse", dso=SO),
             fr("LLVMFuzzerTestOneInput"), fr("main")]
    res = build(tmp_path, sample(chain, 80) + sample([fr("parse_doc")], 20))
    hg = row(res, "hashmap_get")
    assert hg["dso"] == SO and hg["caused_pct"] == 80.0
    assert row(res, "link_config_parse")["inclusive_pct"] == 80.0
    assert SO in res["build_dsos"]
    txt = (tmp_path / "out" / "hotspots.txt").read_text()
    assert "in libproj-shared.so" in txt


def test_build_image_libraries_the_profiler_supplies_are_libc_class(tmp_path, monkeypatch,
                                                                    fake_binary):
    """target_libs.py mounts the build image's own libraries (glib) at
    /opt/target-libs: outside /out, so never build DSOs or rows, never
    symbolized, and their cost lands in the libc class like any system library."""
    glib = "/opt/target-libs/libglib-2.0.so.0"
    assert not ht.is_build_dso(glib, "demo")
    assert ht.Classifier.classify_dso_frame(glib) == ht.CLS_LIBC
    seen = []
    monkeypatch.setattr(ht, "resolve_sources",
                        lambda binary, addrs, **k: seen.append(binary) or _fake_resolve(binary, addrs))
    text = (sample([lib("g_hash_table_lookup", dso=glib), fr("parse_doc")], 30)
            + sample([lib("g_slice_alloc", dso=glib)], 10)
            + sample([fr("next_char")], 60))
    res = build(tmp_path, text)
    pd = row(res, "parse_doc")
    assert pd["libc_pct"] == 30.0 and pd["caused_pct"] == 30.0
    assert not any(r["function"].startswith("g_") for r in res["functions"])
    assert res["totals"]["outside_target"]["by_class"]["libc"]["pct"] == 10.0
    assert glib not in res["build_dsos"] and not any(glib in b for b in seen)


def test_a_build_library_missing_on_the_host_is_not_project_code(tmp_path, fake_binary):
    gone = "/out/lib/libgone.so"
    line = f"\t{0x9010:16x} gone_fn+0x10 ({gone}+0x9010)\n"
    res = build(tmp_path, sample([line, fr("parse_doc")], 10))
    assert row(res, "parse_doc")["thirdparty_pct"] == 100.0
    assert res["timings"]["build_dsos_missing_on_host"] == [gone]


# --- finding: source root / editable tree -------------------------------------------
def test_a_copy_built_under_another_prefix_maps_by_path_suffix(tmp_path, monkeypatch, tree):
    """The build compiled a COPY of the tree (/src/fuzzers/x/proj/...)."""
    copy = "/src/fuzzers-checkout/projects/x/proj"
    funcs = {(T, n): (s, f.replace("/src/proj", copy) if f else f, ln)
             for (d, n), (s, f, ln) in FUNCS.items() if d == T}
    by_addr = {s: (n, f, ln) for (d, n), (s, f, ln) in funcs.items()}
    monkeypatch.setattr(ht, "ElfInfo", FakeElf)
    monkeypatch.setattr(ht, "resolve_sources", lambda b, addrs, **k: {
        a: by_addr[a] for a in addrs if a in by_addr})
    res = build(tmp_path, sample([fr("next_char"), fr("parse_doc")], 10),
                source_root="/src/proj", source_tree=tree)
    nc = row(res, "next_char")
    assert nc["rel_path"] == "parser.c" and nc["editable"] is True
    assert nc["file"] == f"{copy}/parser.c"


def test_editable_flag_marks_generated_and_non_c_sources(tmp_path, fake_binary, tree):
    text = (sample([fr("next_char")], 10) + sample([fr("lex_scan")], 10)
            + sample([fr("amalgam_fn")], 10))
    res = build(tmp_path, text, source_root="/src/proj", source_tree=tree)
    assert row(res, "next_char")["editable"] is True
    lx = row(res, "lex_scan")
    assert lx["editable"] is False and "generator input" in lx["edit_note"]
    am = row(res, "amalgam_fn")           # generated at build time, still a row
    assert am["editable"] is False and "generated" in am["edit_note"]
    assert am["rel_path"] == "bld/amalgam.c"
    txt = (tmp_path / "out" / "hotspots.txt").read_text()
    assert " n   amalgam_fn" in txt and " y   next_char" in txt
    # Without the tree the flag is unknown, never guessed.
    assert row(build(tmp_path, sample([fr("next_char")], 1)), "next_char")["editable"] is None


def test_source_root_mismatch_fails_loudly(tmp_path, fake_binary, tree, monkeypatch):
    """Nothing maps, yet the build's file names exist in the tree."""
    names = ("a.c", "b.c", "c.c", "d.c", "e.c")
    for n in names:
        (tree / n).write_text("")
    funcs = {0x1000 + i * 0x100: (f"f{i}", f"/elsewhere/odd/{n}", 1)
             for i, n in enumerate(names)}
    monkeypatch.setattr(ht, "resolve_sources", lambda b, addrs, **k: {
        a: funcs[a] for a in addrs if a in funcs})
    text = "".join(sample([f"\t{a + 4:16x} {v[0]}+0x4 ({T}+0x{a + 4:x})\n"], 10)
                   for a, v in funcs.items())
    with pytest.raises(ht.HotspotError, match="source-root mismatch"):
        build(tmp_path, text, source_root="/src/proj", source_tree=tree)


# --- finding: the leaf is the sample IP ---------------------------------------------
def test_sample_ip_is_the_leaf_under_lbr(tmp_path, fake_binary):
    """LBR puts a just-called callee first (sample taken on the call): drop it.
    A chain whose first entry is the caller of the IP's function: prepend."""
    inflight = sample([fr("__sanitizer_cov_trace_pc_guard", 0), fr("next_char"),
                       fr("parse_doc")], 60)
    returned = sample([fr("parse_doc")], 40)
    ips = ip_line(fr("next_char"), 60) + ip_line(fr("skip_blanks"), 40)
    res = build(tmp_path, inflight + returned, ips)
    nc = row(res, "next_char")
    assert nc["self_pct"] == 60.0 and nc["sanitizer_pct"] == 0.0
    assert row(res, "skip_blanks")["self_pct"] == 40.0
    assert row(res, "parse_doc")["inclusive_pct"] == 100.0
    assert res["timings"]["ip_leaf_fixed_samples"] == 2


def test_mismatched_dumps_fail_loudly(tmp_path, fake_binary):
    text = sample([fr("next_char")], 10) + sample([fr("parse_doc")], 20)
    with pytest.raises(ht.HotspotError, match="ended after"):
        build(tmp_path, text, ip_line(fr("next_char"), 10))
    with pytest.raises(ht.HotspotError, match="disagree"):
        build(tmp_path, text, ip_line(fr("next_char"), 10) + ip_line(fr("parse_doc"), 99))
    with pytest.raises(ht.HotspotError, match="more samples"):
        build(tmp_path, text, ip_line(fr("next_char"), 10) + ip_line(fr("parse_doc"), 20)
              + ip_line(fr("parse_doc"), 5))
    with pytest.raises(ht.HotspotError, match="perf report counts 3"):
        build(tmp_path, text, expected_samples=3)


def test_totals_add_up_and_every_sampled_function_is_listed(tmp_path, fake_binary):
    text = "".join(sample([fr(n), fr("parse_doc")], p) for n, p in
                   (("next_char", 5), ("skip_blanks", 7), ("str_dup", 11)))
    text += sample([kern()], 13) + sample([fr("parse_doc")], 17)
    res = build(tmp_path, text, expected_samples=5)
    t = res["totals"]
    assert t["target_attributed"]["samples"] + t["outside_target"]["samples"] == t["samples"] == 5
    assert t["target_attributed"]["period"] + t["outside_target"]["period"] == t["period"] == 53
    assert {r["function"] for r in res["functions"]} == {
        "next_char", "skip_blanks", "str_dup", "parse_doc"}
    assert [r["rank"] for r in res["functions"]] == [1, 2, 3, 4]
    assert res["functions"][0]["function"] == "parse_doc"
    for r in res["functions"]:
        parts = sum(r[k] for k in ("self_pct", "sanitizer_pct", "thirdparty_pct",
                                   "allocator_pct", "libc_pct", "kernel_pct", "other_pct"))
        assert parts == pytest.approx(r["caused_pct"], abs=1e-3)
    raw = (tmp_path / "out" / "hotspots.json").read_text()
    on_disk = json.loads(raw)
    assert on_disk["totals"] == t
    assert str(tmp_path) not in raw and on_disk["binary"] == "/out/demo"
    txt = (tmp_path / "out" / "hotspots.txt").read_text()
    assert "target-attributed:" in txt and "outside target:" in txt
    assert "Inlined functions are reported under" in txt
    assert "parse_doc  [parser.c:400]" in txt          # tree-relative when it maps


def test_explicit_source_root_wins(tmp_path, fake_binary):
    res = build(tmp_path, sample([fr("next_char")], 1), source_root="/src/other")
    assert res["functions"] == [] and res["source_root"] == "/src/other"


def test_missing_or_empty_input_is_a_hotspot_error(tmp_path, fake_binary):
    with pytest.raises(ht.HotspotError):
        ht.build_hotspot_table(perf_script=tmp_path / "nope.gz", binary=tmp_path / "demo",
                               fuzz_target="demo", out_dir=tmp_path)
    with pytest.raises(ht.HotspotError, match="no samples"):
        build(tmp_path, "\n\n")


def test_pie_binaries_use_the_dso_offset(tmp_path, monkeypatch):
    class Pie(FakeElf):
        is_pie = True

        def file_offset_to_vaddr(self, off):
            return off + 0x1000

    monkeypatch.setattr(ht, "ElfInfo", Pie)
    monkeypatch.setattr(ht, "resolve_sources", lambda b, addrs, **k: {
        0x2000: ("pie_fn", "/src/proj/a.c", 1)})
    line = "\t    55d0deadb010 pie_fn+0x10 (/out/demo+0x1010)\n"
    res = build(tmp_path, sample([line]), source_root="/src/proj")
    assert row(res, "pie_fn")["addr"] == "0x2000"


# --- source resolution ----------------------------------------------------------
def test_resolve_sources_takes_the_outermost_inline_frame(monkeypatch):
    out = ("0x0000000000001000\ninlined_helper\n/src/proj/h.h:3\n"
           "outer_fn\n/src/proj/a.c:42 (discriminator 2)\n"
           "0x0000000000002000\n??\n??:0\n")
    monkeypatch.setattr(ht, "find_symbolizer", lambda: ["addr2line"])
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["input"] = cmd, kw["input"]
        return subprocess.CompletedProcess(cmd, 0, out, "")
    monkeypatch.setattr(ht.subprocess, "run", fake_run)
    got = ht.resolve_sources("/bin/x", [0x2000, 0x1000, 0x1000])
    assert got[0x1000] == ("outer_fn", "/src/proj/a.c", 42)
    assert got[0x2000] == ("??", None, None)
    assert seen["input"] == "0x1000\n0x2000\n"
    assert seen["cmd"][1:6] == ["-a", "-f", "-i", "-C", "-e"]


def test_no_symbolizer_is_loud(monkeypatch):
    monkeypatch.setattr(ht, "find_symbolizer", lambda: None)
    with pytest.raises(ht.HotspotError, match="addr2line"):
        ht.resolve_sources("/bin/x", [0x1000])
    assert ht.symbolizer_selftest()[0] is False


def test_symbolizer_finds_versioned_llvm_addr2line(monkeypatch, tmp_path):
    (tmp_path / "llvm-addr2line-18").write_text("")
    monkeypatch.setattr(ht.shutil, "which", lambda name: None)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert ht.find_symbolizer() == [str(tmp_path / "llvm-addr2line-18")]


def test_symbolizer_selftest_runs_the_real_tool():
    if ht.find_symbolizer() is None:
        pytest.skip("no addr2line on this host")
    ok, note = ht.symbolizer_selftest()
    assert ok, note


def test_elf_reader_on_a_real_binary():
    elf = ht.ElfInfo(sys.executable)
    assert elf.e_type in (2, 3) and elf.loads
    off, vaddr, _ = elf.loads[0]
    assert elf.file_offset_to_vaddr(off) == vaddr


def test_compiler_generated_module_ctors_are_sanitizer_not_rows(tmp_path, fake_binary):
    """asan.module_ctor / sancov.module_ctor_* carry the project file's debug
    info but no edit can touch them."""
    text = (sample([fr("asan.module_ctor")], 40)
            + sample([fr("sancov.module_ctor_trace_pc_guard")], 10)
            + sample([fr("next_char")], 50))
    res = build(tmp_path, text)
    assert {r["function"] for r in res["functions"]} == {"next_char"}
    assert res["totals"]["outside_target"]["by_class"]["sanitizer"]["pct"] == 50.0


def test_inc_fragments_are_not_called_generator_input(tmp_path, fake_binary, tree):
    res = build(tmp_path, sample([fr("gen_writer")], 10), source_root="/src/proj",
                source_tree=tree)
    r = row(res, "gen_writer")
    assert r["editable"] is False
    assert ".inc file" in r["edit_note"] and "generator" not in r["edit_note"]
    lx = row(build(tmp_path, sample([fr("lex_scan")], 10), source_root="/src/proj",
                   source_tree=tree), "lex_scan")
    assert "generator input (.l)" in lx["edit_note"]


def test_build_dso_samples_counts_any_frame_in_the_build(tmp_path, fake_binary):
    text = (sample([fr("asan.module_ctor")], 10)                 # build, no project row
            + sample([lib("showmap_run", dso="/out/afl-showmap")], 10, comm="afl-showmap")
            + sample([kern(), fr("next_char")], 10))
    t = build(tmp_path, text)["totals"]
    assert t["build_dso_samples"] == 2 and t["target_attributed"]["samples"] == 1
