"""ccache plumbing (main + cmplog builds) for FuzzBench-parity rebuilds (prework/fb_ccache.py,
prework/fb_ccache_probe.py, the build-command / broker / phase3 wiring, and
fb_build.sh's container-side guards). No docker: commands are built, not run."""
import json
import subprocess
from pathlib import Path

import pytest

from prework import fb_ccache, fb_ccache_probe as probe
from prework import fuzzbench_image as fbi
from prework.prework_build import build_prework_rebuild_command, rebuild_with_prework_image
from sandbox.broker import BrokerContext, _build_command

REPO = Path(__file__).resolve().parent.parent
FB_IMG = "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
FB_ENTRY = {"project": "mruby", "cve": "fuzzbench-900026", "local_id": 900026,
            "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
            "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}


# ------------------------------------------------------------------ verified list

def test_shipped_verified_list_names_real_targets():
    """Every listed target is a vendored FuzzBench benchmark (a typo would silently
    leave it uncached); stb and woff2 cannot pass the equivalence test."""
    assert fb_ccache.VERIFIED_LIST.is_file()
    listed = fb_ccache.read_verified()
    fb_root = fb_ccache.PREWORK_DIR / "fuzzbench"
    assert all((fb_root / d).is_dir() for d in listed), listed
    assert not listed & {"stb_stbi_read_fuzzer", "woff2_convert_woff2ttf_fuzzer"}


def test_read_verified_ignores_comments_and_blanks(tmp_path):
    f = tmp_path / "v.txt"
    f.write_text("# header\n\nzlib_zlib_uncompress_fuzzer  # passed 2026-10-11\n  re2_fuzzer\n")
    assert fb_ccache.read_verified(f) == {"zlib_zlib_uncompress_fuzzer", "re2_fuzzer"}
    assert fb_ccache.read_verified(tmp_path / "missing.txt") == set()


def test_verified_list_markers(tmp_path):
    f = tmp_path / "v.txt"
    f.write_text("a_dir\nb_dir pass\nc_dir  pass_noise_masked  # curl: buildinf date\n"
                 "d_dir bogus\ne_dir pass extra\n")
    assert fb_ccache.read_verified_modes(f) == {
        "a_dir": "pass", "b_dir": "pass", "c_dir": "pass_noise_masked"}
    assert fb_ccache.read_verified(f) == {"a_dir", "b_dir", "c_dir"}
    e = {**FB_ENTRY, "fuzzbench_dir": "c_dir"}
    assert fb_ccache.target_ccache_mode(e, verified_path=f) == "pass_noise_masked"
    assert fb_ccache.target_ccache_mode({**e, "fuzzbench_dir": "d_dir"},
                                        verified_path=f) is None


def test_container_verified_check_matches_host_parser(tmp_path):
    """fb_build.sh's ccache_verified() accepts exactly the lines read_verified_modes
    accepts (plain and marked entries), so the marker never turns caching off."""
    s = _fb_build()
    fn = s[s.index("ccache_verified() {"):s.index("# Prints \"<identifier>")]
    f = tmp_path / "v.txt"
    f.write_text("a_dir\nb_dir pass\nc_dir  pass_noise_masked  # x\r\n"
                 "d_dir bogus\ne_dir pass extra\n# f_dir\n")
    script = fn.replace("/fold/ccache_verified.txt", str(f))
    got = set()
    for d in ("a_dir", "b_dir", "c_dir", "d_dir", "e_dir", "f_dir", "a_di"):
        r = subprocess.run(["bash", "-c", script + f"\nccache_verified {d}"])
        if r.returncode == 0:
            got.add(d)
    assert got == set(fb_ccache.read_verified_modes(f)) == {"a_dir", "b_dir", "c_dir"}


def test_target_uses_ccache_needs_fuzzbench_verified_and_switch(tmp_path, monkeypatch):
    f = tmp_path / "v.txt"
    f.write_text("mruby_mruby_fuzzer_8c8bbd\n")
    monkeypatch.delenv("FB_CCACHE", raising=False)
    assert fb_ccache.target_uses_ccache(FB_ENTRY, verified_path=f)
    assert not fb_ccache.target_uses_ccache({**FB_ENTRY, "fuzzbench_dir": "x"},
                                            verified_path=f)
    assert not fb_ccache.target_uses_ccache({"project": "libavc", "local_id": 1},
                                            verified_path=f)
    monkeypatch.setenv("FB_CCACHE", "0")
    assert not fb_ccache.target_uses_ccache(FB_ENTRY, verified_path=f)


# ------------------------------------------------------------------ log parsing

def test_parse_stats_takes_last_record_and_computes_rate():
    log = ("noise\nFB_CCACHE_STATS {\"enabled\": false, \"reason\": \"no-mount\"}\n"
           "x FB_CCACHE_STATS {\"enabled\": true, \"hits_direct\": 6, "
           "\"hits_preprocessed\": 2, \"misses\": 2}\n")
    st = fb_ccache.parse_stats(log)
    assert st["enabled"] and st["hits"] == 8 and st["hit_rate"] == 0.8
    assert fb_ccache.parse_stats("FB_CCACHE_STATS {\"enabled\": false, "
                                 "\"reason\": \"not-verified\"}")["reason"] == "not-verified"
    assert fb_ccache.parse_stats("no stats here") is None
    assert fb_ccache.parse_stats(None) is None


def test_parse_stats_per_build_records():
    log = ('FB_CCACHE_STATS {"build": "main", "enabled": true, "hits_direct": 3, '
           '"hits_preprocessed": 1, "misses": 1}\n'
           'FB_CCACHE_STATS {"build": "cmplog", "enabled": true, "hits_direct": 5, '
           '"misses": 5}\n')
    st = fb_ccache.parse_stats(log)
    assert st["enabled"] and st["all_builds_enabled"]
    assert st["hits"] == 9 and st["misses"] == 6 and st["hit_rate"] == 0.6
    assert st["builds"]["main"]["hit_rate"] == 0.8
    assert st["builds"]["cmplog"]["hits"] == 5
    assert fb_ccache.parse_stats(log, "main")["hits"] == 4
    assert fb_ccache.parse_stats(log, "cmplog")["misses"] == 5
    slim = fb_ccache.slim_stats({**st, "counters": {"x": 1}})
    assert "counters" not in slim and set(slim["builds"]) == {"main", "cmplog"}
    # one half uncached (or an old cmplog-only log): not all builds enabled
    half = ('FB_CCACHE_STATS {"build": "main", "enabled": false, "reason": "x"}\n'
            'FB_CCACHE_STATS {"build": "cmplog", "enabled": true, "misses": 2}\n')
    st = fb_ccache.parse_stats(half)
    assert st["enabled"] and not st["all_builds_enabled"] and st["misses"] == 2
    old = 'FB_CCACHE_STATS {"enabled": true, "misses": 2}\n'
    assert not fb_ccache.parse_stats(old)["all_builds_enabled"]
    assert fb_ccache.parse_stats(old, "cmplog")["misses"] == 2


def test_parse_build_timings():
    log = "FB_BUILD_TIMING out=/out secs=12.5\nFB_BUILD_TIMING out=/out/cmplog secs=40.0\n"
    assert fb_ccache.parse_build_timings(log) == {"/out": 12.5, "/out/cmplog": 40.0}


# ------------------------------------------------------------------ /out compare

def _out(d: Path, main=b"M", cmplog=b"C", dict_lines=('"a"', '"b"')):
    (d / "cmplog").mkdir(parents=True)
    (d / "t").write_bytes(main)
    (d / "cmplog" / "t").write_bytes(cmplog)
    (d / "afl++.dict").write_text("\n".join(dict_lines) + "\n")
    return d


def test_compare_outs_uses_dict_entry_set_not_order(tmp_path):
    a = _out(tmp_path / "a", dict_lines=('"a"', '"b"', '"a"'))
    b = _out(tmp_path / "b", dict_lines=('"b"', '"a"'))
    assert fb_ccache.compare_outs(a, b, "t")["identical"]


def test_compare_outs_flags_each_part(tmp_path):
    a = _out(tmp_path / "a")
    b = _out(tmp_path / "b", cmplog=b"X", dict_lines=('"a"',))
    r = fb_ccache.compare_outs(a, b, "t")
    assert not r["identical"]
    assert r["parts"] == {"main": True, "cmplog": False, "dict_set": False}
    assert r["dict_only_in_a"] == ['"b"']


def test_compare_outs_missing_file_is_not_identical(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    assert not fb_ccache.compare_outs(a, b, "t")["identical"]


def test_seed_cache_copies_fresh(tmp_path):
    tpl = tmp_path / "tpl"
    (tpl / "a" / "b").mkdir(parents=True)
    (tpl / "a" / "b" / "obj.o").write_text("x")
    (tpl / "tmp").mkdir()
    (tpl / "tmp" / "junk").write_text("y")
    dest = tmp_path / "trial" / "ccache"
    dest.mkdir(parents=True)
    (dest / "stale").write_text("z")
    fb_ccache.seed_cache(tpl, dest)
    assert (dest / "a" / "b" / "obj.o").read_text() == "x"
    assert not (dest / "stale").exists() and not (dest / "tmp").exists()
    assert (tpl / "a" / "b" / "obj.o").exists(), "template untouched"


# ------------------------------------------------------------------ build commands

def _mounts(cmd):
    return [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]


def test_build_command_unchanged_without_cache():
    base = fbi.fuzzbench_build_command(image=FB_IMG, source_dir="/x/src/mruby",
                                       out_dir="/x/out", cpu=7)
    assert base == fbi.fuzzbench_build_command(image=FB_IMG, source_dir="/x/src/mruby",
                                               out_dir="/x/out", cpu=7, ccache_dir=None)
    assert not any("ccache" in m for m in _mounts(base))


def test_build_command_mounts_cache_and_verified_list():
    cmd = fbi.fuzzbench_build_command(image=FB_IMG, source_dir="/x/src/mruby",
                                      out_dir="/x/out", cpu=7, ccache_dir="/x/trial/ccache")
    m = _mounts(cmd)
    assert "/x/trial/ccache:/ccache" in m
    assert f"{fb_ccache.VERIFIED_LIST}:/fold/ccache_verified.txt:ro" in m
    assert "FB_CCACHE_FORCE=1" not in cmd, "only the equivalence tool forces"
    assert cmd[-2:] == [FB_IMG, "/fold/fb_build.sh"]


def test_harness_and_broker_pass_the_same_cache():
    harness = build_prework_rebuild_command(image=FB_IMG, source_dir="/x/src/mruby",
                                            out_dir="/x/out", project="mruby", cpu=7,
                                            ccache_dir="/x/c")
    ctx = BrokerContext(image=FB_IMG, source_dir="/x/src/mruby", out_dir="/x/out",
                        corpus_dir="/x/c", fuzz_target="t", project="mruby", cpu=7,
                        ccache_dir="/x/c")
    broker = _build_command(ctx)
    broker = broker[:broker.index("--ulimit")] + broker[broker.index("--ulimit") + 2:]
    assert broker == harness and "/x/c:/ccache" in _mounts(harness)


def test_arvo_command_refuses_a_cache():
    with pytest.raises(ValueError):
        build_prework_rebuild_command(image="bench-aflpp/libavc-arvo-16505",
                                      source_dir="/x/src/libavc", out_dir="/x/out",
                                      project="libavc", cpu=7, ccache_dir="/x/c")


def test_rebuild_with_cache_creates_and_chowns_it(tmp_path, monkeypatch):
    import prework.prework_build as pb
    calls = {}
    monkeypatch.setattr(pb, "restore_ownership",
                        lambda image, paths: calls.setdefault("chown", paths))

    class R:
        returncode, stderr = 0, ""
        stdout = 'FB_CCACHE_STATS {"enabled": true, "hits_direct": 1, "misses": 0}\n'
    monkeypatch.setattr(pb.subprocess, "run",
                        lambda cmd, **k: calls.setdefault("cmd", cmd) and R())
    src, out, cache = tmp_path / "src" / "mruby", tmp_path / "out", tmp_path / "t" / "cc"
    src.mkdir(parents=True)
    ok, log = rebuild_with_prework_image(entry=FB_ENTRY, source_dir=str(src),
                                         out_dir=str(out), cpu=41, capture_log=True,
                                         ccache_dir=str(cache))
    assert ok and cache.is_dir()
    assert calls["chown"] == [str(out), str(cache)]
    assert f"{cache}:/ccache" in _mounts(calls["cmd"])


def test_ccache_dir_reaches_the_broker_but_not_the_agent():
    from sandbox.launch import ENV_ALLOWLIST, build_agent_env
    assert fb_ccache.BROKER_ENV_KEY not in ENV_ALLOWLIST
    assert fb_ccache.BROKER_ENV_KEY not in build_agent_env(
        {fb_ccache.BROKER_ENV_KEY: "/x/trial/ccache"})


def test_online_strategy_threads_cache_to_both_build_paths(monkeypatch):
    import config
    import phase3_online
    import prework.prework_build as pb
    monkeypatch.setattr(config, "PHASE2_SANDBOX", True, raising=False)
    seen = {}
    monkeypatch.setattr(pb, "rebuild_with_prework_image",
                        lambda **k: seen.update(k) or (True, ""))
    monkeypatch.setattr(phase3_online.phase2_setup, "_find_project_source",
                        lambda root, project: Path(root) / project)
    rb, wenv = phase3_online._online_target_strategy(FB_ENTRY, "mruby_fuzzer",
                                                     profile_cpu=5, ccache_dir="/x/cc")
    rb("/x/root", "/x/out")
    assert seen["ccache_dir"] == "/x/cc" and seen["cpu"] == 5
    assert wenv("/x/root", "/x/state")[fb_ccache.BROKER_ENV_KEY] == "/x/cc"
    seen.clear()
    rb, wenv = phase3_online._online_target_strategy(FB_ENTRY, "mruby_fuzzer",
                                                     profile_cpu=5)
    rb("/x/root", "/x/out")
    assert "ccache_dir" not in seen
    assert fb_ccache.BROKER_ENV_KEY not in wenv("/x/root", "/x/state")


def test_template_skipped_for_unverified_target(tmp_path, monkeypatch):
    import phase3_online
    monkeypatch.setattr(fb_ccache, "VERIFIED_LIST", tmp_path / "empty.txt")
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path),
        baseline_bin_dir="/x", fuzz_target="t", profile_cpu=1)
    assert rec == {"enabled": False, "template": None, "reason": "not-verified"}
    rec = phase3_online._prepare_fb_ccache_template(
        entry={"project": "libavc", "local_id": 1}, project_src_dir="/x",
        online_dir=str(tmp_path), baseline_bin_dir="/x", fuzz_target="t", profile_cpu=1)
    assert rec["template"] is None


_BOTH_STATS = ('FB_CCACHE_STATS {"build": "main", "enabled": true, "misses": 3}\n'
               'FB_CCACHE_STATS {"build": "cmplog", "enabled": true, "misses": 3}\n')


def test_template_rejected_when_cold_build_differs(tmp_path, monkeypatch):
    import phase3_online
    import prework.prework_build as pb
    v = tmp_path / "v.txt"
    v.write_text("mruby_mruby_fuzzer_8c8bbd\n")
    monkeypatch.setattr(fb_ccache, "VERIFIED_LIST", v)
    monkeypatch.delenv("FB_CCACHE", raising=False)
    base = _out(tmp_path / "base", main=b"M", cmplog=b"C")

    def fake_rebuild(*, out_dir, ccache_dir, **k):
        assert ccache_dir.endswith("ccache_template")
        _out(Path(out_dir) / "x")      # wrong layout -> missing files -> differs
        return True, _BOTH_STATS
    monkeypatch.setattr(pb, "rebuild_with_prework_image", fake_rebuild)
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=1)
    assert rec["template"] is None
    assert rec["reason"] == "cold-cache-build-differs-from-uncached-baseline"
    assert not (tmp_path / "ccache_template").exists()

    def good_rebuild(*, out_dir, ccache_dir, **k):
        for p in (Path(out_dir) / "cmplog",):
            p.mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "t").write_bytes(b"M")
        (Path(out_dir) / "cmplog" / "t").write_bytes(b"C")
        (Path(out_dir) / "afl++.dict").write_text('"b"\n"a"\n')
        return True, _BOTH_STATS
    monkeypatch.setattr(pb, "rebuild_with_prework_image", good_rebuild)
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=1)
    assert rec["enabled"] and rec["template"] == str(tmp_path / "ccache_template")


# ------------------------------------------------------------------ image + script

def test_ccache_step_is_last_and_marked():
    text = fbi.patched_benchmark_builder_dockerfile(fuzzbench_dir="d", workdir="/src/p")
    assert text.rstrip().endswith("tee /fb_ccache_version")
    i = text.index("# fuzz-opt deviation: ccache")
    assert text.index("ENV FB_WORKDIR=/src/p") < i
    step = text[i:]
    assert f"apt-get download ccache={fbi.CCACHE_DEB_VERSION}" in step
    assert f"install -D -m 0755 x/usr/bin/ccache {fbi.CCACHE_BIN}" in step
    assert fbi.CCACHE_BIN == fb_ccache.CONTAINER_CCACHE_BIN == "/opt/fb_ccache/ccache"


def test_ccache_is_never_findable_by_build_systems():
    """jsoncpp's CMakeLists auto-detects ccache (find_program + COMPILER_LAUNCHER):
    the image must not have one on PATH, in /usr/lib/ccache or in cmake's hints."""
    step = fbi.CCACHE_STEP
    assert "apt-get install" not in step, "dpkg install puts ccache in /usr/bin"
    assert "command -v ccache" in step and "/usr/lib/ccache" in step and "exit 1" in step
    assert not fbi.CCACHE_BIN.startswith(("/usr/bin", "/usr/local/bin", "/bin",
                                          "/opt/local/bin"))


def _fb_build():
    return (REPO / "prework" / "fb_build.sh").read_text()


def test_fb_build_ccache_contract():
    s = _fb_build()
    assert "[ ! -d /ccache ]" in s and "FB_CCACHE_FORCE" in s
    assert "/fold/ccache_verified.txt" in s
    assert "use_cc = ccache_on\n" in s, "both builds are cached"
    assert "_ccache_env(env, kind)" in s and "'/ccache/fb_dict/' + kind" in s
    assert "env['CCACHE_COMPILERCHECK'] = key_string(env, real_dict)" in s
    assert "compilercheck.sh" not in s, "no per-call compiler-check process"
    assert "sha256sum /fold/fb_build.sh /afl/afl-cc /afl/*.so" in s
    for bad in ("CCACHE_SLOPPINESS=", "CCACHE_BASEDIR=", "CCACHE_NOHASHDIR"):
        assert bad not in s, bad
    assert "FB_AUDIT_CC_LOG" in s and '"$OUT"/*' in s
    # ccache by absolute path only, never via PATH.
    assert "FB_CCACHE_BIN=/opt/fb_ccache/ccache" in s
    assert "CCACHE_BIN = '/opt/fb_ccache/ccache'" in s
    assert "command -v ccache" not in s
    assert "['ccache'" not in s and "exec ccache" not in s


def test_ccache_changes_nothing_the_build_can_observe():
    """ccache goes BELOW afl-cc (AFL_CC/AFL_CXX); CC/CXX/CFLAGS/CXXFLAGS/PATH stay
    those of the uncached build (OpenSSL embeds "compiler: $CC $CFLAGS")."""
    s = _fb_build()
    fn = s[s.index("def _ccache_env(env, kind):"):s.index("def _audit_env(")]
    for var in ("'CC'", "'CXX'", "'CFLAGS'", "'CXXFLAGS'", "'PATH'", "CCACHE_DIR"):
        assert f"env[{var}] =" not in fn, var
    assert "append_flags" not in fn
    assert "env[var] = w" in fn and "('AFL_CC', real[0]), ('AFL_CXX', real[1])" in fn
    assert "build-sets-AFL_CC" in fn


def test_wrapper_imports_stay_minimal():
    """Python startup is most of the wrapper's per-compile cost: no subprocess /
    tempfile imports (posix_spawn instead)."""
    s = _fb_build()
    body = s[s.index('CCWRAP_PY = r"""'):]
    body = body[:body.index('"""', 20)]
    imports = [ln for ln in body.splitlines() if ln.startswith(("import ", "from "))]
    assert imports == ["import os, sys", "from hashlib import sha256 as _sha256"]
    assert "posix_spawn" in body and "subprocess" not in body


# ------------------------------------------------------------------ cc wrapper

def _wrapper_ns(tmp_path, *, is_bug=False, kind="cmplog", toolchain="tc1"):
    """CCWRAP_PY from fb_build.sh, its constants pointed into tmp_path, main() not run."""
    s = _fb_build()
    body = s[s.index('CCWRAP_PY = r"""') + len('CCWRAP_PY = r"""'):]
    body = body[:body.index('"""')]
    assert body.rstrip().endswith("main()")
    body = body.rstrip()[:-len("main()")]
    deny, ign = tmp_path / "deny.txt", tmp_path / "ign.txt"
    deny.write_text("# x\n")
    ign.write_text("# x\n")
    ns = {"REAL": str(tmp_path / "clang"), "REAL_RESOLVED": str(tmp_path / "clang"),
          "CCACHE": str(tmp_path / "ccache"),
          "STORE": str(tmp_path / "cache" / "fb_dict" / kind), "DICT_TMP": str(tmp_path),
          "DENY_FILE": str(deny),
          "IGNORE_FLAG": f"-fsanitize-coverage-ignorelist={ign}", "IS_BUG": is_bug,
          "FOLD_LISTS": {str(deny), str(ign)}, "CCACHE_CONF": {"CCACHE_DIR": "/x"},
          "KIND": kind, "TOOLCHAIN": toolchain}
    return body, ns


def test_wrapper_job_parsing(tmp_path):
    body, ns = _wrapper_ns(tmp_path)
    exec(compile(body, "ccwrap", "exec"), ns)
    job = ns["job"]
    src = tmp_path / "a.c"
    src.write_text("int x;\n")
    s = str(src)
    assert job(["-c", s, "-o", "a.o", "-I", "inc", "-DX"]) == (s, "a.o")
    assert job(["-c", s, "-oout.o"]) == (s, "out.o")
    assert job(["-c", s]) == (s, "a.o")
    assert job(["-c", "-x", "c", s, "-o", "b.o"]) == (s, "b.o")
    assert job(["-Xclang", "-load", "-Xclang", "/afl/p.so", "-c", s, "-o", "a.o"]) == (s, "a.o")
    for bad in ([s, "-o", "a"],                        # link
                ["-c", s, s, "-o", "a.o"],              # two inputs
                ["-E", "-c", s], ["-S", "-c", s],
                ["-c", "-", "-o", "a.o"],               # stdin
                ["-c", s, "-o", "-"],                   # stdout
                ["@rsp", "-c", s],                      # response file
                ["-c", str(tmp_path / "missing.c"), "-o", "a.o"]):
        assert job(bad) is None, bad


_FAKE_CLANG = """#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
open(os.environ['LOG'], 'a').write(repr(args) + ' DICT=' +
    os.environ.get('AFL_LLVM_DICT2FILE', '') + ' DENY=' +
    os.environ.get('AFL_LLVM_DENYLIST', '') + '\\n')
if '-c' in args:
    src = [a for a in args if a.endswith('.c')][0]
    out = args[args.index('-o') + 1]
    open(out, 'w').write('OBJ:' + open(src).read())
    d = os.environ.get('AFL_LLVM_DICT2FILE')
    if d:
        with open(d, 'a') as f:
            f.write('"cmplog_only_%d"\\n' % len(open(src).read()))
"""
# ccache stand-in: with HIT=1 it "hits": writes the object without the compiler.
_FAKE_CCACHE = """#!/usr/bin/env python3
import os, sys
real, args = sys.argv[1], sys.argv[2:]
open(os.environ['LOG'] + '.key', 'a').write(os.environ['CCACHE_COMPILERCHECK'] + '\\n')
if os.environ.get('HIT') == '1':
    src = [a for a in args if a.endswith('.c')][0]
    out = args[args.index('-o') + 1]
    open(out, 'w').write('OBJ:' + open(src).read())
    sys.exit(0)
os.execv(real, [real] + args)
"""


def _wrapper_exe(tmp_path, *, is_bug=False, kind="cmplog", toolchain="tc1"):
    import sys as _sys
    body, ns = _wrapper_ns(tmp_path, is_bug=is_bug, kind=kind, toolchain=toolchain)
    for name, text in (("clang", _FAKE_CLANG), ("ccache", _FAKE_CCACHE)):
        f = tmp_path / name
        f.write_text(text)
        f.chmod(0o755)
    consts = "".join(f"{k} = {v!r}\n" for k, v in ns.items())
    w = tmp_path / f"wrap_{kind}_{toolchain}.py"
    w.write_text(consts + body + "main()\n")
    return [_sys.executable, str(w)], ns


def _run_wrap(cmd, args, tmp_path, **env):
    import os as _os
    e = {**_os.environ, "LOG": str(tmp_path / "log"),
         "AFL_LLVM_DICT2FILE": str(tmp_path / "afl++.dict"), **env}
    return subprocess.run(cmd + args, cwd=tmp_path, env=e, capture_output=True, text=True)


def test_wrapper_dict_sidecar_replays_on_hit(tmp_path):
    cmd, ns = _wrapper_exe(tmp_path)
    (tmp_path / "a.c").write_text("int a;")
    real_dict = tmp_path / "afl++.dict"
    r = _run_wrap(cmd, ["-c", "a.c", "-o", "a.o"], tmp_path)     # miss: compiler runs
    assert r.returncode == 0, r.stderr
    assert real_dict.read_text() == '"cmplog_only_6"\n'
    log = (tmp_path / "log").read_text()
    assert "DICT=" + str(tmp_path) in log and "afl++.dict" not in log.split("DICT=")[1]
    store = list((tmp_path / "cache" / "fb_dict").rglob("*"))
    assert [p for p in store if p.is_file()], "lines stored by object hash"
    r = _run_wrap(cmd, ["-c", "a.c", "-o", "a.o"], tmp_path, HIT="1")  # hit: no compile
    assert r.returncode == 0, r.stderr
    assert real_dict.read_text() == '"cmplog_only_6"\n' * 2, "replayed from the store"
    assert not list(tmp_path.glob("d.*")), "per-call temp files removed"


def test_wrapper_passthrough_and_stable_lists(tmp_path):
    cmd, ns = _wrapper_exe(tmp_path, is_bug=True)
    (tmp_path / "a.c").write_text("int a;")
    r = _run_wrap(cmd, ["a.c", "-o", "prog"], tmp_path)          # link: real clang, as is
    assert r.returncode == 0
    first = (tmp_path / "log").read_text().splitlines()[0]
    assert first.startswith("['a.c', '-o', 'prog']") and "ignorelist" not in first
    assert f"DICT={tmp_path / 'afl++.dict'}" in first, "dict path untouched on passthrough"
    flag = ns["IGNORE_FLAG"]
    r = _run_wrap(cmd, ["-c", flag, "a.c", "-o", "a.o"], tmp_path)
    r = _run_wrap(cmd, ["-c", "a.c", "-o", "a.o"], tmp_path)
    lines = (tmp_path / "log").read_text().splitlines()[1:]
    strip = lambda l: l.split(" DICT=")[0] + " DENY=" + l.split(" DENY=")[1]  # noqa: E731
    assert strip(lines[0]) == strip(lines[1]), "same clang args with/without folds"
    assert lines[0].split(" DICT=")[0].endswith(f"'{flag}']")
    assert f"DENY={ns['DENY_FILE']}" in lines[0]


def _hazards(tmp_path, names, files):
    """Run fb_build.sh's own ccache_fold_hazards() over a fake $SRC."""
    script = (REPO / "prework" / "fb_build.sh").read_text()
    fn = script[script.index("ccache_fold_hazards() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    src = tmp_path / "src"
    for rel, text in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + fn +
                        'SRC="$1"; fold_names="$2"; ccache_fold_hazards',
                        "x", str(src), "\n".join(names)],
                       capture_output=True, text=True, check=True)
    return sorted(r.stdout.split("\n")[:-1])


def test_hazard_check_flags_suffix_and_mangled_substring(tmp_path):
    files = {"a.c": "int unfold_hash(void);\n",
             "a2.c": "int fold_hash(int);\n",
             "b.cc": "void fold_hashxxxxxxxxxx();\n",       # len 19 -> "19fold_hash"
             "c.c": "int case_fold_ab_x; int fold_ab;\n"}
    got = _hazards(tmp_path, ["fold_hash", "fold_ab"], files)
    assert "unfold_hash fold_hash" in got
    assert "fold_hashxxxxxxxxxx fold_hash" in got
    assert not any(g.startswith("case_fold_ab_x") for g in got), got


def test_hazard_check_quiet_for_clean_names(tmp_path):
    files = {"a.c": "int fold_hash(int x) { return x; }\nint fold_hash_fast(int);\n"}
    # fold_hash_fast is itself an added name (excluded anyway), and "14fold_hash_fast"
    # does not contain "9fold_hash".
    assert _hazards(tmp_path, ["fold_hash", "fold_hash_fast"], files) == []
    assert _hazards(tmp_path, [], files) == []


# ------------------------------------------------------------------ probe edits

KNR = """/* c */
#include "zutil.h"
local int f OF((int x));

int ZEXPORT f(x)
int x;
{
    return x;
}
"""
ANSI = """#include "a.h"
#ifdef __cplusplus
extern "C" {
#endif
static const char *s = "{ not a body }";
static int g(int a,
             int b)
{
  if (a) {
    return b;
  }
  return 0;
}
struct q *mk(void) {
  return 0;
}
int tbl[] = { 1, 2 };
#ifdef __cplusplus
}
#endif
"""


def test_function_bodies_found_in_knr_and_ansi():
    assert probe.function_body_lines(KNR) == [6]
    lines = ANSI.split("\n")
    got = probe.function_body_lines(ANSI)
    assert [lines[i].strip() for i in got] == ["{", "struct q *mk(void) {"]


def test_add_c_fold_inserts_helper_and_calls():
    text, info = probe.add_c_fold(ANSI)
    lines = text.split("\n")
    assert lines[0] == "static __attribute__((noinline, used)) int"
    assert lines[1] == f"{probe.C_HELPER}(int x)"
    assert text.count(f"{probe.C_HELPER}(7);") == 2
    assert len(info["call_lines"]) == 2
    for ln in info["call_lines"]:
        assert probe.C_HELPER in lines[ln - 1]
    assert max(len(l) for l in lines) <= probe.MAX_COLS
    assert probe.add_c_fold(text) is None, "never applied twice"


def test_fold_never_goes_into_the_harness():
    h = "int LLVMFuzzerTestOneInput(const char *d, int n)\n{\n  return 0;\n}\n"
    assert probe.add_c_fold(h) is None


def test_call_inserted_after_brace_of_one_line_bodies():
    """jsoncpp: `Reader::Reader() : f_(x) {}` used to get the call after the line,
    i.e. at file scope ('redefinition of fbcc_probe_h_v')."""
    cpp = ("namespace Json {\n"
           "Features Features::all() { return {}; }\n"
           "Reader::Reader() : features_(Features::all()) {}\n"
           "constexpr int k(int a) { return a; }\n"
           "}\n")
    text, info = probe.add_c_fold(cpp)
    lines = text.split("\n")
    assert len(info["call_lines"]) == 2, "constexpr bodies are skipped"
    for ln in info["call_lines"]:
        assert lines[ln - 2].rstrip().endswith("{")
        assert lines[ln - 1].lstrip().startswith("__attribute__((unused)) volatile int")
    assert "return {}; }" in text and "\n}\n" in text


def test_indented_freetype_definitions():
    ft = ("  FT_EXPORT_DEF( FT_Error )\n"
          "  FT_Init_FreeType( FT_Library  *alibrary )\n"
          "  {\n"
          "    return 0;\n"
          "  }\n")
    assert probe.function_defs(ft) == [(2, 2, "FT_Init_FreeType")]
    text, info = probe.add_c_fold(ft)
    assert text.split("\n")[info["call_lines"][0] - 1].startswith("    __attribute__")


def test_inserted_lines_fit_79_columns():
    deep = "namespace a {\n" + " " * 60 + "int f(int x) {\n  return x;\n}\n}\n"
    text, info = probe.add_c_fold(deep)
    assert all(len(l) <= 79 for l in text.split("\n")[:info["call_lines"][0]])


def test_header_fold_goes_inside_guard():
    h = "/* x */\n#ifndef A_H\n#define A_H\nint a(void);\n#endif\n"
    out = probe.add_header_fold(h).split("\n")
    assert out[2] == "#define A_H" and out[3].startswith("static __inline__")
    assert out[4] == f"{probe.H_HELPER}(int x)"
    assert probe.add_header_fold("#pragma once\nint a;\n").split("\n")[1].startswith("static")
    assert probe.add_header_fold("int a;\n") is None


def test_guard_found_far_from_ifndef():
    """lcms2_internal.h: `#ifndef _lcms_internal_H` at the top, `#define` at the end."""
    h = "// c\n#ifndef G_H\n\n#include <x.h>\nint a;\n" + "int b;\n" * 50 + \
        "#define G_H\n#endif\n"
    assert probe.guard_insert_line(h) == 1
    assert probe.guard_insert_line("#ifndef G_H\nint a;\n#endif\n") is None


def test_rank_candidates_prefers_linked_code(tmp_path):
    texts = {"/src/p/ext/opcache.c": "int zend_accel(void)\n{\n  return 0;\n}\n",
             "/src/p/Zend/compile.c": "int zend_compile(void)\n{\n  return 0;\n}\n",
             "/src/p/test/ossfuzz.c": "int LLVMFuzzerTestOneInput(void)\n{\n  return 0;\n}\n",
             "/src/p/lib/linked.c": "static int helper(void)\n{\n  return 0;\n}\n"}
    ranked = probe.rank_candidates(list(texts), texts=texts, symbols={"zend_compile"},
                                   linked={"/src/p/lib/linked.c"})
    assert [p for p, _ in ranked] == ["/src/p/lib/linked.c", "/src/p/Zend/compile.c",
                                      "/src/p/ext/opcache.c"]


def test_link_line_sources():
    recs = [
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "-c", "a.c", "-o", "obj/a.o"]},
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "-c", "b.c", "-o", "b.o"]},
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "obj/a.o", "libx.a", "-o", "/out/t"]},
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "b.o", "-o", "/out/other"]},
    ]
    assert probe.link_line_sources(recs, target="t", src_root="/src/p") == {"/src/p/a.c"}


def test_compiled_sources_and_header_candidates(tmp_path):
    recs = [
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "-c", "a.c", "-o", "a.o"]},
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "-c", "/src/p/sub/b.c"]},
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "-c", "test/t.c"]},
        {"build": "main", "cwd": "/src", "argv": ["cc", "-c", "other/x.c"]},
        {"build": "main", "cwd": "/src/p", "argv": ["cc", "a.o", "-o", "t"]},
        {"build": "cmplog", "cwd": "/src/p", "argv": ["cc", "-c", "c.c"]},
    ]
    srcs = probe.compiled_sources(recs, src_root="/src/p")
    assert srcs == ["/src/p/a.c", "/src/p/sub/b.c", "/src/p/test/t.c"]
    assert probe.rank_sources(srcs)[-1] == "/src/p/test/t.c"
    tree = tmp_path / "p"
    (tree / "sub").mkdir(parents=True)
    (tree / "inc.h").write_text("#ifndef I\n#define I\n#endif\n")
    (tree / "a.c").write_text('#include "inc.h"\n')
    (tree / "sub" / "b.c").write_text('#include "../inc.h"\n')
    got = probe.header_candidates(tree, [tree / "a.c", tree / "sub" / "b.c"])
    assert got and got[0][0] == tree / "inc.h" and len(got[0][1]) == 2


def test_load_audit_skips_bad_lines(tmp_path):
    f = tmp_path / "a.jsonl"
    f.write_text(json.dumps({"build": "main"}) + "\nnot json\n\n")
    assert probe.load_audit(f) == [{"build": "main"}]


# ------------------------------------------------------------------ noise masking

def _elf(sections):
    """Minimal little-endian ELF64: [(name, flags, bytes)] -> file bytes."""
    import struct
    names = b"\0" + b"".join(n.encode() + b"\0" for n, _f, _b in sections) + b".shstrtab\0"
    body, offs = b"", []
    off = 64
    for _n, _f, data in sections:
        offs.append(off + len(body))
        body += data
    stroff = off + len(body)
    body += names
    shoff = off + len(body)
    shdrs = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    pos = 1
    for (n, f, data), o in zip(sections, offs):
        shdrs += struct.pack("<IIQQQQIIQQ", pos, 1, f, 0, o, len(data), 0, 0, 1, 0)
        pos += len(n) + 1
    shdrs += struct.pack("<IIQQQQIIQQ", pos, 3, 0, 0, stroff, len(names), 0, 0, 1, 0)
    hdr = bytearray(64)
    hdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", hdr, 0x28, shoff)
    struct.pack_into("<HHH", hdr, 0x3A, 64, len(sections) + 2, len(sections) + 1)
    return bytes(hdr) + body + shdrs


def _wb(path, data):
    path.write_bytes(data)
    return path


def _bin(host, md5, code=b"\x90" * 64, pad=b""):
    rodata = pad + b"\0hello\0Linux " + host + b" 6.8.0 x86_64\0Oct 12 2026\0tail\0"
    debug = b"D" * 40 + md5 + b"E" * 40
    return _elf([(".text", 0x6, code), (".rodata", 0x2, rodata), (".debug_line", 0, debug)])


def test_noise_masked_strings_and_debug_blocks(tmp_path):
    w = lambda n, b: _wb(tmp_path / n, b)   # noqa: E731
    p0 = w("p0", _bin(b"3fa2b1c0d9e8", b"\x01" * 16))
    p1 = w("p1", _bin(b"77aa00bb11cc", b"\x02" * 16))
    m = fb_ccache.noise_model(p0, p1)
    assert m["ok"] and not m["deterministic"]
    assert {r["kind"] for r in m["regions"]} == {"string", "block"}
    # cached build of the same tree: different hostname / MD5 -> masked
    c0 = w("c0", _bin(b"0123456789ab", b"\x03" * 16))
    r = fb_ccache.masked_compare(p0, c0, m)
    assert r["status"] == "masked", r
    assert any("Linux 0123456789ab" in x or "Linux 3fa2b1c0d9e8" in x for x in r["masked"])
    # a fold moved the layout: found again by context
    pc = w("pc", _bin(b"aaaaaaaaaaaa", b"\x04" * 16, pad=b"xyz" * 7))
    wc = w("wc", _bin(b"bbbbbbbbbbbb", b"\x05" * 16, pad=b"xyz" * 7))
    assert fb_ccache.masked_compare(pc, wc, m)["status"] == "masked"
    # a compiler-path string of a different length is never masked
    cc = w("cc", _bin(b"3fa2b1c0d9e8", b"\x01" * 16).replace(b"hello", b"hellX"))
    assert fb_ccache.masked_compare(p0, cc, m)["status"] == "differs"


def test_code_differences_are_never_noise(tmp_path):
    """woff2: a build race changes code; P0 vs P0' then has no usable noise model."""
    w = lambda n, b: _wb(tmp_path / n, b)   # noqa: E731
    p0 = w("p0", _bin(b"3fa2b1c0d9e8", b"\x01" * 16, code=b"\x90" * 64))
    p1 = w("p1", _bin(b"3fa2b1c0d9e8", b"\x01" * 16, code=b"\x90" * 32 + b"\xcc" * 32))
    m = fb_ccache.noise_model(p0, p1)
    assert not m["ok"] and "not maskable" in m["why"]
    assert fb_ccache.masked_compare(p0, p1, m)["status"] == "differs"
    det = fb_ccache.noise_model(p0, p0)
    assert det["deterministic"]
    other = w("o", _bin(b"0123456789ab", b"\x01" * 16))
    assert fb_ccache.masked_compare(p0, other, det)["status"] == "differs", \
        "P0 == P0' -> nothing is noise"


def test_compare_outs_masked_needs_equal_dict_sets(tmp_path):
    a = _out(tmp_path / "a", main=_bin(b"3fa2b1c0d9e8", b"\x01" * 16))
    b = _out(tmp_path / "b", main=_bin(b"77aa00bb11cc", b"\x02" * 16))
    c = _out(tmp_path / "c", main=_bin(b"0123456789ab", b"\x03" * 16), dict_lines=('"a"',))
    models = {"main": fb_ccache.noise_model(a / "t", b / "t"),
              "cmplog": fb_ccache.noise_model(a / "cmplog" / "t", b / "cmplog" / "t")}
    assert fb_ccache.compare_outs_masked(a, b, "t", models)["status"] == "masked"
    assert fb_ccache.compare_outs_masked(a, c, "t", models)["status"] == "differs"


# ------------------------------------------------------------------ equivalence tool

def _eq():
    import importlib
    return importlib.import_module("tools.fb_ccache_equivalence")


def test_cpu_pool_helpers():
    eq = _eq()
    assert eq.parse_cpus("40-43,47") == [40, 41, 42, 43, 47]
    chunks = eq.split_pool(list(range(40, 59)), 4)
    assert [len(c) for c in chunks] == [5, 5, 5, 4]
    assert sorted(sum(chunks, [])) == list(range(40, 59))
    with pytest.raises(eq.EqError):
        eq.split_pool([1, 2], 4)


def _runner(pairs, builds=None, noise=None):
    eq = _eq()
    r = eq.Runner.__new__(eq.Runner)
    r.a = type("A", (), {"dir": "d", "src": "/x/p", "cpuset": "1-4", "one_core": "5",
                         "parallel": False})()
    r.image, r.target, r.notes, r.edits = "img", "t", [], {}
    r.pairs, r.noise = pairs, noise or {}
    cc = {"enabled": True, "builds": {"main": {"enabled": True},
                                      "cmplog": {"enabled": True}}}
    r.builds = builds or {k: {"ccache": cc, "timings": {}, "wall_s": 1, "cpus": "5"}
                          for k in ("P0", "C0", "W0", "WC", "WH")}
    return r


def test_verdict_pass_masked_and_fail():
    ok = {k: {"status": "identical"} for k in _eq().NEEDED_PAIRS}
    assert _runner(dict(ok)).verdict("v")["verdict"] == "pass"
    masked = dict(ok, PC_vs_WC={"status": "masked", "masked_detail": {
        "main": {"status": "masked", "masked": ["Oct 12 2026"]}}})
    rep = _runner(masked, noise={"main": {"ok": True, "deterministic": False}}).verdict("v")
    assert rep["verdict"] == "pass_noise_masked" and rep["masked_noise"] == ["Oct 12 2026"]
    race = dict(ok, P0_vs_P0prime={"status": "differs", "parts": {"dict_set": True}})
    rep = _runner(race, noise={"cmplog": {"ok": False, "deterministic": False,
                                          "why": "code"}}).verdict("v")
    assert rep["verdict"] == "fail"
    missing = {k: v for k, v in ok.items() if k != "PH_vs_WH"}
    assert _runner(missing).verdict("v")["verdict"] == "fail"
    # a cached build whose MAIN half did not use the cache fails
    r = _runner(dict(ok))
    r.builds["W0"] = {**r.builds["W0"], "ccache": {"enabled": True, "builds": {
        "main": {"enabled": False, "reason": "x"}, "cmplog": {"enabled": True}}}}
    rep = r.verdict("v")
    assert rep["verdict"] == "fail" and any("main build" in x for x in rep["problems"])
    # hooks: cmplog keeps them, main has none
    r = _runner(dict(ok))
    r.builds["P0"]["cmplog_hook_sites"] = {"main": 0, "cmplog": 603}
    r.builds["W0"] = {**r.builds["W0"], "cmplog_hook_sites": {"main": 0, "cmplog": 603}}
    assert r.verdict("v")["verdict"] == "pass"
    r.builds["W0"]["cmplog_hook_sites"] = {"main": 5, "cmplog": 2}
    assert len(r.verdict("v")["problems"]) == 2


def test_report_explains_missing_variants_without_dangling_reference():
    eq = _eq()
    rep = _runner({}).verdict("v")
    rep["notes"] = ["no usable fold-in-.c variant: 3 compiled project sources, 1 "
                    "harness file(s) excluded, 0 with an insertable function body, 0 tried"]
    txt = eq.text_report(rep)
    assert "see notes above" not in txt and "0 tried" in txt
    src = Path(eq.__file__).read_text()
    assert "see notes above" not in src


def _keys(tmp_path):
    return (tmp_path / "log.key").read_text().splitlines()


def test_key_separates_main_and_cmplog(tmp_path):
    """Main and cmplog objects never share a cache entry: the build KIND and
    AFL_LLVM_CMPLOG both feed CCACHE_COMPILERCHECK=string:<digest>."""
    (tmp_path / "a.c").write_text("int a;")
    main, _ = _wrapper_exe(tmp_path, kind="main")
    cmplog, _ = _wrapper_exe(tmp_path, kind="cmplog")
    args = ["-c", "a.c", "-o", "a.o"]
    for cmd, env in ((main, {}), (main, {}), (cmplog, {"AFL_LLVM_CMPLOG": "1"}),
                     (cmplog, {}), (main, {"AFL_LLVM_CMPLOG": "1"})):
        assert _run_wrap(cmd, args, tmp_path, **env).returncode == 0
    k = _keys(tmp_path)
    assert all(x.startswith("string:") and len(x) == 7 + 64 for x in k)
    assert k[0] == k[1], "same build, same env -> same key (per-call dict path not in it)"
    assert len({k[0], k[2], k[3], k[4]}) == 4, k
    # the dictionary sidecar is per kind as well
    assert {p.parent.parent.name for p in (tmp_path / "cache" / "fb_dict").rglob("*")
            if p.is_file()} == {"main", "cmplog"}


def test_key_covers_round2_inputs(tmp_path):
    """Everything round 2's per-call compiler check printed still changes the key:
    toolchain digest, AFL_* (except the per-call dict path), CCC_*/CPATH/...,
    SOURCE_DATE_EPOCH and the build's own dictionary path; unrelated env does not."""
    (tmp_path / "a.c").write_text("int a;")
    cmd, _ = _wrapper_exe(tmp_path)
    cmd2, _ = _wrapper_exe(tmp_path, toolchain="tc2")
    args = ["-c", "a.c", "-o", "a.o"]
    runs = [(cmd, {}), (cmd, {"HOME": "/elsewhere", "PWD": "/x"}), (cmd2, {}),
            (cmd, {"AFL_LLVM_LAF_SPLIT_SWITCHES": "1"}), (cmd, {"CPATH": "/inc"}),
            (cmd, {"CCC_OVERRIDE_OPTIONS": "+-O0"}), (cmd, {"SOURCE_DATE_EPOCH": "1"}),
            (cmd, {"AFL_LLVM_DICT2FILE": str(tmp_path / "other.dict")}),
            (cmd, {"AFL_LLVM_DENYLIST": str(tmp_path / "deny.txt")})]
    for c, env in runs:
        assert _run_wrap(c, args, tmp_path, **env).returncode == 0
    k = _keys(tmp_path)
    assert k[0] == k[1], "unrelated env is not in the key"
    assert k[0] == k[8], "explicit fold denylist == the wrapper's default (stable key)"
    assert len(set(k[2:8]) | {k[0]}) == 7, k


def test_template_noise_mode_runs_extra_uncached_build(tmp_path, monkeypatch):
    """pass_noise_masked target: one extra UNCACHED build learns the noise and the
    cold-cache build may differ from the baseline only inside it (same masked
    comparison as the equivalence test); charged to the optimized arm."""
    import phase3_online
    import prework.prework_build as pb
    from lib import cpu_ledger
    v = tmp_path / "v.txt"
    v.write_text("mruby_mruby_fuzzer_8c8bbd pass_noise_masked\n")
    monkeypatch.setattr(fb_ccache, "VERIFIED_LIST", v)
    monkeypatch.delenv("FB_CCACHE", raising=False)
    stages = []
    real_timed = cpu_ledger.timed

    def timed(stage, **k):
        stages.append((stage, k.get("counts", True)))
        return real_timed(stage, **k)
    monkeypatch.setattr(cpu_ledger, "timed", timed)
    base = _out(tmp_path / "base", main=_bin(b"3fa2b1c0d9e8", b"\x01" * 16))
    calls = []

    def rebuild(host, *, out_dir, ccache_dir=None, **k):
        calls.append(ccache_dir)
        _out(Path(out_dir), main=_bin(host, b"\x02" * 16))
        return True, _BOTH_STATS if ccache_dir else ""
    monkeypatch.setattr(pb, "rebuild_with_prework_image",
                        lambda **k: rebuild(b"0123456789ab" if k.get("ccache_dir")
                                            else b"77aa00bb11cc", **k))
    (tmp_path / "on").mkdir()
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path / "on"),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=1)
    assert rec["enabled"], rec
    assert rec["verified_mode"] == "pass_noise_masked"
    assert rec["matches_uncached_baseline"]["status"] == "masked"
    assert calls[0] and calls[1] is None, "second build is uncached"
    assert ("ccache_template_noise_build", True) in stages
    # a difference outside the noise (code) is still rejected
    monkeypatch.setattr(pb, "rebuild_with_prework_image", lambda **k: (
        _out(Path(k["out_dir"]), main=_bin(b"77aa00bb11cc", b"\x02" * 16,
                                           code=b"\xcc" * 64) if k.get("ccache_dir")
             else _bin(b"77aa00bb11cc", b"\x02" * 16)), (True, _BOTH_STATS))[1])
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path / "on"),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=1)
    assert rec["template"] is None
    assert rec["reason"] == "cold-cache-build-differs-from-uncached-baseline"
    # an unmarked entry keeps the strict check: no extra build, masked != identical
    v.write_text("mruby_mruby_fuzzer_8c8bbd\n")
    calls.clear()
    monkeypatch.setattr(pb, "rebuild_with_prework_image",
                        lambda **k: rebuild(b"0123456789ab", **k))
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path / "on"),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=1)
    assert len(calls) == 1 and rec["template"] is None


def test_template_needs_both_halves_cached(tmp_path, monkeypatch):
    import phase3_online
    import prework.prework_build as pb
    v = tmp_path / "v.txt"
    v.write_text("mruby_mruby_fuzzer_8c8bbd\n")
    monkeypatch.setattr(fb_ccache, "VERIFIED_LIST", v)
    monkeypatch.delenv("FB_CCACHE", raising=False)
    base = _out(tmp_path / "base")
    monkeypatch.setattr(pb, "rebuild_with_prework_image", lambda **k: (
        _out(Path(k["out_dir"])),
        (True, 'FB_CCACHE_STATS {"build": "cmplog", "enabled": true}\n'))[1])
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=1)
    assert rec["template"] is None and rec["reason"].startswith("cache-not-used")


def test_campaign_verifier_uses_noise_for_marked_targets(tmp_path, monkeypatch):
    import importlib
    vc = importlib.import_module("tools.fb_ccache_verify_campaign")
    v = tmp_path / "v.txt"
    v.write_text("curl_curl_fuzzer_http pass_noise_masked\nzlib_zlib_uncompress_fuzzer\n")
    seen = {}

    def fake_verify(td, *, a, image, target, work):
        seen[a.dir] = a.noise
        return {"trial": td.name, "status": "match"}
    monkeypatch.setattr(vc, "verify_trial", fake_verify)
    for d in ("curl_curl_fuzzer_http", "zlib_zlib_uncompress_fuzzer"):
        rc = vc.main(["--online-dir", str(tmp_path), "--dir", d, "--project", "p",
                      "--fuzz-target", "t", "--cpuset", "1", "--work",
                      str(tmp_path / ("w_" + d)), "--verified-list", str(v)])
        assert rc == 0
    assert seen == {"curl_curl_fuzzer_http": True, "zlib_zlib_uncompress_fuzzer": False}
    rep = json.loads((tmp_path / "w_curl_curl_fuzzer_http" / "verify.json").read_text())
    assert rep["verified_mode"] == "pass_noise_masked" and rep["noise"]


def test_compare_with_noise_is_shared(tmp_path):
    """Equivalence tool, template check and campaign verifier use one function."""
    import importlib
    a = _out(tmp_path / "a", main=_bin(b"3fa2b1c0d9e8", b"\x01" * 16))
    b = _out(tmp_path / "b", main=_bin(b"77aa00bb11cc", b"\x02" * 16))
    c = _out(tmp_path / "c", main=_bin(b"0123456789ab", b"\x03" * 16))
    r = fb_ccache.compare_with_noise(a, b, c, "t")
    assert r["ok"] and r["status"] == "masked" and not r["plain_vs_plain"]["identical"]
    r = fb_ccache.compare_with_noise(a, a, c, "t")
    assert not r["ok"], "deterministic plain builds: nothing is noise"
    for mod in ("tools.fb_ccache_verify_campaign", "phase3_online"):
        src = Path(importlib.import_module(mod).__file__).read_text()
        assert "fb_ccache.compare_with_noise(" in src, mod
    assert "fb_ccache.noise_models(" in Path(_eq().__file__).read_text()


def test_harness_files_never_fold_candidates():
    texts = {
        "/src/openssl/fuzz/x509.c": "int FuzzerTestOneInput(const uint8_t *b, size_t n)\n"
                                    "{\n  return 0;\n}\n",
        "/src/openssl/crypto/x509/x_all.c": "int X509_verify(X509 *a)\n{\n  return 1;\n}\n",
        "/src/proj/lib/h.c": "int MyFuzzerTestOneInput(int x) {\n  return x;\n}\n",
        "/src/proj/tests/fuzz/util.c": "int helper(int x)\n{\n  return x;\n}\n",
        "/src/proj/fuzzing/a.c": "int a(int x)\n{\n  return x;\n}\n",
        "/src/proj/lib/decl.c": "int FuzzerTestOneInput(const char *, int);\n"
                                "int g(int x)\n{\n  return x;\n}\n",
    }
    ranked = [p for p, _ in probe.rank_candidates(list(texts), texts=texts, symbols=set())]
    assert ranked == ["/src/openssl/crypto/x509/x_all.c", "/src/proj/lib/decl.c"]
    assert probe.add_c_fold(texts["/src/openssl/fuzz/x509.c"]) is None
    assert probe.is_harness("/src/fuzz/lib/a.c", "int a;") is False, \
        "the project dir itself may be called fuzz"


def test_hazard_check_exempts_identifier_beside_its_fold_name(tmp_path):
    # php style: the struct tag ends in the typedef's name. Every file holding the
    # tag also holds the name, so it always compiles under a list that has it.
    typedef = "typedef struct _fold_buf { int n; } fold_buf;\n"
    assert _hazards(tmp_path, ["fold_buf"], {"z.c": typedef}) == []
    # The same tag in a file WITHOUT the name is still a hazard.
    got = _hazards(tmp_path / "2", ["fold_buf"],
                   {"z.c": typedef, "y.h": "struct _fold_buf;\n"})
    assert got == ["_fold_buf fold_buf"]
