"""The profiler image is given the shared libraries a target loads from its own
build image (target_libs.py). Docker and ldd are faked; one test runs the
generated staging script in a real bash against a fake ldd and a real symlink."""
import importlib.util
import json
import os
import re
import shlex
import subprocess
import types
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "profile-once-fuzz-folds" / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tl = _load("target_libs")
TGT_IMG = "fb-aflpp/demo_fuzzer"
PROF_IMG = "bench-sandbox/profiler"
L = "/lib/x86_64-linux-gnu"

# What the build image's loader finds (harfbuzz's real closure, abridged).
TARGET = {
    "/out/t": [("libdl.so.2", f"{L}/libdl.so.2"), ("libm.so.6", f"{L}/libm.so.6"),
               ("libglib-2.0.so.0", f"{L}/libglib-2.0.so.0"),
               ("libstdc++.so.6", f"{L}/libstdc++.so.6"),
               ("libc.so.6", f"{L}/libc.so.6"), ("libpcre.so.3", f"{L}/libpcre.so.3")],
    "/out/afl-showmap": [("libc.so.6", f"{L}/libc.so.6")],
}
# What the profiler image's loader finds: no glib, and glib's own libpcre need is
# only visible in the listing of the staged glib.
PROFILER = {
    "/out/t": [("libdl.so.2", f"{L}/libdl.so.2"), ("libm.so.6", f"{L}/libm.so.6"),
               ("libglib-2.0.so.0", None), ("libstdc++.so.6", f"{L}/libstdc++.so.6"),
               ("libc.so.6", f"{L}/libc.so.6")],
    "/out/afl-showmap": [("libc.so.6", f"{L}/libc.so.6")],
    "/stage/libglib-2.0.so.0": [("libpcre.so.3", None), ("libc.so.6", f"{L}/libc.so.6")],
    "/stage/libpcre.so.3": [("libc.so.6", f"{L}/libc.so.6")],
    "/stage/libstdc++.so.6": [("libm.so.6", f"{L}/libm.so.6")],
}


def _listing(entries, extra=()):
    out = ["\tlinux-vdso.so.1 (0x00007ffe652fd000)"]
    for name, path in entries:
        out.append(f"\t{name} => " + ("not found" if path is None else f"{path} (0x00007a29de2f7000)"))
    out.append("\t/lib64/ld-linux-x86-64.so.2 (0x00007a29de309000)")
    return out + list(extra)


class FakeDocker:
    """Answers the probe's docker calls: image inspect, then ldd listings per
    image. The target-image run also 'stages' (writes) every resolved library
    outside /out into its /stage mount, as the real cp -L does."""

    def __init__(self, target=None, profiler=None, recheck=None, extra=None,
                 ids=None, fail_rc=None, undefined=None, recheck_undefined=None,
                 timeout=False):
        self.target = target if target is not None else TARGET
        self.profiler = profiler if profiler is not None else PROFILER
        self.recheck = recheck or {}            # file -> entries; default: all found
        self.extra = extra or {}                # file -> extra raw lines (profiler)
        self.ids = ids or {TGT_IMG: "sha256:aaa", PROF_IMG: "sha256:bbb"}
        self.fail_rc = fail_rc
        self.undefined = undefined or {}        # file -> raw ldd -r lines (step 2)
        self.recheck_undefined = recheck_undefined or {}
        self.timeout = timeout
        self.runs, self.removed = [], []

    def __call__(self, cmd, *, timeout=None):
        if cmd[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, self.ids[cmd[-1]] + "\n", "")
        if cmd[:3] == ["docker", "rm", "-f"]:
            assert timeout is not None          # bounded
            self.removed.append((cmd[3], len(self.runs)))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        assert cmd[:3] == ["docker", "run", "--rm"]
        self.runs.append(cmd)
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd, timeout)
        if self.fail_rc is not None:
            return subprocess.CompletedProcess(cmd, self.fail_rc, "",
                                               f"Unable to find image '{cmd[-3]}'")
        image, script = cmd[cmd.index("--entrypoint") + 2], cmd[-1]
        mounts = {}
        for i, a in enumerate(cmd):
            if a == "-v":
                host, ctr = cmd[i + 1].split(":")[:2]
                mounts[ctr] = host
        files = shlex.split(re.match(r"for f in (.*?); do", script).group(1))
        out = []
        for f in files:
            out.append(f"@@ldd {f}")
            if image == TGT_IMG:
                out += _listing(self.target.get(f, []))
            elif "/stage" not in mounts:          # the re-check (step 3)
                out += _listing(self.recheck.get(f, [(n, "/found") for n, _ in
                                                     self.profiler.get(f, [])]),
                                self.recheck_undefined.get(f, ()))
            else:
                out += _listing(self.profiler.get(f, []),
                                list(self.extra.get(f, ())) + list(self.undefined.get(f, ())))
        if image == TGT_IMG:
            for f in files:
                for name, path in self.target.get(f, []):
                    if path and not path.startswith("/out/"):
                        (Path(mounts["/stage"]) / name).write_text(f"real {name}")
        out.append("@@end")
        return subprocess.CompletedProcess(cmd, 0, "\n".join(out) + "\n", "")


@pytest.fixture
def out(tmp_path):
    o = tmp_path / "out"
    o.mkdir()
    (o / "t").write_bytes(b"\x7fELF target v1")
    (o / "afl-showmap").write_bytes(b"\x7fELF showmap")
    return o


def _prepare(out, libs_dir, **kw):
    return tl.prepare(out_dir=out, fuzz_target="t", libs_dir=libs_dir,
                      target_image=TGT_IMG, profiler_image=PROF_IMG,
                      base_ld_path="/opt/oss-libs", cpu=7, **kw)


def test_closure_is_computed_and_only_what_the_profiler_lacks_is_copied(
        tmp_path, out, monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(tl, "_run", fake)
    libs_dir = tmp_path / "prof" / "target_libs"
    res = _prepare(out, libs_dir)

    # glib (missing) and libpcre (needed by the staged glib) -- not libstdc++,
    # which the profiler image has, and never the libc family.
    assert sorted(res["libs"]) == ["libglib-2.0.so.0", "libpcre.so.3"]
    assert res["libs"]["libglib-2.0.so.0"] == f"{L}/libglib-2.0.so.0"
    assert res["needed_by"] == {"libglib-2.0.so.0": "/out/t",
                                "libpcre.so.3": "libglib-2.0.so.0"}
    assert sorted(p.name for p in libs_dir.iterdir()) == [
        "libglib-2.0.so.0", "libpcre.so.3", tl.RECORD]
    assert (libs_dir / "libglib-2.0.so.0").read_text() == "real libglib-2.0.so.0"
    assert res["host_dir"] == str(libs_dir) and res["cached"] is False
    assert res["ld_library_path"] == "/opt/target-libs:/opt/oss-libs"
    assert res["append_out"] is False
    rec = json.loads((libs_dir / tl.RECORD).read_text())
    assert rec["key"] == res["key"] and rec["libs"] == res["libs"]
    # The record sits in the profile the agent reads: no image names in it.
    assert TGT_IMG not in json.dumps(rec) and PROF_IMG not in json.dumps(rec)
    assert not (tmp_path / "prof" / "target_libs.stage").exists()

    # target listing + stage, profiler listing, re-check: three small, capped,
    # offline, pinned containers.
    assert [r[r.index("--entrypoint") + 2] for r in fake.runs] == [TGT_IMG, PROF_IMG, PROF_IMG]
    for r in fake.runs:
        j = " ".join(r)
        assert "--memory 1g --memory-swap 1g" in j and "--network none" in j
        assert r[r.index("--cpuset-cpus") + 1] == "7"
        assert f"{out}:/out:ro" in j
    # The target image probes with /out appended, as FuzzBench's runner has it.
    assert 'LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/out" ldd' in fake.runs[0][-1]
    # Step 2 lists the staged copies but never libc-family ones.
    step2 = fake.runs[1][-1]
    assert "/stage/libglib-2.0.so.0" in step2 and "/stage/libstdc++.so.6" in step2
    assert "/stage/libc.so.6" not in step2 and "/stage/libdl.so.2" not in step2
    assert "LD_LIBRARY_PATH=/opt/oss-libs ldd $r" in step2
    # The re-check mounts the supplied dir and uses the target's final path.
    assert f"{libs_dir}:/opt/target-libs:ro" in " ".join(fake.runs[2])
    assert "LD_LIBRARY_PATH=/opt/target-libs:/opt/oss-libs ldd $r" in fake.runs[2][-1]
    # Symbol-level (ldd -r) only for the target and afl-showmap.
    for r in fake.runs[1:]:
        assert "case \"$f\" in /out/t|/out/afl-showmap) r=-r;; esac" in r[-1]
    assert "r=-r" not in fake.runs[0][-1]


def test_libc_family_is_never_copied_and_a_missing_one_fails(tmp_path, out, monkeypatch):
    assert tl.is_libc_family("libc.so.6") and tl.is_libc_family("ld-linux-x86-64.so.2")
    assert tl.is_libc_family("libpthread.so.0") and tl.is_libc_family("libnsl.so.1")
    assert tl.is_libc_family("/lib/x86_64-linux-gnu/libm.so.6")
    assert not tl.is_libc_family("libglib-2.0.so.0")
    assert not tl.is_libc_family("libcrypto.so.1.1") and not tl.is_libc_family("libcap.so.2")

    target = {"/out/t": TARGET["/out/t"] + [("libnsl.so.1", f"{L}/libnsl.so.1")]}
    profiler = {"/out/t": [("libnsl.so.1", None)]}
    monkeypatch.setattr(tl, "_run", FakeDocker(target=target, profiler=profiler))
    libs_dir = tmp_path / "target_libs"
    with pytest.raises(tl.TargetLibsError, match=tl.UNRESOLVED_MARK) as ei:
        _prepare(out, libs_dir)
    assert "libnsl.so.1" in str(ei.value) and "libc/loader family" in str(ei.value)
    assert not libs_dir.exists()


def test_a_too_old_profiler_copy_is_replaced_by_the_target_images(tmp_path, out, monkeypatch):
    profiler = dict(PROFILER, **{"/out/t": [("libstdc++.so.6", f"{L}/libstdc++.so.6")]})
    extra = {"/out/t": [f"/out/t: {L}/libstdc++.so.6: version `GLIBCXX_3.4.32' "
                        "not found (required by /out/t)"]}
    monkeypatch.setattr(tl, "_run", FakeDocker(profiler=profiler, extra=extra))
    res = _prepare(out, tmp_path / "target_libs")
    assert sorted(res["libs"]) == ["libstdc++.so.6"]


def test_staging_dereferences_symlinks_under_the_requested_name(tmp_path):
    """The real staging script, in a real bash, against a fake ldd: the copy is
    the symlink's target file stored under the name the loader asked for; /out
    libraries are never staged; /out is appended to the image's own path."""
    libdir, bindir, stage = tmp_path / "lib", tmp_path / "bin", tmp_path / "stage"
    for d in (libdir, bindir, stage):
        d.mkdir()
    (libdir / "libglib-2.0.so.0.6400.6").write_bytes(b"GLIB REAL")
    os.symlink("libglib-2.0.so.0.6400.6", libdir / "libglib-2.0.so.0")
    target = tmp_path / "t"
    target.write_bytes(b"\x7fELF")
    (bindir / "ldd").write_text(
        "#!/bin/sh\n"
        'echo "LD=$LD_LIBRARY_PATH ARGS=$*"\n'
        "printf '\\tlinux-vdso.so.1 (0x00007ffe)\\n'\n"
        f"printf '\\tlibglib-2.0.so.0 => {libdir}/libglib-2.0.so.0 (0x00007a29)\\n'\n"
        "printf '\\tlibbuild.so => /out/lib/libbuild.so (0x00007a30)\\n'\n"
        "printf '\\tlibgone.so.1 => not found\\n'\n"
        "printf '\\t/lib64/ld-linux-x86-64.so.2 (0x00007a31)\\n'\n")
    (bindir / "ldd").chmod(0o755)
    other = tmp_path / "libmod.so"
    other.write_bytes(b"\x7fELF")
    script = tl._ldd_script([str(target), str(other)],
                            '"${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/out"',
                            stage=str(stage), relocate=[str(target)])
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "LD_LIBRARY_PATH": "/img"}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.rstrip().endswith("@@end"), r.stderr
    copied = stage / "libglib-2.0.so.0"
    assert copied.is_file() and not copied.is_symlink()
    assert copied.read_bytes() == b"GLIB REAL"
    assert sorted(p.name for p in stage.iterdir()) == ["libglib-2.0.so.0"]
    assert f"LD=/img:/out ARGS=-r {target}" in r.stdout
    assert f"ARGS={other}" in r.stdout and f"ARGS=-r {other}" not in r.stdout
    parsed = tl.parse_ldd(r.stdout)[str(target)]
    assert parsed["needed"] == {"libglib-2.0.so.0": f"{libdir}/libglib-2.0.so.0",
                                "libbuild.so": "/out/lib/libbuild.so", "libgone.so.1": None}


def test_parse_ldd_reads_real_output_and_version_errors():
    text = "\n".join(["@@ldd /out/hb-shape-fuzzer", *_listing(PROFILER["/out/t"]),
                      "@@ldd /out/x",
                      f"/out/x: {L}/libstdc++.so.6: version `GLIBCXX_3.4.30' not found "
                      "(required by /out/x)", "\tnot a dynamic executable",
                      "@@ldd /out/u",
                      "/out/u: /opt/target-libs/libm.so.6: no version information "
                      "available (required by /out/u)",
                      "undefined symbol: tanf, version GLIBC_2.2.5\t(/out/u)",
                      "undefined symbol: _ZNSt3__14cout\t(/out/u)",
                      "@@ldd /out/gone", "@@missing", "@@copyfail a b", "@@end"])
    res = tl.parse_ldd(text)
    assert res["/out/hb-shape-fuzzer"]["needed"]["libglib-2.0.so.0"] is None
    assert res["/out/hb-shape-fuzzer"]["needed"]["libdl.so.2"] == f"{L}/libdl.so.2"
    assert "linux-vdso.so.1" not in res["/out/hb-shape-fuzzer"]["needed"]
    assert res["/out/x"]["version_failed"] == {"libstdc++.so.6"}
    assert res["/out/x"]["needed"] == {}
    assert res["/out/gone"]["exists"] is False and res["/out/gone"]["needed"] == {}
    # ldd -r's real format (captured on the harfbuzz build with a stand-in libm).
    assert res["/out/u"]["undefined"] == ["tanf@GLIBC_2.2.5 (in /out/u)",
                                          "_ZNSt3__14cout (in /out/u)"]
    assert res["/out/u"]["version_failed"] == set()


def test_cache_is_used_until_the_binary_or_an_image_changes(tmp_path, out, monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(tl, "_run", fake)
    libs_dir = tmp_path / "target_libs"
    first = _prepare(out, libs_dir)
    assert len(fake.runs) == 3
    again = _prepare(out, libs_dir)
    assert again["cached"] is True and len(fake.runs) == 3       # no container
    assert again["libs"] == first["libs"] and again["host_dir"] == str(libs_dir)
    assert again["ld_library_path"] == first["ld_library_path"]

    (out / "t").write_bytes(b"\x7fELF target v2")                  # a new round's binary
    assert _prepare(out, libs_dir)["cached"] is False and len(fake.runs) == 6
    fake.ids[PROF_IMG] = "sha256:rebuilt"                           # a rebuilt image
    assert _prepare(out, libs_dir)["cached"] is False and len(fake.runs) == 9
    (libs_dir / "libpcre.so.3").unlink()                            # a damaged dir
    assert _prepare(out, libs_dir)["cached"] is False and len(fake.runs) == 12


def test_unresolved_libraries_fail_loudly(tmp_path, out, monkeypatch):
    target = {"/out/t": [("libfoo.so.1", None), ("libc.so.6", f"{L}/libc.so.6")]}
    profiler = {"/out/t": [("libfoo.so.1", None), ("libc.so.6", f"{L}/libc.so.6")]}
    monkeypatch.setattr(tl, "_run", FakeDocker(target=target, profiler=profiler))
    libs_dir = tmp_path / "target_libs"
    with pytest.raises(tl.TargetLibsError) as ei:
        _prepare(out, libs_dir)
    msg = str(ei.value)
    assert msg.startswith(tl.UNRESOLVED_MARK)
    assert "libfoo.so.1 (needed by /out/t; not in the target's image either)" in msg
    assert TGT_IMG not in msg
    assert not libs_dir.exists() and not (tmp_path / "target_libs.stage").exists()


def test_a_failed_recheck_fails_loudly(tmp_path, out, monkeypatch):
    recheck = {"/out/t": [("libglib-2.0.so.0", None)]}
    monkeypatch.setattr(tl, "_run", FakeDocker(recheck=recheck))
    libs_dir = tmp_path / "target_libs"
    with pytest.raises(tl.TargetLibsError, match="still unresolved") as ei:
        _prepare(out, libs_dir)
    assert "libglib-2.0.so.0" in str(ei.value)
    assert not libs_dir.exists()          # nothing half-made is cached


def test_a_build_library_found_only_via_out_puts_out_on_the_path(tmp_path, out, monkeypatch):
    target = {"/out/t": [("libbuild.so", "/out/lib/libbuild.so"),
                         ("libc.so.6", f"{L}/libc.so.6")]}
    profiler = {"/out/t": [("libbuild.so", None), ("libc.so.6", f"{L}/libc.so.6")]}
    fake = FakeDocker(target=target, profiler=profiler)
    monkeypatch.setattr(tl, "_run", fake)
    res = _prepare(out, tmp_path / "target_libs")
    assert res["libs"] == {} and res["host_dir"] is None
    assert res["append_out"] is True and res["out_libs"] == ["libbuild.so"]
    assert res["ld_library_path"] == "/opt/oss-libs:/out"
    assert "/opt/target-libs" not in " ".join(fake.runs[2])


def test_probe_files_skip_afl_plugins_and_non_elf(out):
    (out / "lib").mkdir()
    (out / "lib" / "libx.so.1").write_bytes(b"\x7fELF x")
    (out / "afl-llvm-pass.so").write_bytes(b"\x7fELF pass")
    (out / "libdislocator.so").write_bytes(b"\x7fELF d")
    (out / "libscript.so").write_text("INPUT(-lfoo)")
    main, sos = tl.probe_files(out, "t")
    assert main == ["/out/t", "/out/afl-showmap"]
    assert sos == ["/out/lib/libx.so.1"]
    with pytest.raises(tl.TargetLibsError, match="does not exist"):
        tl.probe_files(out, "nope")


def test_an_out_library_its_own_image_cannot_load_is_skipped(tmp_path, out, monkeypatch):
    (out / "libmod.so").write_bytes(b"\x7fELF mod")
    target = dict(TARGET, **{"/out/libmod.so": [("libnowhere.so.2", None)]})
    profiler = dict(PROFILER, **{"/out/libmod.so": [("libnowhere.so.2", None)]})
    fake = FakeDocker(target=target, profiler=profiler)
    monkeypatch.setattr(tl, "_run", fake)
    res = _prepare(out, tmp_path / "target_libs")
    assert res["skipped_out_libs"] == {"/out/libmod.so": ["libnowhere.so.2"]}
    assert sorted(res["libs"]) == ["libglib-2.0.so.0", "libpcre.so.3"]
    assert "/out/libmod.so" not in fake.runs[1][-1]


def test_a_probe_container_that_keeps_failing_is_a_marked_probe_error(
        tmp_path, out, monkeypatch):
    fake = FakeDocker(fail_rc=125)
    monkeypatch.setattr(tl, "_run", fake)
    with pytest.raises(tl.TargetLibsProbeError, match=tl.PROBE_FAILED_MARK) as ei:
        _prepare(out, tmp_path / "target_libs")
    assert len(fake.runs) == 2                      # one retry
    assert TGT_IMG not in str(ei.value) and "<image>" in str(ei.value)


# --- the profile ---------------------------------------------------------------

LIBS = {"libs": {"libglib-2.0.so.0": f"{L}/libglib-2.0.so.0"}, "append_out": False,
        "ld_library_path": "/opt/target-libs:/opt/oss-libs", "skipped_out_libs": {},
        "cached": False, "seconds": 1.2}


def _cmd(profile, tmp_path, **kw):
    return profile.build_replay_profile_docker_command(
        out_dir=tmp_path / "out", corpus_dir=tmp_path / "c", artifact_dir=tmp_path / "a",
        fuzz_target="t", min_sample_seconds=60, seed=1337, cpu=3, memory="4g",
        shm_size="2g", **kw)


def test_the_supplied_dir_is_mounted_and_on_the_target_path_only(tmp_path):
    profile = _load("replay_fuzzer_profile")
    host = tmp_path / "a" / "target_libs"
    cmd = _cmd(profile, tmp_path, target_libs=dict(LIBS, host_dir=str(host)))
    mount = f"{host}:/opt/target-libs:ro"
    assert mount in cmd and cmd.index(mount) < cmd.index(profile.PROFILER_IMAGE)
    # perf keeps the profiler's own path ...
    assert "LD_LIBRARY_PATH=/opt/oss-libs" in cmd
    script = cmd[-1]
    # ... and the target's is exported INSIDE the perf-launched replay loop,
    # before the AFL map-size dump and both replay forms.
    exp = script.index("export LD_LIBRARY_PATH=/opt/target-libs:/opt/oss-libs; ")
    assert exp > script.index('"$PERF_BIN" record')
    assert exp > script.index("/bin/bash -c '")
    assert exp < script.index("AFL_DUMP_MAP_SIZE=1") < script.index("-runs=0")
    assert script.count("/opt/target-libs") == 1


def test_without_supplied_libraries_the_command_is_unchanged(tmp_path):
    profile = _load("replay_fuzzer_profile")
    plain = _cmd(profile, tmp_path)
    assert _cmd(profile, tmp_path, target_libs=None) == plain
    nothing = dict(LIBS, libs={}, host_dir=None, ld_library_path="/opt/oss-libs")
    assert _cmd(profile, tmp_path, target_libs=nothing) == plain
    assert "/opt/target-libs" not in " ".join(plain)


def test_run_replay_profile_prepares_once_and_passes_libs_to_every_attempt(
        tmp_path, monkeypatch):
    profile = _load("replay_fuzzer_profile")
    corpus = tmp_path / "c"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    art = tmp_path / "a"
    host = art / "target_libs"
    prepared, cmds = [], []
    monkeypatch.setattr(profile, "prepare_target_libs",
                        lambda **kw: prepared.append(kw) or dict(LIBS, host_dir=str(host)))

    def fake_run(cmd, *, timeout=None):
        cmds.append(cmd)
        art.mkdir(parents=True, exist_ok=True)
        if len(cmds) == 1:
            return subprocess.CompletedProcess(cmd, 1, "", "transient")
        (art / "perf.data").write_bytes(b"PERF")
        (art / "flat.txt").write_text("    10.00%  t  t  [.] foo\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)
    monkeypatch.setattr(profile, "build_hotspots", lambda **kw: {
        "total_samples": 1, "target_source_samples": 1, "target_source_functions": 1,
        "seconds_total": 0.0, "perf_script_seconds": 0, "host_seconds": 0.0})
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=art, fuzz_target="t",
        min_sample_seconds=60, loop_timeout=1800, seed=1337, cpu=3, memory="4g",
        shm_size="2g")
    assert profile.run_replay_profile(args) == 0
    assert len(prepared) == 1 and prepared[0]["artifact_dir"] == art
    assert len(cmds) == 2 and all(f"{host}:/opt/target-libs:ro" in c for c in cmds)
    meta = json.loads((art / "metadata.json").read_text())
    assert meta["target_libs"]["libs"] == LIBS["libs"]
    assert meta["target_libs"]["ld_library_path"] == LIBS["ld_library_path"]


def test_prepare_target_libs_bridges_only_a_different_image(tmp_path, monkeypatch):
    profile = _load("replay_fuzzer_profile")
    monkeypatch.setattr(profile.tlibs, "prepare",
                        lambda **kw: pytest.fail("no probe for the same image"))
    monkeypatch.setattr(profile, "RUNNER_IMAGE", profile.PROFILER_IMAGE)
    assert profile.prepare_target_libs(out_dir=tmp_path, fuzz_target="t",
                                       artifact_dir=tmp_path, cpu=3) is None
    seen = {}
    monkeypatch.setattr(profile, "RUNNER_IMAGE", TGT_IMG)
    monkeypatch.setattr(profile.tlibs, "prepare", lambda **kw: seen.update(kw) or LIBS)
    profile.prepare_target_libs(out_dir=tmp_path, fuzz_target="t", artifact_dir=tmp_path,
                                cpu=3)
    assert seen["target_image"] == TGT_IMG and seen["profiler_image"] == profile.PROFILER_IMAGE
    assert seen["libs_dir"] == tmp_path / "target_libs"
    assert seen["base_ld_path"] == "/opt/oss-libs"


def test_an_unresolved_library_fails_the_profile_before_perf_runs(tmp_path, monkeypatch):
    profile = _load("replay_fuzzer_profile")
    corpus = tmp_path / "c"
    corpus.mkdir()
    (corpus / "u0").write_text("a")

    def boom(**kw):
        raise profile.tlibs.TargetLibsError(f"{profile.tlibs.UNRESOLVED_MARK}: libfoo.so.1")

    monkeypatch.setattr(profile, "prepare_target_libs", boom)
    monkeypatch.setattr(profile, "_run", lambda *a, **k: pytest.fail("perf must not run"))
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=tmp_path / "a",
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337, cpu=3,
        memory="4g", shm_size="2g")
    with pytest.raises(profile.tlibs.TargetLibsError, match="TARGET LIBS UNRESOLVED"):
        profile.run_replay_profile(args)


UNDEF = ["undefined symbol: _ZNSt3__112basic_stringIcEC1Ev\t(/out/t)"]


def test_undefined_symbols_fail_even_when_no_library_is_missing(tmp_path, out, monkeypatch):
    """A profiler library older than the one the build linked (a newer libc++)
    resolves by name but not by symbol: ldd -r catches it, as stage libs."""
    target = {"/out/t": [("libc++.so.1", "/usr/local/lib/libc++.so.1")]}
    profiler = {"/out/t": [("libc++.so.1", "/opt/oss-libs/libc++.so.1")]}
    fake = FakeDocker(target=target, profiler=profiler, undefined={"/out/t": UNDEF})
    monkeypatch.setattr(tl, "_run", fake)
    with pytest.raises(tl.TargetLibsError, match=tl.UNRESOLVED_MARK) as ei:
        _prepare(out, tmp_path / "target_libs")
    assert "undefined symbols" in str(ei.value)
    assert "/out/t: 1, e.g. _ZNSt3__112basic_stringIcEC1Ev (in /out/t)" in str(ei.value)
    assert len(fake.runs) == 2                  # step 2 already used the final path
    assert not (tmp_path / "target_libs").exists()


def test_undefined_symbols_on_the_final_path_fail_after_supplying(tmp_path, out, monkeypatch):
    fake = FakeDocker(undefined={"/out/t": UNDEF},          # glib missing: expected
                      recheck_undefined={"/out/afl-showmap": [
                          "undefined symbol: shm_open, version GLIBC_2.2.5\t(/out/afl-showmap)"]})
    monkeypatch.setattr(tl, "_run", fake)
    with pytest.raises(tl.TargetLibsError, match="undefined symbols") as ei:
        _prepare(out, tmp_path / "target_libs")
    assert "/out/afl-showmap: 1, e.g. shm_open@GLIBC_2.2.5" in str(ei.value)
    assert "/out/t:" not in str(ei.value)       # step 2's were not on the final path


def test_out_modules_may_leave_symbols_to_the_main_binary(tmp_path, out, monkeypatch):
    (out / "libmod.so").write_bytes(b"\x7fELF mod")
    target = dict(TARGET, **{"/out/libmod.so": [("libc.so.6", f"{L}/libc.so.6")]})
    profiler = dict(PROFILER, **{"/out/libmod.so": [("libc.so.6", f"{L}/libc.so.6")]})
    fake = FakeDocker(target=target, profiler=profiler, recheck_undefined={
        "/out/libmod.so": ["undefined symbol: zend_register\t(/out/libmod.so)"]})
    monkeypatch.setattr(tl, "_run", fake)
    assert sorted(_prepare(out, tmp_path / "target_libs")["libs"]) == [
        "libglib-2.0.so.0", "libpcre.so.3"]
    assert "/out/libmod.so) r=-r" not in fake.runs[2][-1]


def test_a_timed_out_probe_container_is_removed_before_the_retry(tmp_path, out, monkeypatch):
    """subprocess's timeout kills only the docker client: the named container
    is removed (bounded) before the retry starts a second one, and again before
    the probe error."""
    fake = FakeDocker(timeout=True)
    monkeypatch.setattr(tl, "_run", fake)
    with pytest.raises(tl.TargetLibsProbeError, match="timed out") as ei:
        _prepare(out, tmp_path / "target_libs")
    names = [r[r.index("--name") + 1] for r in fake.runs]
    assert len(names) == 2 and names[0] != names[1]
    # (name, runs started so far): each removed before the next run.
    assert fake.removed == [(names[0], 1), (names[1], 2)]
    assert TGT_IMG not in str(ei.value)


def test_an_image_inspect_timeout_does_not_leak_the_image_name(tmp_path, out, monkeypatch):
    def slow(cmd, *, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout)
    monkeypatch.setattr(tl, "_run", slow)
    with pytest.raises(tl.TargetLibsProbeError, match=tl.PROBE_FAILED_MARK) as ei:
        _prepare(out, tmp_path / "target_libs")
    assert TGT_IMG not in str(ei.value) and "timed out" in str(ei.value)


def test_the_progress_line_names_no_image(tmp_path, monkeypatch, capsys):
    profile = _load("replay_fuzzer_profile")
    monkeypatch.setattr(profile, "RUNNER_IMAGE", "bench-aflpp/demo-arvo-1234")
    corpus = tmp_path / "c"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    monkeypatch.setattr(profile, "prepare_target_libs",
                        lambda **kw: dict(LIBS, host_dir=str(tmp_path / "l")))
    monkeypatch.setattr(profile, "_run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "x"))
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=tmp_path / "a",
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337, cpu=3,
        memory="4g", shm_size="2g")
    with pytest.raises(RuntimeError):
        profile.run_replay_profile(args)
    err = capsys.readouterr().err
    assert "target libs: supplying ['libglib-2.0.so.0']" in err
    assert "arvo" not in err


def test_bootstrap_requires_every_script_the_profiler_loads(tmp_path, monkeypatch):
    import bootstrap_server as bs
    import config
    from sandbox import egress
    needed = ("replay_timing.py", "build_corpus.py", "replay_fuzzer_profile.py",
              "hotspot_table.py")
    for n in needed:
        (tmp_path / n).write_text("")
    monkeypatch.setattr(config, "PHASE2_SKILL_SCRIPTS_DIR", str(tmp_path))
    monkeypatch.setattr(bs, "_symbolizer_check", lambda: (True, ""))
    monkeypatch.setattr(bs, "_run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))
    monkeypatch.setattr(egress, "credential_outlives", lambda secs: (True, 1e9))

    def skill_row():
        return next(r for r in bs.check_prereqs() if r[0].startswith("optimizer skill"))

    row = skill_row()
    assert row[1] == bs.MISSING and "target_libs.py" in row[2]
    (tmp_path / "target_libs.py").write_text("")
    assert skill_row()[1] == bs.OK
    # The vendored skill ships every one of them.
    assert all((SCRIPTS / n).is_file() for n in needed + ("target_libs.py",))
