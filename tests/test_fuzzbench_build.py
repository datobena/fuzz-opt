"""FuzzBench-parity build: image chain, build command, and the ARVO path left alone.

kind == "fuzzbench" targets build in fb-aflpp/<fuzzbench_dir> with FuzzBench's own
aflplusplus fuzzer.build() (prework/fb_build.sh); ARVO targets keep the OSS-Fuzz
`compile` command byte for byte.
"""
from pathlib import Path

import pytest

import config
from prework import fuzzbench_image as fbi
from prework.prework_build import (
    build_prework_rebuild_command, prework_image_for, rebuild_with_prework_image,
)
from sandbox.broker import BrokerContext, _build_command

REPO = Path(__file__).resolve().parent.parent
DENY = REPO / "prework" / "aflpp_fold_denylist.txt"

# Exact ARVO argv, captured before the FuzzBench switch was added.
ARVO_HARNESS = [
    "docker", "run", "--rm", "--privileged", "--cpuset-cpus", "7",
    "-e", "FUZZING_ENGINE=afl", "-e", "FUZZER_LIB=/usr/lib/libFuzzingEngine.a",
    "-e", "FUZZER=afl", "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
    "-e", "SANITIZER=address", "-e", "ARCHITECTURE=x86_64", "-e", "FUZZING_LANGUAGE=c++",
    "-v", f"{DENY}:/src/aflpp_fold_denylist.txt:ro",
    "-v", "/x/src/libavc:/src/libavc", "-v", "/x/out:/out",
    "bench-aflpp/libavc-arvo-16505", "compile",
]
ARVO_BROKER = ARVO_HARNESS[:6] + ["--ulimit", "core=0"] + ARVO_HARNESS[6:]

FB_ENTRY = {"project": "mruby", "cve": "fuzzbench-900026", "local_id": 900026,
            "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
            "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}


def _ctx(image, source_dir="/x/src/mruby"):
    return BrokerContext(image=image, source_dir=source_dir, out_dir="/x/out",
                         corpus_dir="/x/c", fuzz_target="t", project="mruby", cpu=7)


# ------------------------------------------------------------------ ARVO unchanged

def test_arvo_harness_command_is_byte_identical(monkeypatch):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "", raising=False)
    assert build_prework_rebuild_command(
        image="bench-aflpp/libavc-arvo-16505", source_dir="/x/src/libavc",
        out_dir="/x/out", project="libavc", cpu=7) == ARVO_HARNESS


def test_arvo_broker_command_is_byte_identical():
    ctx = BrokerContext(image="bench-aflpp/libavc-arvo-16505", source_dir="/x/src/libavc",
                        out_dir="/x/out", corpus_dir="/x/c", fuzz_target="t",
                        project="libavc", cpu=7)
    assert _build_command(ctx) == ARVO_BROKER


def test_arvo_image_name_unchanged():
    assert prework_image_for({"project": "libavc", "local_id": 16505}) == \
        "bench-aflpp/libavc-arvo-16505"
    # kind present but not fuzzbench -> still ARVO naming
    assert prework_image_for({"project": "x", "local_id": 3, "kind": "arvo"}) == \
        "bench-aflpp/x-arvo-3"


# ------------------------------------------------------------------ image naming

def test_fuzzbench_entry_maps_to_fb_image():
    assert prework_image_for(FB_ENTRY) == "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"


def test_fuzzbench_entry_requires_fuzzbench_dir():
    e = dict(FB_ENTRY)
    del e["fuzzbench_dir"]
    with pytest.raises(ValueError, match="fuzzbench_dir"):
        prework_image_for(e)


def test_kind_switch_from_image_prefix():
    assert fbi.is_fuzzbench_image("fb-aflpp/x")
    assert not fbi.is_fuzzbench_image("bench-aflpp/fb-aflpp")
    assert not fbi.is_fuzzbench_image("fb-aflpp-stage/x:benchmark")


# ------------------------------------------------------------------ build command

def _assert_fb_command(cmd, image):
    j = " ".join(cmd)
    assert cmd[-2:] == [image, "/fold/fb_build.sh"]
    assert "compile" not in cmd
    # Nothing may be mounted under /src (restore_directory rmtree's it).
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert not any(m.split(":")[1].startswith("/src") for m in mounts), mounts
    assert "/x/src/mruby:/fold/src:ro" in mounts
    assert "FB_SRC_NAME=mruby" in cmd
    assert "/x/out:/out" in mounts
    assert any(m.endswith(":/fold/fb_build.sh:ro") for m in mounts)
    # Fold lists are generated inside the container from the tree's own names.
    assert not any("fold_ignorelist" in m for m in mounts)
    # OSS-Fuzz compile env and -O overrides must not leak into a FuzzBench build.
    for bad in ("CFLAGS=", "CXXFLAGS=", "SANITIZER=", "FUZZING_ENGINE=", "FUZZER=",
                "AFL_LLVM_DENYLIST=", "--privileged"):
        assert bad not in j, bad
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "7"


def test_harness_fuzzbench_command(monkeypatch):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "-O3", raising=False)
    import prework.prework_build as pb
    monkeypatch.setattr(pb, "opt_level_env",
                        lambda *a, **k: pytest.fail("opt_level_env used for fuzzbench"))
    img = "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
    cmd = build_prework_rebuild_command(image=img, source_dir="/x/src/mruby",
                                        out_dir="/x/out", project="mruby", cpu=7)
    _assert_fb_command(cmd, img)


def test_broker_fuzzbench_command():
    img = "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
    cmd = _build_command(_ctx(img))
    _assert_fb_command(cmd, img)
    assert cmd[cmd.index("--ulimit") + 1] == "core=0"


def test_harness_and_broker_build_the_same_way():
    img = "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
    broker = _build_command(_ctx(img))
    broker = broker[:broker.index("--ulimit")] + broker[broker.index("--ulimit") + 2:]
    harness = build_prework_rebuild_command(image=img, source_dir="/x/src/mruby",
                                            out_dir="/x/out", project="mruby", cpu=7)
    assert broker == harness


def test_fuzzbench_rebuild_never_touches_host_tree(tmp_path, monkeypatch):
    """No artifact cleaning or chown of the source tree; out dir is restored."""
    import prework.prework_build as pb
    import phase2_setup
    calls = {}
    monkeypatch.setattr(phase2_setup, "_clean_build_artifacts",
                        lambda *a: pytest.fail("cleaned a copy-in source tree"))
    monkeypatch.setattr(pb, "restore_ownership",
                        lambda image, paths: calls.setdefault("chown", paths))

    class R:
        returncode, stdout, stderr = 0, "ok", ""
    monkeypatch.setattr(pb.subprocess, "run",
                        lambda cmd, **k: calls.setdefault("cmd", cmd) and R())
    src, out = tmp_path / "src" / "mruby", tmp_path / "out"
    src.mkdir(parents=True)
    assert rebuild_with_prework_image(entry=FB_ENTRY, source_dir=str(src),
                                      out_dir=str(out), cpu=41) is True
    assert calls["chown"] == [str(out)]
    assert calls["cmd"][-1] == "/fold/fb_build.sh"


# ------------------------------------------------------------------ image chain

def test_builder_dockerfile_asserts_aflpp_commit():
    text = fbi.patched_builder_dockerfile()
    assert "|| \\\n    true" not in text
    assert f'test "$(git rev-parse HEAD)" = {fbi.AFLPP_COMMIT}' in text


def test_benchmark_builder_dockerfile_deviations():
    text = fbi.patched_benchmark_builder_dockerfile(fuzzbench_dir="d", workdir="/src/p")
    assert f"FROM {fbi.FB_BASE_IMAGE} AS base-image" in text
    assert "fuzzer_build; fi" not in text, "build must run at docker-run time"
    assert "checkout_commit.py $CHECKOUT_COMMIT $SRC" in text, "checkout step is essential"
    assert "ENV FB_WORKDIR=/src/p" in text
    assert "cp -a \"$OUT\" /fb_image_out" in text
    with pytest.raises(ValueError):
        fbi.patched_benchmark_builder_dockerfile(fuzzbench_dir="d", workdir="p")


def test_benchmark_builder_asserts_checkout_landed():
    """checkout_commit.py exits 0 on failure; the image build must not."""
    text = fbi.patched_benchmark_builder_dockerfile(fuzzbench_dir="d", workdir="/src/p")
    i_checkout = text.index("checkout_commit.py $CHECKOUT_COMMIT $SRC")
    i_assert = text.index("no repo under $SRC is at $CHECKOUT_COMMIT")
    assert i_checkout < i_assert
    assert 'if [ -n "$CHECKOUT_COMMIT" ]' in text, "empty commit (sqlite3) is skipped"
    assert "exit 1" in text[i_assert - 200:i_assert + 100]


def test_vendored_files_are_verbatim_upstream_layout():
    up = REPO / "prework" / "fuzzbench_upstream"
    for rel in ("fuzzers/utils.py", "fuzzers/afl/fuzzer.py", "fuzzers/aflplusplus/fuzzer.py",
                "fuzzers/aflplusplus/builder.Dockerfile",
                "fuzzers/aflplusplus/runner.Dockerfile",
                "docker/benchmark-builder/Dockerfile",
                "docker/benchmark-builder/checkout_commit.py",
                "docker/benchmark-builder/fuzzer_build",
                "docker/base-image/Dockerfile", "requirements.txt"):
        assert (up / rel).is_file(), rel
    assert fbi.FUZZBENCH_COMMIT in (up / "README.md").read_text()
    assert f"git checkout {fbi.AFLPP_COMMIT} || \\\n    true" in \
        (up / "fuzzers/aflplusplus/builder.Dockerfile").read_text()


def test_unpinned_benchmark_base_is_refused():
    with pytest.raises(ValueError, match="digest-pinned"):
        fbi.check_benchmark_dockerfile("ARG BASE\nFROM ${BASE}\nRUN true\n")
    fbi.check_benchmark_dockerfile(f"FROM {fbi.BASE_BUILDER}\nRUN true\n")
    fbi.check_benchmark_dockerfile(f"FROM {fbi.BASE_BUILDER} AS b\nFROM b\n")


# ------------------------------------------------ local base-image + stage reuse

def test_local_base_image_dockerfile_is_upstream_python_recipe():
    """gcr.io/fuzzbench/base-image cannot be pulled anonymously any more. The
    benchmark-builder stage copies only its Python 3.10 tree, so the same recipe
    is rebuilt locally: upstream's docker/base-image/Dockerfile with ubuntu:focal
    pinned, PyYAML (the one requirement fuzzers/utils.py imports) at
    requirements.txt's pin instead of the whole list, and no google-cloud-cli."""
    up = (REPO / "prework" / "fuzzbench_upstream" / "docker" / "base-image" /
          "Dockerfile").read_text()
    text = fbi.patched_base_image_dockerfile()
    assert text.startswith(up[:up.index("FROM ubuntu:focal")])
    assert "FROM ubuntu:focal\n" not in text
    assert f"FROM {fbi.UBUNTU_FOCAL}\n" in text
    assert "@sha256:" in fbi.UBUNTU_FOCAL
    # The Python build RUN is upstream's own text, verbatim.
    i = up.index("RUN cd /tmp/ && \\\n    curl -O https://www.python.org")
    j = up.index("ln -s /usr/local/bin/pip3 /usr/local/bin/pip\n", i)
    python_run = up[i:j + len("ln -s /usr/local/bin/pip3 /usr/local/bin/pip\n")]
    assert "ENV PYTHON_VERSION 3.10.8" in text
    assert python_run in text
    assert "RUN pip install PyYAML==6.0\n" in text
    assert "COPY ./requirements.txt" not in text
    # Only the omission note mentions google-cloud; no RUN/ENV line does.
    assert not [l for l in text.splitlines()
                if not l.startswith("#") and ("google-cloud" in l or "apt-key" in l)]
    assert "PyYAML==6.0" in (REPO / "prework" / "fuzzbench_upstream" /
                             "requirements.txt").read_text()


def test_benchmark_builder_dockerfile_records_and_overrides_base_image():
    default = fbi.patched_benchmark_builder_dockerfile(fuzzbench_dir="d", workdir="/src/p")
    assert f'LABEL fb-aflpp.base-image="{fbi.FB_BASE_IMAGE}"' in default
    text = fbi.patched_benchmark_builder_dockerfile(
        fuzzbench_dir="d", workdir="/src/p", base_image="local/base:x")
    assert "FROM local/base:x AS base-image\n" in text
    assert fbi.FB_BASE_IMAGE not in text
    assert 'LABEL fb-aflpp.base-image="local/base:x"' in text
    # Everything else is the default text.
    assert text.replace("local/base:x", fbi.FB_BASE_IMAGE) == default


def _fake_chain(monkeypatch, tmp_path, existing):
    builds = []
    monkeypatch.setattr(fbi, "_docker_build",
                        lambda args, log, timeout: builds.append(list(args)))
    monkeypatch.setattr(fbi, "_image_exists", lambda tag: tag in existing)
    monkeypatch.setattr(fbi, "_image_workdir", lambda tag: "/src/p")
    bdir = tmp_path / "bench"
    bdir.mkdir(exist_ok=True)
    (bdir / "Dockerfile").write_text(f"FROM {fbi.BASE_BUILDER}\nRUN true\n")
    (bdir / "benchmark.yaml").write_text("commit: abc\nfuzz_target: t\n")
    return builds, bdir


def test_build_fuzzbench_image_reuses_existing_stages(monkeypatch, tmp_path):
    tag1 = fbi._stage_tag("d", "benchmark")
    tag2 = fbi._stage_tag("d", "intermediate")
    builds, bdir = _fake_chain(monkeypatch, tmp_path, {tag1, tag2})
    rec = fbi.build_fuzzbench_image("d", dockerfile_dir=bdir, cpuset="6-9",
                                    reuse_stages=True, base_image="local/base:x",
                                    log_path=tmp_path / "log")
    assert len(builds) == 1, builds
    (stage3,) = builds
    assert "--build-arg" in stage3 and f"parent_image={tag2}" in stage3
    assert "--tag" in stage3 and fbi.fuzzbench_image_tag("d") in stage3
    assert rec["reused_stages"] == ["benchmark", "intermediate"]
    assert rec["base_image"] == "local/base:x"
    assert set(rec["stage_secs"]) == {"builder"}
    df = Path(stage3[stage3.index("--file") + 1]).read_text() if \
        Path(stage3[stage3.index("--file") + 1]).exists() else ""
    # The Dockerfile lived in a tempdir that is gone by now; the recorded base
    # image is what matters. (Content is covered by the test above.)
    assert df == "" or "FROM local/base:x AS base-image" in df


def test_build_fuzzbench_image_rebuilds_missing_stages_even_when_reusing(
        monkeypatch, tmp_path):
    tag1 = fbi._stage_tag("d", "benchmark")
    builds, bdir = _fake_chain(monkeypatch, tmp_path, {tag1})
    rec = fbi.build_fuzzbench_image("d", dockerfile_dir=bdir, cpuset=None,
                                    reuse_stages=True, log_path=tmp_path / "log")
    assert len(builds) == 2
    assert rec["reused_stages"] == ["benchmark"]
    assert rec["base_image"] == fbi.FB_BASE_IMAGE
    # Default: every stage is built, existing tags or not.
    builds2, _ = _fake_chain(monkeypatch, tmp_path, {tag1})
    rec2 = fbi.build_fuzzbench_image("d", dockerfile_dir=bdir, cpuset=None,
                                     log_path=tmp_path / "log2")
    assert len(builds2) == 3 and rec2["reused_stages"] == []


# ------------------------------------------------------------------ fold lists

def _fold_lists(tmp_path, names):
    """Run fb_build.sh's own write_fold_lists() on `names`; return (deny, ignore)."""
    import subprocess
    script = (REPO / "prework" / "fb_build.sh").read_text()
    fn = script[script.index("write_fold_lists() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    deny, ign = tmp_path / "deny.txt", tmp_path / "ign.txt"
    subprocess.run(["bash", "-c", fn + 'fold_names="$1"; write_fold_lists "$2" "$3"',
                    "x", "\n".join(names), str(deny), str(ign)], check=True)
    pats = lambda f: [l[4:] for l in f.read_text().splitlines()  # noqa: E731
                      if l.startswith("fun:")]
    return pats(deny), pats(ign)


# Added helpers in every mangling form, and names that must stay instrumented.
_FOLD_HIT = ("fold_hash", "_Z9fold_hashi", "_ZL9fold_hashi", "_ZN2ns9fold_hashEi",
             "_ZN2ns1S9fold_hashEPKhm", "_ZZL9fold_hashiENK3$_0clEv", "fold_ab",
             "_Z7fold_abi", "_ZL7fold_abv")
_FOLD_MISS = ("unfold_hash", "case_fold_hash", "_Z11unfold_hashv", "_Z8fold_absv",
              "fold_hash_other", "normal_fn", "LLVMFuzzerTestOneInput", "fold_abs")


def test_ignorelist_is_generated_and_anchored(tmp_path):
    """clang 15 compiles each fun: pattern to ^(...)$ with * -> .*"""
    import re
    _, ign = _fold_lists(tmp_path, ["fold_hash", "fold_ab"])
    rx = [re.compile("^(" + p.replace("*", ".*") + ")$") for p in ign]
    hit = lambda n: any(r.match(n) for r in rx)  # noqa: E731
    for n in _FOLD_HIT:
        assert hit(n), n
    for n in _FOLD_MISS:
        assert not hit(n), n


def test_denylist_matches_like_aflpp(tmp_path):
    """AFL++ 56d5aa31: skip entries longer than the name, else fnmatch("*"+entry)."""
    from fnmatch import fnmatchcase
    deny, _ = _fold_lists(tmp_path, ["fold_hash", "fold_ab"])
    hit = lambda n: any(len(n) >= len(e) and fnmatchcase(n, "*" + e)  # noqa: E731
                        for e in deny)
    for n in _FOLD_HIT:
        assert hit(n), n
    # A suffix match is inherent to AFL's "*"+entry, so names that END in an added
    # helper's name (unfold_hash) are excluded too; everything else stays.
    for n in ("_Z8fold_absv", "fold_hash_other", "normal_fn", "fold_abs"):
        assert not hit(n), n


def test_fb_build_script_contract():
    s = (REPO / "prework" / "fb_build.sh").read_text()
    assert "utils.initialize_env()" in s and "fuzzer.build()" in s
    assert "-fsanitize-coverage-ignorelist=' + os.environ['FB_FOLD_IGNORELIST']" in s
    assert "get_config_value('type') == 'bug'" in s
    assert "cp /afl/afl-showmap" in s
    assert "/fb_image_out" in s
    assert 'cd "$FB_WORKDIR"' in s
