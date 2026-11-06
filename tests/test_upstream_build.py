"""Tests for the upstream kind's image definition and compile path
(prework/upstream_image.py, prework/prework_build.py). Pure functions only."""
import hashlib
from pathlib import Path

import pytest

import config
from prework import prework_build as pb
from prework import upstream_image as ui

PREWORK = Path(pb.__file__).resolve().parent
DENYLIST = f"{PREWORK / 'aflpp_fold_denylist.txt'}:/src/aflpp_fold_denylist.txt:ro"


@pytest.fixture(autouse=True)
def _no_opt_override(monkeypatch):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "", raising=False)


def test_layout_and_tag():
    assert ui.UPSTREAM_DIR == PREWORK / "upstream"
    assert ui.BASES_FILE == PREWORK / "upstream" / "bases.json"
    assert ui.DEFINITION_LABEL == "bench-upstream.definition-sha256"
    assert ui.upstream_image_tag("PcapPlusPlus") == "bench-upstream/pcapplusplus"


def test_pinned_dockerfile_pins_every_from_and_keeps_the_rest(tmp_path):
    text = "FROM gcr.io/oss-fuzz-base/base-builder\nRUN apt-get install -y x\nFROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 AS b\n"
    bases = {"gcr.io/oss-fuzz-base/base-builder": "gcr.io/oss-fuzz-base/base-builder@sha256:aa",
             "gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04": "gcr.io/oss-fuzz-base/base-builder@sha256:bb"}
    out = ui.pinned_dockerfile(text, bases)
    assert out == "FROM gcr.io/oss-fuzz-base/base-builder@sha256:aa\nRUN apt-get install -y x\nFROM gcr.io/oss-fuzz-base/base-builder@sha256:bb AS b\n"
    already = "FROM gcr.io/oss-fuzz-base/base-builder@sha256:19782f\n"
    assert ui.pinned_dockerfile(already, bases) == already
    with pytest.raises(KeyError, match="base-builder-go"):
        ui.pinned_dockerfile("FROM gcr.io/oss-fuzz-base/base-builder-go\n", bases)


def test_pinned_dockerfile_keeps_flags_case_comments_and_missing_newline():
    bases = {"gcr.io/oss-fuzz-base/base-builder": "gcr.io/oss-fuzz-base/base-builder@sha256:aa"}
    text = ("# FROM gcr.io/oss-fuzz-base/base-builder\n"
            "from --platform=linux/amd64 gcr.io/oss-fuzz-base/base-builder as x\r\n"
            "RUN echo FROM nothing\n"
            "FROM x\n"
            "COPY build.sh $SRC/")
    assert ui.pinned_dockerfile(text, bases) == (
        "# FROM gcr.io/oss-fuzz-base/base-builder\n"
        "from --platform=linux/amd64 gcr.io/oss-fuzz-base/base-builder@sha256:aa as x\r\n"
        "RUN echo FROM nothing\n"
        "FROM x\n"
        "COPY build.sh $SRC/")


def test_definition_hash_covers_every_file_and_ignores_results(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM a@sha256:1\n")
    (tmp_path / "ossfuzz").mkdir()
    (tmp_path / "ossfuzz" / "build.sh").write_text("make\n")
    expected = hashlib.sha256()
    for rel, data in (("Dockerfile", b"FROM a@sha256:1\n"), ("ossfuzz/build.sh", b"make\n")):
        expected.update(rel.encode() + b"\0" + hashlib.sha256(data).hexdigest().encode() + b"\n")
    h0 = ui.definition_hash(tmp_path)
    assert h0 == expected.hexdigest()

    (tmp_path / "onboard_result.json").write_text("{}")
    (tmp_path / "ossfuzz" / "onboard_result.json").write_text("{}")
    assert ui.definition_hash(tmp_path) == h0

    (tmp_path / "ossfuzz" / "build.sh").write_text("make -j\n")
    h1 = ui.definition_hash(tmp_path)
    assert h1 != h0
    (tmp_path / "ossfuzz" / "project.yaml").write_text("language: c\n")
    assert ui.definition_hash(tmp_path) not in (h0, h1)


def test_build_command_labels_the_definition(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM a@sha256:1\n")
    h = ui.definition_hash(tmp_path)
    assert ui.build_command(tmp_path, "bench-upstream/libssh") == [
        "docker", "build", "--label", f"bench-upstream.definition-sha256={h}",
        "-t", "bench-upstream/libssh", "-f", f"{tmp_path}/Dockerfile", str(tmp_path)]


def test_build_upstream_image_refuses_an_unpinned_from(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    ok, log = ui.build_upstream_image(tmp_path)
    assert not ok and "gcr.io/oss-fuzz-base/base-builder" in log


def test_load_meta_and_pins(tmp_path):
    (tmp_path / "meta.json").write_text('{"project": "libssh", "srcdir": "libssh"}')
    (tmp_path / "pins.json").write_text('{"ossfuzz_commit": "abc"}')
    assert ui.load_meta(tmp_path) == {"project": "libssh", "srcdir": "libssh"}
    assert ui.load_pins(tmp_path) == {"ossfuzz_commit": "abc"}


def test_upstream_compile_args_are_oss_fuzz_compile_without_network(tmp_path):
    args = pb.upstream_compile_args(image="bench-upstream/libssh", source_dir=str(tmp_path/"s"), out_dir=str(tmp_path/"o"),
                                    project="libssh", sanitizer="memory", language="c")
    assert args[:2] == ["--network", "none"] and "SANITIZER=memory" in args and "FUZZING_LANGUAGE=c" in args
    assert not any(a.startswith(("FUZZER_LIB=", "FUZZER=", "CFLAGS=")) for a in args) and args[-2:] == ["bench-upstream/libssh", "compile"]
    assert args == [
        "--network", "none",
        "-e", "FUZZING_ENGINE=afl", "-e", "SANITIZER=memory", "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c", "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
        "-v", DENYLIST,
        "-v", f"{tmp_path / 's'}:/src/libssh",
        "-v", f"{tmp_path / 'o'}:/out",
        "bench-upstream/libssh", "compile"]


def test_upstream_compile_args_without_source_compiles_the_image_tree(tmp_path):
    args = pb.upstream_compile_args(image="bench-upstream/libssh", source_dir=None,
                                    out_dir=str(tmp_path / "o"), project="libssh",
                                    sanitizer="address", language="c++")
    assert not any(a.endswith(":/src/libssh") for a in args)
    assert args[-4:] == ["-v", f"{tmp_path / 'o'}:/out", "bench-upstream/libssh", "compile"]


def test_upstream_compile_args_ignore_build_opt_level(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "-O3")
    monkeypatch.setattr(pb, "_image_env", lambda image: pytest.fail("must not read image env"))
    args = pb.upstream_compile_args(image="bench-upstream/libssh", source_dir=None,
                                    out_dir=str(tmp_path), project="libssh",
                                    sanitizer="address", language="c")
    assert not any(a.startswith(("CFLAGS=", "CXXFLAGS=")) for a in args)


def test_prework_image_for_upstream_and_rebuild_dispatch(monkeypatch):
    entry = {"kind": "upstream", "project": "libssh", "ossfuzz_project": "LibSSH",
             "sanitizer": "undefined", "language": "c"}
    assert pb.prework_image_for(entry) == "bench-upstream/libssh"
    with pytest.raises(ValueError, match="ossfuzz_project"):
        pb.prework_image_for({"kind": "upstream", "project": "libssh"})

    cmd = pb.build_prework_rebuild_command(
        image="bench-upstream/libssh", source_dir="/s/libssh", out_dir="/o",
        project="libssh", cpu=5, sanitizer="undefined", language="c")
    assert cmd == ["docker", "run", "--rm", "--privileged", "--cpuset-cpus", "5",
                   *pb.upstream_compile_args(image="bench-upstream/libssh",
                                             source_dir="/s/libssh", out_dir="/o",
                                             project="libssh", sanitizer="undefined",
                                             language="c")]
    with pytest.raises(ValueError):
        pb.build_prework_rebuild_command(image="bench-upstream/libssh", source_dir="/s",
                                         out_dir="/o", project="libssh", ccache_dir="/c")

    seen = {}
    monkeypatch.setattr(pb, "build_prework_rebuild_command",
                        lambda **kw: seen.update(kw) or ["true"])
    monkeypatch.setattr(pb, "restore_ownership", lambda image, paths: seen.update(owned=paths))

    class _R:
        returncode, stdout, stderr = 0, "", ""
    monkeypatch.setattr(pb.subprocess, "run", lambda *a, **k: _R())
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        assert pb.rebuild_with_prework_image(entry=entry, source_dir=d + "/s",
                                             out_dir=d + "/o", cpu=5) is True
        assert seen["image"] == "bench-upstream/libssh"
        assert seen["sanitizer"] == "undefined" and seen["language"] == "c"
        assert seen["owned"] == [d + "/s", d + "/o"]


def test_build_opt_provenance_upstream_reads_image_cflags_without_override(monkeypatch):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "-O3")
    monkeypatch.setattr(pb, "_image_env",
                        lambda image: {"CFLAGS": "-O1 -fno-omit-frame-pointer -fsanitize=address"})
    prov = pb.build_opt_provenance({"kind": "upstream", "project": "libssh",
                                    "ossfuzz_project": "libssh"})
    assert prov["build_opt_level"] == "-O1"
    assert prov["build_opt_level_source"] == "image-cflags"
    assert prov["build_opt"]["override"] == ""
    assert prov["build_opt"]["cflags"] == "-O1 -fno-omit-frame-pointer -fsanitize=address"


def test_arvo_and_fuzzbench_commands_are_unchanged():
    assert pb.build_prework_rebuild_command(
        image="bench-aflpp/libxml2-arvo-1972", source_dir="/s/libxml2", out_dir="/o",
        project="libxml2", cpu=3) == [
        'docker', 'run', '--rm', '--privileged', '--cpuset-cpus', '3',
        '-e', 'FUZZING_ENGINE=afl', '-e', 'FUZZER_LIB=/usr/lib/libFuzzingEngine.a',
        '-e', 'FUZZER=afl', '-e', 'AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt',
        '-e', 'SANITIZER=address', '-e', 'ARCHITECTURE=x86_64', '-e', 'FUZZING_LANGUAGE=c++',
        '-v', DENYLIST, '-v', '/s/libxml2:/src/libxml2', '-v', '/o:/out',
        'bench-aflpp/libxml2-arvo-1972', 'compile']
    assert pb.build_prework_rebuild_command(
        image="fb-aflpp/libxml2_xml", source_dir="/s/libxml2", out_dir="/o",
        project="libxml2", cpu=3) == [
        'docker', 'run', '--rm', '--cpuset-cpus', '3', '-e', 'FB_SRC_NAME=libxml2',
        '-v', '/s/libxml2:/fold/src:ro',
        '-v', f"{PREWORK / 'fb_build.sh'}:/fold/fb_build.sh:ro", '-v', '/o:/out',
        '--entrypoint', '/bin/bash', 'fb-aflpp/libxml2_xml', '/fold/fb_build.sh']
    # ARVO provenance keeps its own source tag.
    assert pb.prework_image_for({"project": "libxml2", "local_id": 1972}) == \
        "bench-aflpp/libxml2-arvo-1972"


def test_build_command_uses_the_vendored_tree_as_context(tmp_path):
    """OSS-Fuzz Dockerfiles COPY relative to their own directory, so the context
    is ossfuzz/ while the pinned Dockerfile next to it is passed with -f."""
    (tmp_path / "Dockerfile").write_text("FROM a@sha256:1\n")
    (tmp_path / "ossfuzz").mkdir()
    (tmp_path / "ossfuzz" / "build.sh").write_text("make\n")
    cmd = ui.build_command(tmp_path, "bench-upstream/libssh")
    assert cmd[-3:] == ["-f", f"{tmp_path}/Dockerfile", str(tmp_path / "ossfuzz")]
    assert f"bench-upstream.definition-sha256={ui.definition_hash(tmp_path)}" in cmd
