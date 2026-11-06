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


def _expected_hash(*files):
    h = hashlib.sha256()
    for rel, data in sorted(files):
        h.update(rel.encode() + b"\0" + hashlib.sha256(data).hexdigest().encode() + b"\n")
    return h.hexdigest()


def test_definition_hash_without_ossfuzz_covers_every_file_but_results(tmp_path):
    """A hand-written definition (no vendored tree): every file, results excluded."""
    (tmp_path / "Dockerfile").write_text("FROM a@sha256:1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "build.sh").write_text("make\n")
    (tmp_path / "meta.json").write_text("{}")
    h0 = ui.definition_hash(tmp_path)
    assert h0 == _expected_hash(("Dockerfile", b"FROM a@sha256:1\n"),
                                ("src/build.sh", b"make\n"), ("meta.json", b"{}"))

    (tmp_path / "onboard_result.json").write_text("{}")
    (tmp_path / "src" / "onboard_result.json").write_text("{}")
    assert ui.definition_hash(tmp_path) == h0

    (tmp_path / "src" / "build.sh").write_text("make -j\n")
    h1 = ui.definition_hash(tmp_path)
    assert h1 != h0
    (tmp_path / "meta.json").write_text('{"x": 1}')
    assert ui.definition_hash(tmp_path) not in (h0, h1)


def test_definition_hash_with_ossfuzz_covers_only_the_build_inputs(tmp_path):
    """The onboarded layout: the -f Dockerfile plus the ossfuzz/ context, and
    nothing of the metadata onboarding writes around the build."""
    (tmp_path / "Dockerfile").write_text("FROM a@sha256:1\n")
    (tmp_path / "ossfuzz" / "sub").mkdir(parents=True)
    (tmp_path / "ossfuzz" / "build.sh").write_text("make\n")
    (tmp_path / "ossfuzz" / "sub" / "f.c").write_text("int x;\n")
    h0 = ui.definition_hash(tmp_path)
    assert h0 == _expected_hash(("Dockerfile", b"FROM a@sha256:1\n"),
                                ("ossfuzz/build.sh", b"make\n"),
                                ("ossfuzz/sub/f.c", b"int x;\n"))

    for name in ("meta.json", "pins.json", "onboard_result.json", "notes.txt"):
        (tmp_path / name).write_text('{"harnesses": {"address": ["t"]}}')
    assert ui.definition_hash(tmp_path) == h0

    (tmp_path / "ossfuzz" / "sub" / "f.c").write_text("int y;\n")
    h1 = ui.definition_hash(tmp_path)
    assert h1 != h0
    (tmp_path / "Dockerfile").write_text("FROM a@sha256:2\n")
    h2 = ui.definition_hash(tmp_path)
    assert h2 not in (h0, h1)
    (tmp_path / "ossfuzz" / "project.yaml").write_text("language: c\n")
    assert ui.definition_hash(tmp_path) not in (h0, h1, h2)


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
    assert not any(a.startswith(("FUZZER_LIB=", "FUZZER=", "CFLAGS=")) for a in args) and args[-4:-1] == ["bench-upstream/libssh", "bash", "-c"]
    assert args == [
        "--network", "none",
        "-e", "FUZZING_ENGINE=afl", "-e", "SANITIZER=memory", "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c", "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
        "-v", DENYLIST,
        "-v", f"{tmp_path / 's'}:/staging/libssh:ro",
        "-v", f"{tmp_path / 'o'}:/out",
        "bench-upstream/libssh", "bash", "-c", pb._staged_compile_command("libssh")]
    # Nothing under /src/libssh is a mount: the host tree is never written.
    assert not any(":/src/libssh" in a for a in args)


def test_staged_compile_command_copies_the_read_only_tree_in():
    assert pb._staged_compile_command("libssh") == (
        "wd=$(pwd) && rm -rf /src/libssh && cp -a /staging/libssh /src/libssh"
        ' && cd "$wd" && exec compile')
    # The project name is shell-quoted.
    assert "rm -rf '/src/a b'" not in pb._staged_compile_command("a b")
    assert "rm -rf /src/'a b' && cp -a /staging/'a b' /src/'a b'" in \
        pb._staged_compile_command("a b")


def test_upstream_compile_args_without_source_compiles_the_image_tree(tmp_path):
    args = pb.upstream_compile_args(image="bench-upstream/libssh", source_dir=None,
                                    out_dir=str(tmp_path / "o"), project="libssh",
                                    sanitizer="address", language="c++")
    assert not any(a.endswith(":/src/libssh") for a in args)
    assert args[-4:] == ["-v", f"{tmp_path / 'o'}:/out", "bench-upstream/libssh", "compile"]
    # Byte-identical to the pre-staging onboarding argv: the bare `compile`.
    assert args == [
        "--network", "none",
        "-e", "FUZZING_ENGINE=afl", "-e", "SANITIZER=address", "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++", "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
        "-v", DENYLIST, "-v", f"{tmp_path / 'o'}:/out", "bench-upstream/libssh", "compile"]


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


# --------------------------------------------------------------------------- #
# The project's own .git: moved aside at extract, mounted read-only, copied in
# --------------------------------------------------------------------------- #
GIT_ENV = ["-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
           "-e", "GIT_CONFIG_VALUE_0=*"]


def test_vcs_dir_for_finds_the_source_trees_vcs(tmp_path):
    st = tmp_path / "online" / "source_tree"
    src = st / "src" / "tpm2-tss"
    src.mkdir(parents=True)
    assert pb.vcs_dir_for(src) is None
    (st / "vcs").mkdir()
    assert pb.vcs_dir_for(src) == st / "vcs"
    assert pb.vcs_dir_for(str(src)) == st / "vcs"
    assert pb.vcs_dir_for(tmp_path / "elsewhere" / "src" / "tpm2-tss") is None


def test_vcs_dir_for_finds_a_per_trial_copy(tmp_path):
    """Per-trial trees are copies of source_tree named source_root."""
    sr = tmp_path / "trials" / "trial_00" / "source_root"
    (sr / "src" / "tpm2-tss").mkdir(parents=True)
    (sr / "vcs").mkdir()
    assert pb.vcs_dir_for(sr / "src" / "tpm2-tss") == sr / "vcs"


def test_upstream_compile_args_mount_the_preserved_git_dirs(tmp_path):
    vcs = tmp_path / "vcs"
    (vcs / "tpm2-tss" / ".git" / "refs").mkdir(parents=True)
    (vcs / "tpm2-tss" / "deps" / "x" / ".git").mkdir(parents=True)
    (vcs / "tpm2-tss" / "deps" / ".hg").mkdir(parents=True)
    (vcs / "other" / ".git").mkdir(parents=True)
    kw = dict(image="bench-upstream/tpm2-tss", source_dir=str(tmp_path / "s"),
              out_dir=str(tmp_path / "o"), project="tpm2-tss", sanitizer="address",
              language="c")
    plain = pb.upstream_compile_args(**kw)
    assert not any("GIT_CONFIG" in a for a in plain)
    args = pb.upstream_compile_args(**kw, vcs_dir=vcs)
    # Mounted beside the read-only tree, not inside it: runc cannot create a
    # mountpoint in a read-only bind mount (and the stripped tree has none).
    assert args == plain[:-4] + [
        "-v", f"{vcs / 'tpm2-tss' / '.git'}:/staging-vcs/tpm2-tss/.git:ro",
        "-v", f"{vcs / 'tpm2-tss' / 'deps' / 'x' / '.git'}"
              ":/staging-vcs/tpm2-tss/deps/x/.git:ro",
        *GIT_ENV, "bench-upstream/tpm2-tss", "bash", "-c",
        pb._staged_compile_command("tpm2-tss", [".git", "deps/x/.git"])]
    assert f"{tmp_path / 's'}:/staging/tpm2-tss:ro" in args
    out = args.index(f"{tmp_path / 'o'}:/out")       # read-write, no :ro
    assert args[out - 1] == "-v"
    assert not any(":/src/tpm2-tss" in a for a in args)


def test_staged_compile_command_copies_the_preserved_git_dirs_in():
    assert pb._staged_compile_command("tpm2-tss", [".git", "deps/x/.git"]) == (
        "wd=$(pwd) && rm -rf /src/tpm2-tss && cp -a /staging/tpm2-tss /src/tpm2-tss"
        " && cp -a /staging-vcs/tpm2-tss/.git /src/tpm2-tss/.git"
        " && mkdir -p /src/tpm2-tss/deps/x"
        " && cp -a /staging-vcs/tpm2-tss/deps/x/.git /src/tpm2-tss/deps/x/.git"
        ' && cd "$wd" && exec compile')


def test_upstream_compile_args_unchanged_without_preserved_git(tmp_path):
    kw = dict(image="bench-upstream/libssh", source_dir=str(tmp_path / "s"),
              out_dir=str(tmp_path / "o"), project="libssh", sanitizer="address",
              language="c")
    plain = pb.upstream_compile_args(**kw)
    (tmp_path / "vcs").mkdir()
    assert pb.upstream_compile_args(**kw, vcs_dir=tmp_path / "vcs") == plain
    assert pb.upstream_compile_args(**kw, vcs_dir=tmp_path / "missing") == plain
    assert pb.upstream_compile_args(**kw, vcs_dir=None) == plain


def test_upstream_compile_args_no_mount_without_source_dir(tmp_path):
    """Onboarding compiles the image's own tree (source_dir=None): its .git is there."""
    (tmp_path / "vcs" / "libssh" / ".git").mkdir(parents=True)
    kw = dict(image="bench-upstream/libssh", source_dir=None,
              out_dir=str(tmp_path / "o"), project="libssh", sanitizer="address",
              language="c")
    assert pb.upstream_compile_args(**kw, vcs_dir=tmp_path / "vcs") == \
        pb.upstream_compile_args(**kw)


def test_rebuild_command_mounts_the_source_trees_git(tmp_path):
    st = tmp_path / "source_tree"
    src = st / "src" / "tpm2-tss"
    src.mkdir(parents=True)
    kw = dict(image="bench-upstream/tpm2-tss", source_dir=str(src),
              out_dir=str(tmp_path / "o"), project="tpm2-tss", cpu=2,
              sanitizer="address", language="c")
    without = pb.build_prework_rebuild_command(**kw)
    assert not any(a.endswith(":ro") and "/.git" in a for a in without)
    assert f"{src}:/staging/tpm2-tss:ro" in without
    (st / "vcs" / "tpm2-tss" / ".git").mkdir(parents=True)
    cmd = pb.build_prework_rebuild_command(**kw)
    assert f"{st / 'vcs' / 'tpm2-tss' / '.git'}:/staging-vcs/tpm2-tss/.git:ro" in cmd
    assert cmd[-1] == pb._staged_compile_command("tpm2-tss", [".git"])
    assert cmd.index("GIT_CONFIG_COUNT=1") < cmd.index("bench-upstream/tpm2-tss")


def test_broker_build_mounts_the_live_source_trees_git(tmp_path):
    """The broker compiles a private snapshot; the .git comes from beside the live tree."""
    from sandbox import broker
    st = tmp_path / "source_tree"
    src = st / "src" / "tpm2-tss"
    src.mkdir(parents=True)
    (st / "vcs" / "tpm2-tss" / ".git").mkdir(parents=True)
    ctx = broker.BrokerContext(image="bench-upstream/tpm2-tss", source_dir=str(src),
                               out_dir=str(tmp_path / "o"), corpus_dir=str(tmp_path / "c"),
                               fuzz_target="t", project="tpm2-tss", cpu=3)
    ctx.build_source_dir = str(tmp_path / "snap" / "tpm2-tss")
    cmd = broker._build_command(ctx)
    assert f"{tmp_path / 'snap' / 'tpm2-tss'}:/staging/tpm2-tss:ro" in cmd
    assert f"{st / 'vcs' / 'tpm2-tss' / '.git'}:/staging-vcs/tpm2-tss/.git:ro" in cmd
    assert not any(":/src/tpm2-tss" in a for a in cmd)
