"""Tests for resolving and building against the pinned prework images.

Phase 2 used to build through `arvo compile` inside the ARVO image, which bakes
FUZZING_ENGINE=libfuzzer and carries the historical toolchain. It now builds in
the prework image instead: same source, pinned AFL++ v5.02c on LLVM 18, and no
`arvo` wrapper or /tmp/poc for a sandboxed agent to find.
"""
import pytest

from prework.build_image import image_tag
from prework.prework_build import (
    prework_image_for,
    build_prework_rebuild_command,
)


def test_prework_image_is_derived_from_project_and_local_id():
    entry = {"project": "libavc", "cve": "arvo-16505", "local_id": 16505}
    assert prework_image_for(entry) == "bench-aflpp/libavc-arvo-16505"


def test_prework_image_matches_what_the_prework_stage_tagged():
    """Drift here silently builds against a stale or missing image."""
    entry = {"project": "selinux", "cve": "CVE-2021-36085", "local_id": 42493454}
    assert prework_image_for(entry) == image_tag("selinux", 42493454)


def test_prework_image_requires_a_local_id():
    with pytest.raises(ValueError, match="local_id"):
        prework_image_for({"project": "x", "cve": "y"})


def test_rebuild_command_mounts_source_over_the_project_dir(tmp_path):
    cmd = build_prework_rebuild_command(
        image="bench-aflpp/libavc-arvo-16505", source_dir=str(tmp_path / "src"),
        out_dir=str(tmp_path / "out"), project="libavc",
    )
    joined = " ".join(cmd)
    assert "/src/libavc" in joined, "modified source must land at $SRC/<project>"
    assert joined.rstrip().endswith("compile")


def test_rebuild_command_selects_afl_not_libfuzzer(tmp_path):
    cmd = build_prework_rebuild_command(
        image="i", source_dir=str(tmp_path), out_dir=str(tmp_path),
        project="p",
    )
    joined = " ".join(cmd)
    assert "FUZZING_ENGINE=afl" in joined
    assert "SANITIZER=address" in joined
    assert "arvo" not in cmd, "the arvo wrapper hardcodes FUZZING_ENGINE=libfuzzer"


def test_rebuild_command_can_pin_a_cpu(tmp_path):
    cmd = build_prework_rebuild_command(
        image="i", source_dir=str(tmp_path), out_dir=str(tmp_path),
        project="p", cpu=7,
    )
    assert "--cpuset-cpus" in cmd
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "7"


# ---------------------------------------------------------------- -O level parity
#
# Every ARVO build path must compile at the SAME -O level: the campaign's
# baseline/reference build, the per-round harness rebuild, the noise-floor and
# setup rebuilds (all rebuild_with_prework_image -> build_prework_rebuild_command)
# and the agent's own builds through the broker (sandbox/broker._build_command).
# They diverged once: the launcher defaulted BUILD_OPT_LEVEL to O3, the harness
# applied it, the broker never did -- so the agent timed -O1 builds while -O3
# builds were gated and deployed.

import config  # noqa: E402
import prework.prework_build as pb  # noqa: E402
from sandbox.broker import BrokerContext, _build_command  # noqa: E402

ARVO_IMG = "bench-aflpp/libavc-arvo-16505"
ARVO_ENTRY = {"project": "libavc", "cve": "arvo-16505", "local_id": 16505}
FB_ENTRY = {"project": "mruby", "cve": "fuzzbench-900026", "local_id": 900026,
            "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
            "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}
FB_IMG = "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
# The real bench-aflpp image ENV (docker image inspect), trimmed.
IMG_CFLAGS = ("-O1   -fno-omit-frame-pointer   -gline-tables-only   "
              "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION")
IMG_CXXFLAGS = IMG_CFLAGS + " -stdlib=libc++"


class _R:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


@pytest.fixture
def fake_docker(monkeypatch):
    """Fake `docker image inspect` (the image's ENV) and record every `docker run`."""
    runs, inspects = [], []
    monkeypatch.setattr(pb, "_OPT_ENV_CACHE", {})
    monkeypatch.setattr(pb, "_IMAGE_ENV_CACHE", {})

    def run(cmd, **_k):
        if cmd[:3] == ["docker", "image", "inspect"]:
            inspects.append(cmd)
            return _R(out=f"PATH=/usr/bin\nCFLAGS={IMG_CFLAGS}\nCXXFLAGS={IMG_CXXFLAGS}\n")
        runs.append(cmd)
        return _R()
    monkeypatch.setattr(pb.subprocess, "run", run)
    return runs, inspects


def _harness(image=ARVO_IMG, project="libavc"):
    return build_prework_rebuild_command(image=image, source_dir=f"/x/src/{project}",
                                         out_dir="/x/out", project=project, cpu=7)


def _broker(image=ARVO_IMG, project="libavc"):
    return _build_command(BrokerContext(
        image=image, source_dir=f"/x/src/{project}", out_dir="/x/out",
        corpus_dir="/x/c", fuzz_target="t", project=project, cpu=7))


def _drop_ulimit(cmd):
    i = cmd.index("--ulimit")
    return cmd[:i] + cmd[i + 2:]


def _env(cmd):
    return {cmd[i + 1].split("=", 1)[0]: cmd[i + 1].split("=", 1)[1]
            for i, a in enumerate(cmd) if a == "-e"}


def test_unset_level_builds_with_the_images_own_flags(monkeypatch, fake_docker):
    """The default: no CFLAGS/CXXFLAGS override anywhere, so build.sh compiles with
    the image's own ENV exactly as ARVO/OSS-Fuzz did. No image inspect either."""
    _runs, inspects = fake_docker
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "")
    for cmd in (_harness(), _broker()):
        assert "CFLAGS" not in _env(cmd) and "CXXFLAGS" not in _env(cmd)
    assert _drop_ulimit(_broker()) == _harness()
    assert not inspects


@pytest.mark.parametrize("level", ["O3", "-O3", " O3 "])
def test_override_reaches_harness_and_broker_identically(monkeypatch, fake_docker, level):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", level)
    harness, broker = _harness(), _broker()
    want_c = IMG_CFLAGS.replace("-O1", "-O3", 1)
    for cmd in (harness, broker):
        env = _env(cmd)
        assert env["CFLAGS"] == want_c
        assert env["CXXFLAGS"] == IMG_CXXFLAGS.replace("-O1", "-O3", 1)
        assert "-O1" not in env["CFLAGS"]
    # The broker differs from the harness ONLY by the core-dump ulimit.
    assert _drop_ulimit(broker) == harness


def test_every_harness_build_path_carries_the_override(monkeypatch, fake_docker, tmp_path):
    """rebuild_with_prework_image is what the baseline build, the noise-floor and
    setup rebuilds (phase3_online._setup_build) and every round rebuild call."""
    import phase2_setup
    runs, _ = fake_docker
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "O3")
    monkeypatch.setattr(phase2_setup, "_clean_build_artifacts", lambda *_a: None)
    monkeypatch.setattr(pb, "restore_ownership", lambda *_a: None)
    src = tmp_path / "src" / "libavc"
    src.mkdir(parents=True)
    assert pb.rebuild_with_prework_image(entry=ARVO_ENTRY, source_dir=str(src),
                                         out_dir=str(tmp_path / "out"), cpu=None)
    (cmd,) = [c for c in runs if c[:2] == ["docker", "run"]]
    assert _env(cmd)["CFLAGS"] == IMG_CFLAGS.replace("-O1", "-O3", 1)
    assert cmd[-2:] == [ARVO_IMG, "compile"]


def test_fuzzbench_commands_ignore_the_override(monkeypatch, fake_docker):
    """FuzzBench builds are FuzzBench's own (-O1 bug / -O3 coverage), whatever
    BUILD_OPT_LEVEL says: identical argv with and without it, no image inspect."""
    _runs, inspects = fake_docker
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "")
    before = (_harness(FB_IMG, "mruby"), _broker(FB_IMG, "mruby"))
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "O3")
    after = (_harness(FB_IMG, "mruby"), _broker(FB_IMG, "mruby"))
    assert before == after
    assert not inspects
    for cmd in after:
        assert "CFLAGS" not in _env(cmd)


def test_provenance_records_the_level_that_ran(monkeypatch, fake_docker):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "")
    p = pb.build_opt_provenance(ARVO_ENTRY)
    assert p["build_opt_level"] == "-O1"          # read from the image's CFLAGS
    assert p["build_opt_level_source"] == "arvo-image-cflags"
    assert p["build_opt"]["override"] == "" and p["build_opt"]["cflags"] == IMG_CFLAGS

    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "O3")
    p = pb.build_opt_provenance(ARVO_ENTRY)
    assert p["build_opt_level"] == "-O3"
    assert p["build_opt_level_source"] == "BUILD_OPT_LEVEL"
    # Exactly the string the build commands carried.
    assert p["build_opt"]["cflags"] == _env(_harness())["CFLAGS"]


def test_fuzzbench_provenance_is_unchanged(monkeypatch, fake_docker):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "O3")
    assert pb.build_opt_provenance(FB_ENTRY) == {
        "build_opt_level": "-O1", "build_opt_level_source": "fuzzbench:bug"}
    cov = dict(FB_ENTRY, type="coverage")
    assert pb.build_opt_provenance(cov) == {
        "build_opt_level": "-O3", "build_opt_level_source": "fuzzbench:coverage"}


def test_provenance_survives_an_unreadable_image(monkeypatch):
    monkeypatch.setattr(config, "BUILD_OPT_LEVEL", "")
    monkeypatch.setattr(pb, "_IMAGE_ENV_CACHE", {})
    monkeypatch.setattr(pb.subprocess, "run", lambda *a, **k: _R(rc=1, err="no such image"))
    p = pb.build_opt_provenance(ARVO_ENTRY)
    assert p["build_opt_level"] is None and "no such image" in p["build_opt"]["error"]


def test_launcher_defaults_to_the_benchmarks_own_build():
    """run_online_pertrial.sh must not default BUILD_OPT_LEVEL to a level."""
    import re
    import subprocess
    from pathlib import Path
    script = (Path(__file__).resolve().parent.parent / "run_online_pertrial.sh").read_text()
    (line,) = [l for l in script.splitlines() if l.startswith("export BUILD_OPT_LEVEL=")
               and "${" in l]
    assert re.fullmatch(r"export BUILD_OPT_LEVEL=\$\{BUILD_OPT_LEVEL:?-\}", line), line
    out = subprocess.run(["env", "-u", "BUILD_OPT_LEVEL", "bash", "-c",
                          f'{line}; printf "[%s]" "$BUILD_OPT_LEVEL"'],
                         capture_output=True, text=True).stdout
    assert out == "[]"
