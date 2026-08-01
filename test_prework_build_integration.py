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
