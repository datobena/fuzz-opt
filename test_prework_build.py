"""Tests for prework/build_image.py — pinned per-target image construction."""
from pathlib import Path

import pytest

from prework.build_image import build_docker_command, image_tag, load_meta, read_pin

TARGET = Path("prework/targets/libxml2-arvo-1972")


def test_image_tag_is_neutral():
    """The tag must not carry '-vul' or anything that names the bug."""
    tag = image_tag("libxml2", 1972)
    assert tag == "bench-aflpp/libxml2-arvo-1972"
    assert "vul" not in tag


def test_load_meta_reads_the_committed_target():
    meta = load_meta(TARGET)
    assert meta["project"] == "libxml2"
    assert meta["arvo_id"] == 1972
    assert meta["fuzz_target"] == "libxml2_xml_read_memory_fuzzer"
    assert meta["crash_type"]


def test_pins_are_present_and_shaped_correctly():
    assert "@sha256:" in read_pin("base.pin")
    assert read_pin("aflpp.pin").startswith("v")


def test_build_docker_command_pins_base_and_aflpp(tmp_path):
    base = "gcr.io/oss-fuzz-base/base-builder@sha256:deadbeef"
    cmd = build_docker_command(
        target_dir=tmp_path, tag="bench-aflpp/x-arvo-1", base=base, aflpp_ref="v5.02c",
    )
    joined = " ".join(cmd)
    assert "BASE=" + base in joined, "base must be digest-pinned, not tag-pinned"
    assert "AFLPP_REF=v5.02c" in joined
    assert "@sha256:" in joined


def test_build_docker_command_rejects_unpinned_base(tmp_path):
    """A tag-pinned base silently drifts when re-pulled; refuse it."""
    with pytest.raises(ValueError, match="digest"):
        build_docker_command(
            target_dir=tmp_path, tag="bench-aflpp/x-arvo-1",
            base="gcr.io/oss-fuzz-base/base-builder:latest", aflpp_ref="v5.02c",
        )


def test_stage_source_prunes_engine_trees_but_keeps_the_project(tmp_path):
    """ARVO ships its own aflplusplus under /src; it must not shadow the pin."""
    from prework.build_image import stage_source

    src = tmp_path / "src"
    for engine in ("aflplusplus", "honggfuzz", "libfuzzer", "fuzztest"):
        (src / engine).mkdir(parents=True)
        (src / engine / "stale.c").write_text("\n")
    (src / "libxml2" / "parser.c").parent.mkdir(parents=True)
    (src / "libxml2" / "parser.c").write_text("\n")
    (src / "build.sh").write_text("#!/bin/bash\n")
    (src / "libxml2_xml_read_memory_fuzzer.cc").write_text("\n")

    pruned = stage_source(src, tmp_path / "staged")
    staged = tmp_path / "staged"

    assert not (staged / "aflplusplus").exists()
    assert set(pruned) == {"aflplusplus", "honggfuzz", "libfuzzer", "fuzztest"}
    assert (staged / "libxml2" / "parser.c").exists()
    assert (staged / "build.sh").exists()
    assert (staged / "libxml2_xml_read_memory_fuzzer.cc").exists()


def test_stage_source_keeps_a_nested_dir_that_shares_an_engine_name(tmp_path):
    """Only top-level engine trees are pruned; a project subdir named 'afl' stays."""
    from prework.build_image import stage_source

    src = tmp_path / "src"
    (src / "proj" / "afl").mkdir(parents=True)
    (src / "proj" / "afl" / "keep.c").write_text("\n")

    stage_source(src, tmp_path / "staged")

    assert (tmp_path / "staged" / "proj" / "afl" / "keep.c").exists()
