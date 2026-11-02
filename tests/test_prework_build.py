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


def test_definition_hash_is_stable_and_covers_every_definition_file(tmp_path):
    from prework.build_image import definition_hash
    pins = tmp_path / "pins"; pins.mkdir()
    (pins / "base.pin").write_text("gcr.io/x@sha256:aa\n"); (pins / "aflpp.pin").write_text("v5.02c\n")
    t = tmp_path / "t"; t.mkdir()
    (t / "Dockerfile").write_text("FROM x\n"); (t / "meta.json").write_text("{}")
    h1 = definition_hash(t, prework_dir=pins)
    assert len(h1) == 64 and h1 == definition_hash(t, prework_dir=pins)
    (t / "build.sh").write_text("make\n")
    h2 = definition_hash(t, prework_dir=pins)
    assert h2 != h1, "adding build.sh must change the hash"
    (t / "build.sh").write_text("make all\n")
    assert definition_hash(t, prework_dir=pins) != h2
    (pins / "aflpp.pin").write_text("v5.03c\n")
    assert definition_hash(t, prework_dir=pins) not in (h1, h2), "a pin change must change the hash"


def test_build_docker_command_carries_labels(tmp_path):
    cmd = build_docker_command(target_dir=tmp_path, tag="bench-aflpp/x-arvo-1",
                               base="gcr.io/x@sha256:aa", aflpp_ref="v5.02c",
                               labels={"bench-aflpp.definition-sha256": "abc"})
    assert "--label" in cmd and "bench-aflpp.definition-sha256=abc" in cmd
    assert cmd.index("--label") > cmd.index("-t")


def test_build_image_stamps_the_definition_hash(tmp_path, monkeypatch):
    from prework import build_image as bi
    seen = {}
    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()
    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    monkeypatch.setattr(bi, "read_pin", lambda n: {"base.pin": "gcr.io/x@sha256:aa", "aflpp.pin": "v5.02c"}[n])
    t = tmp_path / "t"; t.mkdir(); (t / "Dockerfile").write_text("FROM x\n"); (t / "meta.json").write_text("{}")
    src = tmp_path / "src"; src.mkdir(); (src / "p").mkdir()
    ok, _ = bi.build_image(t, src, "bench-aflpp/x-arvo-1")
    assert ok
    expected = f"{bi.DEFINITION_LABEL}={bi.definition_hash(t)}"
    assert expected in seen["cmd"]
