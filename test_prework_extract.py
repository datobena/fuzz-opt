"""Tests for prework/extract.py — ARVO artifact extraction and identity stripping."""
import pytest
from pathlib import Path

from prework.extract import build_cp_command, build_poc_command, strip_identity


def test_strip_identity_removes_git_dir(tmp_path):
    """The upstream .git exposes the vulnerable commit and remote (leak vector 7)."""
    src = tmp_path / "libxml2"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text('[remote "origin"]\n')
    (src / "parser.c").write_text("int main(void){return 0;}\n")

    removed = strip_identity(src)

    assert not (src / ".git").exists()
    assert (src / "parser.c").exists(), "source files must survive"
    assert str(src / ".git") in removed


def test_strip_identity_removes_nested_git(tmp_path):
    """Submodules carry their own .git; those leak upstream identity too."""
    src = tmp_path / "assimp"
    (src / "contrib" / "zlib" / ".git").mkdir(parents=True)
    (src / "contrib" / "zlib" / "zlib.c").write_text("\n")

    strip_identity(src)

    assert not (src / "contrib" / "zlib" / ".git").exists()
    assert (src / "contrib" / "zlib" / "zlib.c").exists()


def test_strip_identity_removes_submodule_git_file(tmp_path):
    """A submodule's .git is a FILE pointing at the parent's modules dir."""
    src = tmp_path / "proj"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / ".git").write_text("gitdir: ../.git/modules/sub\n")

    strip_identity(src)

    assert not (src / "sub" / ".git").exists()


def test_strip_identity_is_idempotent(tmp_path):
    """Re-running on an already-clean tree must not raise."""
    src = tmp_path / "lua"
    src.mkdir()
    (src / "lua.c").write_text("\n")

    assert strip_identity(src) == []


def test_build_cp_command_targets_the_container_not_the_image():
    cmd = build_cp_command("arvo_extract_1972", "/src/.", "/tmp/out")
    assert cmd[:2] == ["docker", "cp"]
    assert cmd[2] == "arvo_extract_1972:/src/."
    assert cmd[3] == "/tmp/out"


def test_build_poc_command_writes_poc_and_log_to_the_mounted_dir():
    cmd = build_poc_command("n132/arvo:1972-vul", "/host/poc")
    joined = " ".join(cmd)
    assert "-v" in cmd and "/host/poc:/pocout" in cmd
    assert "--entrypoint" in cmd
    assert "arvo" in joined and "/pocout/repro.log" in joined
    assert "/tmp/poc" in joined, "the PoC is baked at /tmp/poc in ARVO images"


# --- source-only extraction (images with no `arvo` wrapper) -------------------

def test_extract_source_only_requires_a_poc(tmp_path, monkeypatch):
    """An image with no baked reproducer cannot verify itself, so an external
    PoC is mandatory -- an unverified target must never reach the benchmark."""
    import prework.extract as e

    monkeypatch.setattr(e, "copy_src_from_image", lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="poc_source not found"):
        e.extract_source_only(
            "gcr.io/oss-fuzz/1", "selinux", tmp_path,
            poc_source=tmp_path / "missing",
        )


def test_extract_source_only_copies_poc_and_strips_git(tmp_path, monkeypatch):
    import prework.extract as e

    poc = tmp_path / "orig_poc"
    poc.write_bytes(b"CRASHME")

    def fake_copy(image, src_out, *, tag):
        (src_out / "selinux" / ".git").mkdir(parents=True)
        (src_out / "selinux" / "sepol.c").write_text("\n")
        (src_out / "build.sh").write_text("#!/bin/bash\n")

    monkeypatch.setattr(e, "copy_src_from_image", fake_copy)
    r = e.extract_source_only(
        "gcr.io/oss-fuzz/1", "selinux", tmp_path / "work", poc_source=poc,
    )

    assert r.poc_path.read_bytes() == b"CRASHME"
    assert not (r.source_dir / "selinux" / ".git").exists()
    assert (r.source_dir / "selinux" / "sepol.c").exists()
    assert r.build_sh.is_file()
    # This image cannot self-reproduce; verify.py checks the NEW build instead.
    assert r.baseline_crashed is False


def test_extract_source_only_fails_without_build_sh(tmp_path, monkeypatch):
    import prework.extract as e

    poc = tmp_path / "p"
    poc.write_bytes(b"x")
    monkeypatch.setattr(e, "copy_src_from_image",
                        lambda image, src_out, *, tag: (src_out / "x").mkdir())
    with pytest.raises(RuntimeError, match="build.sh"):
        e.extract_source_only("img", "p", tmp_path / "w", poc_source=poc)
