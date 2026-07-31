"""Tests for prework/extract.py — ARVO artifact extraction and identity stripping."""
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
