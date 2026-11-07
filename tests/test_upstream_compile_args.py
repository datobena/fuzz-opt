from pathlib import Path

import pytest

import prework.prework_build as pb
from prework.prework_build import build_prework_rebuild_command, upstream_compile_args
from prework.upstream_ccache import CONTAINER_CACHE_DIR

DENY = str(Path(pb.__file__).resolve().parent / "aflpp_fold_denylist.txt")
KW = dict(image="bench-upstream/x", out_dir="/tmp/o", project="p",
          sanitizer="address", language="c++")

# Captured from upstream_compile_args(source_dir=None) BEFORE the ccache change.
GOLDEN_ONBOARDING = [
    "--network", "none", "-e", "FUZZING_ENGINE=afl", "-e", "SANITIZER=address",
    "-e", "ARCHITECTURE=x86_64", "-e", "FUZZING_LANGUAGE=c++",
    "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
    "-v", f"{DENY}:/src/aflpp_fold_denylist.txt:ro",
    "-v", "/tmp/o:/out", "bench-upstream/x", "compile"]


def staged_cmd(args):
    assert args[-3:-1] == ["bash", "-c"]
    return args[-1]


def test_onboarding_args_unchanged():
    assert upstream_compile_args(source_dir=None, ccache_dir=None, **KW) == GOLDEN_ONBOARDING
    assert upstream_compile_args(source_dir=None, **KW) == GOLDEN_ONBOARDING


def test_uncached_staged_build_has_disable():
    a = upstream_compile_args(source_dir="/s", ccache_dir=None, **KW)
    assert "CCACHE_DISABLE=1" in a
    assert staged_cmd(a).endswith("exec compile")
    assert not any("afl-clang-fast" in x or "upstream_ccache" in x for x in a)


def test_cached_staged_build_resets_stats_and_mounts_wrapper(tmp_path):
    a = upstream_compile_args(source_dir="/s", ccache_dir=str(tmp_path), **KW)
    assert "CCACHE_DISABLE=1" not in a
    assert f"{tmp_path}:{CONTAINER_CACHE_DIR}" in a
    assert f"CCACHE_STATSLOG={CONTAINER_CACHE_DIR}/statslog" in a
    cmd = staged_cmd(a)
    assert "ccache -z" in cmd and "exec compile" not in cmd
    assert cmd.index("ccache -z") < cmd.index("&& compile") < cmd.index("--show-stats")
    assert "cp -a /staging/p" in cmd  # copy-in intact


def test_arvo_still_rejects_ccache():
    with pytest.raises(ValueError):
        build_prework_rebuild_command(image="n132/arvo:1-vul", source_dir="/s",
                                      out_dir="/o", project="p", ccache_dir="/c")


def test_rebuild_command_threads_ccache_for_upstream(tmp_path):
    cmd = build_prework_rebuild_command(image="bench-upstream/x", source_dir=str(tmp_path),
                                        out_dir="/o", project="p", ccache_dir="/c")
    assert "/c:" + CONTAINER_CACHE_DIR in cmd
