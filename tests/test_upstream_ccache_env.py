import os
import stat

from prework.upstream_ccache import (
    CONTAINER_CACHE_DIR, CONTAINER_WRAPPER_DIR, WRAPPER_DIR, ccache_docker_args)


def env_val(args, key):
    for i, x in enumerate(args[:-1]):
        if x == "-e" and args[i + 1].startswith(key + "="):
            return args[i + 1].split("=", 1)[1]
    return None


def test_uncached_sets_disable_and_no_mounts():
    a = ccache_docker_args(cache_dir=None, statslog=None)
    assert a == ["-e", "CCACHE_DISABLE=1"]
    assert "-v" not in a


def test_cached_mounts_wrapper_and_overrides_ccache_dir():
    a = ccache_docker_args(cache_dir="/host/c", statslog="/upstream_ccache/statslog")
    assert any(x.endswith("/cc") or x.endswith(":ro") for x in a)
    assert env_val(a, "CCACHE_DIR") == CONTAINER_CACHE_DIR
    assert env_val(a, "AFL_CC").startswith(CONTAINER_WRAPPER_DIR)
    assert env_val(a, "AFL_CXX").startswith(CONTAINER_WRAPPER_DIR)
    assert env_val(a, "CCACHE_COMPILERCHECK") == "content"
    assert env_val(a, "CCACHE_EXTRAFILES") == "/src/aflpp_fold_denylist.txt"
    assert env_val(a, "CCACHE_STATSLOG")
    assert "CCACHE_DISABLE=1" not in a
    assert "/host/c:" + CONTAINER_CACHE_DIR in a


def test_wrappers_exec_ccache_on_backend_clang():
    for name, clang in (("cc", "clang"), ("cxx", "clang++")):
        p = WRAPPER_DIR / name
        assert os.stat(p).st_mode & stat.S_IXUSR
        body = p.read_text()
        assert body.startswith("#!/bin/sh")
        assert f'exec /usr/local/bin/ccache /usr/local/bin/{clang} "$@"' in body
