"""Upstream OSS-Fuzz seed staging follows run_fuzzer.

infra/base-images/base-runner/run_fuzzer: when $OUT/<t>_seed_corpus.zip
exists it is unzipped into the corpus dir, and `echo input >
${CORPUS_DIR}/input` always adds one file `input` holding b"input\\n".
"""
import zipfile

import phase3_online
from lib import corpus as corpus_util

UPSTREAM = {"project": "libpng", "fuzz_target": "libpng_read_fuzzer",
            "kind": "upstream"}
FUZZBENCH = {"project": "zlib", "fuzz_target": "t", "kind": "fuzzbench",
             "fuzzbench_dir": "zlib_zlib_uncompress_fuzzer"}


def _names(d):
    return sorted(p.name for p in d.iterdir())


def test_with_zip_merged_gets_zip_plus_input(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    big = b"z" * (2 * 1024 * 1024)                  # no size limit
    with zipfile.ZipFile(b / "t_seed_corpus.zip", "w") as z:
        z.writestr("dir/", "")
        z.writestr("dir/one", b"one")
        z.writestr("two", b"two")
        z.writestr("huge", big)
    merged, build = tmp_path / "merged", tmp_path / "build"
    st = corpus_util.stage_upstream_seed_corpus(str(b), "t", str(merged), str(build))
    assert _names(merged) == ["dir__one", "huge", "input", "two"]
    assert _names(build) == ["dir__one", "huge", "two"]
    assert all(p.is_file() for p in merged.iterdir()), "flattened, no subdirs"
    assert (merged / "input").read_bytes() == b"input\n"
    assert (merged / "dir__one").read_bytes() == b"one"
    assert (build / "huge").read_bytes() == big
    assert st == {"staged": 4, "zip": True, "input_file": True}


def test_same_basename_in_different_dirs_never_collides(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    with zipfile.ZipFile(b / "t_seed_corpus.zip", "w") as z:
        z.writestr("a/x", b"from-a")
        z.writestr("b/x", b"from-b")
        z.writestr("./c/y", b"from-c")
    merged, build = tmp_path / "merged", tmp_path / "build"
    st = corpus_util.stage_upstream_seed_corpus(str(b), "t", str(merged), str(build))
    assert _names(merged) == ["a__x", "b__x", "c__y", "input"]
    assert _names(build) == ["a__x", "b__x", "c__y"]
    assert (merged / "a__x").read_bytes() == b"from-a"
    assert (merged / "b__x").read_bytes() == b"from-b"
    assert (build / "a__x").read_bytes() == b"from-a"
    assert (build / "b__x").read_bytes() == b"from-b"
    assert (merged / "input").read_bytes() == b"input\n"
    assert st["staged"] == 4


def test_without_zip_merged_and_build_hold_only_input(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    merged, build = tmp_path / "merged", tmp_path / "build"
    st = corpus_util.stage_upstream_seed_corpus(str(b), "t", str(merged), str(build))
    assert _names(merged) == _names(build) == ["input"]
    assert (merged / "input").read_bytes() == b"input\n"
    assert (build / "input").read_bytes() == b"input\n"
    assert st == {"staged": 1, "zip": False, "input_file": True}


def test_generic_seed_corpus_zip_is_not_used(tmp_path):
    """run_fuzzer only looks for ${FUZZER}_seed_corpus.zip."""
    b = tmp_path / "bin"
    b.mkdir()
    with zipfile.ZipFile(b / "seed_corpus.zip", "w") as z:
        z.writestr("s", b"seed")
    merged, build = tmp_path / "merged", tmp_path / "build"
    st = corpus_util.stage_upstream_seed_corpus(str(b), "t", str(merged), str(build))
    assert _names(merged) == ["input"] and st["zip"] is False


def test_directories_are_recreated_each_call(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    merged, build = tmp_path / "merged", tmp_path / "build"
    for d in (merged, build):
        d.mkdir()
        (d / "stale").write_bytes(b"old")
    corpus_util.stage_upstream_seed_corpus(str(b), "t", str(merged), str(build))
    assert _names(merged) == _names(build) == ["input"]


def test_online_staging_routes_upstream_to_run_fuzzer_rules(tmp_path, monkeypatch):
    exp = tmp_path / "exp"
    b = tmp_path / "bin"
    b.mkdir()
    with zipfile.ZipFile(b / "t_seed_corpus.zip", "w") as z:
        z.writestr("x/a", b"aaa")

    def _no_fb(*a, **k):
        raise AssertionError("upstream must not use the fuzzbench helper")
    monkeypatch.setattr(corpus_util, "stage_fuzzbench_seed_corpus", _no_fb)
    n = phase3_online._stage_online_seed_corpus(str(exp), str(b), "t", entry=UPSTREAM)
    merged = exp / "seed_corpus" / "merged"
    build = exp / "seed_corpus" / "build"
    assert n == 2
    assert _names(merged) == ["input", "x__a"]
    assert _names(build) == ["x__a"]


def test_online_staging_fuzzbench_still_uses_fuzzbench_helper(tmp_path, monkeypatch):
    calls = []
    real = corpus_util.stage_fuzzbench_seed_corpus

    def _spy(*a, **k):
        calls.append(a)
        return real(*a, **k)

    def _no_up(*a, **k):
        raise AssertionError("fuzzbench must not use the upstream helper")
    monkeypatch.setattr(corpus_util, "stage_fuzzbench_seed_corpus", _spy)
    monkeypatch.setattr(corpus_util, "stage_upstream_seed_corpus", _no_up,
                        raising=False)
    exp = tmp_path / "exp"
    b = tmp_path / "bin"
    b.mkdir()
    assert phase3_online._stage_online_seed_corpus(str(exp), str(b), "t",
                                                   entry=FUZZBENCH) == 0
    assert len(calls) == 1
    assert (exp / "seed_corpus" / "merged" / "default_seed").read_bytes() == b"hi"
