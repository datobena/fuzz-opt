"""Tests for tools/onboard_upstream.py: the pure parts of onboarding an OSS-Fuzz
project as an upstream target. Docker never runs: every docker call goes
through a wrapper the tests replace."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import onboard_upstream as ob  # noqa: E402

from prework import upstream_image as ui

BASES = {"gcr.io/oss-fuzz-base/base-builder": "gcr.io/oss-fuzz-base/base-builder@sha256:aa",
         "gcr.io/oss-fuzz-base/base-builder-go": "gcr.io/oss-fuzz-base/base-builder-go@sha256:gg"}


@pytest.fixture(autouse=True)
def _no_docker(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError(f"docker called: {a}")
    for name in ("resolve_base", "image_label", "image_has_dir", "run_logged",
                 "image_checkouts_output", "restore_out_ownership", "build_image"):
        monkeypatch.setattr(ob, name, refuse)


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def _fake_oss_fuzz(tmp_path, yaml_text, dockerfile="FROM gcr.io/oss-fuzz-base/base-builder\n"
                   "RUN git clone https://github.com/x/foo-lib.git foo-lib\nCOPY build.sh $SRC/\n"):
    repo = tmp_path / "oss-fuzz"
    p = repo / "projects" / "foo"
    p.mkdir(parents=True)
    (p / "Dockerfile").write_text(dockerfile)
    (p / "project.yaml").write_text(yaml_text)
    (p / "build.sh").write_text("make\n")
    (repo / "projects" / "other").mkdir()
    (repo / "projects" / "other" / "x").write_text("x\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    return repo, sha


def _bases_file(tmp_path):
    f = tmp_path / "up" / "bases.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(BASES))
    return f.parent


def test_vendor_pins_the_dockerfile_and_writes_meta_and_pins(tmp_path):
    repo, sha = _fake_oss_fuzz(
        tmp_path, "language: c\nmain_repo: 'https://github.com/x/foo-lib.git'\n"
                  "sanitizers:\n  - undefined\n  - address\n  - memory:\n      experimental: True\n"
                  "  - thread\n")
    up = _bases_file(tmp_path)
    ob.vendor("foo", oss_fuzz=repo, commit="HEAD", upstream_dir=up)
    d = up / "foo"
    assert (d / "ossfuzz" / "build.sh").read_text() == "make\n"
    assert not (d / "ossfuzz" / "x").exists()
    assert (d / "Dockerfile").read_text() == (
        "FROM gcr.io/oss-fuzz-base/base-builder@sha256:aa\n"
        "RUN git clone https://github.com/x/foo-lib.git foo-lib\nCOPY build.sh $SRC/\n")
    meta = json.loads((d / "meta.json").read_text())
    assert meta == {"project": "foo", "srcdir": "foo-lib", "language": "c",
                    "sanitizers": ["address", "undefined", "memory"],
                    "harnesses": {}, "deviations": []}
    pins = json.loads((d / "pins.json").read_text())
    assert pins == {"ossfuzz_commit": sha,
                    "bases": {"gcr.io/oss-fuzz-base/base-builder": BASES["gcr.io/oss-fuzz-base/base-builder"]},
                    "checkouts": {}}


def test_vendor_two_sanitizers_defaults_and_srcdir_override(tmp_path):
    repo, _ = _fake_oss_fuzz(tmp_path, "main_repo: https://github.com/google/tink\n"
                                       "sanitizers:\n  - undefined\n  - address\n")
    up = _bases_file(tmp_path)
    ob.vendor("foo", oss_fuzz=repo, commit="HEAD", upstream_dir=up)
    meta = json.loads((up / "foo" / "meta.json").read_text())
    assert meta["sanitizers"] == ["address", "undefined"]
    assert meta["language"] == "c++" and meta["srcdir"] == "tink"

    # re-vendoring replaces the previous copy; --srcdir wins over main_repo
    (up / "foo" / "ossfuzz" / "stale.txt").write_text("old")
    ob.vendor("foo", oss_fuzz=repo, commit="HEAD", upstream_dir=up, srcdir="tink-cc")
    assert not (up / "foo" / "ossfuzz" / "stale.txt").exists()
    assert json.loads((up / "foo" / "meta.json").read_text())["srcdir"] == "tink-cc"


def test_vendor_without_sanitizers_uses_the_oss_fuzz_default(tmp_path):
    repo, _ = _fake_oss_fuzz(tmp_path, "main_repo: https://github.com/x/foo\n")
    up = _bases_file(tmp_path)
    ob.vendor("foo", oss_fuzz=repo, commit="HEAD", upstream_dir=up)
    assert json.loads((up / "foo" / "meta.json").read_text())["sanitizers"] == \
        ["address", "undefined"]


def test_sanitizers_of():
    assert ob.sanitizers_of({}) == ["address", "undefined"]
    assert ob.sanitizers_of({"sanitizers": ["memory"]}) == ["address", "memory"]
    assert ob.sanitizers_of({"sanitizers": ["undefined", "address", "thread"]}) == \
        ["address", "undefined"]


def test_vendor_refuses_an_unknown_base(tmp_path):
    repo, _ = _fake_oss_fuzz(tmp_path, "main_repo: x\n",
                             dockerfile="FROM gcr.io/oss-fuzz-base/base-builder-python\n")
    up = _bases_file(tmp_path)
    with pytest.raises(KeyError, match="base-builder-python"):
        ob.vendor("foo", oss_fuzz=repo, commit="HEAD", upstream_dir=up)


def _elf(path, body=b"", mode=0o755):
    path.write_bytes(b"\x7fELF" + b"\0" * 60 + body)
    path.chmod(mode)


def test_discover_harnesses(tmp_path):
    _elf(tmp_path / "good_fuzzer", b"..LLVMFuzzerTestOneInput..")
    _elf(tmp_path / "afl-fuzz", b"LLVMFuzzerTestOneInput")
    (tmp_path / "run.sh").write_text("#!/bin/sh\n# LLVMFuzzerTestOneInput\n")
    (tmp_path / "run.sh").chmod(0o755)
    _elf(tmp_path / "plain_tool")
    _elf(tmp_path / "llvm-symbolizer", b"LLVMFuzzerTestOneInput")
    _elf(tmp_path / "not_exec", b"LLVMFuzzerTestOneInput", mode=0o644)
    (tmp_path / "seed_corpus.zip").write_bytes(b"PK")
    (tmp_path / "sub").mkdir()
    _elf(tmp_path / "sub" / "nested_fuzzer", b"LLVMFuzzerTestOneInput")
    os.symlink(tmp_path / "good_fuzzer", tmp_path / "link_fuzzer")
    assert ob.discover_harnesses(tmp_path) == ["good_fuzzer"]


def _meta(up, project, harnesses, srcdir=None, language="c"):
    d = up / project
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({
        "project": project, "srcdir": srcdir or project, "language": language,
        "sanitizers": list(harnesses), "harnesses": harnesses, "deviations": []}))
    return d


def test_manifest_allocates_stable_ids(tmp_path):
    up = tmp_path / "up"
    _meta(up, "libFoo", {"address": ["t"], "memory": ["t"]}, srcdir="foo")
    out = tmp_path / "m.json"
    ob.write_manifest(["libFoo"], out, upstream_dir=up)
    m = json.loads(out.read_text())
    assert m == [
        {"project": "foo", "ossfuzz_project": "libFoo", "kind": "upstream",
         "sanitizer": "address", "language": "c", "fuzz_target": "t",
         "image": "bench-upstream/libfoo", "local_id": 970001, "cve": "upstream-970001"},
        {"project": "foo", "ossfuzz_project": "libFoo", "kind": "upstream",
         "sanitizer": "memory", "language": "c", "fuzz_target": "t",
         "image": "bench-upstream/libfoo", "local_id": 970002, "cve": "upstream-970002"},
    ]
    assert json.loads((up / "local_ids.json").read_text()) == {
        "libFoo/address/t": 970001, "libFoo/memory/t": 970002}

    # a new harness and a new project get fresh ids; the old ones never move
    _meta(up, "libFoo", {"address": ["a", "t"], "memory": ["t"]}, srcdir="foo")
    _meta(up, "bar", {"address": ["b"]})
    ob.write_manifest(["bar", "libFoo"], out, upstream_dir=up)
    m = json.loads(out.read_text())
    ids = {(e["ossfuzz_project"], e["sanitizer"], e["fuzz_target"]): e["local_id"] for e in m}
    assert ids[("libFoo", "address", "t")] == 970001
    assert ids[("libFoo", "memory", "t")] == 970002
    assert sorted(ids.values()) == [970001, 970002, 970003, 970004]
    assert [e["local_id"] for e in m] == sorted(e["local_id"] for e in m)
    assert all(e["cve"] == f"upstream-{e['local_id']}" for e in m)

    # a dropped harness keeps its id reserved: nothing is ever reassigned
    _meta(up, "bar", {"address": []})
    ob.write_manifest(["bar", "libFoo"], out, upstream_dir=up)
    _meta(up, "bar", {"address": ["c"]})
    ob.write_manifest(["bar", "libFoo"], out, upstream_dir=up)
    ids2 = json.loads((up / "local_ids.json").read_text())
    assert ids2["bar/address/c"] == 970005 and ids2["bar/address/b"] in (970003, 970004)


def test_compile_failed_memory_keeps_the_address_entries(tmp_path):
    up = tmp_path / "up"
    d = _meta(up, "foo", {"address": ["t1", "t2"], "memory": ["t1"]})
    (d / "onboard_result.json").write_text(json.dumps({
        "project": "foo", "status": "compiled",
        "sanitizers": {"address": {"status": "compiled", "harnesses": ["t1", "t2"]},
                       "memory": {"status": "compile_failed", "log": "x/compile.log"}}}))
    out = tmp_path / "m.json"
    ob.write_manifest(["foo"], out, upstream_dir=up)
    m = json.loads(out.read_text())
    assert [(e["sanitizer"], e["fuzz_target"]) for e in m] == [("address", "t1"), ("address", "t2")]


def _ready_project(up, work, *, harness_files=("address",)):
    d = _meta(up, "foo", {}, language="c++")
    meta = json.loads((d / "meta.json").read_text())
    meta["sanitizers"] = ["address", "memory"]
    (d / "meta.json").write_text(json.dumps(meta))
    (d / "ossfuzz").mkdir()
    (d / "Dockerfile").write_text("FROM a@sha256:1\n")
    (d / "pins.json").write_text(json.dumps({"ossfuzz_commit": "c", "bases": {},
                                             "checkouts": {"foo": "abc"}}))
    for s in harness_files:
        (work / "foo" / s).mkdir(parents=True)
        (work / "foo" / s / "harnesses.json").write_text(json.dumps(["t"]))
    return d


def _fake_docker(monkeypatch, up, *, compile_ok):
    calls = []
    monkeypatch.setattr(ob, "image_label", lambda tag: ui.definition_hash(up / "foo"))
    monkeypatch.setattr(ob, "image_has_dir", lambda tag, path: True)
    monkeypatch.setattr(ob, "restore_out_ownership", lambda tag, out: None)

    def run_logged(cmd, log, timeout):
        calls.append(cmd)
        san = next(a.split("=", 1)[1] for a in cmd if a.startswith("SANITIZER="))
        out = Path(next(a.split(":", 1)[0] for a in cmd if a.endswith(":/out")))
        Path(log).write_text("log\n")
        if compile_ok(san):
            _elf(out / "t", b"LLVMFuzzerTestOneInput")
            return 0
        return 1
    monkeypatch.setattr(ob, "run_logged", run_logged)
    return calls


def test_run_resumes_and_records_a_non_address_failure(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    d = _ready_project(up, work)
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: s != "memory")
    res = ob.run_project("foo", sanitizers="all", work=work, upstream_dir=up)
    # vendor, build, pins and the address compile were all done already
    assert len(calls) == 1 and "SANITIZER=memory" in calls[0]
    assert res["status"] == "compiled"
    assert res["sanitizers"]["address"]["status"] == "compiled"
    assert res["sanitizers"]["memory"]["status"] == "compile_failed"
    assert res["sanitizers"]["memory"]["log"] == str(work / "foo" / "memory" / "compile.log")
    assert json.loads((d / "onboard_result.json").read_text()) == res
    assert json.loads((work / "foo" / "onboard_result.json").read_text()) == res
    assert "memory" not in json.loads((d / "meta.json").read_text())["harnesses"]


def test_run_compiles_address_first_and_an_address_failure_fails_the_project(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    d = _ready_project(up, work, harness_files=())
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: s == "memory")
    res = ob.run_project("foo", sanitizers="all", work=work, upstream_dir=up)
    assert "SANITIZER=address" in calls[0]
    assert res["status"] == "compile_failed"
    assert res["sanitizers"]["address"]["status"] == "compile_failed"


def test_run_address_only_records_harnesses(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    d = _ready_project(up, work, harness_files=())
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: True)
    res = ob.run_project("foo", sanitizers="address", work=work, upstream_dir=up)
    assert len(calls) == 1
    assert res["status"] == "compiled" and set(res["sanitizers"]) == {"address"}
    assert json.loads((d / "meta.json").read_text())["harnesses"] == {"address": ["t"]}
    assert json.loads((work / "foo" / "address" / "harnesses.json").read_text()) == ["t"]
    assert res["sanitizers"]["address"]["srcdir_verified"] is True
    cmd = calls[0]
    assert cmd[:4] == ["docker", "run", "--rm", "--privileged"]
    assert "--ulimit" in cmd and "core=0" in cmd and "--network" in cmd
    assert cmd[-2:] == ["bench-upstream/foo", "compile"]
    assert not any(a.endswith(":/src/foo") for a in cmd)


def test_compile_stops_on_a_missing_srcdir(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    _ready_project(up, work, harness_files=())
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: True)
    monkeypatch.setattr(ob, "image_has_dir", lambda tag, path: False)
    res = ob.run_project("foo", sanitizers="address", work=work, upstream_dir=up)
    assert calls == [] and res["status"] == "srcdir_missing"


def test_run_rebuild_invalidates_downstream_outputs(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    d = _ready_project(up, work)
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: True)
    monkeypatch.setattr(ob, "image_label", lambda tag: "stale")
    built = []
    monkeypatch.setattr(ob, "build_image", lambda pdir, cpuset=None: (built.append(pdir), (True, "ok"))[1])
    monkeypatch.setattr(ob, "image_checkouts_output", lambda tag: "foo deadbeef\nbar \n")
    res = ob.run_project("foo", sanitizers="address", work=work, upstream_dir=up)
    assert built == [d] and len(calls) == 1
    assert json.loads((d / "pins.json").read_text())["checkouts"] == {"foo": "deadbeef", "bar": None}
    assert res["status"] == "compiled"


def test_build_refuses_a_matching_image_unless_rebuild(tmp_path, monkeypatch):
    up = tmp_path / "up"
    _ready_project(up, tmp_path / "work", harness_files=())
    monkeypatch.setattr(ob, "image_label", lambda tag: ui.definition_hash(up / "foo"))
    ok, why = ob.build("foo", upstream_dir=up)
    assert not ok and "up to date" in why
    monkeypatch.setattr(ob, "build_image", lambda pdir, cpuset=None: (True, "built"))
    assert ob.build("foo", upstream_dir=up, rebuild=True) == (True, "built")


def test_parse_checkouts():
    assert ob.parse_checkouts("a 0123\nb \n\nc fff\n") == {"a": "0123", "b": None, "c": "fff"}


def test_bases_never_overwrites_without_refresh(tmp_path, monkeypatch):
    f = tmp_path / "bases.json"
    f.write_text(json.dumps({"gcr.io/oss-fuzz-base/base-builder-go": "old@sha256:1"}))
    monkeypatch.setattr(ob, "resolve_base", lambda ref: f"{ref.split(':')[0]}@sha256:new")
    monkeypatch.setattr(ob, "read_pin", lambda name: "gcr.io/oss-fuzz-base/base-builder@sha256:pin")
    ob.write_bases(f)
    b = json.loads(f.read_text())
    assert b["gcr.io/oss-fuzz-base/base-builder-go"] == "old@sha256:1"
    assert b["gcr.io/oss-fuzz-base/base-builder"] == "gcr.io/oss-fuzz-base/base-builder@sha256:pin"
    assert b["gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04"] == "gcr.io/oss-fuzz-base/base-builder@sha256:new"
    assert set(b) == set(ob.BASE_REFS)
    ob.write_bases(f, refresh=True)
    assert json.loads(f.read_text())["gcr.io/oss-fuzz-base/base-builder-go"] == \
        "gcr.io/oss-fuzz-base/base-builder-go@sha256:new"


def test_report_renders_a_row_per_harness(tmp_path):
    up = tmp_path / "up"
    d = _meta(up, "foo", {"address": ["t1"]})
    meta = json.loads((d / "meta.json").read_text())
    meta["deviations"] = ["build.sh: dropped -Werror"]
    (d / "meta.json").write_text(json.dumps(meta))
    (d / "onboard_result.json").write_text(json.dumps({
        "project": "foo", "status": "compiled",
        "sanitizers": {"address": {"status": "compiled", "harnesses": ["t1"]},
                       "memory": {"status": "compile_failed", "log": "l"}}}))
    (up / "local_ids.json").write_text(json.dumps({"foo/address/t1": 970001}))
    pf = tmp_path / "pf" / "x"
    pf.mkdir(parents=True)
    (pf / "preflight_foo.json").write_text(json.dumps({
        "local_id": 970001, "ok": True, "stages": {"smoke": {"ok": True, "execs_per_sec": 1234.5}}}))
    intro = tmp_path / "intro_rows.json"
    intro.write_text(json.dumps([["foo", 3, 900, 41.5, 22.25, 12345]]))
    text = ob.render_report(["foo"], upstream_dir=up, preflight_dir=tmp_path / "pf",
                            intro_rows=intro)
    lines = [l for l in text.splitlines() if l.startswith("| foo")]
    assert len(lines) == 2
    assert "t1" in lines[0] and "970001" in lines[0] and "READY" in lines[0] and "1234" in lines[0]
    assert "22.25" in lines[0] and "12345" in lines[0] and "3" in lines[0]
    assert "memory" in lines[1] and "compile_failed" in lines[1]
    assert "dropped -Werror" in text


def test_a_second_run_does_not_rebuild(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    d = _ready_project(up, work, harness_files=())
    p = json.loads((d / "pins.json").read_text())
    p["checkouts"] = {}
    (d / "pins.json").write_text(json.dumps(p))
    _fake_docker(monkeypatch, up, compile_ok=lambda s: True)
    stamped = {"label": None}
    monkeypatch.setattr(ob, "image_label", lambda tag: stamped["label"])

    def build_image(pdir, cpuset=None):
        stamped["label"] = ui.definition_hash(pdir)   # what docker build stamps
        return True, "ok"
    monkeypatch.setattr(ob, "build_image", build_image)
    monkeypatch.setattr(ob, "image_checkouts_output", lambda tag: "foo abc\n")
    ob.run_project("foo", sanitizers="address", work=work, upstream_dir=up)
    # pins and compile wrote meta.json/pins.json after the build: still current
    assert stamped["label"] == ui.definition_hash(d)
    assert json.loads((d / "meta.json").read_text())["harnesses"] == {"address": ["t"]}
    built = []
    monkeypatch.setattr(ob, "build_image", lambda pdir, cpuset=None: built.append(pdir))
    res = ob.run_project("foo", sanitizers="address", work=work, upstream_dir=up)
    assert built == [] and res["status"] == "compiled"


def test_run_does_not_retry_a_recorded_non_address_failure(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    _ready_project(up, work)                       # address already compiled
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: s != "memory")
    res = ob.run_project("foo", sanitizers="all", work=work, upstream_dir=up)
    assert len(calls) == 1 and res["sanitizers"]["memory"]["status"] == "compile_failed"
    res = ob.run_project("foo", sanitizers="all", work=work, upstream_dir=up)
    assert len(calls) == 1 and res["sanitizers"]["memory"]["status"] == "compile_failed"
    assert res["status"] == "compiled"
    ob.run_project("foo", sanitizers="all", work=work, upstream_dir=up, retry_failed=True)
    assert len(calls) == 2 and "SANITIZER=memory" in calls[1]


def test_run_always_retries_a_failed_address(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    _ready_project(up, work, harness_files=())
    calls = _fake_docker(monkeypatch, up, compile_ok=lambda s: False)
    assert ob.run_project("foo", sanitizers="all", work=work,
                          upstream_dir=up)["status"] == "compile_failed"
    ob.run_project("foo", sanitizers="all", work=work, upstream_dir=up)
    assert len(calls) == 2 and all("SANITIZER=address" in c for c in calls)


def test_compile_timeout_is_passed_and_recorded(tmp_path, monkeypatch):
    up, work = tmp_path / "up", tmp_path / "work"
    _ready_project(up, work, harness_files=())
    _fake_docker(monkeypatch, up, compile_ok=lambda s: True)
    seen = []
    inner = ob.run_logged
    monkeypatch.setattr(ob, "run_logged",
                        lambda cmd, log, timeout: (seen.append(timeout), inner(cmd, log, timeout))[1])
    res = ob.run_project("foo", sanitizers="address", work=work, upstream_dir=up,
                         compile_timeout=123)
    assert seen == [123]
    assert res["compile_timeout"] == 123 and res["sanitizers"]["address"]["timeout"] == 123
    assert ob.COMPILE_TIMEOUT == 21600
