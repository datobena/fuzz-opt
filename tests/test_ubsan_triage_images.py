"""Image resolution for analysis replays, and the FuzzBench binary fingerprint."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "analysis"))

from lib import provenance  # noqa: E402

FB_ENTRY = {"project": "mruby", "cve": "fuzzbench-900026", "local_id": 900026,
            "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
            "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd",
            "image": "fb-aflpp/mruby_mruby_fuzzer_8c8bbd:latest"}
ARVO_ENTRY = {"project": "yara", "cve": "arvo-3848", "local_id": 3848,
              "fuzz_target": "pe_fuzzer"}


def _fake_prework(monkeypatch, fn):
    import prework.prework_build as pb
    monkeypatch.setattr(pb, "prework_image_for", fn)


def _cve_dir(tmp_path, image=None, trial_image=None):
    d = tmp_path / "mruby-fuzzbench-900026"
    (d / "optimized" / "online").mkdir(parents=True)
    (d / "baseline" / "trial_00").mkdir(parents=True)
    if image:
        (d / "optimized" / "online" / "campaign_provenance.json").write_text(
            json.dumps({"baseline_toolchain": {"image": image}}))
    if trial_image:
        (d / "baseline" / "trial_00" / "metadata.json").write_text(
            json.dumps({"toolchain": {"image": trial_image}}))
    return d


# --------------------------------------------------------------------------- #
# recorded_image / experiment_image
# --------------------------------------------------------------------------- #
def test_recorded_image_prefers_campaign_provenance(tmp_path):
    d = _cve_dir(tmp_path, image="bench-aflpp/mruby-arvo-900026",
                 trial_image="something/else")
    assert provenance.recorded_image(d) == "bench-aflpp/mruby-arvo-900026"


def test_recorded_image_falls_back_to_trial_metadata(tmp_path):
    d = _cve_dir(tmp_path, trial_image="bench-aflpp/mruby-arvo-900026")
    assert provenance.recorded_image(d) == "bench-aflpp/mruby-arvo-900026"
    assert provenance.recorded_image(tmp_path / "missing") is None
    assert provenance.recorded_image(None) is None


def test_finished_experiment_keeps_the_image_it_ran_with(tmp_path, monkeypatch):
    d = _cve_dir(tmp_path, image="bench-aflpp/mruby-arvo-900026")
    _fake_prework(monkeypatch, lambda e: "fb-aflpp/mruby_mruby_fuzzer_8c8bbd")
    monkeypatch.setattr(provenance, "_image_present", lambda i: True)
    assert provenance.experiment_image(d, FB_ENTRY) == "bench-aflpp/mruby-arvo-900026"


def test_new_experiment_uses_prework_image_for(tmp_path, monkeypatch):
    _fake_prework(monkeypatch, lambda e: "fb-aflpp/mruby_mruby_fuzzer_8c8bbd")
    monkeypatch.setattr(provenance, "_image_present", lambda i: True)
    assert provenance.experiment_image(_cve_dir(tmp_path), FB_ENTRY) == \
        "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"


def test_falls_back_to_legacy_tag_when_prework_image_for_fails(monkeypatch):
    def boom(e):
        raise ValueError("no fuzzbench_dir")
    _fake_prework(monkeypatch, boom)
    monkeypatch.setattr(provenance, "_image_present", lambda i: True)
    assert provenance.experiment_image(None, ARVO_ENTRY) == "bench-aflpp/yara-arvo-3848"


def test_check_local_skips_absent_images(monkeypatch):
    _fake_prework(monkeypatch, lambda e: "fb-aflpp/mruby_mruby_fuzzer_8c8bbd")
    present = {"bench-aflpp/mruby-arvo-900026"}
    monkeypatch.setattr(provenance, "_image_present", lambda i: i in present)
    assert provenance.experiment_image(None, FB_ENTRY) == "bench-aflpp/mruby-arvo-900026"
    # nothing present: first candidate, unverified
    present.clear()
    assert provenance.experiment_image(None, FB_ENTRY) == "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
    assert provenance.experiment_image(None, None) is None


# --------------------------------------------------------------------------- #
# analysis scripts use it
# --------------------------------------------------------------------------- #
def test_bug_discovery_curve_uses_experiment_image(tmp_path, monkeypatch):
    import bug_discovery_curve as B
    import config
    exp = tmp_path / "exp1"
    d = _cve_dir(exp, image="bench-aflpp/mruby-arvo-900026")
    (d / "baseline" / "bin").mkdir()
    man = tmp_path / "m.json"
    man.write_text(json.dumps([FB_ENTRY]))
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(man))
    monkeypatch.setattr(provenance, "_image_present", lambda i: True)
    seen = []

    def fake_trial_bugs(t):
        seen.append(t[3].image)
        return t[0], t[1], {}
    monkeypatch.setattr(B, "trial_bugs", fake_trial_bugs)
    monkeypatch.setattr(sys, "argv", ["x", "--experiment", "exp1", "--project", "mruby"])
    assert B.main() == 0
    assert seen == ["bench-aflpp/mruby-arvo-900026"]


def test_retriage_experiment_uses_experiment_image(tmp_path, monkeypatch):
    import config
    import retriage_experiment as R
    exp = tmp_path / "exp1"
    d = _cve_dir(exp, image="bench-aflpp/mruby-arvo-900026")
    (d / "baseline" / "trial_00" / "metadata.json").write_text(json.dumps(
        {"crash_times": [{"artifact": "id:000000", "timestamp_s": 5.0,
                          "crash_type": "crash"}]}))
    man = tmp_path / "m.json"
    man.write_text(json.dumps([FB_ENTRY]))
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(man))
    monkeypatch.setattr(provenance, "_image_present", lambda i: True)
    seen = []

    def fake_triage(crashes_dir, **kw):
        seen.append(kw["image"])
        return []
    monkeypatch.setattr(R.afl_triage, "triage_trial", fake_triage)
    monkeypatch.setattr(sys, "argv", ["x", "--experiment", "exp1", "--project", "mruby",
                                      "--reproduce"])
    assert R.main() == 0
    assert seen == ["bench-aflpp/mruby-arvo-900026"]


def test_line_exec_counts_prefers_recorded_image(tmp_path, monkeypatch):
    import line_exec_counts as L
    d = _cve_dir(tmp_path, image="bench-aflpp/mruby-arvo-900026")
    info = {"cve": d.name, "root": d,
            "provenance": {"baseline_toolchain": {"image": "bench-aflpp/mruby-arvo-900026"}}}
    monkeypatch.setattr(L, "_image_present", lambda i: True)
    assert L.resolve_image(d.name, "", info) == "bench-aflpp/mruby-arvo-900026"
    assert L.resolve_image(d.name, "override/img", info) == "override/img"


def test_line_exec_counts_new_experiment_resolves_fb_image(tmp_path, monkeypatch):
    import line_exec_counts as L
    _fake_prework(monkeypatch, lambda e: "fb-aflpp/mruby_mruby_fuzzer_8c8bbd")
    monkeypatch.setattr(L, "_manifest_entry", lambda n: FB_ENTRY)
    monkeypatch.setattr(L, "_image_present", lambda i: i.startswith("fb-aflpp/"))
    monkeypatch.setattr(provenance, "_image_present", lambda i: i.startswith("fb-aflpp/"))
    info = {"cve": "mruby-fuzzbench-900026", "root": _cve_dir(tmp_path)}
    assert L.resolve_image(info["cve"], "", info) == "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"


# --------------------------------------------------------------------------- #
# binary_fingerprint
# --------------------------------------------------------------------------- #
ARVO_KEYS = {"image", "image_id", "compilers", "cxx_runtime_dynamic",
             "cxx_runtime_dynamically_linked", "binary_sha256",
             "asan_symbols_in_binary", "cflags", "cxxflags"}


def _fake_docker(monkeypatch, run_output, labels=None, layers=None):
    layers = layers or {}

    def fake(cmd, timeout=60):
        if cmd[:3] == ["docker", "image", "inspect"]:
            fmt, img = cmd[4], cmd[5]
            if fmt == "{{.Id}}":
                return "sha256:" + "a" * 64 + "\n", 0
            if "Labels" in fmt:
                return json.dumps(labels or {}), 0
            if "Layers" in fmt:
                return (json.dumps(layers[img]), 0) if img in layers else ("Error", 1)
        return run_output, 0
    monkeypatch.setattr(provenance, "_run", fake)


ARVO_OUT = """__COMMENT__
String dump of section '.comment':
  [     0]  Ubuntu clang version 18.1.8
__LDD__
\tlibc++.so.1 => /usr/local/lib/libc++.so.1 (0x1)
\tlibc++abi.so.1 => /usr/local/lib/libc++abi.so.1 (0x2)
__SHA__
abc123  /out/t
__ASANSYM__
320
__CXXFLAGS__
-O1 -stdlib=libc++
__CFLAGS__
-O1 -fno-omit-frame-pointer
__FBENV__
FUZZER=
BENCHMARK=
__NEEDED__
 0x0000000000000001 (NEEDED)             Shared library: [libc++.so.1]
__OUTFILES__
cmplog=no
dict=no
__AFLHEAD__
__BENCHYAML__
"""


def test_fingerprint_arvo_output_unchanged(monkeypatch):
    _fake_docker(monkeypatch, ARVO_OUT)
    rec = provenance.binary_fingerprint("bench-aflpp/yara-arvo-3848", "/tmp", "t")
    assert set(rec) == ARVO_KEYS
    assert rec["cflags"] == "-O1 -fno-omit-frame-pointer"
    assert rec["cxxflags"] == "-O1 -stdlib=libc++"
    assert rec["cxx_runtime_dynamic"] == ["libc++.so.1", "libc++abi.so.1"]
    assert rec["cxx_runtime_dynamically_linked"] is True
    assert rec["binary_sha256"] == "abc123"


FB_OUT = """__COMMENT__
  [     0]  clang version 15.0.0 (https://github.com/llvm/llvm-project.git bf7f8d6f)
__LDD__
\tlinux-vdso.so.1 (0x1)
\tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x2)
__SHA__
def456  /out/mruby_fuzzer
__ASANSYM__
900
__CXXFLAGS__
-O1 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++
__CFLAGS__
-O1 -fno-omit-frame-pointer -gline-tables-only
__FBENV__
FUZZER=aflplusplus
BENCHMARK=mruby_mruby_fuzzer_8c8bbd
__NEEDED__
 0x0000000000000001 (NEEDED)             Shared library: [libm.so.6]
__OUTFILES__
cmplog=yes
dict=yes
__AFLHEAD__
56d5aa3101945e81519a3fac8783d0d8fad82779
__BENCHYAML__
commit: 8c8bbd94dce3b3eabcf72c674e690516c075b0ee
fuzz_target: mruby_fuzzer
project: mruby
type: bug
"""


def test_fingerprint_fuzzbench_bug_records_real_build(monkeypatch):
    base = provenance.FB_BASE_BUILDER
    _fake_docker(monkeypatch, FB_OUT,
                 labels={"fb-aflpp.benchmark": "mruby_mruby_fuzzer_8c8bbd",
                         "fb-aflpp.base-builder": base,
                         "fb-aflpp.fuzzbench-commit": "3234e151"},
                 layers={base: ["sha256:l1", "sha256:l2"],
                         "fb-aflpp/mruby_mruby_fuzzer_8c8bbd": ["sha256:l1", "sha256:l2", "sha256:l3"]})
    rec = provenance.binary_fingerprint("fb-aflpp/mruby_mruby_fuzzer_8c8bbd", "/tmp",
                                        "mruby_fuzzer", entry=FB_ENTRY)
    assert ARVO_KEYS <= set(rec)
    assert "-fno-sanitize-recover=array-bounds" in rec["cflags"]
    assert rec["cflags"].endswith("-O1") and "-stdlib=libc++" in rec["cxxflags"]
    # the image ENV is kept, but labelled as such
    assert rec["image_env_cflags"] == "-O1 -fno-omit-frame-pointer -gline-tables-only"
    assert rec["cxx_runtime_dynamically_linked"] is False   # measured: no libc++ in ldd/NEEDED
    fb = rec["fuzzbench"]
    assert fb["benchmark"] == "mruby_mruby_fuzzer_8c8bbd"
    assert fb["benchmark_type"] == "bug"
    assert fb["instrumentation_mode"] == "LLVMNATIVE"
    assert fb["optimization_level"] == "-O1"
    assert fb["cmplog_binary_present"] is True and fb["aflpp_dict_present"] is True
    assert fb["aflpp_commit"].startswith("56d5aa31") and fb["aflpp_commit_matches"] is True
    assert fb["base_builder"] == base and fb["base_builder_layers_verified"] is True
    assert fb["fuzzbench_commit"] == "3234e151"


def test_fingerprint_fuzzbench_coverage_and_dynamic_libcxx(monkeypatch):
    out = (FB_OUT.replace("type: bug\n", "")
           .replace("56d5aa3101945e81519a3fac8783d0d8fad82779\n", "")   # no /afl checkout
           .replace("[libm.so.6]", "[libc++.so.1]")
           .replace("cmplog=yes", "cmplog=no"))
    _fake_docker(monkeypatch, out)
    rec = provenance.binary_fingerprint("fb-aflpp/bloaty_fuzz_target", "/tmp", "t")
    fb = rec["fuzzbench"]
    assert fb["benchmark_type"] == "coverage"            # FuzzBench: absent type = coverage
    assert fb["instrumentation_mode"] == "PCGUARD"
    assert "-fsanitize" not in rec["cflags"] and rec["cflags"].endswith("-O3")
    assert rec["cxx_runtime_needed"] == ["libc++.so.1"]
    assert rec["cxx_runtime_dynamically_linked"] is True  # from readelf NEEDED
    assert fb["cmplog_binary_present"] is False
    assert fb["base_builder_layers_verified"] is None     # base not inspectable
    # an empty probe must not swallow the next section
    assert fb["aflpp_commit"] is None and fb["aflpp_commit_matches"] is None


def test_build_flags_constant_fallback_matches_vendored(tmp_path):
    vendored = provenance.fuzzbench_build_flags("bug")
    fallback = provenance.fuzzbench_build_flags("bug", utils_path=tmp_path / "missing.py")
    assert fallback["source"].startswith("constant mapping")
    for k in ("cflags", "cxxflags", "optimization_level", "instrumentation_mode"):
        assert vendored[k] == fallback[k], k
    assert provenance.fuzzbench_build_flags("coverage", utils_path=tmp_path / "x")["cflags"] == \
        provenance.fuzzbench_build_flags("coverage")["cflags"]


@pytest.mark.parametrize("image,env,expected", [
    ("fb-aflpp/x", {}, True),
    ("bench-aflpp/mruby-arvo-900026", {}, False),
    ("some/img", {"FUZZER": "aflplusplus", "BENCHMARK": "b"}, True),
    ("some/img", {"FUZZER": "aflplusplus", "BENCHMARK": ""}, False),
])
def test_is_fuzzbench_build(image, env, expected):
    assert provenance._is_fuzzbench_build(image, env) is expected
