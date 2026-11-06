"""Pipeline routing for the upstream kind (manifest entries with "kind": "upstream").

An upstream entry has no PoC and its baseline is built at extract, like a
FuzzBench entry; its image comes from prework_image_for (bench-upstream/<p>).
Several entries share one project, so --local-id selects one harness.
"""
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

import config
import phase3_online
import phase3_runner
import run_benchmark
from lib import afl_launch, target_kind
from lib.afl_mutation_capture import build_capture_command

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import preflight_online  # noqa: E402


def _up(local_id=970001, fuzz_target="ssh_server_fuzzer"):
    return {"project": "libssh", "ossfuzz_project": "libssh", "kind": "upstream",
            "sanitizer": "address", "language": "c", "fuzz_target": fuzz_target,
            "image": "bench-upstream/libssh", "local_id": local_id,
            "cve": f"upstream-{local_id}"}


UP = _up()
UP2 = _up(970002, "ssh_client_fuzzer")
ARVO = {"project": "libxml2", "cve": "arvo-1", "local_id": 1, "fuzz_target": "xml"}
FB = {"project": "mruby", "cve": "fuzzbench-900025", "local_id": 900025,
      "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
      "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}


# --------------------------------------------------------------------------- #
# phase3_online
# --------------------------------------------------------------------------- #
def test_extract_takes_the_image_extract_path(monkeypatch, tmp_path):
    import phase2_setup
    seen = {}
    monkeypatch.setattr(phase3_online, "prework_image_for",
                        lambda e: "bench-upstream/" + e["ossfuzz_project"])
    monkeypatch.setattr(phase2_setup, "extract_source_from_image",
                        lambda img, dst: seen.setdefault("image", img) and True)
    monkeypatch.setattr(phase2_setup, "_find_project_source",
                        lambda root, p: Path(root) / p)
    monkeypatch.setattr(phase3_online.tracked_git, "strip_vcs_metadata",
                        lambda r: seen.setdefault("stripped", str(r)))
    monkeypatch.setattr(phase3_online, "_setup_build",
                        lambda **k: seen.setdefault("build", k) and (True, ""))
    monkeypatch.setattr(phase2_setup, "_lazy_import_arvo",
                        lambda: (_ for _ in ()).throw(AssertionError("ARVO path")))
    root = str(tmp_path / "src")
    got = phase3_online._extract_online_target(
        UP, root, str(tmp_path / "bin"), str(tmp_path / "poc"), UP["fuzz_target"],
        "libssh", cpu=3, setup_cpus="2-39")
    assert got == (False, None, None, root)
    assert seen["image"] == "bench-upstream/libssh"
    assert seen["stripped"] == root
    assert seen["build"]["entry"] is UP and seen["build"]["setup_cpus"] == "2-39"


def test_run_online_skips_poc_gate_and_afl_rebuild(monkeypatch, tmp_path, caplog):
    import phase2_setup
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "NUM_TRIALS", 2)
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", True)
    monkeypatch.setattr(config, "PHASE2_SANDBOX", False)
    monkeypatch.setattr(phase3_online.cpu_ledger, "set_ledger_path", lambda p: None)
    monkeypatch.setattr(phase3_online.cpu_ledger, "set_round", lambda **k: None)

    def extract(entry, src_root, bin_dir, *a, **k):
        Path(bin_dir).mkdir(parents=True, exist_ok=True)
        (Path(bin_dir) / entry["fuzz_target"]).write_bytes(b"x")
        return False, None, None, src_root

    monkeypatch.setattr(phase3_online, "_extract_online_target", extract)
    monkeypatch.setattr(phase2_setup, "_find_project_source", lambda r, p: Path(r))
    monkeypatch.setattr(phase3_online.tracked_git, "strip_vcs_metadata", lambda r: None)
    monkeypatch.setattr(phase3_online, "_stage_online_seed_corpus", lambda *a, **k: 0)
    monkeypatch.setattr(phase3_online, "_build_afl_baseline",
                        lambda **k: (_ for _ in ()).throw(AssertionError("rebuilt")))
    reached = []
    monkeypatch.setattr(phase3_online, "_preflight_profile",
                        lambda **k: reached.append(1) or (False, "stop here"))
    caplog.set_level(logging.INFO)
    assert phase3_online.run_online(UP, "exp", duration=60) is False
    assert reached == [1], "the PoC gate must not stop an upstream run"
    assert "did not reproduce" not in caplog.text
    assert "skipping PoC gate" in caplog.text


def _upstream_out(d, *, cmplog=True, aflpp_dict=True, lib=True):
    d.mkdir(parents=True, exist_ok=True)
    (d / "t").write_bytes(b"bin")
    if cmplog:
        (d / "cmplog").mkdir(exist_ok=True)
        (d / "cmplog" / "t").write_bytes(b"cmplog")
    if aflpp_dict:
        (d / "afl++.dict").write_text('"x"\n')
    if lib:
        (d / "lib").mkdir(exist_ok=True)
        (d / "lib" / "libfoo.so.1").write_bytes(b"so")
    return d


def test_swap_set_for_upstream(tmp_path):
    new = _upstream_out(tmp_path / "new")
    live = _upstream_out(tmp_path / "live", lib=False)
    assert phase3_online._swap_extra_files(UP, "t", new) == ("cmplog/t", "afl++.dict")
    bare = _upstream_out(tmp_path / "bare", cmplog=False, aflpp_dict=False, lib=False)
    assert phase3_online._swap_extra_files(UP, "t", bare) == ()
    assert phase3_online._swap_runtime_libs(UP, new, live) == ("lib/libfoo.so.1",)


def test_swap_set_unchanged_for_arvo_and_fuzzbench(tmp_path):
    new = _upstream_out(tmp_path / "new")
    assert phase3_online._swap_extra_files(ARVO, "t", new) == ()
    assert phase3_online._swap_runtime_libs(ARVO, new, new) == ()
    bare = _upstream_out(tmp_path / "bare", cmplog=False, aflpp_dict=False, lib=False)
    # FuzzBench always swaps its whole /out set (a missing one is removed live).
    assert phase3_online._swap_extra_files(FB, "t", bare) == ("cmplog/t", "afl++.dict")
    assert phase3_online._swap_extra_files(FB, "t") == ("cmplog/t", "afl++.dict")


# --------------------------------------------------------------------------- #
# phase3_runner
# --------------------------------------------------------------------------- #
def _trial(entry=UP):
    return phase3_runner.Trial(project=entry["project"], cve=entry["cve"],
                               local_id=entry["local_id"], entry=entry,
                               variant="baseline", trial_id=0, seed=1)


def test_resolve_trial_image_uses_the_upstream_image(monkeypatch):
    import prework.prework_build as pb
    monkeypatch.setattr(pb, "prework_image_for",
                        lambda e: "bench-upstream/" + e["ossfuzz_project"])
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: seen.append(cmd[-1])
                        or subprocess.CompletedProcess(cmd, 0))
    assert phase3_runner._resolve_trial_image(_trial()) == "bench-upstream/libssh"
    assert seen == ["bench-upstream/libssh"]


def test_resolve_trial_image_none_when_upstream_image_missing(monkeypatch):
    import prework.prework_build as pb
    monkeypatch.setattr(pb, "prework_image_for",
                        lambda e: "bench-upstream/" + e["ossfuzz_project"])
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1))
    assert phase3_runner._resolve_trial_image(_trial()) is None


def test_trial_env_record_records_the_upstream_launch():
    t = _trial()
    t._afl_launch = {"kind": "upstream", "argv": ["/out/afl-fuzz"],
                     "env": {"ASAN_OPTIONS": "a=1", "AFL_X": "1", "MSAN_OPTIONS": "m"},
                     "flags": {"sanitizer": "address"}}
    rec = phase3_runner._trial_env_record(t)
    assert rec["launch"] is t._afl_launch
    assert rec["ASAN_OPTIONS"] == "a=1" and rec["AFL_ENV"] == {"AFL_X": "1"}
    t._afl_launch = {"kind": "arvo", "env": {"ASAN_OPTIONS": "z"}}
    assert "launch" not in phase3_runner._trial_env_record(t)


def test_trial_toolchain_records_upstream_build(monkeypatch, tmp_path):
    import prework.upstream_image as ui
    monkeypatch.setattr(ui, "UPSTREAM_DIR", tmp_path)
    (tmp_path / "libssh").mkdir()
    (tmp_path / "libssh" / "pins.json").write_text(json.dumps({"libssh": "abc"}))
    monkeypatch.setattr(phase3_runner.provenance, "binary_fingerprint",
                        lambda img, b, t: {"compiler": "clang"})
    t = _trial()
    t._bin_dir, t._docker_image, t._fuzz_target_name = str(tmp_path), "i", "t"
    fp = phase3_runner._trial_toolchain(t)
    assert fp["upstream"] == {"sanitizer": "address", "ossfuzz_project": "libssh",
                              "pins": {"libssh": "abc"}}
    (tmp_path / "libssh" / "pins.json").unlink()
    assert phase3_runner._trial_toolchain(t)["upstream"]["pins"] is None


# --------------------------------------------------------------------------- #
# run_benchmark --local-id
# --------------------------------------------------------------------------- #
def test_select_entries_by_project_and_local_id():
    manifest = [UP, UP2, ARVO, dict(ARVO, project="other", local_id=970002)]
    assert run_benchmark._select_entries(manifest, "libssh", 970002) == [UP2]
    assert run_benchmark._select_entries(manifest, "libssh", None) == [UP, UP2]
    assert run_benchmark._select_entries(manifest, None, None) == manifest
    assert len(run_benchmark._select_entries(manifest, None, 970002)) == 2


def test_run_phase_trials_filters_on_local_id(monkeypatch, tmp_path):
    m = tmp_path / "manifest.json"
    m.write_text(json.dumps([UP, UP2, ARVO]))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(m))
    monkeypatch.setattr(config, "ONLINE_ENABLED", True, raising=False)
    monkeypatch.setattr(run_benchmark, "_phase3_backend", lambda: "local")
    monkeypatch.setattr(run_benchmark, "save_state", lambda *a, **k: None)
    ran = []
    monkeypatch.setattr(phase3_online, "run_online",
                        lambda entry, exp, duration=None: ran.append(entry["cve"]) or True)
    state = {"errors": [], "current_phase": None}
    run_benchmark.run_phase_trials("exp", state, duration=60, max_parallel=1,
                                   project="libssh", local_id=970002)
    assert ran == ["upstream-970002"]


def test_run_benchmark_parses_local_id():
    import inspect
    src = inspect.getsource(run_benchmark.main)
    assert '"--local-id", type=int' in src
    assert src.count("local_id=args.local_id") == 3


def test_launcher_script_passes_local_id():
    sh = (Path(run_benchmark.__file__).parent / "run_online_pertrial.sh").read_text()
    assert 'LOCAL_ID=${LOCAL_ID:-}' in sh
    assert '--local-id "$LOCAL_ID"' in sh
    assert '${EXP_PREFIX}-${PROJ}-${LOCAL_ID}-' in sh or "${PROJ}${LOCAL_ID:+-${LOCAL_ID}}" in sh
    assert '"upstream"' in sh


# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #
def test_preflight_entry_selects_by_local_id(monkeypatch, tmp_path):
    m = tmp_path / "manifest.json"
    m.write_text(json.dumps([UP, UP2, ARVO]))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(m))
    assert preflight_online._entry("libssh", 970002) == UP2
    assert preflight_online._entry("libssh") == UP
    assert preflight_online._entry("libxml2", None) == ARVO
    with pytest.raises(SystemExit):
        preflight_online._entry("libxml2", 970002)


def test_preflight_upstream_skips_poc_and_rebuild(monkeypatch, tmp_path):
    exp = tmp_path / "results" / "preflight-libssh" / "libssh-upstream-970002"
    (exp / "baseline" / "bin").mkdir(parents=True)
    (exp / "baseline" / "bin" / UP2["fuzz_target"]).write_bytes(b"x")
    monkeypatch.setattr(preflight_online, "_entry",
                        lambda p, i=None: UP2 if i == 970002 else UP)
    monkeypatch.setattr(preflight_online.phase2_setup, "get_experiment_dir",
                        lambda i, e: str(exp))
    monkeypatch.setattr(preflight_online, "prework_image_for",
                        lambda e: "bench-upstream/libssh")
    monkeypatch.setattr(preflight_online.subprocess, "run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    monkeypatch.setattr(preflight_online.phase3_online, "_extract_online_target",
                        lambda *a, **k: (False, None, None, str(tmp_path / "src")))
    monkeypatch.setattr(preflight_online.phase3_online, "_src_subtree_has_files",
                        lambda p: True)
    monkeypatch.setattr(preflight_online.phase3_online, "_stage_online_seed_corpus",
                        lambda *a, **k: 0)
    monkeypatch.setattr(preflight_online.phase2_setup, "_find_project_source",
                        lambda r, p: str(tmp_path / "src"))
    monkeypatch.setattr(preflight_online.tracked_git, "strip_vcs_metadata", lambda r: None)
    monkeypatch.setattr(preflight_online.phase3_online, "_build_afl_baseline",
                        lambda **k: (_ for _ in ()).throw(AssertionError("rebuilt")))
    monkeypatch.setattr(preflight_online.phase3_online, "_preflight_profile",
                        lambda **k: (False, "stop"))
    res = preflight_online.preflight("libssh", 3, 5, False, local_id=970002)
    assert res["stages"]["poc"]["ok"] is True and "upstream" in res["stages"]["poc"]["skipped"]
    assert res["stages"]["aflbuild"]["ok"] is True
    assert "upstream" in res["stages"]["aflbuild"]["skipped"]
    out = json.loads((exp.parent / "preflight_libssh.json").read_text())
    assert out["local_id"] == 970002 and out["kind"] == "upstream"
    assert out["sanitizer"] == "address" and out["fuzz_target"] == "ssh_client_fuzzer"
    assert out["cve"] == "upstream-970002"


# --------------------------------------------------------------------------- #
# bootstrap
# --------------------------------------------------------------------------- #
def _upstream_def(root, project="libssh"):
    d = root / project
    d.mkdir(parents=True)
    (d / "Dockerfile").write_text("FROM base-builder\n")
    (d / "meta.json").write_text(json.dumps({"project": project}))
    (d / "pins.json").write_text("{}")
    return d


@pytest.mark.parametrize("label,state", [("good", "OK"), ("bad", "STALE"),
                                         (None, "UNVERIFIED")])
def test_check_images_lists_upstream_with_upstream_label(monkeypatch, tmp_path, label, state):
    import bootstrap_server as bs
    from prework import upstream_image as ui
    targets, up = tmp_path / "targets", tmp_path / "upstream"
    targets.mkdir()
    d = _upstream_def(up)
    (up / "bases.json").write_text("{}")         # a file, not a project dir
    monkeypatch.setattr(bs, "TARGETS_DIR", targets)
    monkeypatch.setattr(bs, "UPSTREAM_TARGETS_DIR", up)
    monkeypatch.setattr(bs, "_image_exists", lambda img: img == "bench-upstream/libssh")
    asked = []

    def fake_run(cmd, **kw):
        asked.append(cmd)
        out = {"good": ui.definition_hash(d), "bad": "0" * 64, None: ""}[label]
        return subprocess.CompletedProcess(cmd, 0, stdout=out + "\n", stderr="")

    monkeypatch.setattr(bs, "_run", fake_run)
    rows = {r[0]: r for r in bs.check_images()}
    assert rows["bench-upstream/libssh"][1] == state
    assert any(ui.DEFINITION_LABEL in " ".join(c) for c in asked)
    if state == "STALE":
        assert "onboard with tools/onboard_upstream.py" in rows["bench-upstream/libssh"][2]


def test_check_images_missing_upstream_says_onboard(monkeypatch, tmp_path):
    import bootstrap_server as bs
    targets, up = tmp_path / "targets", tmp_path / "upstream"
    targets.mkdir()
    _upstream_def(up, "LibSSH")
    monkeypatch.setattr(bs, "TARGETS_DIR", targets)
    monkeypatch.setattr(bs, "UPSTREAM_TARGETS_DIR", up)
    monkeypatch.setattr(bs, "_image_exists", lambda img: False)
    rows = {r[0]: r for r in bs.check_images()}
    assert rows["bench-upstream/libssh"][1] == bs.MISSING
    assert "onboard with tools/onboard_upstream.py" in rows["bench-upstream/libssh"][2]


def test_check_images_without_upstream_dir(monkeypatch, tmp_path):
    import bootstrap_server as bs
    targets = tmp_path / "targets"
    targets.mkdir()
    monkeypatch.setattr(bs, "TARGETS_DIR", targets)
    monkeypatch.setattr(bs, "UPSTREAM_TARGETS_DIR", tmp_path / "absent")
    monkeypatch.setattr(bs, "_image_exists", lambda img: False)
    assert [r[0] for r in bs.check_images()] == [bs.AGENT_IMAGE, bs.PROXY_IMAGE]


def test_build_target_images_never_builds_upstream(monkeypatch, tmp_path):
    import bootstrap_server as bs
    targets, up = tmp_path / "targets", tmp_path / "upstream"
    targets.mkdir()
    _upstream_def(up)
    monkeypatch.setattr(bs, "TARGETS_DIR", targets)
    monkeypatch.setattr(bs, "UPSTREAM_TARGETS_DIR", up)
    monkeypatch.setattr(bs.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert bs.build_target_images(str(tmp_path / "w")) == []


def test_main_forwards_local_id_to_phases_3_and_4(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "ONLINE_ENABLED", False)
    monkeypatch.setenv("PHASE3_BACKEND", "local")
    seen = {}
    monkeypatch.setattr(run_benchmark, "run_phase_trials",
                        lambda *a, **k: seen.setdefault(3, (k["project"], k["local_id"])) and True)
    monkeypatch.setattr(run_benchmark, "run_phase_analysis",
                        lambda *a, **k: seen.setdefault(4, (k["project"], k["local_id"])) and True)
    monkeypatch.setattr(sys, "argv", ["run_benchmark.py", "--experiment-id", "exp",
                                      "--skip-setup", "--project", "libssh",
                                      "--local-id", "970002"])
    run_benchmark.main()
    assert seen == {3: ("libssh", 970002), 4: ("libssh", 970002)}
