"""Tests for tools/triage_upstream_crashes.py: the pure parts of turning a
campaign's crashes into a 0-day report. Docker never runs: the pristine replay
is the injected ``replay`` callable, and the module's docker runner is replaced
by one that refuses."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import triage_upstream_crashes as tu  # noqa: E402


@pytest.fixture(autouse=True)
def _no_docker(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError(f"docker called: {a}")
    monkeypatch.setattr(tu, "_run_docker", refuse)


def asan(kind, frames, addr="0x60200000001d", pc="0x4d862a"):
    """A canned ASan report: interceptor frame on top, then ``frames``, then
    an allocation stack whose frames must never enter the key."""
    lines = ["=================================================================",
             f"==19==ERROR: AddressSanitizer: {kind} on address {addr} at pc {pc} bp 0x7ffc sp 0x7ffc",
             "READ of size 1 at {addr} thread T0".format(addr=addr),
             f"    #0 {pc} in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3"]
    for i, f in enumerate(frames, 1):
        lines.append(f"    #{i} 0x{0x4d8000 + 16 * i + int(addr, 16) % 7:x} in {f} /src/p/x.c:{10 + i}:3")
    lines += ["", f"{addr} is located 9 bytes to the right of 4-byte region",
              "allocated by thread T0 here:",
              "    #0 0x49d746 in __interceptor_malloc /src/llvm-project/asan_malloc_linux.cpp:69:3",
              "    #1 0x4d8543 in alloc_site_only /src/p/y.c:12:15",
              "", f"SUMMARY: AddressSanitizer: {kind} /src/p/x.c:11:3 in {frames[0]}"]
    return "\n".join(lines) + "\n"


FR = ["parse_header", "read_chunk", "decode_image", "LLVMFuzzerTestOneInput"]


# --------------------------------------------------------------------------- #
# dedupe_key
# --------------------------------------------------------------------------- #
def test_same_frames_different_addresses_are_one_key():
    a = asan("heap-buffer-overflow", FR, addr="0x60200000001d", pc="0x4d862a")
    b = asan("heap-buffer-overflow", FR, addr="0x6030000000f4", pc="0x55aa10")
    assert a != b
    assert tu.dedupe_key(a) == tu.dedupe_key(b) == (
        "heap-buffer-overflow", ("parse_header", "read_chunk", "decode_image"))


def test_a_different_third_frame_is_a_second_key():
    a = asan("heap-buffer-overflow", FR)
    c = asan("heap-buffer-overflow", ["parse_header", "read_chunk", "decode_text", "LLVMFuzzerTestOneInput"])
    assert tu.dedupe_key(a) != tu.dedupe_key(c)


def test_runtime_and_fold_frames_never_enter_the_key():
    k = tu.dedupe_key(asan("heap-use-after-free", ["fold_fast_path", "parse_header", "read_chunk", "decode_image"]))
    assert k == ("heap-use-after-free", ("parse_header", "read_chunk", "decode_image"))


def test_frames_come_from_the_crash_stack_only():
    k = tu.dedupe_key(asan("heap-buffer-overflow", ["only_frame"]))
    assert k == ("heap-buffer-overflow", ("only_frame",))


def test_kind_aliases_match_the_dedup_pipeline():
    assert tu.dedupe_key(asan("use-after-poison", FR))[0] == "heap-use-after-free"


def test_no_parsable_report_is_unclassified():
    assert tu.dedupe_key("") == ("unclassified", ())
    assert tu.dedupe_key(None) == ("unclassified", ())
    assert tu.dedupe_key("Segmentation fault (core dumped)\n") == ("unclassified", ())


def test_assert_abort_keys_on_the_frames_below_libc():
    blob = Path(__file__).parent.joinpath("fixtures/sanitizer/assert_handle_abort.txt").read_text()
    assert tu.dedupe_key(blob) == ("ABRT", ("main",))


def test_ubsan_without_a_stack_keys_on_its_location():
    blob = ("/src/p/x.c:7:12: runtime error: signed integer overflow: 2147483647 + 1 "
            "cannot be represented in type 'int'\n"
            "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/p/x.c:7:12\n")
    kind, frames = tu.dedupe_key(blob)
    assert kind.startswith("ubsan:") and frames == ("/src/p/x.c:7",)


def test_msan_warning_is_classified():
    blob = ("==7==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
            "    #0 0x4d8 in parse_header /src/p/x.c:3:1\n"
            "    #1 0x4d9 in LLVMFuzzerTestOneInput /src/p/f.c:9:2\n\n"
            "SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/p/x.c:3:1 in parse_header\n")
    assert tu.dedupe_key(blob) == ("use-of-uninitialized-value", ("parse_header", "LLVMFuzzerTestOneInput"))


# --------------------------------------------------------------------------- #
# classify_run / combine_runs
# --------------------------------------------------------------------------- #
def test_classify_run_statuses():
    rep = asan("heap-buffer-overflow", FR)
    assert tu.classify_run(rep, 1)["status"] == "crash"
    assert tu.classify_run("", 0)["status"] == "clean"
    assert tu.classify_run(rep, 0)["status"] == "clean"          # exited 0: not a crash
    assert tu.classify_run("loader: libfoo.so: not found", 127)["status"] == "infra"
    assert tu.classify_run("", 126)["status"] == "infra"
    assert tu.classify_run("", 124)["status"] == "infra"
    assert tu.classify_run("", None)["status"] == "infra"
    assert tu.classify_run("Segmentation fault", 139)["status"] == "unparsed"


def test_combine_runs_needs_every_try_clean_for_clean():
    crash = {"status": "crash", "report": asan("SEGV", FR)}
    clean, infra = {"status": "clean"}, {"status": "infra", "error": "exit 127"}
    assert tu.combine_runs([clean, crash])["verdict"] == "reproduces"
    assert tu.combine_runs([clean, clean, clean]) == {"tries": 3, "hits": 0, "verdict": "clean"}
    v = tu.combine_runs([clean, infra, clean])
    assert v["verdict"] == "unverified" and v["reason"] == "infra"
    v = tu.combine_runs([clean, {"status": "unparsed", "error": "exit 139 ..."}])
    assert v["verdict"] == "unverified" and v["reason"] == "unclassified"


# --------------------------------------------------------------------------- #
# summarize
# --------------------------------------------------------------------------- #
A = asan("heap-buffer-overflow", FR)
A2 = asan("heap-buffer-overflow", FR, addr="0x6030000000f4")
B = asan("heap-buffer-overflow", ["parse_header", "read_chunk", "decode_text"])
C = asan("SEGV", ["fold_x", "walk_tree", "visit"])


def rec(arm, trial, t, path, it=None):
    return {"arm": arm, "trial": trial, "time_s": t, "path": path, "iter": it}


def crash(report):
    return {"status": "crash", "report": report}


CLEAN = {"status": "clean"}
CLEAN3 = [CLEAN, CLEAN, CLEAN]

RECORDS = [
    rec("baseline", "trial_00", 300.0, "/r/base/t0/a1"),
    rec("optimized", "trial_01", 120.0, "/r/opt/t1/a1", "iter_02"),
    rec("optimized", "trial_02", 500.0, "/r/opt/t2/a1", "iter_01"),
    rec("optimized", "trial_01", 900.0, "/r/opt/t1/b1", "iter_03"),   # only optimized, reproduces
    rec("optimized", "trial_00", 50.0, "/r/opt/t0/c1", "iter_01"),    # induced (control crashes)
    rec("optimized", "trial_02", 70.0, "/r/opt/t2/d1", "iter_01"),    # pristine infra
    rec("baseline", "trial_01", 10.0, "/r/base/t1/u1"),               # nonzero, no report
    rec("baseline", "trial_02", 20.0, "/r/base/t2/n1"),               # baseline, clean: never induced
    rec("optimized", "trial_03", 30.0, "/r/opt/t3/n2", "iter_01"),    # clean on both binaries
]

PRISTINE = {
    "/r/base/t0/a1": [crash(A)],
    "/r/opt/t1/a1": [CLEAN, crash(A2)],
    "/r/opt/t2/a1": [crash(A)],
    "/r/opt/t1/b1": [crash(B)],
    "/r/opt/t0/c1": CLEAN3,
    "/r/base/t1/u1": [{"status": "unparsed", "error": "exit 139 without a parsable sanitizer report"}] * 3,
    "/r/base/t2/n1": CLEAN3,
    "/r/opt/t3/n2": CLEAN3,
}
CONTROL = {"/r/opt/t0/c1": [crash(C)], "/r/opt/t3/n2": CLEAN3}


def fake_replay(path):
    if path == "/r/opt/t2/d1":
        raise RuntimeError("docker: exit 125")
    return PRISTINE[path]


def fake_control(r):
    return CONTROL[r["path"]]


def by_sig(items):
    return {d["signature"]: d for d in items}


def run():
    return tu.summarize(RECORDS, replay=fake_replay, control=fake_control)


def test_summarize_splits_every_outcome():
    r = run()
    assert set(by_sig(r["distinct"])) == {
        "heap-buffer-overflow:parse_header<-read_chunk<-decode_image",
        "heap-buffer-overflow:parse_header<-read_chunk<-decode_text"}
    assert [x["signature"] for x in r["optimizer_induced"]] == ["SEGV:walk_tree<-visit"]
    assert r["optimizer_induced"][0]["reproduces_on_pristine"] is False
    assert {u["path"]: u["reason"] for u in r["unverified"]} == {
        "/r/opt/t2/d1": "infra", "/r/base/t1/u1": "unclassified"}
    assert "exit 125" in by_path(r["unverified"])["/r/opt/t2/d1"]["error"]
    assert [x["path"] for x in r["unclassified"]] == ["/r/base/t1/u1"]
    assert sorted(x["path"] for x in r["non_reproducing"]) == ["/r/base/t2/n1", "/r/opt/t3/n2"]


def by_path(items):
    return {d["path"]: d for d in items}


def test_summarize_reports_first_seen_trials_tries_and_earliest_path_per_key():
    a = by_sig(run()["distinct"])["heap-buffer-overflow:parse_header<-read_chunk<-decode_image"]
    assert a["kind"] == "heap-buffer-overflow"
    assert a["key"] == ["heap-buffer-overflow", ["parse_header", "read_chunk", "decode_image"]]
    assert a["first_seen_s"] == {"baseline": 300.0, "optimized": 120.0}
    assert a["trials"] == {"baseline": ["trial_00"], "optimized": ["trial_01", "trial_02"]}
    assert a["earliest_path"] == "/r/opt/t1/a1" and a["earliest_iter"] == "iter_02"
    assert a["reproduces_on_pristine"] is True
    assert (a["pristine_tries"], a["pristine_hits"]) == (4, 3)
    assert a["stack"][:4] == ["__asan_memcpy", "parse_header", "read_chunk", "decode_image"]
    assert len(a["stack"]) <= 10


def test_summarize_counts_per_arm_exclude_everything_not_distinct():
    c = run()["counts"]
    assert c["distinct"] == 2
    assert c["per_arm"]["baseline"] == {"distinct": 1, "artifacts": 1, "unverified": 1}
    assert c["per_arm"]["optimized"] == {"distinct": 2, "artifacts": 3, "unverified": 1}
    assert (c["optimizer_induced"], c["non_reproducing"], c["unverified"], c["unclassified"]) == (1, 2, 2, 1)


def test_only_optimized_found_is_reproducing_keys_the_baseline_never_found():
    assert [x["signature"] for x in run()["only_optimized_found"]] == [
        "heap-buffer-overflow:parse_header<-read_chunk<-decode_text"]


def test_every_artifact_is_replayed_on_pristine_and_control_only_when_clean():
    seen, ctl = [], []

    def replay(path):
        seen.append(path)
        return fake_replay(path)

    def control(r):
        ctl.append(r["path"])
        return fake_control(r)
    tu.summarize(RECORDS, replay=replay, control=control)
    assert sorted(seen) == sorted(r["path"] for r in RECORDS)
    assert sorted(ctl) == ["/r/opt/t0/c1", "/r/opt/t3/n2"]      # never a baseline artifact


def test_probe_A_inlining_on_the_folded_binary_cannot_make_a_headline():
    # Baseline stack [f1,f2,f3,f4]; on the folded binary the same bug reads
    # [fold_fast,f1,f3,f4] (f2 inlined). Identity is the pristine replay, so the
    # optimized artifact keys with the baseline's crash.
    base = asan("heap-buffer-overflow", ["f1", "f2", "f3", "f4"])
    recs = [rec("baseline", "trial_00", 10.0, "/b"), rec("optimized", "trial_00", 5.0, "/o", "iter_01")]
    r = tu.summarize(recs, replay=lambda p: [crash(base)],
                     control=lambda x: [crash(asan("heap-buffer-overflow", ["fold_fast", "f1", "f3", "f4"]))])
    assert r["counts"]["distinct"] == 1 and r["counts"]["only_optimized_found"] == 0
    assert r["distinct"][0]["trials"] == {"baseline": ["trial_00"], "optimized": ["trial_00"]}


def test_probe_B_missing_library_on_pristine_is_unverified():
    r = tu.summarize([rec("optimized", "trial_00", 1.0, "/o")],
                     replay=lambda p: [tu.classify_run("error while loading shared libraries", 127)] * 3,
                     control=lambda x: [crash(A)])
    assert r["counts"]["unverified"] == 1 and r["optimizer_induced"] == [] and r["distinct"] == []


def test_probe_C_nonzero_exit_without_report_is_unverified():
    r = tu.summarize([rec("optimized", "trial_00", 1.0, "/o")],
                     replay=lambda p: [tu.classify_run("Killed", 137)] * 3,
                     control=lambda x: [crash(A)])
    assert r["counts"]["unverified"] == 1 and r["counts"]["unclassified"] == 1
    assert r["optimizer_induced"] == []


def test_probe_D_induced_needs_a_control_crash_and_a_key_unseen_on_pristine():
    recs = [rec("baseline", "trial_00", 1.0, "/b"),
            rec("optimized", "trial_00", 2.0, "/o1", "iter_01"),     # control crashes with A's key
            rec("optimized", "trial_01", 3.0, "/o2", "iter_01"),     # control crashes, new key
            rec("optimized", "trial_02", 4.0, "/o3", "iter_01"),     # control clean
            rec("optimized", "trial_03", 5.0, "/o4", "iter_01")]     # control infra
    pristine = {"/b": [crash(A)], "/o1": CLEAN3, "/o2": CLEAN3, "/o3": CLEAN3, "/o4": CLEAN3}
    ctl = {"/o1": [crash(A2)], "/o2": [crash(C)], "/o3": CLEAN3,
           "/o4": [{"status": "infra", "error": "docker exit 125"}]}
    r = tu.summarize(recs, replay=lambda p: pristine[p], control=lambda x: ctl[x["path"]])
    assert [d["signature"] for d in r["optimizer_induced"]] == ["SEGV:walk_tree<-visit"]
    assert sorted(x["path"] for x in r["non_reproducing"]) == ["/o1", "/o3"]
    assert [x["path"] for x in r["unverified"]] == ["/o4"]
    assert by_path(r["unverified"])["/o4"]["stage"] == "control"
    assert r["counts"]["distinct"] == 1


def test_a_baseline_artifact_is_never_optimizer_induced():
    r = tu.summarize([rec("baseline", "trial_00", 1.0, "/b")], replay=lambda p: CLEAN3,
                     control=lambda x: (_ for _ in ()).throw(AssertionError("control on baseline")))
    assert r["optimizer_induced"] == [] and [x["path"] for x in r["non_reproducing"]] == ["/b"]


def test_found_key_is_kept_as_provenance():
    arts = by_path(run()["artifacts"])
    assert arts["/r/opt/t0/c1"]["found_key"] == ["SEGV", ["walk_tree", "visit"]]
    assert arts["/r/opt/t0/c1"]["verdict"] == "optimizer_induced"
    assert arts["/r/opt/t1/a1"]["pristine_key"][0] == "heap-buffer-overflow"
    assert arts["/r/opt/t1/a1"]["iter"] == "iter_02"


def test_summarize_output_is_json_serializable():
    json.dumps(run())


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def test_markdown_lists_reproducer_paths_and_the_only_optimized_section():
    r = run()
    r.update({"experiment": "E1", "entry": {"project": "libssh", "cve": "upstream-970001",
                                             "fuzz_target": "ssh_fuzzer"},
              "pins": {"ossfuzz_commit": "f3af0cb37", "checkouts": {"libssh": "abc123"}}})
    md = tu.render_markdown(r)
    assert "E1" in md and "libssh-upstream-970001" in md
    assert "f3af0cb37" in md and "abc123" in md
    assert "/r/opt/t1/a1" in md and "/r/opt/t1/b1" in md
    assert "## Only found by the optimized arm" in md
    only = md.split("## Only found by the optimized arm", 1)[1].split("\n## ", 1)[0]
    assert "decode_text" in only and "decode_image" not in only
    assert "time:" in md and "hot-swap downtime" in md
    for section in ("## Optimizer-induced", "## Non-reproducing", "## Unverified", "## Unclassified"):
        assert section in md
    for p in ("/r/opt/t0/c1", "/r/opt/t2/d1", "/r/base/t1/u1", "/r/base/t2/n1"):
        assert p in md


def test_markdown_without_pins_says_so():
    r = tu.summarize([], replay=lambda p: CLEAN3)
    r.update({"experiment": "E1", "entry": {"project": "p", "cve": "c"}, "pins": None})
    assert "not recorded" in tu.render_markdown(r)


# --------------------------------------------------------------------------- #
# campaign layout helpers (no docker)
# --------------------------------------------------------------------------- #
def _artifact(d, name):
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(b"x")


def test_campaign_artifacts_reads_both_arms_and_archived_crash_dirs(tmp_path):
    cve = tmp_path / "libssh-upstream-970001"
    _artifact(cve / "baseline/trial_00/afl_out/default/crashes", "id:000000,sig:06,src:000001,time:4500,execs:9")
    _artifact(cve / "optimized/trial_01/afl_out/default/crashes.2026-11-05-01:00:00",
              "id:000000,sig:11,src:000002,time:120000,execs:9")
    (cve / "optimized/trial_01/afl_out/default/crashes").mkdir(parents=True)
    (cve / "optimized/trial_01/afl_out/default/crashes/README.txt").write_text("x")
    arts = tu.campaign_artifacts(cve)
    assert [(a["arm"], a["trial"], a["time_s"]) for a in arts] == [
        ("baseline", "trial_00", 4.5), ("optimized", "trial_01", 120.0)]
    assert all(Path(a["path"]).is_file() for a in arts)
    assert Path(arts[1]["own_bin"]) == cve / "baseline" / "bin"   # no swap timeline: iter_00
    assert arts[1]["iter"] == "iter_00" and arts[0]["iter"] is None


def test_campaign_pins_prefers_the_trial_record(tmp_path):
    cve = tmp_path / "x-upstream-1"
    t = cve / "baseline/trial_00"
    t.mkdir(parents=True)
    (t / "metadata.json").write_text(json.dumps(
        {"toolchain": {"upstream": {"pins": {"ossfuzz_commit": "rec"}}}}))
    up = tmp_path / "upstream"
    (up / "x").mkdir(parents=True)
    (up / "x/pins.json").write_text(json.dumps({"ossfuzz_commit": "prework"}))
    assert tu.campaign_pins(cve, "x", upstream_dir=up)["ossfuzz_commit"] == "rec"
    (t / "metadata.json").write_text("{}")
    assert tu.campaign_pins(cve, "x", upstream_dir=up)["ossfuzz_commit"] == "prework"
    assert tu.campaign_pins(cve, "y", upstream_dir=up) is None


def test_classify_env_symbolizes_the_kinds_options(tmp_path):
    env = tu.classify_env({"kind": "upstream", "sanitizer": "address"}, str(tmp_path), "t")
    assert "symbolize=0" not in env["ASAN_OPTIONS"] and "symbolize=1" in env["ASAN_OPTIONS"]
    assert "detect_leaks=0" in env["ASAN_OPTIONS"]
    assert "symbolize=0" not in env["UBSAN_OPTIONS"] and "MSAN_OPTIONS" in env


def test_cli_parses_the_documented_flags():
    a = tu.parse_args(["--experiment-id", "E", "--project", "libssh", "--local-id", "970001",
                       "--cpu", "7", "--timeout", "60"])
    assert (a.experiment_id, a.project, a.local_id, a.cpu, a.timeout) == ("E", "libssh", 970001, 7, 60)


def test_replay_once_maps_inner_exit_status(tmp_path, monkeypatch):
    art = tmp_path / "id:000000,sig:06"
    art.write_bytes(b"x")
    outs = iter([(0, "error while loading shared libraries\n__RC=127\n"),
                 (0, "__RC=0\n"),
                 (0, asan("SEGV", FR) + "__RC=1\n"),
                 (125, "docker: invalid spec"),
                 (None, "docker run exceeded 90s")])
    monkeypatch.setattr(tu, "_run_docker", lambda cmd, timeout: next(outs))
    got = [tu.replay_once("img", tmp_path, "t", art, {}, cpu=None, timeout=90)["status"]
           for _ in range(5)]
    assert got == ["infra", "clean", "crash", "infra", "infra"]
    assert tu.replay_once("img", tmp_path, "t", tmp_path / "missing", {}, cpu=None,
                          timeout=90)["status"] == "infra"


def _no_control(x):
    raise AssertionError("control replay on the pristine binary")


@pytest.mark.parametrize("found", [{"iter": "iter_00"}, {"iter": None, "found_is_pristine": True}])
def test_a_pre_swap_optimized_crash_gets_no_control_and_is_never_induced(found):
    r = tu.summarize([{**rec("optimized", "trial_00", 5.0, "/o"), **found}],
                     replay=lambda p: CLEAN3, control=_no_control)
    assert r["optimizer_induced"] == [] and r["counts"]["optimizer_induced"] == 0
    (n,) = r["non_reproducing"]
    assert n["path"] == "/o" and "pristine binary" in n["reason"]


def test_a_pre_swap_optimized_crash_that_crashes_on_a_later_pristine_try_is_distinct():
    r = tu.summarize([rec("optimized", "trial_00", 5.0, "/o", "iter_00")],
                     replay=lambda p: [CLEAN, CLEAN, crash(C)], control=_no_control)
    (d,) = r["distinct"]
    assert d["signature"] == "SEGV:walk_tree<-visit" and (d["pristine_tries"], d["pristine_hits"]) == (3, 1)
    assert r["optimizer_induced"] == []


def test_a_post_swap_crash_whose_bin_is_missing_is_unverified_at_control():
    """The timeline says iter_01 but iter_01/bin is gone: never "found on
    pristine", never non_reproducing, never optimizer_induced."""
    r = tu.summarize([{**rec("optimized", "trial_00", 5.0, "/o", "iter_01"),
                       "bin_missing": True}],
                     replay=lambda p: CLEAN3, control=_no_control)
    assert r["non_reproducing"] == [] and r["optimizer_induced"] == []
    (u,) = r["unverified"]
    assert u["stage"] == "control" and u["reason"] == "found binary iter_01/bin missing"
    assert u["found_is_pristine"] is False
    assert tu.found_on_pristine({"iter": "iter_01", "bin_missing": True}) is False


def test_campaign_artifacts_flags_a_missing_swapped_in_bin(tmp_path):
    cve = tmp_path / "libssh-upstream-970001"
    _artifact(cve / "optimized/trial_00/afl_out/default/crashes",
              "id:000000,sig:11,src:000002,time:120000,execs:9")
    t = cve / "optimized/online/trials/trial_00"
    t.mkdir(parents=True)
    (t / "swap_timeline.json").write_text(json.dumps(
        [{"trial_id": 0, "iter": 1, "ts": 1, "state_at_swap": {"run_time": "60"}}]))
    (a,) = tu.campaign_artifacts(cve)
    assert a["iter"] == "iter_01" and a["bin_missing"] is True and a["own_bin"] is None
    (t / "iter_01" / "bin").mkdir(parents=True)          # present: the normal answer
    (a,) = tu.campaign_artifacts(cve)
    assert a["bin_missing"] is False and Path(a["own_bin"]) == t / "iter_01" / "bin"
