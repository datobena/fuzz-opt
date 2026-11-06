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
# summarize
# --------------------------------------------------------------------------- #
A = asan("heap-buffer-overflow", FR)
A2 = asan("heap-buffer-overflow", FR, addr="0x6030000000f4")
B = asan("heap-buffer-overflow", ["parse_header", "read_chunk", "decode_text"])
C = asan("SEGV", ["fold_x", "walk_tree", "visit"])
D = asan("stack-buffer-overflow", ["copy_name", "visit"])


def rec(arm, trial, t, path, report):
    return {"arm": arm, "trial": trial, "time_s": t, "path": path, "report": report}


RECORDS = [
    rec("baseline", "trial_00", 300.0, "/r/base/t0/a1", A),
    rec("optimized", "trial_01", 120.0, "/r/opt/t1/a1", A2),
    rec("optimized", "trial_02", 500.0, "/r/opt/t2/a1", A),
    rec("optimized", "trial_01", 900.0, "/r/opt/t1/b1", B),       # only optimized, reproduces
    rec("optimized", "trial_00", 50.0, "/r/opt/t0/c1", C),        # does not reproduce
    rec("optimized", "trial_02", 70.0, "/r/opt/t2/d1", D),        # infra failure
    rec("baseline", "trial_01", 10.0, "/r/base/t1/u1", "timeout: no report\n"),
]


def fake_replay(path):
    return {"/r/opt/t1/a1": True, "/r/opt/t1/b1": True, "/r/opt/t0/c1": False}[path] \
        if path != "/r/opt/t2/d1" else (_ for _ in ()).throw(RuntimeError("docker: exit 125"))


def by_sig(items):
    return {d["signature"]: d for d in items}


def test_summarize_splits_distinct_induced_unverified_unclassified():
    r = tu.summarize(RECORDS, replay=fake_replay)
    d = by_sig(r["distinct"])
    assert set(d) == {"heap-buffer-overflow:parse_header<-read_chunk<-decode_image",
                      "heap-buffer-overflow:parse_header<-read_chunk<-decode_text"}
    assert [x["signature"] for x in r["optimizer_induced"]] == ["SEGV:walk_tree<-visit"]
    (u,) = r["unverified"]
    assert u["signature"] == "stack-buffer-overflow:copy_name<-visit"
    assert "exit 125" in u["pristine_error"] and u["reproduces_on_pristine"] is None
    assert [x["path"] for x in r["unclassified"]] == ["/r/base/t1/u1"]


def test_summarize_reports_first_seen_trials_and_earliest_path_per_key():
    r = tu.summarize(RECORDS, replay=fake_replay)
    a = by_sig(r["distinct"])["heap-buffer-overflow:parse_header<-read_chunk<-decode_image"]
    assert a["kind"] == "heap-buffer-overflow"
    assert a["key"] == ["heap-buffer-overflow", ["parse_header", "read_chunk", "decode_image"]]
    assert a["first_seen_s"] == {"baseline": 300.0, "optimized": 120.0}
    assert a["trials"] == {"baseline": ["trial_00"], "optimized": ["trial_01", "trial_02"]}
    assert a["earliest_path"] == "/r/opt/t1/a1"
    assert a["reproduces_on_pristine"] is True
    assert a["stack"][:4] == ["__asan_memcpy", "parse_header", "read_chunk", "decode_image"]
    assert len(a["stack"]) <= 10


def test_summarize_counts_per_arm_exclude_induced_and_unverified():
    r = tu.summarize(RECORDS, replay=fake_replay)
    assert r["counts"]["distinct"] == 2
    assert r["counts"]["per_arm"]["baseline"] == {"distinct": 1, "artifacts": 1}
    assert r["counts"]["per_arm"]["optimized"] == {"distinct": 2, "artifacts": 3}
    assert r["counts"]["optimizer_induced"] == 1
    assert r["counts"]["unverified"] == 1
    assert r["counts"]["unclassified"] == 1


def test_only_optimized_found_is_reproducing_keys_the_baseline_never_found():
    r = tu.summarize(RECORDS, replay=fake_replay)
    assert [x["signature"] for x in r["only_optimized_found"]] == [
        "heap-buffer-overflow:parse_header<-read_chunk<-decode_text"]


def test_summarize_replays_only_the_earliest_artifact_of_each_key():
    seen = []

    def replay(path):
        seen.append(path)
        return True
    tu.summarize(RECORDS, replay=replay)
    assert sorted(seen) == sorted(["/r/opt/t1/a1", "/r/opt/t1/b1", "/r/opt/t0/c1", "/r/opt/t2/d1"])


def test_replay_returning_none_is_unverified_not_a_verdict():
    r = tu.summarize([rec("optimized", "trial_00", 1.0, "/p", A)], replay=lambda p: None)
    assert r["distinct"] == [] and r["optimizer_induced"] == []
    assert len(r["unverified"]) == 1


def test_replay_may_report_the_pristine_key():
    r = tu.summarize([rec("optimized", "trial_00", 1.0, "/p", A)],
                     replay=lambda p: {"reproduces": True, "pristine_key": tu.dedupe_key(B)})
    (d,) = r["distinct"]
    assert d["pristine_key"] == ["heap-buffer-overflow", ["parse_header", "read_chunk", "decode_text"]]
    assert d["pristine_key_differs"] is True


def test_summarize_output_is_json_serializable():
    json.dumps(tu.summarize(RECORDS, replay=fake_replay))


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def test_markdown_lists_reproducer_paths_and_the_only_optimized_section():
    r = tu.summarize(RECORDS, replay=fake_replay)
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
    for section in ("## Optimizer-induced", "## Unverified", "## Unclassified"):
        assert section in md
    assert "/r/opt/t0/c1" in md and "/r/opt/t2/d1" in md and "/r/base/t1/u1" in md


def test_markdown_without_pins_says_so():
    r = tu.summarize([], replay=lambda p: True)
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
