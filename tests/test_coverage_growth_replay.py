"""coverage_growth.py must replay each queue in discovery order and only accept
a replay that provably ran every input in that order.

The persistent harnesses credit one-time-per-process edges to whichever input
runs first. A resumed AFL++ renumbers its queue newest-first, so replaying in
``id:`` order handed openssl's ~140 init edges to a 17 h find in every
hot-swapped trial. The slow test reproduces that on a real afl-showmap, with a
crashing and a hanging input mid-queue (the case whose colour-glued log lines
once failed complete replays).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
import coverage_growth as cg  # noqa: E402

SEED_A = "id:000068,time:0,execs:0,orig:00d0431fe2883d53587a12a46f43f010f351c281"
SEED_B = "id:000069,time:0,execs:0,orig:00f4793354500d93b3621d8277140504b8455a90"
LATE = ("id:000000,time:0,execs:0,orig:id:002620,src:001533+001909,"
        "time:61052610,execs:1731747047,op:splice,rep:3")
NEW = "id:002700,src:000882,time:70000000,execs:2448356561,op:havoc,rep:1"
SYNC = "id:002701,sync:other,src:000004"


def test_seeds_replay_first_even_when_a_late_find_holds_id_000000():
    order = sorted([NEW, SEED_B, LATE, SEED_A], key=cg.replay_key)
    assert order == [SEED_A, SEED_B, LATE, NEW]


def test_seed_tiebreak_is_the_same_whichever_way_a_resume_numbered_them():
    shas = ["00aa", "3f00", "ff01"]
    fresh = [f"id:{i:06d},time:0,execs:0,orig:{s}" for i, s in enumerate(shas)]
    resumed = [f"id:{i:06d},time:0,execs:0,orig:{s}"
               for i, s in enumerate(reversed(shas), start=40)]
    orig = lambda names: [n.split(",orig:", 1)[1] for n in names]  # noqa: E731
    assert orig(sorted(fresh, key=cg.replay_key)) == shas
    assert orig(sorted(resumed, key=cg.replay_key)) == shas
    # ... which is exactly a fresh AFL++'s own id order
    assert sorted(fresh, key=cg.replay_key) == sorted(fresh)


def test_untimed_entries_replay_last_and_stay_out_of_the_curve(tmp_path):
    q = tmp_path / "queue"
    q.mkdir()
    (q / ".state").mkdir()
    for n in (SYNC, NEW, SEED_A, LATE):
        (q / n).write_bytes(b"x")
    order = cg.replay_order(q)
    assert order == [SEED_A, LATE, NEW, SYNC]

    maps = tmp_path / "maps"
    maps.mkdir()
    for n, edges in ((SEED_A, "1:1\n2:1\n"), (LATE, "2:1\n3:1\n"),
                     (NEW, "4:1\n"), (SYNC, "9:1\n")):
        (maps / n).write_text(edges)
    rows, unreadable = cg.growth_from_maps(maps, order)
    assert rows == [(0.0, 1, 2), (61052.61, 2, 3), (70000.0, 3, 4)]
    assert unreadable == []


def test_unreadable_map_is_counted_with_no_edges_not_fatal(tmp_path, monkeypatch):
    maps = tmp_path / "maps"
    maps.mkdir()
    for n in (SEED_A, LATE, NEW):
        (maps / n).write_text("5:1\n")
    real = Path.read_text

    def flaky(self, *a, **kw):
        if self.name == LATE:
            raise PermissionError(13, "denied")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", flaky)
    rows, unreadable = cg.growth_from_maps(maps, [SEED_A, LATE, NEW])
    assert [r[1] for r in rows] == [1, 2, 3]
    assert unreadable == [LATE]


# Captured from the image's afl-showmap (AFL++ 4.21a, ALWAYS_COLORED): a crash
# or timeout notice ends with a colour reset and NO newline, so the next
# "Processing" line starts with "\x1b[0m".
_CRASH_LOG = (
    b"\x1b[1;94m[*] \x1b[0mReading from '/w/replay_order.txt'...\x1b[0m\n"
    b"Processing /queue/a\n"
    b"-- Program output begins --\n\x1b[0m\x1b[0m-- Program output ends --\n"
    b"Processing /queue/b\n"
    b"-- Program output begins --\n\x1b[0m\x1b[0m-- Program output ends --\n"
    b"\x1b[1;91m\n+++ Program killed by signal 6 +++\n\x1b[0m"
    b"Processing /queue/c\n"
    b"-- Program output begins --\n\x1b[0m\x1b[0m-- Program output ends --\n"
    b"\x1b[1;91m\n+++ Program timed off +++\n\x1b[0m"
    b"Processing /queue/d\n"
    b"-- Program output begins --\n\x1b[0m\x1b[0m-- Program output ends --\n"
)
_SUMMARY = b"\x1b[1;92m[+] \x1b[0mProcessed 4 input files.\x1b[0m\n"


def test_log_parser_sees_processing_lines_glued_to_a_colour_reset():
    assert cg.parse_replay_log(_CRASH_LOG + _SUMMARY) == (["a", "b", "c", "d"], 4)


def test_log_without_the_final_summary_reports_no_count():
    # afl-showmap died while running the LAST input: its Processing line is
    # there, the "Processed N" summary is not.
    assert cg.parse_replay_log(_CRASH_LOG) == (["a", "b", "c", "d"], None)


_OLD_CSV = "time_s,inputs,cumulative_edges\n0.0,1,99\n"


def _trial_with_old_csv(tmp_path):
    trial = tmp_path / "exp" / "optimized" / "trial_00"
    q = trial / "afl_out" / "default" / "queue"
    q.mkdir(parents=True)
    (q / SEED_A).write_bytes(b"x")
    outdir = tmp_path / "cov"
    outdir.mkdir()
    old = outdir / "optimized_trial_00.csv"
    old.write_text(_OLD_CSV)
    args = (str(tmp_path / "exp"), "optimized", str(trial), "img", "t", 0, str(outdir))
    return args, old


def test_failed_replay_removes_the_stale_csv(tmp_path, monkeypatch):
    args, old = _trial_with_old_csv(tmp_path)
    monkeypatch.setattr(cg, "showmap_maps", lambda *a, **k: False)
    arm, name, edges, ok, note = cg.one_trial(args)
    assert not ok and "showmap failed" in note
    assert not old.exists()


def test_replay_that_raises_removes_the_stale_csv(tmp_path, monkeypatch):
    args, old = _trial_with_old_csv(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("docker went away")

    monkeypatch.setattr(cg, "showmap_maps", boom)
    with pytest.raises(RuntimeError):
        cg.one_trial(args)
    assert not old.exists()


def test_interrupted_replay_keeps_the_previous_csv(tmp_path, monkeypatch):
    args, old = _trial_with_old_csv(tmp_path)
    seen = []

    def interrupted(*a, **k):
        seen.append(old.read_text())          # still there while in flight
        raise KeyboardInterrupt

    monkeypatch.setattr(cg, "showmap_maps", interrupted)
    with pytest.raises(KeyboardInterrupt):
        cg.one_trial(args)
    assert seen == [_OLD_CSV]
    assert old.read_text() == _OLD_CSV


def test_successful_replay_replaces_the_csv_atomically(tmp_path, monkeypatch):
    args, old = _trial_with_old_csv(tmp_path)

    def fake_showmap(image, bin_dir, target, queue, order, maps, cpu):
        assert old.read_text() == _OLD_CSV   # old curve kept until the new one is ready
        maps.mkdir()
        (maps / SEED_A).write_text("1:1\n2:1\n")
        return True

    monkeypatch.setattr(cg, "showmap_maps", fake_showmap)
    arm, name, edges, ok, note = cg.one_trial(args)
    assert ok and edges == 2
    assert old.read_text().splitlines() == ["time_s,inputs,cumulative_edges", "0.0,1,2"]
    assert not old.with_suffix(".csv.part").exists()


def test_main_exits_nonzero_and_names_the_failed_trials(tmp_path, monkeypatch, capsys):
    import json
    exp = tmp_path / "results" / "exp1" / "proj-fuzzbench-1"
    for arm in ("baseline", "optimized"):
        (exp / arm / "trial_00").mkdir(parents=True)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps([{"project": "proj", "fuzz_target": "t"}]))
    monkeypatch.setattr(cg.config, "MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(cg.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(cg, "experiment_image", lambda *a, **k: "img")
    monkeypatch.setattr(cg, "ProcessPoolExecutor", ThreadPoolExecutor)
    monkeypatch.setattr(cg, "one_trial", lambda t: (
        t[1], Path(t[2]).name, 5, t[1] == "baseline",
        "" if t[1] == "baseline" else "showmap failed (incomplete or out-of-order replay)"))
    monkeypatch.setattr(sys, "argv", ["cg", "--experiment-id", "exp1",
                                      "--jobs", "2", "--outdir", str(tmp_path / "cov")])
    assert cg.main() == 1
    out = capsys.readouterr().out
    assert "1 of 2 trials FAILED" in out
    assert "proj-fuzzbench-1 optimized trial_00: showmap failed" in out


def test_main_prints_the_traceback_of_a_crashed_trial_and_carries_on(
        tmp_path, monkeypatch, capsys):
    import json
    exp = tmp_path / "results" / "exp1" / "proj-fuzzbench-1"
    for arm in ("baseline", "optimized"):
        (exp / arm / "trial_00").mkdir(parents=True)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps([{"project": "proj", "fuzz_target": "t"}]))
    monkeypatch.setattr(cg.config, "MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(cg.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(cg, "experiment_image", lambda *a, **k: "img")
    monkeypatch.setattr(cg, "ProcessPoolExecutor", ThreadPoolExecutor)

    def crash_optimized(t):
        if t[1] == "optimized":
            raise ValueError("parse blew up")
        return (t[1], Path(t[2]).name, 5, True, "")

    monkeypatch.setattr(cg, "one_trial", crash_optimized)
    monkeypatch.setattr(sys, "argv", ["cg", "--experiment-id", "exp1",
                                      "--jobs", "2", "--outdir", str(tmp_path / "cov")])
    assert cg.main() == 1
    cap = capsys.readouterr()
    assert "Traceback (most recent call last)" in cap.err
    assert "crash_optimized" in cap.err and "ValueError: parse blew up" in cap.err
    assert "baseline  trial_00: 5 edges" in cap.out          # the other trial still ran
    assert "optimized trial_00: error: ValueError('parse blew up')" in cap.out


# ---------------------------------------------------------------------------
# End to end on the real afl-showmap from a FuzzBench AFL++ 4.21a image.

_HARNESS = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int ready;
static volatile int sink;
/* One-time-per-process work on the first REAL input (aflpp_driver's own
   4-byte warm-up call does not trigger it), like openssl's lazy init. */
static void init_once(void) {
  for (int i = 0; i < 4; i++) { if (i & 1) sink += i; else sink -= i; }
}
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  if (!ready && n > 4) { ready = 1; init_once(); }
  if (n >= 5 && !memcmp(d, "CRASH", 5)) abort();
  if (n >= 5 && !memcmp(d, "HANGS", 5)) for (;;) sink++;
  if (n && d[0] == 'B') sink = 2;
  return 0;
}
"""


def _image() -> str | None:
    if not shutil.which("docker"):
        return None
    want = os.environ.get("COVERAGE_TEST_IMAGE")
    r = subprocess.run(["docker", "images", want or "fb-aflpp/*",
                        "--format", "{{.Repository}}:{{.Tag}}"],
                       capture_output=True, text=True)
    imgs = r.stdout.split()
    return imgs[0] if r.returncode == 0 and imgs else None


@pytest.mark.slow
def test_real_replay_runs_discovery_order_through_a_crash_and_a_hang(tmp_path):
    image = _image()
    if image is None:
        pytest.skip("no fb-aflpp/* image (AFL++ 4.21a) available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "h.c").write_text(_HARNESS)
    build = subprocess.run(
        ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
         "-e", "HOME=/tmp", "-e", "AFL_QUIET=1", "-v", f"{bin_dir}:/x",
         "--entrypoint", "/bin/bash", image, "-lc",
         "/afl/afl-clang-fast -O0 /x/h.c /afl/libAFLDriver.a -o /x/target"
         " && cp /afl/afl-showmap /x/"],
        capture_output=True, text=True, timeout=600)
    assert build.returncode == 0, build.stdout + build.stderr

    q = tmp_path / "queue"
    q.mkdir()
    (q / ".state").mkdir()
    entries = {
        # resumed-queue shape: a late find holds id:000000 and sorts first
        "id:000000,time:0,execs:0,orig:id:000009,src:000001,time:900,op:havoc": b"Bzzzzz",
        "id:000001,time:0,execs:0,orig:aaaa": b"seed-one",
        "id:000002,time:0,execs:0,orig:bbbb": b"seed-two",
        "id:000003,src:000001,time:100,op:havoc": b"CRASH!",
        "id:000004,src:000001,time:200,op:havoc": b"Bafter-crash",
        "id:000005,src:000001,time:300,op:havoc": b"HANGS!",
        "id:000006,src:000001,time:400,op:havoc": b"after-hang",
        SYNC: b"synced",
    }
    for n, data in entries.items():
        (q / n).write_bytes(data)

    order = cg.replay_order(q)
    assert order[:2] == ["id:000001,time:0,execs:0,orig:aaaa",
                         "id:000002,time:0,execs:0,orig:bbbb"]
    assert order[-1] == SYNC

    w = tmp_path / "w"
    w.mkdir()
    maps = w / "maps"
    cpu = max(os.sched_getaffinity(0))
    assert cg.showmap_maps(image, bin_dir, "target", q, order, maps, cpu, timeout=600)

    log = (w / "replay.log").read_bytes()
    # The regression case really happened: a Processing line glued to a reset.
    assert b"\x1b[0mProcessing /queue/" in log
    ran, processed = cg.parse_replay_log(log)
    assert ran == order and processed == len(order)
    assert sorted(p.name for p in maps.iterdir()) == sorted(entries)

    def edges(n):
        return {int(l.split(":")[0]) for l in (maps / n).read_text().splitlines()}
    # init_once's edges land on the first REPLAYED input (the first seed), not
    # on id:000000, the late find that the old id-order replay ran first.
    first, late = edges(order[0]), edges("id:000000,time:0,execs:0,orig:id:000009,"
                                         "src:000001,time:900,op:havoc")
    assert first - edges(order[1]) - late, "seed did not absorb the one-time edges"

    rows, unreadable = cg.growth_from_maps(maps, order)
    assert unreadable == [] and len(rows) == len(order) - 1   # sync entry not counted
    assert [r[0] for r in rows] == [0.0, 0.0, 0.1, 0.2, 0.3, 0.4, 0.9]
