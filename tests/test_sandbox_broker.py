"""Tests for sandbox/broker.py — the only channel from the agent to docker."""
import json

import pytest

from sandbox.broker import BrokerContext, handle_request


def _ctx(tmp_path):
    return BrokerContext(
        image="bench-aflpp/x-arvo-1", source_dir=str(tmp_path), out_dir=str(tmp_path),
        corpus_dir=str(tmp_path), fuzz_target="t", project="x", cpu=3,
    )


def test_unknown_op_is_rejected(tmp_path):
    r = handle_request({"op": "rm -rf /"}, _ctx(tmp_path))
    assert r["ok"] is False and "unknown op" in r["error"]


def test_missing_op_is_rejected(tmp_path):
    assert handle_request({}, _ctx(tmp_path))["ok"] is False


def test_op_must_be_a_string_not_a_structure(tmp_path):
    """Guards against a request smuggling a list that reaches subprocess."""
    assert handle_request({"op": ["build"]}, _ctx(tmp_path))["ok"] is False


def test_build_log_reaches_the_agent_unscrubbed(tmp_path, monkeypatch):
    """The agent may see any bug the run has hit, and needs the real error."""
    import sandbox.broker as b
    monkeypatch.setattr(
        b, "_run_build",
        lambda ctx: (False, "==1==ERROR: AddressSanitizer: heap-use-after-free"),
    )
    r = handle_request({"op": "build"}, _ctx(tmp_path))
    assert r["ok"] is False
    assert "AddressSanitizer: heap-use-after-free" in r["log"]


def test_smoke_log_reaches_the_agent_unscrubbed(tmp_path, monkeypatch):
    import sandbox.broker as b
    monkeypatch.setattr(
        b, "_run_smoke",
        lambda ctx: (False, "SUMMARY: AddressSanitizer: stack-buffer-overflow /s/valid.c"),
    )
    r = handle_request({"op": "smoke"}, _ctx(tmp_path))
    assert "valid.c" in r["log"]


def test_a_huge_log_is_cut_to_its_tail(tmp_path, monkeypatch):
    """A multi-megabyte compile log must not flood the agent's context; the
    error is at the end, so the tail is what survives."""
    import sandbox.broker as b
    blob = "noise\n" * 100000 + "error: the real one"
    monkeypatch.setattr(b, "_run_build", lambda ctx: (False, blob))
    log = handle_request({"op": "build"}, _ctx(tmp_path))["log"]
    assert len(log) < b.LOG_TAIL_CHARS + 200
    assert log.endswith("error: the real one") and "omitted" in log


def _sample(tmp_path, n=4):
    d = tmp_path / "smoke"
    d.mkdir()
    for i in range(n):
        (d / f"unit_{i:08d}").write_bytes(b"x")
    return d


def test_crash_scan_names_crashers_with_cmin_crashes_only(tmp_path):
    """afl-showmap -Z + AFL_CMIN_CRASHES_ONLY leaves a non-empty map only for a
    crashing input; both AFL++ 4.03a and 5.02c behave this way."""
    import sandbox.broker as b
    cmd = " ".join(b._crash_scan_command(_ctx(tmp_path), "/o", "/c"))
    assert "afl-showmap -q -Z -i /corpus -o /maps" in cmd
    assert "AFL_CMIN_CRASHES_ONLY=1" in cmd
    assert "/o:/out:ro" in cmd and "/c:/corpus:ro" in cmd
    assert "--memory" in cmd and "--tmpfs /maps" in cmd
    assert "-t 5000+" in cmd            # same per-input timeout as the replay gate


def test_scan_parses_crashers_and_requires_full_coverage(tmp_path, monkeypatch):
    import sandbox.broker as b
    d = _sample(tmp_path)
    monkeypatch.setattr(b, "_run", lambda cmd, t, ctx=None: (
        0, "CRASHER unit_00000002\nSCANNED 4\nSCAN_RC=0\n"))
    r = b.scan_for_crashers(_ctx(tmp_path), str(tmp_path), str(d))
    assert r["ok"] and r["crashers"] == ["unit_00000002"] and r["expected"] == 4


@pytest.mark.parametrize("blob", [
    "SCANNED 0\nSCAN_RC=0\n",        # ran nothing -- the old filter's failure mode
    "SCANNED 3\nSCAN_RC=0\n",        # stopped early
    "",                                 # container never started
])
def test_scan_that_did_not_cover_every_input_is_not_ok(tmp_path, monkeypatch, blob):
    import sandbox.broker as b
    d = _sample(tmp_path)
    monkeypatch.setattr(b, "_run", lambda cmd, t, ctx=None: (0, blob))
    assert b.scan_for_crashers(_ctx(tmp_path), str(tmp_path), str(d))["ok"] is False


def test_smoke_on_sample_reports_crashers_with_their_sanitizer_report(tmp_path, monkeypatch):
    import sandbox.broker as b
    d = _sample(tmp_path)
    ctx = _ctx(tmp_path)
    ctx.smoke_corpus_dir = str(d)
    monkeypatch.setattr(b, "scan_for_crashers", lambda c, o, cd: {
        "ok": True, "crashers": ["unit_00000001"], "scanned": 4, "expected": 4,
        "seconds": 0.1, "log": ""})
    monkeypatch.setattr(b, "crash_report", lambda c, o, cd, names:
                        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/p/fold.c:9")
    r = handle_request({"op": "smoke"}, ctx)
    assert r["ok"] is False
    assert "unit_00000001" in r["log"] and "fold.c:9" in r["log"]
    assert "this round's edits" in r["log"]


def test_clean_smoke_on_sample_passes(tmp_path, monkeypatch):
    import sandbox.broker as b
    d = _sample(tmp_path)
    ctx = _ctx(tmp_path)
    ctx.smoke_corpus_dir = str(d)
    monkeypatch.setattr(b, "scan_for_crashers", lambda c, o, cd: {
        "ok": True, "crashers": [], "scanned": 4, "expected": 4,
        "seconds": 0.1, "log": ""})
    r = handle_request({"op": "smoke"}, ctx)
    assert r["ok"] is True and "4 fuzzer inputs" in r["log"]


def test_crash_report_ignores_unsafe_names(tmp_path, monkeypatch):
    import sandbox.broker as b
    seen = {}
    monkeypatch.setattr(b, "_run",
                        lambda cmd, t, ctx=None: seen.setdefault("cmd", cmd) and (0, "r"))
    b.crash_report(_ctx(tmp_path), "/o", "/c", ["unit_1; rm -rf /", "unit_2"])
    script = seen["cmd"][-1]
    assert "unit_2" in script and "rm -rf" not in script


def test_replay_time_returns_only_a_number(tmp_path, monkeypatch):
    import sandbox.broker as b
    # _run_replay returns a dict (seconds + host-side bracketing detail); the
    # agent-facing reply must stay just the number plus repeats.
    monkeypatch.setattr(b, "_run_replay",
                        lambda ctx, repeats: {"seconds": 12.5, "bracketed": False})
    r = handle_request({"op": "replay_time", "repeats": 3}, _ctx(tmp_path))
    assert r == {"ok": True, "seconds": 12.5, "repeats": 3}


def test_replay_repeats_is_clamped(tmp_path, monkeypatch):
    """An agent asking for 10_000 repeats must not wedge the host."""
    import sandbox.broker as b
    seen = {}
    def fake(ctx, repeats):
        seen["n"] = repeats
        return {"seconds": 1.0, "bracketed": False}
    monkeypatch.setattr(b, "_run_replay", fake)
    handle_request({"op": "replay_time", "repeats": 10000}, _ctx(tmp_path))
    assert seen["n"] <= b.MAX_REPLAY_REPEATS


def test_replay_repeats_rejects_non_integer(tmp_path):
    r = handle_request({"op": "replay_time", "repeats": "; rm -rf /"}, _ctx(tmp_path))
    assert r["ok"] is False


def test_handler_never_raises_on_malformed_input(tmp_path):
    """A crash in the broker would take down the round; always answer."""
    for bad in (None, [], "build", {"op": None}, {"op": ""}):
        r = handle_request(bad, _ctx(tmp_path))
        assert r["ok"] is False and "error" in r


def test_replies_are_json_serializable(tmp_path):
    r = handle_request({"op": "nope"}, _ctx(tmp_path))
    json.dumps(r)  # must not raise


def test_socket_round_trip(tmp_path, monkeypatch):
    """serve() must actually speak the protocol the agent_tools clients use."""
    import socket as _s
    import threading

    import sandbox.broker as b

    monkeypatch.setattr(b, "_run_replay",
                        lambda ctx, repeats: {"seconds": 4.25, "bracketed": False})
    sock_path = str(tmp_path / "broker.sock")
    ctx = _ctx(tmp_path)

    t = threading.Thread(target=b.serve, args=(sock_path, ctx), daemon=True)
    t.start()
    for _ in range(50):                      # wait for bind
        if (tmp_path / "broker.sock").exists():
            break
        __import__("time").sleep(0.02)

    c = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    c.connect(sock_path)
    c.sendall(json.dumps({"op": "replay_time", "repeats": 3}).encode() + b"\n")
    reply = json.loads(c.recv(65536).decode())
    c.close()

    assert reply == {"ok": True, "seconds": 4.25, "repeats": 3}


def test_socket_survives_garbage(tmp_path):
    """Malformed bytes must get an error reply, not kill the broker."""
    import socket as _s
    import threading

    import sandbox.broker as b

    sock_path = str(tmp_path / "b2.sock")
    t = threading.Thread(target=b.serve, args=(sock_path, _ctx(tmp_path)), daemon=True)
    t.start()
    for _ in range(50):
        if (tmp_path / "b2.sock").exists():
            break
        __import__("time").sleep(0.02)

    c = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    c.connect(sock_path)
    c.sendall(b"not json at all\n")
    reply = json.loads(c.recv(65536).decode())
    c.close()
    assert reply["ok"] is False


def test_timed_out_container_is_killed(monkeypatch):
    """A timeout must kill the container, not just the `docker run` client."""
    import subprocess
    import sandbox.broker as b
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(b.subprocess, "run", fake_run)
    rc, blob = b._run(["docker", "run", "--rm", "img", "true"], 5)
    assert (rc, blob) == (124, "timeout")
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "-f", name]


# --- the session's end stops the broker ---------------------------------------
#
# serve() used to block in accept() forever on a daemon thread, so a session that
# timed out left its broker building and replaying for the orphaned agent.

def test_broker_containers_carry_launcher_and_session_labels(tmp_path, monkeypatch):
    import subprocess
    import sandbox.broker as b
    from sandbox import launch
    calls = []
    monkeypatch.setattr(b.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or
                        subprocess.CompletedProcess(cmd, 0, "", ""))
    ctx = _ctx(tmp_path)
    ctx.labels = {launch.LABEL_SESSION: "s1", launch.LABEL_TRIAL: 4}
    b._run(["docker", "run", "--rm", "img", "true"], 5, ctx)
    cmd = calls[0]
    labels = {cmd[i + 1] for i, a in enumerate(cmd) if a == "--label"}
    assert {f"{launch.LABEL_LAUNCHER}={launch.launcher_token()}",
            f"{launch.LABEL_ROLE}=broker", f"{launch.LABEL_SESSION}=s1",
            f"{launch.LABEL_TRIAL}=4"} <= labels
    assert cmd.index("--label") < cmd.index("img")
    assert not ctx.inflight, "a finished container must leave the in-flight set"


def test_serve_returns_when_the_session_stops(tmp_path):
    import threading
    import time
    import sandbox.broker as b
    ctx = _ctx(tmp_path)
    sock = tmp_path / "b3.sock"
    t = threading.Thread(target=b.serve, args=(str(sock), ctx), daemon=True)
    t.start()
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.02)
    assert sock.exists()
    ctx.stop.set()
    t.join(timeout=b.ACCEPT_POLL_SECS * 6)
    assert not t.is_alive(), "serve() ignored the stop"
    assert not sock.exists()


def test_stop_session_kills_in_flight_containers_and_refuses_new_ones(tmp_path, monkeypatch):
    """A container still running when the session ends is force-removed, the
    call that started it reports the session's end -- not the killed container's
    output -- and nothing new starts."""
    import subprocess
    import threading
    import time
    import sandbox.broker as b
    started, killed, removed = threading.Event(), threading.Event(), []

    def fake_run(cmd, **kw):
        if cmd[:3] == ["docker", "rm", "-f"]:
            removed.append(cmd[3])
            killed.set()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        started.set()
        killed.wait(5)                                # runs until removed
        return subprocess.CompletedProcess(cmd, 137, "half a build", "")

    monkeypatch.setattr(b.subprocess, "run", fake_run)
    real_sleep = time.sleep
    monkeypatch.setattr(b.time, "sleep", lambda s: real_sleep(0.01))
    ctx = _ctx(tmp_path)
    out = {}
    t = threading.Thread(target=lambda: out.update(
        r=b._run(["docker", "run", "--rm", "img", "make"], 60, ctx)))
    t.start()
    assert started.wait(5)
    name = next(iter(ctx.inflight))
    assert b.stop_session(ctx, wait_s=5) == []
    t.join(5)
    assert removed and removed[0] == name
    rc, blob = out["r"]
    assert rc == b.SESSION_ENDED_RC and b.SESSION_ENDED_MSG in blob
    # After the stop: refused without a docker call.
    n = len(removed)
    assert b._run(["docker", "run", "--rm", "img", "true"], 5, ctx) == (
        b.SESSION_ENDED_RC, b.SESSION_ENDED_MSG)
    assert len(removed) == n and not ctx.inflight


def test_a_build_cut_short_by_the_session_end_records_no_result(tmp_path, monkeypatch):
    """No reference binary, a failed reply, an audit entry that says why, and a
    ledger row that keeps the CPU it used but is tagged session_ended."""
    import contextlib
    import subprocess
    import sandbox.broker as b
    from lib import cpu_ledger
    ledger = tmp_path / "l.jsonl"
    monkeypatch.setenv(cpu_ledger.LEDGER_ENV, str(ledger))
    monkeypatch.setattr(b, "core_lock", lambda cpu: contextlib.nullcontext())
    monkeypatch.setattr(b, "ownership_command", lambda image, paths: None)
    ctx = _ctx(tmp_path)
    ctx.baseline_ref_dir = str(tmp_path / "ref")
    ctx.audit_log = str(tmp_path / "audit.log")

    def fake_run(cmd, **kw):
        ctx.stop.set()                    # the session ends while it builds
        return subprocess.CompletedProcess(cmd, 0, "built", "")

    monkeypatch.setattr(b.subprocess, "run", fake_run)
    r = handle_request({"op": "build"}, ctx)
    assert r["ok"] is False
    assert not ctx.ref_ready and not (tmp_path / "ref").exists()
    assert b.SESSION_ENDED_MSG in (tmp_path / "audit.log").read_text()
    row = json.loads(ledger.read_text().splitlines()[-1])
    assert row["stage"] == "broker_build" and row["session_ended"] is True
    assert row["ok"] is False and "wall_s" in row


def test_no_broker_container_starts_once_the_launcher_is_shutting_down(tmp_path, monkeypatch):
    import threading
    import sandbox.broker as b
    from sandbox import launch
    calls = []
    monkeypatch.setattr(b.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(launch, "SHUTTING_DOWN", threading.Event())
    launch.SHUTTING_DOWN.set()
    for ctx in (None, _ctx(tmp_path)):           # harness call and session call alike
        assert b._run(["docker", "run", "--rm", "img", "true"], 5, ctx) == (
            b.SESSION_ENDED_RC, b.LAUNCHER_STOPPING_MSG)
    assert calls == []


def _chown_harness(tmp_path, monkeypatch, *, stop_during_build):
    """A build whose chown is observable: returns (ctx, docker calls)."""
    import contextlib
    import subprocess
    import sandbox.broker as b
    from sandbox import launch
    monkeypatch.setattr(b, "core_lock", lambda cpu: contextlib.nullcontext())
    monkeypatch.setattr(b, "ownership_command", lambda image, paths: [
        "docker", "run", "--rm", "--entrypoint", "chown", image, "-R", "1000:1000",
        *paths])
    ctx = _ctx(tmp_path)
    ctx.labels = {launch.LABEL_SESSION: "s9"}
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw.get("timeout")))
        if "chown" not in cmd and stop_during_build:
            ctx.stop.set()
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(b.subprocess, "run", fake_run)
    return ctx, calls


def test_a_build_chowns_its_output_through_a_named_labelled_timed_container(tmp_path, monkeypatch):
    import sandbox.broker as b
    from sandbox import launch
    ctx, calls = _chown_harness(tmp_path, monkeypatch, stop_during_build=False)
    assert b._run_build(ctx)[0] is True
    chown, timeout = calls[-1]
    assert "chown" in chown and timeout == b.CHOWN_TIMEOUT_SECS
    assert chown[chown.index("--name") + 1].startswith("broker-")
    assert f"{launch.LABEL_SESSION}=s9" in chown
    assert ctx.ownership_pending is False


def test_a_stopped_build_leaves_its_chown_to_the_session_teardown(tmp_path, monkeypatch):
    """After the stop the broker thread starts nothing -- not even the chown --
    and finish_ownership() runs it from the session's teardown, so the harness
    can still `git clean` the tree."""
    import sandbox.broker as b
    from sandbox import launch
    ctx, calls = _chown_harness(tmp_path, monkeypatch, stop_during_build=True)
    assert b._run_build(ctx)[0] is False
    assert not any("chown" in c for c, _ in calls)
    assert ctx.ownership_pending is True
    assert b.finish_ownership(ctx) is True
    chown, timeout = calls[-1]
    assert "chown" in chown and timeout == b.CHOWN_TIMEOUT_SECS
    assert "--name" in chown and f"{launch.LABEL_SESSION}=s9" in chown
    assert ctx.ownership_pending is False and not ctx.inflight
    n = len(calls)
    assert b.finish_ownership(ctx) is True and len(calls) == n      # nothing pending


def test_chown_back_outside_a_session_is_named_labelled_and_timed(monkeypatch):
    import subprocess
    import sandbox.broker as b
    from sandbox import launch
    calls = []
    monkeypatch.setattr(b, "ownership_command", lambda image, paths: [
        "docker", "run", "--rm", "--entrypoint", "chown", image, "-R", "1:1", *paths])
    monkeypatch.setattr(b.subprocess, "run", lambda cmd, **kw: calls.append(
        (cmd, kw.get("timeout"))) or subprocess.CompletedProcess(cmd, 0, "", ""))
    assert b.chown_back("img", ["/tree"], labels={launch.LABEL_TRIAL: 3}) is True
    cmd, timeout = calls[0]
    assert timeout == b.CHOWN_TIMEOUT_SECS and cmd[cmd.index("--name") + 1].startswith("broker-")
    assert f"{launch.LABEL_TRIAL}=3" in cmd
    assert f"{launch.LABEL_LAUNCHER}={launch.launcher_token()}" in cmd
    monkeypatch.setattr(b.subprocess, "run", lambda cmd, **kw:
                        subprocess.CompletedProcess(cmd, 1, "", "chown: denied"))
    assert b.chown_back("img", ["/tree"]) is False
    monkeypatch.setattr(b, "ownership_command", lambda image, paths: None)   # as root
    assert b.chown_back("img", ["/tree"]) is True
