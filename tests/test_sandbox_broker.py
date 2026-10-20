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
    monkeypatch.setattr(b, "_run", lambda cmd, t: (
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
    monkeypatch.setattr(b, "_run", lambda cmd, t: (0, blob))
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
    monkeypatch.setattr(b, "_run", lambda cmd, t: seen.setdefault("cmd", cmd) and (0, "r"))
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
