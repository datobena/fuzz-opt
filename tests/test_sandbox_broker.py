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


def test_build_result_is_scrubbed(tmp_path, monkeypatch):
    import sandbox.broker as b
    monkeypatch.setattr(
        b, "_run_build",
        lambda ctx: (False, "==1==ERROR: AddressSanitizer: heap-use-after-free"),
    )
    r = handle_request({"op": "build"}, _ctx(tmp_path))
    assert r["ok"] is False
    assert "Sanitizer" not in r["log"]


def test_smoke_result_is_scrubbed(tmp_path, monkeypatch):
    import sandbox.broker as b
    monkeypatch.setattr(
        b, "_run_smoke",
        lambda ctx: (False, "SUMMARY: AddressSanitizer: stack-buffer-overflow /s/valid.c"),
    )
    r = handle_request({"op": "smoke"}, _ctx(tmp_path))
    assert "valid.c" not in r["log"] and "Sanitizer" not in r["log"]


def test_replay_time_returns_only_a_number(tmp_path, monkeypatch):
    import sandbox.broker as b
    monkeypatch.setattr(b, "_run_replay", lambda ctx, repeats: 12.5)
    r = handle_request({"op": "replay_time", "repeats": 3}, _ctx(tmp_path))
    assert r == {"ok": True, "seconds": 12.5, "repeats": 3}


def test_replay_repeats_is_clamped(tmp_path, monkeypatch):
    """An agent asking for 10_000 repeats must not wedge the host."""
    import sandbox.broker as b
    seen = {}
    monkeypatch.setattr(
        b, "_run_replay", lambda ctx, repeats: seen.setdefault("n", repeats) and 1.0)
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

    monkeypatch.setattr(b, "_run_replay", lambda ctx, repeats: 4.25)
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
