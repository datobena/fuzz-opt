"""The broker socket must fit AF_UNIX's 108-byte sun_path limit.

This is a length bug, so it is invisible until a path happens to be long enough:
`shakedown-1` produced 104 bytes and passed, while the campaign it was meant to
de-risk produced 114 and lost every optimization round to "broker died: AF_UNIX
path too long". A test is the only thing that catches that ordering.
"""
from __future__ import annotations

import re
from pathlib import Path

SESSION = Path(__file__).with_name("sandbox") / "session.py"


def test_socket_is_not_placed_under_the_experiment_directory():
    """The natural location -- beside the round's artifacts -- is what overflows:
    <results>/<experiment>/<project>-<cve>/optimized/online/iter_NN/sandbox/."""
    src = SESSION.read_text()
    assert 'sock_path = str(session_dir / "broker.sock")' not in src
    assert "tempfile.mkdtemp" in src


def test_the_length_is_asserted_at_runtime():
    """A guard, not just a short default: someone re-pointing this at a longer
    directory should get an error naming the path, not a dead broker thread whose
    only symptom is that the agent has no build command."""
    src = SESSION.read_text()
    assert re.search(r"len\(sock_path\.encode\(\)\)\s*>\s*\d+", src)
    assert "broker socket path too long" in src


def test_a_realistic_campaign_path_would_have_overflowed():
    """Documents the actual numbers, so the margin is not silently eaten later."""
    natural = ("/home/sefcom/fuzz-opt/results/online-24h-b1-libxml2/"
               "libxml2-arvo-1972/optimized/online/iter_01/sandbox/broker.sock")
    assert len(natural.encode()) > 108

    shakedown = ("/home/sefcom/fuzz-opt/results/shakedown-1/"
                 "libxml2-arvo-1972/optimized/online/iter_01/sandbox/broker.sock")
    assert len(shakedown.encode()) <= 108      # why the shakedown missed it


def test_the_replacement_path_shape_is_short_and_neutral(tmp_path):
    """Short enough for any results root, and carrying no project or CVE -- the
    host path is otherwise one of the few places those names appear."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="bs-"))
    try:
        sock = str(d / "b.sock")
        assert len(sock.encode()) <= 100
        for leak in ("libxml2", "wolfssl", "selinux", "arvo", "CVE"):
            assert leak not in sock
    finally:
        d.rmdir()
