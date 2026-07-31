#!/usr/bin/env python3
"""Minimal broker client shared by the fold-* tools.

The agent has no docker access; these three commands are its entire interface to
building and measuring. One JSON object out, one JSON object back.
"""
from __future__ import annotations

import json
import socket
import sys

SOCK = "/run/broker.sock"


def request(payload: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(SOCK)
    except OSError as e:
        print(f"broker unreachable: {e}", file=sys.stderr)
        raise SystemExit(70)
    try:
        s.sendall(json.dumps(payload).encode() + b"\n")
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
            if b.endswith(b"\n"):
                break
    finally:
        s.close()
    try:
        return json.loads(b"".join(chunks).decode("utf-8", "replace"))
    except ValueError as e:
        print(f"malformed broker reply: {e}", file=sys.stderr)
        raise SystemExit(70)


def main(payload: dict) -> int:
    reply = request(payload)
    if reply.get("log"):
        print(reply["log"])
    if "seconds" in reply:
        print(f"replay_seconds={reply['seconds']:.4f} repeats={reply['repeats']}")
    if not reply.get("ok"):
        if reply.get("error"):
            print(f"error: {reply['error']}", file=sys.stderr)
        return 1
    return 0
