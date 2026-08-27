"""Allowlisting HTTPS CONNECT proxy — the agent's only route off the internal network.

The agent container sits on a docker `--internal` network with no route out. This
proxy is attached to BOTH that network and a normal bridge, so it is the single
place traffic can leave, and it forwards only to allowlisted hosts.

Why a proxy rather than firewall rules: the decision is per-HOSTNAME, and it is
made in one auditable place that LOGS every allow and deny. That log is evidence
-- it is how you show the agent never reached github.com or the ARVO metadata,
rather than asserting it. Without network confinement an agent can look up the
CVE, fetch ARVO-Meta by image id, or diff the vulnerable tree against upstream,
and a measured bug-survival rate then means nothing.

Deny is the default: an unlisted host gets 403 and a log line.
"""
from __future__ import annotations

import argparse
import logging
import select
import socket
import socketserver
import sys
import threading

logger = logging.getLogger("egress")

# Subscription-OAuth endpoints for both optimizer backends. Inference plus the
# token-refresh hosts: a long run outlives its access token, and a refresh that
# cannot reach its endpoint fails partway through rather than at startup.
DEFAULT_ALLOWLIST = (
    # Claude (claude.ai Max / Pro subscription auth)
    "api.anthropic.com",
    "console.anthropic.com",
    # The CLI refreshes its OAuth token against platform.claude.com, which this
    # list predates. Without it the refresh is denied, the access token expires
    # a few hours in, and EVERY remaining round dies on "401 OAuth access token
    # has expired" -- observed 2026-08-14: first DENY 12:40:49, first 401 at
    # 12:50:54, and the yara arm lost rounds 5 and 6 outright.
    "platform.claude.com",
    "claude.ai",
    # Codex (ChatGPT subscription auth)
    "api.openai.com",
    "auth.openai.com",
    "chatgpt.com",
)

BUFFER = 65536


def host_allowed(host: str, allowlist) -> bool:
    """Exact match or a dotted-suffix match, so a lookalike cannot slip through.

    'evil-api.anthropic.com.attacker.net' must NOT match 'api.anthropic.com';
    requiring the '.' boundary is what prevents that.
    """
    host = (host or "").lower().strip().rstrip(".")
    for allowed in allowlist:
        allowed = allowed.lower()
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


class Handler(socketserver.BaseRequestHandler):
    allowlist: tuple = DEFAULT_ALLOWLIST

    def handle(self):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(BUFFER)
                if not chunk:
                    return
                data += chunk
                if len(data) > 32768:
                    return
            line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                # Plain HTTP is not proxied at all: it would let content through
                # unencrypted and inspectable, and nothing here needs it.
                self._deny(line, reason="non-CONNECT")
                return
            hostport = parts[1]
            host, _, port = hostport.partition(":")
            port = int(port or 443)

            if not host_allowed(host, self.allowlist):
                self._deny(hostport, reason="not allowlisted")
                return

            try:
                upstream = socket.create_connection((host, port), timeout=30)
            except OSError as e:
                logger.warning("FAIL %s:%s (%s)", host, port, e)
                self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            logger.info("ALLOW %s:%s", host, port)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._tunnel(self.request, upstream)
        except Exception as e:                                   # noqa: BLE001
            logger.debug("handler error: %s", e)

    def _deny(self, what: str, *, reason: str):
        logger.warning("DENY %s (%s)", what, reason)
        try:
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        except OSError:
            pass

    @staticmethod
    def _tunnel(a: socket.socket, b: socket.socket):
        socks = [a, b]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 60)
                if x or not r:
                    break
                for s in r:
                    other = b if s is a else a
                    buf = s.recv(BUFFER)
                    if not buf:
                        return
                    other.sendall(buf)
        except OSError:
            pass
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass


class ThreadedProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = "0.0.0.0", port: int = 8888, allowlist=DEFAULT_ALLOWLIST):
    Handler.allowlist = tuple(allowlist)
    logger.info("egress proxy on %s:%d; allowlist=%s", host, port, ",".join(allowlist))
    with ThreadedProxy((host, port), Handler) as srv:
        srv.serve_forever()


def main() -> int:
    ap = argparse.ArgumentParser(description="Allowlisting CONNECT proxy")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--allow", action="append", default=[],
                    help="extra allowed host (repeatable)")
    args = ap.parse_args()
    logging.basicConfig(
        level=logging.INFO, stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    serve(port=args.port, allowlist=tuple(DEFAULT_ALLOWLIST) + tuple(args.allow))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
