"""Bring up the egress proxy and stage the agent's credentials.

Topology:

    agent container            proxy container          internet
    (bench-agent-egress,  -->  (both networks)     -->  allowlisted hosts only
     --internal, no route)          |
                                    +--> egress.log  (ALLOW/DENY audit trail)

The agent has no route out at all; the proxy is the only path, and it forwards
only to allowlisted hosts. Every decision is logged, so "the agent never reached
the CVE database" is something you can show rather than assert.

Credentials: both backends use subscription OAuth (a claude.ai Max plan, a
ChatGPT plan) rather than API keys. Two consequences:

  * The credential is a FILE, not an env var, so it has to be mounted.
  * Access tokens are short-lived (hours) while runs are long, so the CLI must
    refresh -- which needs the file to be WRITABLE. A read-only mount works until
    the first expiry and then fails partway through a campaign.

So a per-session COPY is mounted writable. The host credential is never exposed
to the container, and a refresh inside the sandbox cannot corrupt it.

Critically, only the single credentials FILE is mounted -- never ~/.claude, which
holds projects/ with session transcripts from prior runs on these very targets
(ASAN traces, CVE ids, bug locations). Mounting the parent directory to get the
credential would hand the agent the answer through the door the sandbox exists
to close. That is leak-inventory item 10.
"""
from __future__ import annotations

import logging
import fcntl
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

PROXY_IMAGE = os.environ.get("SANDBOX_PROXY_IMAGE", "bench-sandbox/egress")
PROXY_NAME = os.environ.get("SANDBOX_PROXY_NAME", "bench-egress-proxy")
PROXY_PORT = 8888
EXTERNAL_NETWORK = os.environ.get("SANDBOX_EXTERNAL_NETWORK", "bridge")

# Host paths holding subscription credentials, and where each backend expects
# them inside the container.
# Persistent credential store, seeded from the host once and thereafter
# maintained by the sandbox's own refreshes.
#
# This must NOT be per-session. Access tokens last hours and runs last days, so
# the CLI refreshes constantly -- and OAuth refresh tokens typically ROTATE, the
# old one being invalidated as the new one is issued. With a per-session copy the
# refreshed credential is discarded at session end and the next session re-seeds
# from a host file whose refresh token has just been revoked: auth works for
# about one token lifetime and then fails permanently, mid-campaign.
CREDENTIAL_STORE = Path(os.environ.get(
    "SANDBOX_CREDENTIAL_STORE",
    Path(__file__).resolve().parent.parent / ".sandbox-creds",
))

CREDENTIAL_FILES = {
    "claude": (Path.home() / ".claude" / ".credentials.json", "/home/agent/.claude/.credentials.json"),
    "codex": (Path.home() / ".codex" / "auth.json", "/home/agent/.codex/auth.json"),
}


def proxy_url() -> str:
    return f"http://{PROXY_NAME}:{PROXY_PORT}"


def _container_running(name: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "true"


def build_proxy_image(context_dir: str | Path) -> bool:
    """Build the proxy image. Python-only, so no package installs are needed."""
    context_dir = Path(context_dir)
    dockerfile = context_dir / "Dockerfile.egress"
    dockerfile.write_text(
        "# syntax=docker/dockerfile:1\n"
        "FROM python:3.12-alpine\n"
        "COPY egress_proxy.py /egress_proxy.py\n"
        "ENTRYPOINT [\"python3\", \"/egress_proxy.py\"]\n"
    )
    r = subprocess.run(
        ["docker", "build", "-t", PROXY_IMAGE, "-f", str(dockerfile), str(context_dir)],
        capture_output=True, text=True, errors="replace",
    )
    if r.returncode != 0:
        logger.error("egress proxy image build failed: %s", (r.stderr or "")[-500:])
    return r.returncode == 0


def build_proxy_run_command(
    *, internal_network: str, log_dir: str, extra_allow: list[str] | None = None,
) -> list[str]:
    """Run the proxy attached to the INTERNAL network, then join it to a routed one."""
    cmd = [
        "docker", "run", "-d", "--rm",
        "--name", PROXY_NAME,
        "--network", internal_network,
        "-v", f"{Path(log_dir).absolute()}:/logs",
        PROXY_IMAGE,
        "--port", str(PROXY_PORT),
    ]
    for host in (extra_allow or []):
        cmd += ["--allow", host]
    return cmd


def start_proxy(*, internal_network: str, log_dir: str,
                extra_allow: list[str] | None = None) -> str:
    """Start (or reuse) the proxy and return the URL agents should point at."""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    if _container_running(PROXY_NAME):
        return proxy_url()

    subprocess.run(["docker", "rm", "-f", PROXY_NAME], capture_output=True)
    cmd = build_proxy_run_command(
        internal_network=internal_network, log_dir=log_dir, extra_allow=extra_allow,
    )
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"could not start egress proxy: {(r.stderr or '')[-400:]}")

    # Second network gives the proxy -- and ONLY the proxy -- a route out.
    join = subprocess.run(
        ["docker", "network", "connect", EXTERNAL_NETWORK, PROXY_NAME],
        capture_output=True, text=True,
    )
    if join.returncode != 0 and "already exists" not in (join.stderr or ""):
        raise RuntimeError(
            f"proxy has no route out: {(join.stderr or '')[-300:]}"
        )
    logger.info("egress proxy up at %s (allowlisted hosts only)", proxy_url())
    return proxy_url()


def stop_proxy() -> None:
    subprocess.run(["docker", "rm", "-f", PROXY_NAME], capture_output=True)


def _credential_expiry(path) -> int:
    """Best-effort freshness key for a credential file.

    Uses the OAuth ``expiresAt`` when present (the only field that reliably
    orders two copies of a rotating credential), else falls back to mtime so a
    backend with a different file shape still compares sensibly.
    """
    from pathlib import Path as _P
    path = _P(path)
    try:
        blob = json.loads(path.read_text())
    except Exception:                                     # noqa: BLE001
        try:
            return int(path.stat().st_mtime * 1000)
        except OSError:
            return 0
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and holder.get("expiresAt"):
            try:
                return int(holder["expiresAt"])
            except (TypeError, ValueError):
                pass
        # An OAuth-shaped credential whose expiresAt is 0/absent is a FAILED
        # refresh, not an old one, and it must sort as the oldest thing there
        # is. Falling through to mtime instead ranks it by when it was written,
        # which is precisely when it is freshest -- so a poisoned copy outranks
        # the good host credential and seed_store refuses to heal from it. That
        # is what stranded b3r2: the store sat at expiresAt=0 from 18:46 on,
        # every later round reported "no fresher credential is available", and
        # the refresh token underneath was valid for another 12 days.
        if isinstance(holder, dict) and "refreshToken" in holder:
            return 0
    try:
        return int(path.stat().st_mtime * 1000)
    except OSError:
        return 0


def seed_store(backends=None) -> None:
    """Copy host credentials into the store, but only to initialize it.

    Seed-only on purpose. Once the store exists it is the authority, because it
    carries refreshes the sandbox has performed; re-seeding from the host would
    overwrite a current token with a stale (possibly revoked) one.
    """
    CREDENTIAL_STORE.mkdir(parents=True, exist_ok=True)
    os.chmod(CREDENTIAL_STORE, 0o700)
    for backend in (backends if backends is not None else CREDENTIAL_FILES):
        entry = CREDENTIAL_FILES.get(backend)
        if entry is None:
            continue
        host_path, _ = entry
        stored = CREDENTIAL_STORE / f"{backend}.json"
        if not host_path.is_file():
            if not stored.exists():
                logger.info("no %s credential at %s to seed from", backend, host_path)
            continue
        if stored.exists():
            # Take the HOST copy only when it is strictly newer. Refresh tokens
            # ROTATE: whoever refreshes last revokes the other side's token. The
            # store must win after a sandbox-side refresh (that was the original
            # reason this was seed-only), but the HOST also refreshes -- it is a
            # live CLI on this machine -- and then the store silently holds a
            # revoked token and every session dies with "401 OAuth access token
            # has been revoked". Comparing expiry handles both directions.
            if _credential_expiry(host_path) <= _credential_expiry(stored):
                continue
            logger.info("host %s credential is newer than the store; refreshing "
                        "it (the host refreshed and rotated the token)", backend)
        shutil.copy2(host_path, stored)
        os.chmod(stored, 0o600)
        logger.info("seeded %s credential into the sandbox store", backend)


# How much life an access token must have left before a session may be launched.
# The optimizer backstop is PHASE2_OPTIMIZER_TIMEOUT_SECS (4h by default), so a
# token that outlives the backstop cannot expire mid-session no matter how long
# the agent runs. Observed sessions are 13-60 min; the margin is deliberate.
MIN_TOKEN_REMAINING_SECS = int(
    os.environ.get("SANDBOX_MIN_TOKEN_REMAINING_SECS", str(5 * 3600)))

# Serialises check-and-refresh across concurrent projects. b3r2's two projects
# launched their first sandboxes 21 SECONDS apart, so without this both would
# see "under threshold", both would refresh the one shared refresh token, and the
# loser would get a rejection -- the failure this whole path exists to avoid.
CREDENTIAL_LOCK = CREDENTIAL_STORE / ".refresh.lock"

# Command that makes the HOST CLI refresh its own credential. Deliberately not a
# hand-rolled OAuth call: the CLI owns the token endpoint and the client id, and
# reimplementing that here would silently rot. Override if a cheaper trigger
# exists.
#
# It must be a command that actually TALKS to the API. Verified 2026-08-22:
# `claude auth status` never refreshes; a real prompt does, once the CLI has
# reason to believe the token is stale.
REFRESH_CMD = os.environ.get("SANDBOX_CREDENTIAL_REFRESH_CMD", 'claude -p "ok"')

# How near expiry the credential is stamped in order to make the CLI refresh it.
# See _force_refresh_via_stamp.
STAMP_REMAINING_SECS = int(os.environ.get("SANDBOX_REFRESH_STAMP_SECS", "60"))


def _access_token(path) -> str:
    """The access token STRING, or "" when absent/blank/unreadable."""
    from pathlib import Path as _P
    try:
        blob = json.loads(_P(path).read_text())
    except Exception:                                     # noqa: BLE001
        return ""
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and "accessToken" in holder:
            return str(holder.get("accessToken") or "")
    return ""


def _set_access_token(path, token: str) -> bool:
    """Restore the access token STRING, preserving the rest of the file."""
    from pathlib import Path as _P
    path = _P(path)
    try:
        blob = json.loads(path.read_text())
    except Exception:                                     # noqa: BLE001
        return False
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and "accessToken" in holder:
            holder["accessToken"] = token
            path.write_text(json.dumps(blob))
            os.chmod(path, 0o600)
            return True
    return False


def access_token_remaining_secs(path) -> float:
    """Seconds of life left in a credential's ACCESS token; 0.0 if unreadable.

    Reads expiresAt only. refreshTokenExpiresAt is a different, far longer clock
    (28 days vs ~8 hours) and confusing the two reads a dead credential as valid.
    """
    from pathlib import Path as _P
    try:
        blob = json.loads(_P(path).read_text())
    except Exception:                                     # noqa: BLE001
        return 0.0
    # A BLANK access token has no life left, however healthy expiresAt looks.
    # A CLI whose refresh is rejected rewrites accessToken to "" and leaves the
    # rest of the file intact, so the clock keeps reporting hours of life on a
    # credential that authenticates nothing. That is what stranded all ten
    # optimizers in online-24h-c1: every freshness check passed, every session
    # got an empty token, and the only symptom was "Not logged in" 10x.
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and "accessToken" in holder:
            if not str(holder.get("accessToken") or ""):
                return 0.0
            break
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and holder.get("expiresAt"):
            try:
                return max(0.0, int(holder["expiresAt"]) / 1000.0 - time.time())
            except (TypeError, ValueError):
                pass
    return 0.0


def refresh_token_remaining_secs(path) -> float:
    """Seconds of life left in a credential's REFRESH token; 0.0 if unreadable.

    The companion to access_token_remaining_secs, and the one nothing checked.
    The access token is short-lived by design and is refreshed transparently --
    but ONLY while the refresh token is alive. Once the refresh token expires,
    the CLI's startup refresh is rejected, it declares "Not logged in" and blanks
    its own copy of the access token, even though that access token had not yet
    expired.

    That is not hypothetical: campaign online-24h-c1 launched at 22:06 with a
    refresh token due to expire at 00:08. Preflight passed (the ACCESS token was
    healthy), the 20 fuzzing trials ran fine for the full budget, and every one
    of the 10 optimizers failed its first round at 00:24 -- 16 minutes after the
    refresh token died. A campaign in that state still produces a complete-looking
    result set in which the optimized arm never received a single optimization.
    """
    from pathlib import Path as _P
    try:
        blob = json.loads(_P(path).read_text())
    except Exception:                                     # noqa: BLE001
        return 0.0
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and holder.get("refreshTokenExpiresAt"):
            try:
                return max(0.0, int(holder["refreshTokenExpiresAt"]) / 1000.0 - time.time())
            except (TypeError, ValueError):
                pass
    return 0.0


def credential_outlives(seconds: float) -> tuple[bool, float]:
    """(ok, refresh_seconds_left) for the credential a campaign would actually use.

    Checks the freshest of host and store, because stage_credentials seeds from
    whichever is newer before every session.
    """
    from pathlib import Path as _P
    best = 0.0
    for cand in [p for p, _ in CREDENTIAL_FILES.values()] + \
                [CREDENTIAL_STORE / f"{b}.json" for b in CREDENTIAL_FILES]:
        if _P(cand).is_file():
            best = max(best, refresh_token_remaining_secs(cand))
    return (best >= seconds, best)


# Sessions currently holding a staged access token. A refresh REVOKES the token
# every running session is using -- observed twice in b3r3 (08:52 and 12:01),
# each costing 20-40 min of optimizer work to a relaunch. Refreshes land roughly
# every 3h while rounds run every 2h and sessions take 15-60 min, so colliding is
# the normal case, not an edge case.
INFLIGHT_DIR = CREDENTIAL_STORE / "inflight"

# A marker older than this is assumed to belong to a session that died without
# cleaning up, and stops holding off refreshes.
INFLIGHT_STALE_SECS = int(os.environ.get("SANDBOX_INFLIGHT_STALE_SECS", str(5 * 3600)))

# Below this, refresh even if sessions are in flight: revoking their token costs
# a relaunch, but letting it expire underneath them costs the same and leaves no
# valid token for the next session either.
TOKEN_HARD_FLOOR_SECS = int(os.environ.get("SANDBOX_TOKEN_HARD_FLOOR_SECS", str(90 * 60)))


def _marker_path(session_dir):
    import hashlib
    from pathlib import Path as _P
    key = hashlib.sha1(str(_P(session_dir).resolve()).encode()).hexdigest()[:16]
    return INFLIGHT_DIR / key


def mark_session_start(session_dir) -> None:
    """Record that a session is about to run on the current access token."""
    try:
        INFLIGHT_DIR.mkdir(parents=True, exist_ok=True)
        _marker_path(session_dir).write_text(str(time.time()))
    except OSError as e:
        logger.warning("could not mark session in flight: %s", e)


def clear_session_marker(session_dir) -> None:
    """Session finished; it no longer holds a token worth protecting."""
    try:
        _marker_path(session_dir).unlink()
    except OSError:
        pass


def sessions_in_flight() -> int:
    """How many sessions are currently running on a staged token.

    Stale markers are removed as they are found, so a session killed without
    cleanup cannot block refreshes forever.
    """
    if not INFLIGHT_DIR.is_dir():
        return 0
    now, live = time.time(), 0
    for p in INFLIGHT_DIR.iterdir():
        try:
            if now - p.stat().st_mtime < INFLIGHT_STALE_SECS:
                live += 1
            else:
                p.unlink()
        except OSError:
            pass
    return live


def _set_expires_at(path, when_ms: int) -> bool:
    """Rewrite only the expiresAt field of a credential, preserving the rest."""
    from pathlib import Path as _P
    path = _P(path)
    try:
        blob = json.loads(path.read_text())
    except Exception:                                     # noqa: BLE001
        return False
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict) and "expiresAt" in holder:
            holder["expiresAt"] = when_ms
            path.write_text(json.dumps(blob))
            os.chmod(path, 0o600)
            return True
    return False


def _force_refresh_via_stamp(host_path) -> bool:
    """Refresh the host access token on demand, by telling the CLI it is stale.

    The CLI refreshes only when it believes its token is about to expire, and a
    HEALTHY token cannot be refreshed by any command -- verified 2026-08-22:
    neither `claude auth status` nor a real prompt moved a token with 5.9h left.
    So stamp expiresAt a minute out and let the CLI's own logic do the rest.

    This lies DOWNWARD, which is sound: expiresAt is the client's own note about
    when to renew, and the renewal that follows is a real, server-validated
    exchange of a genuine refresh token. Lying UPWARD -- a far-future stamp to
    dodge expiry -- cannot work, because the server decides what it accepts, not
    this file.

    Verified by A/B on credentials differing only in expiresAt: at ~5.6h the CLI
    used the access token and answered normally; stamped to 60s it attempted a
    refresh instead.

    On failure the original expiry is restored, so a refresh that does not take
    cannot leave the operator's own CLI believing its token is stale.
    """
    from pathlib import Path as _P
    original = None
    # Capture the TOKEN too, not just the clock. A rejected refresh blanks
    # accessToken in place; restoring only expiresAt then writes back an EMPTY
    # token wearing a healthy future expiry -- a credential that passes every
    # check downstream and authenticates nothing. That is exactly how
    # online-24h-c1 lost all ten optimizers, and it also destroyed the
    # operator's own host login, which this function's docstring promises it
    # will not do.
    original_token = _access_token(host_path)
    try:
        blob = json.loads(_P(host_path).read_text())
        for holder in (blob, blob.get("claudeAiOauth") or {},
                       blob.get("tokens") or {}):
            if isinstance(holder, dict) and holder.get("expiresAt"):
                original = int(holder["expiresAt"])
                break
    except Exception:                                     # noqa: BLE001
        return False
    if original is None:
        return False

    stamp = int((time.time() + STAMP_REMAINING_SECS) * 1000)
    if not _set_expires_at(host_path, stamp):
        return False
    try:
        subprocess.run(REFRESH_CMD, shell=True, capture_output=True,
                       stdin=subprocess.DEVNULL, timeout=180)
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("refresh command failed: %s", e)

    if access_token_remaining_secs(host_path) > STAMP_REMAINING_SECS + 30:
        return True
    # Put the credential back EXACTLY as it was -- token first, then clock.
    # Order matters only for readability; both must be restored or the "failed
    # refresh writes nothing" guarantee is false.
    if original_token and not _access_token(host_path):
        _set_access_token(host_path, original_token)
        logger.warning(
            "the refresh attempt blanked the access token (the refresh token is "
            "expired or revoked); restored the original token, which still has "
            "%.2fh left. Run `claude` on the host to re-authenticate -- once "
            "that access token expires there is no way to renew it.",
            max(0.0, original / 1000.0 - time.time()) / 3600)
    _set_expires_at(host_path, original)      # put the clock back exactly
    return False


def ensure_fresh_host_credential(min_remaining: int | None = None) -> float:
    """Make sure the host access token outlives any session about to start.

    Returns the seconds remaining after any refresh. Serialised with flock, and
    the remaining life is RE-CHECKED after the lock is taken: a second project
    that blocked here wakes to find a freshly minted token and does nothing,
    which is what keeps one refresh per threshold crossing however many projects
    are running.

    A failed refresh writes NOTHING. A CLI that cannot refresh rewrites its
    credential with expiresAt=0, and folding that back is what stranded b3r2 for
    the last eight hours of a 24h campaign.
    """
    min_remaining = MIN_TOKEN_REMAINING_SECS if min_remaining is None else min_remaining
    host_path, _ = CREDENTIAL_FILES["claude"]
    CREDENTIAL_STORE.mkdir(parents=True, exist_ok=True)
    os.chmod(CREDENTIAL_STORE, 0o700)

    with open(CREDENTIAL_LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            remaining = access_token_remaining_secs(host_path)
            if remaining >= min_remaining:
                return remaining
            # Defer rather than collide. The threshold is generous (5h) precisely
            # so there is room to wait: a session needs at most the 4h backstop
            # and in practice 15-60 min, so a token below the threshold is still
            # comfortably enough for whoever is running. Refreshing now would
            # revoke their token for no benefit.
            busy = sessions_in_flight()
            if busy and remaining > TOKEN_HARD_FLOOR_SECS:
                logger.info(
                    "access token has %.2fh left (< %.2fh) but %d session(s) are "
                    "in flight; deferring the refresh so their token is not "
                    "revoked mid-run", remaining / 3600, min_remaining / 3600, busy)
                return remaining
            logger.info(
                "access token has %.2fh left (< %.2fh); forcing a refresh%s",
                remaining / 3600, min_remaining / 3600,
                f" despite {busy} session(s) in flight (below the "
                f"{TOKEN_HARD_FLOOR_SECS / 3600:.1f}h floor)" if busy else "")
            _force_refresh_via_stamp(host_path)
            after = access_token_remaining_secs(host_path)
            if after > remaining:
                logger.info("refreshed: access token now has %.2fh left",
                            after / 3600)
            else:
                # Not necessarily fatal, and the wording matters: a token with
                # 2h left still carries a typical 13-60 min session fine. What
                # is at risk is a session that runs to the 4h backstop. Verified
                # 2026-08-22: neither `claude auth status` nor a real inference
                # call refreshes a HEALTHY token -- the CLI refreshes only when
                # near expiry, so this branch is expected to be a no-op until
                # then and must not cry wolf.
                logger.warning(
                    "access token still has %.2fh left (wanted %.2fh) and could "
                    "not be refreshed early; short sessions are unaffected, but "
                    "one that runs to the optimizer backstop may outlive it. "
                    "Run `claude` on the host to re-authenticate.",
                    after / 3600, min_remaining / 3600)
            return after
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


API_KEY_ENV = "ANTHROPIC_API_KEY"


def api_key() -> str:
    """The sandbox's own API key, or "" to fall back to subscription OAuth.

    An API key removes the failure that cost b3r2 seven optimizer rounds. OAuth
    access tokens expire and their refresh tokens ROTATE, and this benchmark
    points three independent refreshers at ONE identity: the operator's host CLI
    and both projects' sandboxes, which run concurrently (b3r2's lcms and yara
    sessions started 21s apart and ran ~40 min each). Whichever refreshes last
    invalidates the others, so a long campaign reliably loses its back half --
    yara died at 16.7h, lcms at 18.9h, and neither recovered.

    stage_credentials hands each session a COPY so the CLI can refresh without
    racing on the file; that fixes file contention, not lineage contention. An
    API key does not expire, refresh or rotate, so N concurrent clients is fine.
    """
    return os.environ.get(API_KEY_ENV, "").strip()


def _has_refresh_token(path) -> bool:
    """Whether a credential file still carries a refresh token."""
    from pathlib import Path as _P
    try:
        blob = json.loads(_P(path).read_text())
    except Exception:                                     # noqa: BLE001
        return False
    return any(
        isinstance(h, dict) and (h.get("refreshToken") or h.get("refresh_token"))
        for h in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {})
    )


def _strip_refresh_token(path) -> bool:
    """Remove the refresh token from a staged copy, in place.

    The sandbox gets an ACCESS token and nothing else. An access token is a
    bearer credential: using it neither consumes nor rotates it, so N concurrent
    sessions holding the same one is safe. A refresh token is the opposite --
    using it destroys it and mints a replacement, so the first session to refresh
    invalidates every other holder, including the host. Removing the field makes
    that physically impossible rather than merely unlikely.

    Verified 2026-08-22: the CLI reports loggedIn and completes a real inference
    call with no refreshToken field present, and does not write one back.
    """
    from pathlib import Path as _P
    path = _P(path)
    try:
        blob = json.loads(path.read_text())
    except Exception:                                     # noqa: BLE001
        return False
    stripped = False
    for holder in (blob, blob.get("claudeAiOauth") or {}, blob.get("tokens") or {}):
        if isinstance(holder, dict):
            for field in ("refreshToken", "refresh_token"):
                if holder.pop(field, None) is not None:
                    stripped = True
    if stripped:
        path.write_text(json.dumps(blob))
        os.chmod(path, 0o600)
    return stripped


def stage_credentials(session_dir: str | Path, backends=None) -> list[str]:
    """Copy each backend's credential from the STORE into the session dir.

    A copy, mounted writable, so the CLI can refresh without racing other
    sessions on one shared file. harvest_credentials folds the result back into
    the store. Only the credential file itself is exposed -- never its parent
    directory.
    """
    session_dir = Path(session_dir)
    # Gate FIRST: refresh the host credential if it is too close to expiry,
    # before anything is copied downstream, so a session never starts on a
    # token that will die under it.
    ensure_fresh_host_credential()
    seed_store(backends)
    creds_dir = session_dir / "creds"
    creds_dir.mkdir(parents=True, exist_ok=True)
    mounts: list[str] = []
    # Default to whatever backends are actually configured, so adding or
    # removing one cannot KeyError at run time.
    for backend in (backends if backends is not None else CREDENTIAL_FILES):
        entry = CREDENTIAL_FILES.get(backend)
        if entry is None:
            logger.warning("no credential path configured for %s", backend)
            continue
        _host_path, container_path = entry
        source = CREDENTIAL_STORE / f"{backend}.json"
        if not source.is_file():
            logger.info("no %s credential in the store; skipping", backend)
            continue
        staged = creds_dir / f"{backend}.json"
        shutil.copy2(source, staged)
        os.chmod(staged, 0o600)
        stripped = _strip_refresh_token(staged)
        mark_session_start(session_dir)
        mounts.append(f"{staged}:{container_path}")
        logger.info(
            "staged %s credential for the sandbox (%s, %.2fh of access-token "
            "life left)", backend,
            "access token only" if stripped else "no refresh token present",
            access_token_remaining_secs(staged) / 3600)
    return mounts


def harvest_credentials(session_dir: str | Path, backends=None) -> list[str]:
    """Fold a session's refreshed credentials back into the store.

    Without this the sandbox re-seeds from a stale credential every session and,
    under refresh-token rotation, stops authenticating once the first rotation
    happens. Copies back only when the session file is strictly newer, so
    concurrent sessions converge on the most recent refresh instead of an
    arbitrary one.

    The HOST credential is never written. The sandbox reads it once and then
    keeps its own lineage.
    """
    creds_dir = Path(session_dir) / "creds"
    updated: list[str] = []
    # The session is over either way, so it must stop holding off refreshes even
    # if there is nothing to harvest.
    clear_session_marker(session_dir)
    if not creds_dir.is_dir():
        return updated
    CREDENTIAL_STORE.mkdir(parents=True, exist_ok=True)
    for backend in (backends if backends is not None else CREDENTIAL_FILES):
        staged = creds_dir / f"{backend}.json"
        if not staged.is_file():
            continue
        stored = CREDENTIAL_STORE / f"{backend}.json"
        try:
            # Never fold back a credential the session left un-authenticated.
            # A CLI that fails to refresh rewrites the file with expiresAt=0,
            # and mtime alone cannot tell that from a successful refresh -- so
            # the failure overwrites a WORKING store credential and every later
            # round inherits the dead one. Validate the content, not the clock.
            if _credential_expiry(staged) <= 0:
                logger.warning(
                    "not harvesting %s: the session's credential has no valid "
                    "expiry (a failed refresh, not a new token)", backend)
                continue
            # An access-token-only copy cannot have refreshed anything, so it has
            # nothing to fold back. Without this the strip propagates UPWARD: the
            # staleness test below is mtime-based, _strip_refresh_token rewrites
            # the staged file (bumping its mtime) while seed_store copy2's the
            # store (preserving the host's), so every stripped copy looks newer
            # and quietly deletes the store's own refresh token.
            if not _has_refresh_token(staged):
                continue
            if stored.exists() and staged.stat().st_mtime <= stored.stat().st_mtime:
                continue
            if stored.exists() and staged.read_bytes() == stored.read_bytes():
                continue
            shutil.copy2(staged, stored)
            os.chmod(stored, 0o600)
            updated.append(backend)
            logger.info("stored refreshed %s credential from the sandbox", backend)
        except OSError as e:
            logger.warning("could not harvest %s credential: %s", backend, e)
    return updated
