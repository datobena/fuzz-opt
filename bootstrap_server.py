#!/usr/bin/env python3
"""Bring a fresh machine up to the point where an online run can start.

Everything the pipeline needs at runtime is either in this repo or rebuildable
from it -- with one exception per target: the multi-GB prework images, which are
built here rather than shipped.

Deliberately NOT required on a new machine:
  * an oss-fuzz checkout (only phase2_setup's legacy OSV/ARVO-reproducer paths
    touch config.OSS_FUZZ_DIR; the sandboxed AFL path does not)
  * any prior results/ directory (the one target whose PoC could not be
    re-extracted from its image now ships beside the target)

Still manual, because they cannot be automated safely:
  * `claude` (and/or `codex`) login, so the sandbox has a credential to stage
  * core-count settings, which depend on the machine

    python3 bootstrap_server.py --check      # report readiness, change nothing
    python3 bootstrap_server.py              # build everything missing
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
TARGETS_DIR = REPO / "prework" / "targets"
AGENT_IMAGE = "bench-sandbox/agent"
PROXY_IMAGE = "bench-sandbox/egress"

OK, MISSING, FAIL = "OK", "MISSING", "FAIL"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", **kw)


def _image_exists(image: str) -> bool:
    if not shutil.which("docker"):
        return False
    return _run(["docker", "image", "inspect", image]).returncode == 0


def check_prereqs() -> list[tuple[str, str, str]]:
    rows = []
    for tool in ("docker", "git", "python3"):
        rows.append((tool, OK if shutil.which(tool) else MISSING, ""))
    if not shutil.which("docker"):
        rows.append(("docker daemon", MISSING, "docker is not installed"))
    else:
        d = _run(["docker", "info"])
        rows.append(("docker daemon", OK if d.returncode == 0 else FAIL,
                     "" if d.returncode == 0 else "cannot talk to the daemon"))

    cores = os.cpu_count() or 0
    import config
    note = ""
    if cores and cores != config.TOTAL_CORES:
        note = (f"config.TOTAL_CORES={config.TOTAL_CORES} but this box has {cores}; "
                f"set TOTAL_CORES and ONLINE_TRIAL_CORES/ONLINE_OPTIMIZER_CORES")
    rows.append((f"cpu cores ({cores})", OK if not note else MISSING, note))

    from sandbox import egress
    have_cred = any(p.is_file() for p, _ in egress.CREDENTIAL_FILES.values()) or \
        (egress.CREDENTIAL_STORE / "claude.json").is_file()
    rows.append(("optimizer credential", OK if have_cred else MISSING,
                 "" if have_cred else "run `claude` once to log in (Max plan is fine)"))

    # The store SHADOWS the host credential: seed_store never re-seeds once a
    # file exists, so a stub left there (a test that forgot to redirect it, a
    # truncated write) silently authenticates nothing for the rest of the
    # machine's life. The agent then exits "Not logged in" and the round is
    # recorded as "no changes made" -- a real-looking negative result.
    stub = []
    for backend in egress.CREDENTIAL_FILES:
        stored = egress.CREDENTIAL_STORE / f"{backend}.json"
        if stored.is_file() and stored.stat().st_size < 200:
            stub.append(str(stored))
    rows.append((
        "credential store is not a stub",
        OK if not stub else FAIL,
        "" if not stub else
        f"{', '.join(stub)} is implausibly small; delete it and it re-seeds from "
        "the host credential on the next run",
    ))

    # The REFRESH token must outlive the campaign, not just the access token.
    # The access token is short-lived and refreshed transparently -- but only
    # while the refresh token is alive. When it dies mid-campaign the CLI's
    # startup refresh is rejected, it reports "Not logged in" and blanks its own
    # access token, and EVERY optimizer round fails from that moment on while
    # the fuzzing trials keep running to the full budget. The result set looks
    # complete; the optimized arm simply never got an optimization.
    #
    # online-24h-c1 launched with 2.0h of refresh token left on a 24h budget and
    # lost all 10 optimizers at 00:08. Checked here because nothing else looks:
    # access_token_remaining_secs reads expiresAt only, by design.
    want_secs = float(os.environ.get("PREFLIGHT_CAMPAIGN_SECS",
                                     getattr(config, "TRIAL_DURATION_SECS", 86400)))
    cred_ok, refresh_left = egress.credential_outlives(want_secs)
    rows.append((
        "refresh token outlives the campaign",
        OK if cred_ok else FAIL,
        "" if cred_ok else
        f"only {refresh_left/3600:.1f}h of refresh-token life left but the "
        f"campaign needs {want_secs/3600:.1f}h; run `claude` on the host to "
        f"re-authenticate BEFORE launching, or every optimizer round will fail "
        f"once it expires while the trials keep fuzzing",
    ))

    # The optimization skill is NOT in this repo -- it lives in the agent's skill
    # tree. Without it phase 2 cannot load replay_timing.py, so run_replay_speedup
    # returns None and the gate rejects EVERY round: a campaign that burns its
    # full budget and accepts nothing. Silent because run_replay_speedup catches
    # its own failures by design, which is exactly why it is checked up front.
    scripts = Path(getattr(config, "PHASE2_SKILL_SCRIPTS_DIR", ""))
    needed = ("replay_timing.py", "build_corpus.py", "replay_fuzzer_profile.py")
    missing = [n for n in needed if not (scripts / n).is_file()]
    rows.append((
        f"optimizer skill ({config.PHASE2_OPTIMIZER_SKILL})",
        OK if not missing else MISSING,
        "" if not missing else
        f"missing {', '.join(missing)} under {scripts}; copy the skill tree from "
        "a machine that has it -- it is not carried in this repo",
    ))
    return rows


def check_images() -> list[tuple[str, str, str]]:
    rows = [
        (AGENT_IMAGE, OK if _image_exists(AGENT_IMAGE) else MISSING, ""),
        (PROXY_IMAGE, OK if _image_exists(PROXY_IMAGE) else MISSING, ""),
    ]
    for target in sorted(TARGETS_DIR.iterdir()):
        if not (target / "meta.json").is_file():
            continue
        meta = json.loads((target / "meta.json").read_text())
        tag = f"bench-aflpp/{meta['project']}-arvo-{meta['arvo_id']}"
        rows.append((tag, OK if _image_exists(tag) else MISSING, target.name))
    return rows


def build_support_images() -> bool:
    ok = True
    if not _image_exists(AGENT_IMAGE):
        print(f"[build] {AGENT_IMAGE}")
        r = _run(["docker", "build", "-t", AGENT_IMAGE,
                  "-f", str(REPO / "sandbox" / "Dockerfile.agent"),
                  str(REPO / "sandbox")])
        if r.returncode != 0:
            print(r.stderr[-800:])
            ok = False
    if not _image_exists(PROXY_IMAGE):
        print(f"[build] {PROXY_IMAGE}")
        from sandbox.egress import build_proxy_image
        ok = build_proxy_image(REPO / "sandbox") and ok
    return ok


def build_target_images(work: str) -> list[tuple[str, str, str]]:
    """Run prework per target. Each pulls a multi-GB ARVO image, so this is slow.

    A target whose bug no longer reproduces is reported and skipped, not patched
    around -- the benchmark must only measure bugs that exist in the binary.
    """
    results = []
    for target in sorted(TARGETS_DIR.iterdir()):
        if not (target / "meta.json").is_file():
            continue
        meta = json.loads((target / "meta.json").read_text())
        tag = f"bench-aflpp/{meta['project']}-arvo-{meta['arvo_id']}"
        if _image_exists(tag):
            results.append((target.name, OK, "already built"))
            continue
        print(f"[prework] {target.name} (pulls a multi-GB ARVO image; slow)")
        r = subprocess.run(
            [sys.executable, "-m", "prework.run_prework",
             "--target", str(target), "--work", work],
            cwd=str(REPO),
        )
        results.append((target.name, OK if r.returncode == 0 else FAIL,
                        "" if r.returncode == 0 else f"exit {r.returncode}"))
    return results


def report(title: str, rows) -> bool:
    print(f"\n{title}")
    worst_ok = True
    for name, status, note in rows:
        mark = {OK: "  ok  ", MISSING: " todo ", FAIL: " FAIL "}[status]
        print(f"  [{mark}] {name}" + (f"  -- {note}" if note else ""))
        if status != OK:
            worst_ok = False
    return worst_ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare a machine for an online run")
    ap.add_argument("--check", action="store_true", help="report only, build nothing")
    ap.add_argument("--work", default="/tmp/prework", help="prework artifact root")
    args = ap.parse_args()
    sys.path.insert(0, str(REPO))

    a = report("prerequisites", check_prereqs())
    b = report("images", check_images())

    if args.check:
        print("\n--check: nothing built.")
        return 0 if (a and b) else 1

    if not build_support_images():
        print("\nsupport images failed to build; stopping before prework")
        return 2
    rows = build_target_images(args.work)
    c = report("prework targets", rows)

    ready = [n for n, s, _ in rows if s == OK]
    print(f"\n{len(ready)}/{len(rows)} targets ready")
    if not c:
        print("A failed target is EXCLUDED, not patched around: the benchmark "
              "only measures bugs that demonstrably exist in the binary.")
    print("\nnext: python3 run_benchmark.py --phase online   (see docs/)")
    return 0 if (a and b and c) else 1


if __name__ == "__main__":
    raise SystemExit(main())
