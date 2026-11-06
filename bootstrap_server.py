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
    python3 bootstrap_server.py              # build everything missing or stale
    python3 bootstrap_server.py --rebuild-unverified   # ...and pre-stamping images
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from prework.build_image import DEFINITION_LABEL, definition_hash, image_tag

REPO = Path(__file__).resolve().parent
TARGETS_DIR = REPO / "prework" / "targets"
# Upstream OSS-Fuzz definitions (prework/upstream/<p>/meta.json). Checked here,
# never built here: tools/onboard_upstream.py onboards them.
UPSTREAM_TARGETS_DIR = REPO / "prework" / "upstream"
UPSTREAM_ONBOARD_NOTE = "onboard with tools/onboard_upstream.py"
AGENT_IMAGE = "bench-sandbox/agent"
PROXY_IMAGE = "bench-sandbox/egress"

OK, MISSING, FAIL = "OK", "MISSING", "FAIL"
# An image whose stamped definition hash no longer matches its target dir
# (STALE), or that predates stamping and so cannot be checked (UNVERIFIED).
STALE, UNVERIFIED = "STALE", "UNVERIFIED"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", **kw)


def _image_exists(image: str) -> bool:
    if not shutil.which("docker"):
        return False
    return _run(["docker", "image", "inspect", image]).returncode == 0


def image_definition_label(image: str) -> str | None:
    """The definition hash build_image stamped on IMAGE, or None when the image
    is absent or carries no stamp."""
    r = _run(["docker", "image", "inspect", "-f",
              f'{{{{index .Config.Labels "{DEFINITION_LABEL}"}}}}', image])
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def upstream_image_definition_label(image: str) -> str | None:
    """The definition hash prework.upstream_image stamped on IMAGE (its own
    label, not build_image's), or None when absent or unstamped."""
    from prework.upstream_image import DEFINITION_LABEL as UPSTREAM_LABEL
    r = _run(["docker", "image", "inspect", "-f",
              f'{{{{index .Config.Labels "{UPSTREAM_LABEL}"}}}}', image])
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def image_state(tag: str, target_dir: Path, *, exists=_image_exists,
                label=image_definition_label, definition=definition_hash) -> str:
    """Asking only whether the tag exists let an image fall behind its
    definition unnoticed (two did on the test box). Compare the stamped hash
    with the definition on disk instead."""
    if not exists(tag):
        return MISSING
    stamped = label(tag)
    if stamped is None:
        return UNVERIFIED
    return OK if stamped == definition(target_dir) else STALE


def _symbolizer_check() -> tuple[bool, str]:
    """Run the profiler's DWARF 5 header attribution probe, plus resolve
    LLVMFuzzerTestOneInput of an earlier fuzz target when one is on disk."""
    import importlib.util
    import config
    path = Path(config.PHASE2_SKILL_SCRIPTS_DIR) / "hotspot_table.py"
    try:
        spec = importlib.util.spec_from_file_location("hotspot_table", path)
        ht = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ht)
    except Exception as e:  # noqa: BLE001
        return False, f"cannot load {path}: {e}"
    binary = None
    for bindir in sorted(Path(config.RESULTS_DIR).glob("*/*/baseline/bin"))[:20]:
        for f in sorted(bindir.iterdir()):
            if not f.is_file() or f.suffix or f.name.startswith("afl-"):
                continue
            try:
                if ht.ElfInfo(f).symbol_addresses(["LLVMFuzzerTestOneInput"]):
                    binary = str(f)
                    break
            except Exception:  # noqa: BLE001 - not an ELF we can read
                continue
        if binary:
            break
    return ht.symbolizer_selftest(binary)


def check_prereqs() -> list[tuple[str, str, str]]:
    rows = []
    for tool in ("docker", "git", "python3"):
        rows.append((tool, OK if shutil.which(tool) else MISSING, ""))
    # The profile step maps each hotspot function to its source file on the
    # host (hotspot_table.py); without a WORKING symbolizer every round ends
    # prebuild-failed. Same lookup as the profiler (llvm-addr2line, highest numeric
    # llvm-addr2line-NN, then GNU addr2line), including header attribution.
    ok, note = _symbolizer_check()
    rows.append(("addr2line (hotspot table)", OK if ok else FAIL, note))
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

    # The Claude optimization skill is vendored under skills/; the Codex one still
    # lives in ~/.codex/skills. Without it phase 2 cannot load replay_timing.py, so run_replay_speedup
    # returns None and the gate rejects EVERY round: a campaign that burns its
    # full budget and accepts nothing. Silent because run_replay_speedup catches
    # its own failures by design, which is exactly why it is checked up front.
    scripts = Path(getattr(config, "PHASE2_SKILL_SCRIPTS_DIR", ""))
    # hotspot_table.py and target_libs.py: replay_fuzzer_profile.py loads both
    # when it starts, so without them every profile dies on import.
    needed = ("replay_timing.py", "build_corpus.py", "replay_fuzzer_profile.py",
              "hotspot_table.py", "target_libs.py")
    missing = [n for n in needed if not (scripts / n).is_file()]
    rows.append((
        f"optimizer skill ({config.PHASE2_OPTIMIZER_SKILL})",
        OK if not missing else MISSING,
        "" if not missing else
        f"missing {', '.join(missing)} under {scripts}; the Claude skill ships "
        "in skills/ (check PHASE2_SKILL_DIR / PHASE2_OPTIMIZER_SKILL), the Codex "
        "one must be copied into ~/.codex/skills",
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
        # image_tag lowercases, as docker requires; building the tag by hand
        # reported PcapPlusPlus as missing although its image was built.
        tag = image_tag(meta["project"], meta["arvo_id"])
        state = image_state(tag, target, exists=_image_exists,
                            label=image_definition_label)
        note = {
            STALE: "stale: definition changed since the image was built",
            UNVERIFIED: "unverified: built before stamping; rebuild with --rebuild-unverified",
        }.get(state, target.name)
        rows.append((tag, state, note))
    rows += _check_upstream_images()
    return rows


def _check_upstream_images() -> list[tuple[str, str, str]]:
    """One row per prework/upstream/<p>/ definition, keyed on its own label and
    definition hash. Never built by this script (build_target_images skips them):
    a missing or stale one is onboarded with tools/onboard_upstream.py."""
    rows = []
    if not UPSTREAM_TARGETS_DIR.is_dir():
        return rows
    from prework.upstream_image import definition_hash as upstream_definition_hash
    from prework.upstream_image import upstream_image_tag
    for target in sorted(UPSTREAM_TARGETS_DIR.iterdir()):
        if not (target.is_dir() and (target / "meta.json").is_file()):
            continue
        meta = json.loads((target / "meta.json").read_text())
        tag = upstream_image_tag(meta["project"])
        state = image_state(tag, target, exists=_image_exists,
                            label=upstream_image_definition_label,
                            definition=upstream_definition_hash)
        note = {
            MISSING: f"upstream {target.name}: {UPSTREAM_ONBOARD_NOTE}",
            STALE: f"stale: definition changed since the image was built; "
                   f"{UPSTREAM_ONBOARD_NOTE}",
            UNVERIFIED: f"unverified: built before stamping; {UPSTREAM_ONBOARD_NOTE}",
        }.get(state, f"upstream {target.name}")
        rows.append((tag, state, note))
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


def build_target_images(work: str, *, rebuild_unverified: bool = False
                        ) -> list[tuple[str, str, str]]:
    """Run prework per target. Each pulls a multi-GB ARVO image, so this is slow.

    Missing and stale images are rebuilt; an unverified one (built before
    stamping) only with REBUILD_UNVERIFIED, since it is most likely still fine.

    A target whose bug no longer reproduces is reported and skipped, not patched
    around -- the benchmark must only measure bugs that exist in the binary.

    Only prework/targets: upstream images (prework/upstream) are never built
    here; check_images reports them and tools/onboard_upstream.py onboards them.
    """
    results = []
    for target in sorted(TARGETS_DIR.iterdir()):
        if not (target / "meta.json").is_file():
            continue
        meta = json.loads((target / "meta.json").read_text())
        tag = image_tag(meta["project"], meta["arvo_id"])
        state = image_state(tag, target, exists=_image_exists,
                            label=image_definition_label)
        rebuild = state in (MISSING, STALE) or (state == UNVERIFIED and rebuild_unverified)
        if not rebuild:
            results.append((target.name, OK, state))
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
        mark = {OK: "  ok  ", MISSING: " todo ", FAIL: " FAIL ",
                STALE: " STALE", UNVERIFIED: "unver."}[status]
        print(f"  [{mark}] {name}" + (f"  -- {note}" if note else ""))
        if status != OK:
            worst_ok = False
    return worst_ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare a machine for an online run")
    ap.add_argument("--check", action="store_true", help="report only, build nothing")
    ap.add_argument("--work", default="/tmp/prework", help="prework artifact root")
    ap.add_argument("--rebuild-unverified", action="store_true",
                    help="also rebuild images built before definition stamping")
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
    rows = build_target_images(args.work, rebuild_unverified=args.rebuild_unverified)
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
