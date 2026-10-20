#!/usr/bin/env python3
"""End-of-campaign check for ccache (fuzzbench-parity-ccache, section 3).

For every optimized trial that had its own ccache (main + cmplog builds), rebuild the
trial's FINAL
ACCEPTED tree (git tag of its last `kept` round) WITHOUT a cache and compare with
the binaries the campaign actually used (iter_NN/bin of that round): sha256 of
/out/<t> and /out/cmplog/<t> and the dictionary entry set. A mismatch flags the
trial: a binary it fuzzed was not what an uncached FuzzBench build would produce.

  python3 tools/fb_ccache_verify_campaign.py \\
      --online-dir results/<exp>/<project>-<cve>/optimized/online \\
      --dir php_php-fuzz-parser_0dbedb --project php \\
      --cpuset 40-59 --work <scratch>/verify_php

Writes <work>/verify.json and prints a short table. Exit 0 iff no trial differs
(trials with no cache or no accepted round are reported as skipped). A target
marked `pass_noise_masked` on the verified list (--verified-list, default the repo's
prework/fuzzbench_ccache_verified.txt) gets --noise automatically: the tree is
rebuilt twice uncached and the used binaries may differ from it only inside that
noise (fb_ccache.compare_with_noise, the same check the equivalence test and the
campaign template check use). --noise forces it for any target.
"""
from __future__ import annotations

import argparse
import atexit
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from lib import tracked_git  # noqa: E402
from prework import fb_ccache  # noqa: E402
from prework.fuzzbench_image import fuzzbench_build_command, fuzzbench_image_tag  # noqa: E402
from tools.fb_ccache_equivalence import (  # noqa: E402
    VCS_DIRS, _CONTAINERS, _cleanup_containers, _fuzz_target, _on_signal, chown_back,
)


def trial_dirs(online_dir: Path) -> list[Path]:
    """trials/trial_XX in per-trial mode, else the online dir itself."""
    t = sorted((online_dir / "trials").glob("trial_*"))
    return t or [online_dir]


def last_kept_iter(trial_dir: Path) -> int | None:
    try:
        ledger = json.loads((trial_dir / "ledger.json").read_text())
    except (OSError, ValueError):
        return None
    kept = [int(e["iter"]) for e in ledger if e.get("outcome") == "kept"]
    return max(kept) if kept else None


def project_tree(trial_dir: Path, project: str) -> Path | None:
    root = trial_dir / "source_root"
    if not root.is_dir():
        root = trial_dir / "source_tree"
    if not root.is_dir():
        return None
    try:
        import phase2_setup
        return Path(phase2_setup._find_project_source(root, project))
    except Exception:  # noqa: BLE001
        cand = root / "src" / project
        return cand if cand.is_dir() else None


def materialize(tree: Path, tag: str, dest: Path) -> dict:
    """Copy the working tree (keeps git-ignored inputs the build needs), then
    overlay the tagged commit's tracked files. Records whether the working tree
    already matched the tag (it should: rejected rounds are reset to it)."""
    g = tracked_git.git_cmd(tree)
    clean = subprocess.run(g + ["diff", "--quiet", tag, "--"], cwd=tree,
                           capture_output=True).returncode == 0
    untracked = subprocess.run(g + ["ls-files", "--others", "--exclude-standard"],
                               cwd=tree, capture_output=True, text=True).stdout.split()
    shutil.copytree(tree, dest, symlinks=True, ignore=shutil.ignore_patterns(*VCS_DIRS))
    arc = subprocess.run(g + ["archive", "--format=tar", tag], cwd=tree,
                         capture_output=True)
    if arc.returncode != 0:
        raise RuntimeError(f"git archive {tag} failed: {arc.stderr.decode()[-200:]}")
    with tarfile.open(fileobj=io.BytesIO(arc.stdout)) as tf:
        tf.extractall(dest, filter="tar")   # our own commit; keep modes as-is
    return {"worktree_matches_tag": clean and not untracked,
            "untracked_files": untracked[:20]}


def verify_trial(trial_dir: Path, *, a, image: str, target: str, work: Path) -> dict:
    rec: dict = {"trial": trial_dir.name}
    cache = Path(fb_ccache.trial_cache_dir(trial_dir))
    if not cache.is_dir():
        return {**rec, "status": "skipped", "why": "no ccache dir"}
    n = last_kept_iter(trial_dir)
    if n is None:
        return {**rec, "status": "skipped", "why": "no accepted round (baseline is uncached)"}
    tag = f"iter_{n:02d}"
    used = trial_dir / tag / "bin"
    if not (used / target).is_file():
        return {**rec, "status": "error", "why": f"{used}/{target} missing"}
    try:
        prov = json.loads((trial_dir / tag / "round_provenance.json").read_text())
        rec["round_ccache"] = prov.get("ccache", prov.get("cmplog_ccache"))
    except (OSError, ValueError):
        rec["round_ccache"] = None
    tree = project_tree(trial_dir, a.project)
    if tree is None:
        return {**rec, "status": "error", "why": "trial source tree not found"}
    tdir = work / trial_dir.name
    if tdir.exists():
        chown_back(image, [tdir], a.cpuset)
        shutil.rmtree(tdir)
    src = tdir / "src" / tree.name
    rec["tag"] = tag
    rec.update(materialize(tree, tag, src))
    rebuilds = []
    for k in range(2 if a.noise else 1):
        out = tdir / ("out" if k == 0 else "out2")
        out.mkdir(parents=True)
        cname = f"fbcc-verify-{os.getpid()}-{trial_dir.name}-{k}"
        cmd = fuzzbench_build_command(image=image, source_dir=str(src), out_dir=str(out),
                                      cpu=a.cpuset,
                                      extra_docker_args=["--name", cname, "--ulimit", "core=0"])
        _CONTAINERS.add(cname)
        t0 = time.time()
        log = tdir / ("build.log" if k == 0 else "build2.log")
        try:
            with open(log, "w") as fh:
                r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                   timeout=a.timeout)
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = 124
        finally:
            subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
            _CONTAINERS.discard(cname)
        chown_back(image, [out], a.cpuset)
        rec.setdefault("rebuild_s", []).append(round(time.time() - t0, 1))
        if rc != 0:
            return {**rec, "status": "error", "why": f"uncached rebuild failed (rc={rc})",
                    "log": str(log)}
        rebuilds.append(out)
    if a.noise:
        # Two uncached rebuilds of the same tree give the build's own noise (php's
        # hostname / __DATE__); the used binary may differ from them only there.
        cmp = fb_ccache.compare_with_noise(rebuilds[0], rebuilds[1], used, target)
        rec["compare"] = cmp
        rec["status"] = ("MISMATCH" if not cmp["ok"] else
                         {"identical": "match", "masked": "match_noise_masked"}[cmp["status"]])
        return rec
    cmp = fb_ccache.compare_outs(used, rebuilds[0], target)
    rec["compare"] = cmp
    rec["status"] = "match" if cmp["identical"] else "MISMATCH"
    return rec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--online-dir", required=True, help="<experiment>/optimized/online")
    ap.add_argument("--dir", required=True, help="fuzzbench_dir")
    ap.add_argument("--project", required=True, help="manifest project (source subdir)")
    ap.add_argument("--fuzz-target")
    ap.add_argument("--image")
    ap.add_argument("--cpuset", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--trials", help="comma list of trial dir names (default: all)")
    ap.add_argument("--timeout", type=int, default=6 * 3600)
    ap.add_argument("--noise", action="store_true",
                    help="rebuild twice and mask the build's own noise (automatic for "
                         "a target marked pass_noise_masked on the verified list)")
    ap.add_argument("--verified-list", help="verified list to read the target's marker "
                    "from (default: prework/fuzzbench_ccache_verified.txt)")
    a = ap.parse_args(argv)
    mode = fb_ccache.read_verified_modes(a.verified_list).get(a.dir)
    if mode == fb_ccache.MODE_NOISE and not a.noise:
        a.noise = True
        print(f"{a.dir} is marked {mode} on the verified list: using --noise", flush=True)
    atexit.register(_cleanup_containers)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    image = a.image or fuzzbench_image_tag(a.dir)
    target = a.fuzz_target or _fuzz_target(a.dir)
    if not target:
        print("cannot find fuzz_target; pass --fuzz-target", file=sys.stderr)
        return 2
    work = Path(a.work).absolute()
    work.mkdir(parents=True, exist_ok=True)
    want = set(a.trials.split(",")) if a.trials else None
    results = []
    for td in trial_dirs(Path(a.online_dir).absolute()):
        if want and td.name not in want:
            continue
        try:
            r = verify_trial(td, a=a, image=image, target=target, work=work)
        except Exception as e:  # noqa: BLE001 -- report, keep going
            r = {"trial": td.name, "status": "error", "why": f"{type(e).__name__}: {e}"}
        results.append(r)
        print(f"{r['trial']:10s} {r['status']:9s} {r.get('tag', '')} {r.get('why', '')}",
              flush=True)
    bad = [r for r in results if r["status"] in ("MISMATCH", "error")]
    out = {"online_dir": a.online_dir, "dir": a.dir, "image": image, "target": target,
           "verified_mode": mode, "noise": bool(a.noise),
           "trials": results, "flagged": [r["trial"] for r in bad],
           "ok": not any(r["status"] == "MISMATCH" for r in results) and not bad}
    (work / "verify.json").write_text(json.dumps(out, indent=1, default=str))
    print(f"verify: {'OK' if out['ok'] else 'FLAGGED ' + ', '.join(out['flagged'])} "
          f"-> {work / 'verify.json'}")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
