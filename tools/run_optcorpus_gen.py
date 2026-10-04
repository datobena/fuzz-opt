#!/usr/bin/env python3
"""Generate OPTIMIZED-trial corpora (which the original phase-3 never archived) so
we can do a differential coverage study: replay baseline-generated vs
optimized-generated corpora on the BASELINE binary and compare edge coverage.

Runs ONLY the optimized variant of the 5 optimized projects, 10 trials x 48h,
with ARCHIVE_CORPUS forced on. Fully isolated from new-kube-1-rerun:
  - distinct experiment id 'nk1-covgen' -> distinct job names + distinct NFS path
    (/artifacts/bena/phase3-kube/nk1-covgen/...), so nothing in new-kube-1-rerun
    (report data, the already-archived baseline corpora) is touched.
  - reuses the already-built optimized binaries + poc from new-kube-1-rerun.

The pods write corpus zips straight to NFS; pull them separately afterward with
run_covdiff.py (no orchestrator collect step, so no trial dirs are overwritten).

Run with:  python3 run_optcorpus_gen.py
(Guarded by __main__ so importing this module does NOT launch anything.)
"""
import json, logging, math, os, sys, tempfile
from pathlib import Path

os.environ.setdefault("PHASE3_BACKEND", "k8s")
os.environ["PHASE3_ARCHIVE_ALL_CORPUS"] = "1"   # archive optimized corpora too

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
import phase3_k8s as p3

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stdout)
log = logging.getLogger("optcorpus")

SRC_EXP = "new-kube-1-rerun"     # where the built binaries + poc live
EXP     = "nk1-covgen"           # isolated id for these jobs + NFS corpora
DURATION = 172800                # 48h, matching the existing baseline corpora
TRIALS, PAR = 10, 10
PROJECTS = {"libxml2", "wolfssl", "libavc", "assimp", "selinux"}


def main():
    manifest = [e for e in json.load(open(f"manifest_{SRC_EXP}.json"))
                if e["project"] in PROJECTS]
    log.info("optimized corpus-gen for: %s", [e["project"] for e in manifest])

    dockerfile = Path(__file__).resolve().parent / "k8s" / "phase3" / "Dockerfile"
    images = {}
    for e in manifest:
        project, cve, ft = e["project"], e["cve"], e.get("fuzz_target", "")
        base = Path(config.RESULTS_DIR) / SRC_EXP / p3.cve_key(project, cve)
        image = p3.image_name(project, "optimized", EXP)
        with tempfile.TemporaryDirectory(prefix="optcorpus-ctx-") as ctx, \
             tempfile.TemporaryDirectory(prefix="optcorpus-seed-") as seeddir:
            n = p3.extract_initial_corpus(base / "optimized" / "bin", ft, seeddir)
            log.info("seeds for %s/optimized: %d", project, n)
            p3.stage_build_context(bin_dir=base / "optimized" / "bin",
                                   seed_corpus_dir=seeddir, poc_dir=base / "poc",
                                   fuzz_target=ft, dest=ctx)
            build = ["docker", "build", "-f", str(dockerfile),
                     "--build-arg", f"PROJECT={project}", "--build-arg", f"CVE={cve}",
                     "--build-arg", "VARIANT=optimized", "--build-arg", f"EXPERIMENT_ID={EXP}",
                     "--build-arg", f"FUZZ_TARGET={ft}", "-t", image, ctx]
            if p3._run(build).returncode != 0:
                raise SystemExit(f"docker build failed for {image}")
        if p3._run(["docker", "push", image]).returncode != 0:
            raise SystemExit(f"docker push failed for {image}")
        images[project] = image
        log.info("pushed %s", image)

    jobs = [p3.build_job_spec(project=e["project"], cve=e["cve"], variant="optimized",
                              fuzz_target=e.get("fuzz_target", ""), experiment_id=EXP,
                              image=images[e["project"]], trials=TRIALS,
                              parallelism=PAR, duration=DURATION)
            for e in manifest]
    log.info("applying %d optimized jobs (%d trials x %ds)", len(jobs), TRIALS, DURATION)
    waves = max(1, math.ceil(TRIALS / max(1, PAR)))
    p3.apply_and_wait(jobs, deadline_secs=waves * DURATION * 2 + 3600)
    log.info("DONE: optimized corpus-gen jobs terminal.")


if __name__ == "__main__":
    main()
