#!/usr/bin/env bash
# Re-run selinux phase-3 (baseline + optimized) LOCALLY, now that phase3_runner
# starts fuzzing from the BUNDLED corpus (seed_corpus/build, 11 CIL policies)
# instead of the 1-byte cold-start fallback. Reuses the existing mut-resv binaries.
# Preserves the prior cold-start trials for comparison.
set -u
cd /home/sefcom/asu/project/test/benchmark

EXP=mut-resv
DUR=28800                       # 8h cap; selinux crashes well before this
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="selinux_bundled_p3_${TS}.log"
echo "$LOG" > .selinux_bundled_logname
export PHASE3_BACKEND=local

k="results/${EXP}/selinux-CVE-2021-36085"
BK="${k}/_coldstart_trials_${TS}"

{
  echo "[selinux-bundled $(date -u +%FT%TZ)] START -- preserve cold-start trials, then re-run"
  mkdir -p "${BK}/baseline" "${BK}/optimized"
  mv "${k}"/baseline/trial_*  "${BK}/baseline/"  2>/dev/null || true
  mv "${k}"/optimized/trial_* "${BK}/optimized/" 2>/dev/null || true
  echo "  cold-start trials moved to ${BK}"
  echo "  seed corpus for phase-3: $(python3 -c "import sys;sys.path.insert(0,'.');import phase3_runner as pr,types,os;d=pr.get_seed_corpus_dir('${EXP}',types.SimpleNamespace(project='selinux',cve='CVE-2021-36085'));print(d.split('seed_corpus/')[-1], sum(1 for r,_,f in os.walk(d) for _ in f),'files')")"

  echo "[selinux-bundled $(date -u +%FT%TZ)] PHASE 3 START (local, bundled, ${DUR}s)"
  python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --project selinux --duration "${DUR}"
  echo "[selinux-bundled $(date -u +%FT%TZ)] PHASE 3 DONE rc=$?"

  echo "[selinux-bundled $(date -u +%FT%TZ)] PHASE 4 (selinux) START"
  python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --project selinux
  echo "[selinux-bundled $(date -u +%FT%TZ)] DONE rc=$?"
} >> "$LOG" 2>&1
