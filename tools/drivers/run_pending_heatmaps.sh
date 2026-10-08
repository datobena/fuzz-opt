#!/bin/bash
# Generate line-coverage heatmaps for the three complete bug-* campaigns whose
# .linecov cache does not exist yet -- AFTER every campaign on this host has
# finished.
#
# WHY IT WAITS. line_exec_counts.py does a SANITIZER=coverage build plus a
# replay of all 20 accumulated queues per project. That is heavy, and the only
# cores left on this box are 40-79, which are the HT siblings of the cores a
# running campaign's trials sit on -- they share execution units, so using them
# measurably slows the campaign whose single output is a TIMING measurement.
# So: poll until no run_benchmark.py is alive, then work. The guard is "no
# campaign at all", not "not harfbuzz", because campaigns here are launched
# back to back and a successor deserves the same protection.
set -u
cd "$(dirname "$0")/../.."

EXPS=${EXPS:-"online-24h-bug-libxml2 online-24h-bug-mbedtls online-24h-bug-php-src"}
LOG=.pending_heatmaps.log
POLL=${POLL:-300}

echo "[$(date -u +%FT%TZ)] waiting for all campaigns to finish" >> "$LOG"
while pgrep -f 'run_benchmark\.py' > /dev/null; do sleep "$POLL"; done
# A campaign's containers outlive its orchestrator briefly; do not race them.
sleep 120
echo "[$(date -u +%FT%TZ)] host idle, starting" >> "$LOG"

for exp in $EXPS; do
  echo "[$(date -u +%FT%TZ)] $exp: line_exec_counts" >> "$LOG"
  if ! nice -n 10 python3 analysis/line_exec_counts.py --experiment "$exp" >> "$LOG" 2>&1; then
    echo "[$(date -u +%FT%TZ)] $exp: line_exec_counts FAILED, skipping heatmap" >> "$LOG"
    continue
  fi
  echo "[$(date -u +%FT%TZ)] $exp: heatmap" >> "$LOG"
  nice -n 10 python3 analysis/coverage_heatmap.py --experiment "$exp" >> "$LOG" 2>&1 \
    || echo "[$(date -u +%FT%TZ)] $exp: heatmap FAILED" >> "$LOG"
done
echo "[$(date -u +%FT%TZ)] done" >> "$LOG"
