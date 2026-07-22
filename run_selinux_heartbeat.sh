#!/usr/bin/env bash
# Hourly heartbeat for the no-timeout selinux re-optimization. Records whether the
# optimizer process is alive, whether its log is still growing, and which relevant
# docker containers are active — so a genuine hang is distinguishable from a slow
# but working run. Never kills anything.
#   $1 = pid of run_selinux_opt.py   $2 = its stdout log   $3 = heartbeat out file
set -u
PID="$1"; OPT_LOG="$2"; HB="$3"
echo "$(date -u +%FT%TZ) heartbeat start (watching pid=$PID, log=$OPT_LOG)" >> "$HB"
prev_size=-1
while :; do
  ts=$(date -u +%FT%TZ)
  if kill -0 "$PID" 2>/dev/null; then alive=yes; else alive=no; fi
  size=$(stat -c %s "$OPT_LOG" 2>/dev/null || echo 0)
  mtime=$(stat -c %y "$OPT_LOG" 2>/dev/null | cut -d. -f1)
  last=$(tail -n1 "$OPT_LOG" 2>/dev/null | cut -c1-180)
  dk=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'selinux|secilc|poff|arvo|oss-fuzz' | tr '\n' ',')
  grew="no"; [ "$size" != "$prev_size" ] && grew="yes"; prev_size="$size"
  echo "$ts alive=$alive log_grew_since_last=$grew log_bytes=$size log_mtime=$mtime dockers=[$dk]" >> "$HB"
  echo "    last: $last" >> "$HB"
  [ "$alive" = no ] && { echo "$ts selinux-opt process EXITED" >> "$HB"; break; }
  sleep 3600
done
