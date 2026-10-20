#!/usr/bin/env bash
# shellcheck disable=SC2317  # getters/fixers are called indirectly through item()
# configure_fuzz_host.sh -- check, or reproduce, the CPU and kernel tuning of the
# fuzzing benchmark host r440-2-13 on another host with the same hardware.
#
# Captured 2026-10-20 from:
#   host     r440-2-13 (Dell PowerEdge R440, BIOS 2.11.2)
#   cpu      Intel(R) Xeon(R) Gold 5218R CPU @ 2.10GHz
#            2 sockets x 20 cores x 2 threads = 80 logical CPUs, 2 NUMA nodes
#            (even CPUs on node0, odd on node1, HT sibling of cpuN is cpuN+40)
#   kernel   6.8.0-142-generic, Ubuntu 24.04.2 LTS, microcode 0x5003901
#
# What r440-2-13 sets on purpose, and how it persists there:
#   - governor=performance on every CPU: /etc/systemd/system/cpu-governor.service
#     (oneshot running `cpupower frequency-set -g performance`, added 2026-10-05).
#   - From its BIOS: no HWP, so intel_pstate runs passive (intel_cpufreq); C6 is
#     left out of ACPI _CST (only POLL/C1/C1E are usable); uncore is fixed at
#     2.4 GHz; turbo and Hyper-Threading are on.
#   - apport owns kernel.core_pattern (stock apport.service, re-set at every boot).
# Everything else checked here is the stock Ubuntu/kernel value. It is checked
# because those are the knobs fuzzing tuning (afl-system-config,
# afl-persistent-config) changes, and a twin tuned that way is not a twin. The
# kernel command line on r440-2-13 is only BOOT_IMAGE=, root= and ro.
# Not readable on r440-2-13 without root (so not captured): sched debugfs knobs,
# /dev/cpu_dma_latency holders, root's crontab. Run as root they print as INFO.
#
# --core-pattern=apport (default, as on r440-2-13) spawns a host Python process for
# every target crash; phase3_runner.py:491-497 expects `core`. --check honors it too.
#
# Usage:
#   configure_fuzz_host.sh [--check] [--core-pattern=apport|core]
#       read-only (default); exit 1 on any DIFF or FAILED
#   sudo configure_fuzz_host.sh --apply [--core-pattern=...] [--restart-docker] [--force]
#       refuses (exit 2) while docker containers run, unless --force
#   CFG_ROOT=/tmp/t configure_fuzz_host.sh --apply --files-only
#       test mode: only the /etc, /usr, /run and /var file edits, written under
#       $CFG_ROOT; no sysfs, /proc, systemctl, update-grub or docker. Refuses to
#       run as root, so a test can never write outside $CFG_ROOT.
#
# Output: one line per setting.
#   OK / DIFF    matches / differs (any DIFF makes the exit status 1)
#   FIXED        --apply changed it and it now matches
#   FAILED       --apply tried and failed (exit status 1)
#   WARN         hardware, firmware or kernel mismatch: reported, never applied
#   SKIP / INFO  not checked in this mode / printed for comparison only

set -euo pipefail
shopt -s nullglob
export LC_ALL=C   # byte-order sorting (as systemd-sysctl orders files), stable tool output
exec </dev/null   # nothing here reads stdin: a grep/cat over an empty glob must not hang

MODE=check FILES_ONLY=0 RESTART_DOCKER=0 FORCE=0 CORE_MODE=apport
for arg in "$@"; do
  case $arg in
    --check) MODE=check ;;
    --apply) MODE=apply ;;
    --files-only) FILES_ONLY=1 ;;
    --restart-docker) RESTART_DOCKER=1 ;;
    --force) FORCE=1 ;;
    --core-pattern=apport|--core-pattern=core) CORE_MODE=${arg#*=} ;;
    -h|--help) sed -n '3,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg (see --help)" >&2; exit 2 ;;
  esac
done

# Prefix for every /etc, /usr, /run and /var path (tests only). "//", "/." and a
# trailing slash all mean the real root.
R=""
if [[ -n ${CFG_ROOT:-} ]]; then
  R=$(realpath -m -- "$CFG_ROOT")
  [[ $R != / ]] || R=""
fi
TS=$(date +%Y%m%d-%H%M%S)   # backup suffix: <file>.bak.$TS
CPU=/sys/devices/system/cpu
NODE=/sys/devices/system/node
CLK=/sys/devices/system/clocksource/clocksource0
MM=/sys/kernel/mm
GRUB_CFG=/boot/grub/grub.cfg
LSM_FILE=/sys/kernel/security/lsm
IOMMU_DIR=/sys/kernel/iommu_groups

if [[ $MODE == apply ]]; then
  if [[ $FILES_ONLY == 1 ]]; then
    [[ -n $R ]] || { echo "--files-only needs CFG_ROOT=<test dir> other than /" >&2; exit 2; }
    [[ $EUID -ne 0 ]] || { echo "--files-only is a test mode and refuses to run as root" >&2; exit 2; }
  else
    [[ -z $R ]] || { echo "CFG_ROOT is only for --files-only tests" >&2; exit 2; }
    [[ $EUID -eq 0 ]] || { echo "--apply needs root" >&2; exit 2; }
    if [[ $FORCE == 0 ]] && command -v docker >/dev/null 2>&1; then
      running=$(docker ps -q 2>/dev/null || true)
      if [[ -n $running ]]; then
        echo "refusing --apply: $(wc -l <<<"$running") docker containers are running (a benchmark?)." >&2
        echo "Stop them first, or pass --force to retune this host under load." >&2
        exit 2
      fi
    fi
  fi
fi

# --------------------------------------------------------------------------
# Values captured from r440-2-13
# --------------------------------------------------------------------------
CAPTURE_HOST=r440-2-13
CAPTURE_DATE=2026-10-20
WANT_CPU_MODEL="Intel(R) Xeon(R) Gold 5218R CPU @ 2.10GHz"
WANT_TOPOLOGY="2 sockets x 20 cores x 2 threads"
WANT_NCPU=80
WANT_NUMA=2
WANT_NODE_MEM="node0=156 GiB node1=94 GiB"
WANT_MEM="250 GiB"
WANT_SWAP="8 GiB in 1 file"
WANT_SIBLING_OFFSET=40                # HT sibling of cpuN (N < 40) is cpuN+40
WANT_NODE_CPUS="node0=$(seq -s, 0 2 78) node1=$(seq -s, 1 2 79)"
WANT_KERNEL=6.8.0-142-generic
WANT_UCODE=0x5003901
WANT_OS=24.04
WANT_DMI="Dell Inc. PowerEdge R440, BIOS 2.11.2"
WANT_CPUINFO_RANGE=800000-4000000     # kHz; 4.0 GHz max means turbo is visible
WANT_RAPL=125000000/150000000         # package PL1/PL2 in uW, per socket
WANT_VULNS='gather_data_sampling=Mitigation: Microcode
indirect_target_selection=Mitigation: Aligned branch/return thunks
itlb_multihit=KVM: Mitigation: VMX disabled
l1tf=Not affected
mds=Not affected
meltdown=Not affected
mmio_stale_data=Mitigation: Clear CPU buffers; SMT vulnerable
reg_file_data_sampling=Not affected
retbleed=Mitigation: Enhanced IBRS
spec_rstack_overflow=Not affected
spec_store_bypass=Mitigation: Speculative Store Bypass disabled via prctl
spectre_v1=Mitigation: usercopy/swapgs barriers and __user pointer sanitization
spectre_v2=Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; PBRSB-eIBRS: SW sequence; BHI: SW loop, KVM: SW loop
srbds=Not affected
tsa=Not affected
tsx_async_abort=Mitigation: TSX disabled
vmscape=Mitigation: IBPB before exit to userspace'

WANT_LSM=lockdown,capability,landlock,yama,apparmor   # /sys/kernel/security/lsm
WANT_IOMMU_TYPE=DMA-FQ                # every /sys/kernel/iommu_groups/*/type (lazy DMA)
WANT_IOMMU_GROUPS=135

WANT_PSTATE=passive
WANT_DRIVER=intel_cpufreq
WANT_NO_TURBO=0
WANT_MAX_PERF_PCT=100
WANT_MIN_PERF_PCT=20
WANT_GOVERNOR=performance
WANT_FREQ_RANGE=800000-4000000        # scaling_min-scaling_max, kHz
WANT_EPB=6
WANT_IDLE="POLL:0 C1:0 C1E:0 C6:1"    # cpuidle state name : disable
WANT_IDLE_DRIVER=intel_idle
WANT_IDLE_GOV=menu
WANT_UNCORE=2400000-2400000           # min-max kHz, per package
WANT_NPKG=2                           # uncore frequency domains (one per socket)
WANT_SMT=on
WANT_CLOCKSOURCE=tsc
WANT_THP_ENABLED=madvise
WANT_THP_DEFRAG=madvise
WANT_THP_SHMEM=never
WANT_KSM=0

WANT_DOCKER_VERSION=29.7.1
WANT_CONTAINERD_VERSION=v2.2.6
WANT_DOCKER_DRIVER=overlayfs
WANT_DOCKER_RUNTIME=runc
WANT_DOCKERD_EXEC="/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"

if [[ $CORE_MODE == apport ]]; then   # r440-2-13 today
  WANT_CORE_PATTERN='|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E'
  WANT_SUID_DUMPABLE=2 WANT_CORE_PIPE_LIMIT=10
  WANT_APPORT_DEFAULT=enabled=1 WANT_APPORT_UNIT=enabled WANT_APPORT_ACTIVE=active
else                                   # what phase3_runner.py asks for
  WANT_CORE_PATTERN=core
  WANT_SUID_DUMPABLE=0 WANT_CORE_PIPE_LIMIT=0
  # apport only has to be out of the way: purged (file gone, unit not-found or
  # still masked) is as good as disabled.
  WANT_APPORT_DEFAULT="any:enabled=0,not installed" WANT_APPORT_UNIT="any:masked,not-found"
  WANT_APPORT_ACTIVE=inactive
fi

NCPU=0; for c in "$CPU"/cpu[0-9]*; do NCPU=$((NCPU + 1)); done

# --------------------------------------------------------------------------
# Reporting and the check/fix loop
# --------------------------------------------------------------------------
NOK=0 NDIFF=0 NFIXED=0 NWARN=0 NFAILED=0 ITEM_FAILED=0
NEED_PARITY_UNIT=0 NEED_SYSCTL_FILE=0 NEED_DOCKER_RESTART=0
REBOOT_REASONS=()

say()     { printf '%-6s %-38s %s\n' "$1" "$2" "${3:-}"; }
log()     { printf '       -> %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }
info()    { say INFO "$1" "$2"; }
fail()    { log "FAILED: $*"; ITEM_FAILED=1; return 1; }   # a fixer could not do its job
manual()  { log "manual fix needed: $*"; return 1; }

# A want "~x" is a prefix match, "any:a,b" accepts any listed value; else equality.
matches() {
  local a
  if [[ $1 == '~'* ]]; then [[ $2 == "${1:1}"* ]]; return; fi
  if [[ $1 == any:* ]]; then
    IFS=, read -r -a a <<<"${1#any:}"
    in_list_exact "$2" "${a[@]}"; return
  fi
  [[ $2 == "$1" ]]
}
in_list_exact() { local k=$1 p; shift; for p in "$@"; do if [[ $k == "$p" ]]; then return 0; fi; done; return 1; }

# item KIND NAME WANT GETTER [FIXER]
#   rt     live kernel/systemd state; skipped by --files-only
#   file   a file under $CFG_ROOT; fixed by --apply, also with --files-only
#   hw     hardware/firmware/kernel; verified only, a mismatch is a WARN
#   fwarn  a file under $CFG_ROOT, but a mismatch is only a WARN
# GETTER prints the current value. FIXER gets "WANT HAVE" appended and calls fail()
# when it cannot finish; a FIXER of "manual <text>" only prints <text>. GETTER and
# FIXER may carry their own arguments, so they are expanded unquoted on purpose.
item() {
  local kind=$1 name=$2 want=$3 get=$4 fix=${5:-} have
  if [[ $kind != file && $kind != fwarn && $FILES_ONLY == 1 ]]; then
    say SKIP "$name" "(live state; --files-only)"; return 0
  fi
  # shellcheck disable=SC2086
  have=$($get 2>/dev/null) || have="<unreadable>"
  if matches "$want" "$have"; then
    say OK "$name" "want=$want have=$have"; NOK=$((NOK + 1)); return 0
  fi
  if [[ $kind == hw || $kind == fwarn ]]; then
    say WARN "$name" "want=$want have=$have"; NWARN=$((NWARN + 1)); return 0
  fi
  if [[ $MODE == apply && $fix == "manual "* ]]; then
    log "manual fix needed: ${fix#manual }"
  elif [[ $MODE == apply && -n $fix ]]; then
    ITEM_FAILED=0
    # shellcheck disable=SC2086
    $fix "$want" "$have" || true
    # shellcheck disable=SC2086
    have=$($get 2>/dev/null) || have="<unreadable>"
    if [[ $ITEM_FAILED == 1 ]]; then
      say FAILED "$name" "want=$want have=$have"; NFAILED=$((NFAILED + 1)); return 0
    fi
    if matches "$want" "$have"; then
      say FIXED "$name" "want=$want have=$have"; NFIXED=$((NFIXED + 1)); return 0
    fi
  fi
  say DIFF "$name" "want=$want have=$have"; NDIFF=$((NDIFF + 1))
}

# "value xN, other xM": fold one line per CPU (or package) into one.
tally() {
  sort | uniq -c | awk '{n=$1; sub(/^ *[0-9]+ /, ""); printf "%s%s x%d", (NR > 1 ? ", " : ""), $0, n} END {print ""}'
}
per_cpu() {   # per_cpu <path relative to cpuN>
  local c
  for c in "$CPU"/cpu[0-9]*; do
    if [[ -r $c/$1 ]]; then cat "$c/$1"; else echo "<missing>"; fi
  done | tally
}
set_sysfs() {   # set_sysfs <file> <value>: write only when it differs
  if [[ -w $1 && $(cat "$1") != "$2" ]]; then echo "$2" > "$1" || log "write failed: $1"; fi
  return 0
}
set_per_cpu() { local c; for c in "$CPU"/cpu[0-9]*; do set_sysfs "$c/$1" "$2"; done; }
run_live() {   # commands that are not file edits: skipped under --files-only
  if [[ $FILES_ONLY == 1 ]]; then log "would run: $*"; return 0; fi
  log "run: $*"; "$@"
}

# Backups keep the first copy taken in this run (<file>.bak.<timestamp>).
backup() {
  if [[ ( -e $1 || -L $1 ) && ! -e $1.bak.$TS && ! -L $1.bak.$TS ]]; then
    cp -a "$1" "$1.bak.$TS"; log "backup ${1#"$R"}.bak.$TS"
  fi
}
real_path() {   # real_path <file>: the file a symlink points at; fails if outside CFG_ROOT
  local f; f=$(readlink -f -- "$1")
  if [[ -n $R && $f != "$R"/* ]]; then return 1; fi
  echo "$f"
}
write_file() {   # write_file <path> <mode> <text>; no-op when already identical
  local path=$1 mode=$2 text=$3
  mkdir -p "$(dirname "$path")"
  path=$(real_path "$path") || { fail "${1#"$R"} links outside CFG_ROOT; not written"; return 1; }
  if [[ -f $path && "$(cat "$path")" == "$text" ]]; then chmod "$mode" "$path"; return 0; fi
  backup "$path"
  printf '%s\n' "$text" > "$path"
  chmod "$mode" "$path"
  log "wrote ${path#"$R"}"
}
ensure_link() {   # ensure_link <target> <link>
  if [[ -L $2 && $(readlink "$2") == "$1" ]]; then return 0; fi
  mkdir -p "$(dirname "$2")"
  backup "$2"; rm -f "$2"
  ln -s "$1" "$2"; log "link ${2#"$R"} -> $1"
}
comment_out() {   # comment_out <file> <ERE>: prefix matching active lines with '#'
  local f   # edit (and back up) the file a symlink points at
  f=$(real_path "$1") || { fail "${1#"$R"} links outside CFG_ROOT; not edited"; return 1; }
  backup "$f"
  sed -i --follow-symlinks -E "s/^([[:space:]]*($2))/#\\1/" "$f"
  log "commented out matching lines in ${f#"$R"}"
}
existing() { local f; for f in "$@"; do if [[ -f $f ]]; then echo "$f"; fi; done; }
grep_files() {   # grep_files <ERE> <files...>: "file:match;..." or "none"
  local re=$1 out; shift
  [[ $# -gt 0 ]] || { echo none; return 0; }
  out=$(grep -H -E "$re" "$@" 2>/dev/null </dev/null | sed "s|^$R||" | paste -sd ';' - || true)
  echo "${out:-none}"
}

# systemd unit state. Live: systemctl. Under CFG_ROOT: from the unit links.
unit_state_get() {
  local u=$1 l
  if [[ -z $R ]]; then l=$(systemctl is-enabled "$u" 2>/dev/null || true); echo "${l:-not-found}"; return 0; fi
  if [[ -L $R/etc/systemd/system/$u && $(readlink "$R/etc/systemd/system/$u") == /dev/null ]]; then echo masked; return 0; fi
  for l in "$R"/etc/systemd/system/*.wants; do if [[ -L $l/$u ]]; then echo enabled; return 0; fi; done
  if [[ -e $R/etc/systemd/system/$u || -e $R/usr/lib/systemd/system/$u ]]; then echo disabled; else echo not-found; fi
}
unit_enable_fix() {   # unit_enable_fix <unit> [hint if the unit file is missing]
  local u=$1 m src
  if [[ -z $R ]]; then
    if [[ $(systemctl is-enabled "$u" 2>/dev/null || true) == masked ]]; then run_live systemctl unmask "$u" || true; fi
    run_live systemctl enable "$u" || fail "systemctl enable $u"
    return 0
  fi
  m=$R/etc/systemd/system/$u
  if [[ -L $m && $(readlink "$m") == /dev/null ]]; then backup "$m"; rm -f "$m"; log "unmasked $u"; fi
  if [[ -e $m ]]; then src=/etc/systemd/system/$u
  elif [[ -e $R/usr/lib/systemd/system/$u ]]; then src=/usr/lib/systemd/system/$u
  else manual "${2:-$u is not installed}"; return 1; fi
  ensure_link "$src" "$R/etc/systemd/system/multi-user.target.wants/$u"
}
unit_mask_fix() {   # unit_mask_fix <unit>: disable, stop and mask
  local u=$1 l m=$R/etc/systemd/system/$1
  if [[ -z $R ]]; then
    run_live systemctl disable --now "$u" || true
    run_live systemctl mask "$u" || fail "systemctl mask $u"
    return 0
  fi
  for l in "$R"/etc/systemd/system/*.wants; do
    if [[ -L $l/$u ]]; then backup "$l/$u"; rm -f "$l/$u"; log "removed ${l#"$R"}/$u"; fi
  done
  if ! [[ -L $m && $(readlink "$m") == /dev/null ]]; then backup "$m"; rm -f "$m"; ln -s /dev/null "$m"; log "masked $u"; fi
}
unit_active_get() { systemctl is-active "$1" 2>/dev/null || true; }
unit_start_fix() { run_live systemctl daemon-reload || true; run_live systemctl start "$1" || fail "systemctl start $1"; }
unit_stop_fix()  { run_live systemctl stop "$1" || fail "systemctl stop $1"; }

mode_label=$MODE; if [[ $FILES_ONLY == 1 ]]; then mode_label+=" files-only"; fi
printf 'configure_fuzz_host.sh  mode=%s  core-pattern=%s  host=%s  reference=%s (captured %s)\n' \
  "$mode_label" "$CORE_MODE" "$(hostname)" "$CAPTURE_HOST" "$CAPTURE_DATE"
[[ -z $R ]] || echo "CFG_ROOT=$R"

# --------------------------------------------------------------------------
section "Hardware, firmware and kernel (verified, never applied)"
# Same hardware is the premise; anything here that differs makes results incomparable.
# --------------------------------------------------------------------------
hw_model() { grep -m1 '^model name' /proc/cpuinfo | sed 's/^[^:]*: //'; }
hw_topology() {
  local s cores c ids=()
  for c in "$CPU"/cpu[0-9]*; do ids+=("$(cat "$c/topology/physical_package_id"):$(cat "$c/topology/core_id")"); done
  [[ ${#ids[@]} -gt 0 ]] || { echo "<no cpus>"; return 0; }
  s=$(printf '%s\n' "${ids[@]}" | cut -d: -f1 | sort -u | wc -l)
  cores=$(printf '%s\n' "${ids[@]}" | sort -u | wc -l)
  echo "$s sockets x $((cores / s)) cores x $((NCPU / cores)) threads"
}
hw_ncpu()   { echo "$NCPU"; }
hw_numa()   { local n=0 d; for d in "$NODE"/node[0-9]*; do n=$((n + 1)); done; echo "$n"; }
hw_node_mem() {
  local d out=()
  for d in "$NODE"/node[0-9]*; do out+=("${d##*/}=$(awk '/MemTotal/ {printf "%.0f GiB", $4 / 1048576}' "$d/meminfo")"); done
  echo "${out[*]:-<none>}"
}
hw_mem()    { awk '/^MemTotal/ {printf "%d GiB\n", $2 / 1048576}' /proc/meminfo; }
hw_swap()   { awk 'NR > 1 {kb += $3; n++; t[$2] = 1} END {for (k in t) ty = ty (ty ? "+" : "") k;
                printf "%.0f GiB in %d %s\n", kb / 1048576, n, (n ? ty : "devices")}' /proc/swaps; }
hw_kernel() { uname -r; }
hw_ucode()  { grep -m1 '^microcode' /proc/cpuinfo | awk '{print $3}'; }
hw_os()     { sed -n 's/^VERSION_ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$R/etc/os-release"; }
hw_dmi()    { local d=/sys/class/dmi/id; echo "$(cat "$d/sys_vendor") $(cat "$d/product_name"), BIOS $(cat "$d/bios_version")"; }
hw_hwp()    { if grep -m1 '^flags' /proc/cpuinfo | grep -qw hwp; then echo present; else echo absent; fi; }
hw_cpuinfo_range() {
  local c; for c in "$CPU"/cpu[0-9]*; do
    echo "$(cat "$c/cpufreq/cpuinfo_min_freq")-$(cat "$c/cpufreq/cpuinfo_max_freq")"
  done | tally
}
hw_rapl() {
  local z; for z in /sys/class/powercap/intel-rapl:[0-9]; do
    echo "$(cat "$z/constraint_0_power_limit_uw")/$(cat "$z/constraint_1_power_limit_uw")"
  done | tally
}
hw_idle_driver() { cat "$CPU/cpuidle/current_driver"; }
hw_vulns() {   # names whose mitigation state differs from r440-2-13 (microcode/kernel dependent)
  local f n v w out=()
  declare -A want=()
  while IFS= read -r v; do want[${v%%=*}]=${v#*=}; done <<<"$WANT_VULNS"
  for f in "$CPU"/vulnerabilities/*; do
    n=${f##*/}; v=$(cat "$f")
    w=${want[$n]-<absent>}
    if [[ $v != "$w" ]]; then out+=("$n"); fi
    unset "want[$n]"
  done
  for n in "${!want[@]}"; do out+=("$n(missing)"); done
  if [[ ${#out[@]} -eq 0 ]]; then echo "as on $CAPTURE_HOST"; else echo "differs: ${out[*]}"; fi
}
hw_tools_all() {   # cpu-governor.service fails on any kernel without its linux-tools
  local v k missing=()
  for v in /boot/vmlinuz-*; do
    k=${v#/boot/vmlinuz-}
    [[ -x $R/usr/lib/linux-tools/$k/cpupower ]] || missing+=("$k")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then echo present; else echo "missing for ${missing[*]}"; fi
}

item hw "cpu model"                    "$WANT_CPU_MODEL"          hw_model
item hw "cpu topology"                 "$WANT_TOPOLOGY"           hw_topology
item hw "logical cpus"                 "$WANT_NCPU"               hw_ncpu
item hw "numa nodes"                   "$WANT_NUMA"               hw_numa
item hw "memory per numa node"         "$WANT_NODE_MEM"           hw_node_mem
item hw "memory"                       "$WANT_MEM"                hw_mem
item hw "swap"                         "$WANT_SWAP"               hw_swap
item hw "running kernel"               "$WANT_KERNEL"             hw_kernel
item hw "microcode"                    "$WANT_UCODE"              hw_ucode
item hw "cpu vulnerabilities"          "as on $CAPTURE_HOST"      hw_vulns
item hw "ubuntu release"               "$WANT_OS"                 hw_os
item hw "platform"                     "$WANT_DMI"                hw_dmi
item hw "cpuinfo freq range (turbo)"   "$WANT_CPUINFO_RANGE x$NCPU" hw_cpuinfo_range
item hw "rapl PL1/PL2 per package"     "$WANT_RAPL x2"            hw_rapl
item hw "cpuidle driver"               "$WANT_IDLE_DRIVER"        hw_idle_driver
item hw "cpupower for every kernel"    present                    hw_tools_all

# --------------------------------------------------------------------------
section "CPU numbering (the pipeline's core layout depends on it)"
# run_online_pertrial.sh pins system/optimizer/trial work to cores 0-1/2-11/12-31
# and leaves their HT siblings (+40) idle. Different numbering breaks that layout.
# --------------------------------------------------------------------------
node_cpus_get() {
  local d out=()
  for d in "$NODE"/node[0-9]*; do out+=("${d##*/}=$(cat "$d/cpulist")"); done
  if [[ "${out[*]}" == "$WANT_NODE_CPUS" ]]; then echo "even cpus on node0, odd on node1"; else echo "${out[*]:-<none>}"; fi
}
siblings_get() {
  local c n exp bad=0 first=""
  for c in "$CPU"/cpu[0-9]*; do
    n=${c##*cpu}
    if (( n < WANT_SIBLING_OFFSET )); then exp="$n,$((n + WANT_SIBLING_OFFSET))"; else exp="$((n - WANT_SIBLING_OFFSET)),$n"; fi
    if [[ $(cat "$c/topology/thread_siblings_list" 2>/dev/null) != "$exp" ]]; then
      bad=$((bad + 1)); [[ -n $first ]] || first="cpu$n=$(cat "$c/topology/thread_siblings_list" 2>/dev/null)"
    fi
  done
  if [[ $bad == 0 ]]; then echo "cpuN+$WANT_SIBLING_OFFSET is the sibling of cpuN x$NCPU"; else echo "$bad cpus differ, e.g. $first"; fi
}
LAYOUT_HINT="manual the core layout in run_online_pertrial.sh (TRIAL_CORES, OPT_CORES, AGENT_CPUS) assumes r440-2-13's numbering; adjust it for this host"
item rt "numa node cpu lists"  "even cpus on node0, odd on node1" node_cpus_get "$LAYOUT_HINT"
item rt "HT sibling numbering" "cpuN+$WANT_SIBLING_OFFSET is the sibling of cpuN x$WANT_NCPU" siblings_get "$LAYOUT_HINT"

# --------------------------------------------------------------------------
section "Kernel command line"
# r440-2-13 boots with only BOOT_IMAGE=, root= and ro. Extra parameters fall in
# three groups: tuning keys (isolcpus, nohz_full, mitigations=off, ...) are a DIFF
# and --apply removes them from the grub config; disk/console/boot options
# (root*, rd.*, cryptdevice, console, quiet, crashkernel, ...) are INFO only;
# anything else is a DIFF left for a human.
# --------------------------------------------------------------------------
TUNING_KEYS="isolcpus nohz_full nohz rcu_nocbs rcu_nocb_* irqaffinity housekeeping kthread_cpus
 maxcpus nr_cpus possible_cpus intel_pstate idle intel_idle.* processor.* cpuidle.* cpufreq.*
 nosmt mitigations ibpb ibrs kpti l1tf mds no_stf_barrier noibpb noibrs nopcid nopti
 nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid pti spec_store_bypass_disable
 spectre_v2 spectre_v2_user spectre_bhi stf_barrier srbds retbleed mmio_stale_data
 gather_data_sampling reg_file_data_sampling tsx tsx_async_abort ssbd noexec noexec32
 hardened_usercopy init_on_alloc init_on_free randomize_kstack_offset nokaslr
 page_alloc.shuffle audit split_lock_detect transparent_hugepage numa_balancing
 nmi_watchdog nowatchdog nosoftlockup skew_tick preempt threadirqs tsc notsc nohpet hpet
 clocksource workqueue.power_efficient systemd.unified_cgroup_hierarchy cgroup_disable cgroup_no_v1"

hwp_get() {   # r440-2-13 has no HWP; intel_pstate=no_hwp gives the same passive mode
  if [[ $(hw_hwp) == absent ]]; then echo absent
  elif grep -qw 'intel_pstate=no_hwp' /proc/cmdline; then echo "absent (disabled by intel_pstate=no_hwp)"
  else echo present; fi
}
# IOMMU, LSM, nvme, libata and module-blacklist options are not here: they change DMA,
# syscall or I/O cost or drop drivers, so they are DIFFs unless they repeat this
# kernel's default (HOST_DEFAULT_WORDS). nvme_core.io_timeout (Ubuntu cloud images
# set it) only matters when a command fails.
BENIGN_KEYS="root* rd.* rw cryptdevice cryptopts resume resume_offset console earlycon earlyprintk
 quiet splash vt.* crashkernel rootflags init initrd loglevel ignore_loglevel nomodeset net.ifnames
 biosdevname ip fsck.* plymouth.* systemd.show_status systemd.log_* scsi_mod.* dm.*
 md raid efi panic ds cloud-init nvme_core.io_timeout"
HOST_DEFAULT_WORDS="intel_iommu=on apparmor=1"   # what r440-2-13's kernel does without them
read -r -d '' -a TUNING_ARR <<<"$TUNING_KEYS" || true   # read -a does not glob "intel_idle.*"
read -r -d '' -a BENIGN_ARR <<<"$BENIGN_KEYS" || true
in_list() {   # in_list <key> <pattern...>
  local k=$1 p; shift
  # shellcheck disable=SC2053  # patterns are globs on purpose
  for p in "$@"; do if [[ $k == $p ]]; then return 0; fi; done
  return 1
}
allowed_cmdline() {   # allowed_cmdline <key> <word>: on r440-2-13's command line
  case $1 in BOOT_IMAGE|root|ro) return 0 ;; esac
  [[ $2 == intel_pstate=no_hwp && $(hw_hwp) == present ]]
}
cmdline_extras() {   # cmdline_extras diff|benign; stdin: command line words
  local -a words; local w k diff=() benign=()
  read -r -d '' -a words || true
  for w in "${words[@]}"; do
    [[ $w != '$'* ]] || continue             # $GRUB_CMDLINE_LINUX_DEFAULT references
    k=${w%%=*}
    if allowed_cmdline "$k" "$w"; then continue; fi
    # shellcheck disable=SC2086  # HOST_DEFAULT_WORDS is a plain word list
    if in_list_exact "$w" $HOST_DEFAULT_WORDS; then benign+=("$w")
    elif ! in_list "$k" "${TUNING_ARR[@]}" && in_list "$k" "${BENIGN_ARR[@]}"; then benign+=("$w")
    else diff+=("$w"); fi
  done
  if [[ ${1:-diff} == benign ]]; then echo "${benign[*]:-none}"; else echo "${diff[*]:-none}"; fi
}
cmdline_get() { cmdline_extras "${1:-diff}" < /proc/cmdline; }
grub_files()  { existing "$R/etc/default/grub" "$R"/etc/default/grub.d/*.cfg; }
grub_values() {   # the quoted values of GRUB_CMDLINE_LINUX{,_DEFAULT} in one file
  { grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=' "$1" || true; } \
    | sed -E "s/^[^=]*=//; s/^[\"']//; s/[\"'][^\"']*\$//"
}
grub_get() {   # grub_get [diff|benign]
  local f found=() t
  while read -r f; do
    t=$(grub_values "$f" | tr '\n' ' ' | cmdline_extras "${1:-diff}")
    [[ $t == none ]] || found+=("${f#"$R"}: $t")
  done < <(grub_files)
  if [[ ${#found[@]} -eq 0 ]]; then echo none; else printf '%s; ' "${found[@]}" | sed 's/; $//'; fi
}
grub_fix() {   # drop known tuning keys from GRUB_CMDLINE_LINUX{,_DEFAULT}; keep the rest
  local f tmp real keep_nohwp=0 left changed=0
  [[ $(hw_hwp) == absent ]] || keep_nohwp=1
  while read -r f; do
    grep -qE '^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=' "$f" || continue
    tmp=$(mktemp)
    awk -v keys="$TUNING_KEYS" -v keep_nohwp="$keep_nohwp" '
      function tuning(w,   key, i, p) {
        if (keep_nohwp && w == "intel_pstate=no_hwp") return 0
        key = w; sub(/=.*/, "", key)
        for (i = 1; i <= n; i++) {
          p = k[i]
          if (p ~ /\*$/) { if (index(key, substr(p, 1, length(p) - 1)) == 1) return 1 }
          else if (key == p) return 1
        }
        return 0
      }
      BEGIN { m = split(keys, t, /[ \n]+/); n = 0; for (i = 1; i <= m; i++) if (t[i] != "") k[++n] = t[i] }
      /^[ \t]*GRUB_CMDLINE_LINUX(_DEFAULT)?=/ {
        eq = index($0, "="); head = substr($0, 1, eq); val = substr($0, eq + 1)
        q = substr(val, 1, 1); tail = ""
        if (q == "\"" || q == "\047") {
          rest = substr(val, 2); p = index(rest, q)
          if (p > 0) { body = substr(rest, 1, p - 1); tail = substr(rest, p + 1) } else body = rest
        } else { q = ""; body = val }
        c = split(body, w, /[ \t]+/); out = ""
        for (i = 1; i <= c; i++) if (w[i] != "" && !tuning(w[i])) out = (out == "" ? w[i] : out " " w[i])
        print head q out q tail; next
      }
      { print }' "$f" > "$tmp"
    if ! cmp -s "$tmp" "$f"; then
      if ! real=$(real_path "$f"); then fail "${f#"$R"} links outside CFG_ROOT; not edited"; rm -f "$tmp"; continue; fi
      backup "$real"; cat "$tmp" > "$real"; log "removed tuning parameters from ${real#"$R"}"; changed=1
    fi
    rm -f "$tmp"
  done < <(grub_files)
  # Live, the "grub.cfg generated" item below runs update-grub.
  if [[ $changed == 1 && $FILES_ONLY == 1 ]]; then log "would run: update-grub"; fi
  left=$(grub_get)
  if [[ $left != none ]]; then manual "unknown keys (neither tuning nor boot options), review by hand: $left"; fi
}
grubcfg_get() {   # is /boot/grub/grub.cfg newer than every grub config file?
  local cfg=$GRUB_CFG f newest=""
  [[ -e $cfg ]] || { echo missing; return 0; }
  while read -r f; do if [[ $f -nt $cfg ]]; then newest=${f#"$R"}; fi; done < <(grub_files)
  if [[ -z $newest ]]; then echo "up to date"; else echo "older than $newest"; fi
}
grubcfg_fix() {
  if ! command -v update-grub >/dev/null 2>&1; then
    fail "update-grub not found: apt-get install grub2-common, then run update-grub && reboot"; return 1
  fi
  if run_live update-grub; then
    REBOOT_REASONS+=("the grub kernel command line changed; reboot to boot with it")
  else
    fail "update-grub failed: fix the error above, then run update-grub && reboot"
  fi
}

item rt   "running kernel cmdline"        none   cmdline_get "manual clean the grub config (next lines), run update-grub, reboot"
[[ $FILES_ONLY == 1 ]] || info "boot options (running)" "$(cmdline_get benign) (disk/console/boot only; not compared)"
item file "grub cmdline (grub, grub.d)"   none   grub_get    grub_fix
info "boot options (grub)" "$(grub_get benign) (disk/console/boot only; not compared)"
item rt   "grub.cfg generated"            "up to date" grubcfg_get grubcfg_fix
# What those boot options decide, read back from the running kernel.
lsm_get() { cat "$LSM_FILE"; }
iommu_groups() { local t; for t in "$IOMMU_DIR"/*/type; do echo "$t"; done; }
iommu_type_get() {
  local -a t; mapfile -t t < <(iommu_groups)
  [[ ${#t[@]} -gt 0 ]] || { echo "no iommu groups"; return 0; }
  if [[ $(cat "${t[@]}" | sort -u) == "$WANT_IOMMU_TYPE" ]]; then echo "all $WANT_IOMMU_TYPE"; else cat "${t[@]}" | tally; fi
}
iommu_count_get() { iommu_groups | wc -l; }
# Each LSM hooks syscalls; a different set changes syscall cost in every target.
item rt "active LSMs"           "$WANT_LSM"             lsm_get \
  "manual set by lsm=, security=, apparmor= or selinux= boot options; r440-2-13 has none of them"
# Strict or passthrough IOMMU changes DMA cost for disk and network I/O.
item rt "iommu group DMA mode"  "all $WANT_IOMMU_TYPE"  iommu_type_get \
  "manual set by iommu=, intel_iommu= or iommu.strict= boot options; r440-2-13 uses the kernel default (lazy)"
item hw "iommu group count"     "$WANT_IOMMU_GROUPS"    iommu_count_get
if [[ $MODE == apply && $FILES_ONLY == 0 && $(cmdline_get) != none && $(grub_get) == none && ${#REBOOT_REASONS[@]} -eq 0 ]]; then
  REBOOT_REASONS+=("running kernel command line still has: $(cmdline_get)")
fi

# --------------------------------------------------------------------------
section "SMT, P-states, frequency and clocksource"
# Every trial gets one core; frequency must not depend on load or on the governor's
# guess, or exec/s varies between arms and between hosts. Each fix below that
# --apply has to make live is also re-applied at boot by fuzz-cpu-parity.service.
# --------------------------------------------------------------------------
parity() { NEED_PARITY_UNIT=1; }
smt_get() { cat "$CPU/smt/control"; }
smt_fix() { parity; echo "$1" > "$CPU/smt/control" || manual "SMT is '$2' (BIOS Hyper-Threading off, or nosmt)"; }
pstate_get()  { cat "$CPU/intel_pstate/$1"; }
pstate_fix()  { parity; echo "$2" > "$CPU/intel_pstate/$1"; }
no_turbo_fix() { parity; echo "$1" > "$CPU/intel_pstate/no_turbo" || manual "turbo is disabled in the BIOS"; }
freq_range_get() {
  local c; for c in "$CPU"/cpu[0-9]*; do
    echo "$(cat "$c/cpufreq/scaling_min_freq")-$(cat "$c/cpufreq/scaling_max_freq")"
  done | tally
}
freq_range_fix() {   # raise max first so min never exceeds it
  parity
  set_per_cpu cpufreq/scaling_max_freq "${WANT_FREQ_RANGE#*-}"
  set_per_cpu cpufreq/scaling_min_freq "${WANT_FREQ_RANGE%-*}"
}
governor_fix() { set_per_cpu cpufreq/scaling_governor "$WANT_GOVERNOR"; }
epb_fix() { parity; set_per_cpu power/energy_perf_bias "$WANT_EPB"; }
uncore_get() {
  local u; for u in "$CPU"/intel_uncore_frequency/package_*; do
    echo "$(cat "$u/${1:-}min_freq_khz")-$(cat "$u/${1:-}max_freq_khz")"
  done | tally
}
uncore_fix() {
  local u pkgs=("$CPU"/intel_uncore_frequency/package_*); parity
  if [[ ${#pkgs[@]} -eq 0 ]]; then run_live modprobe -q intel_uncore_frequency || true; fi
  for u in "$CPU"/intel_uncore_frequency/package_*; do
    echo "${WANT_UNCORE#*-}" > "$u/max_freq_khz" || true
    echo "${WANT_UNCORE%-*}" > "$u/min_freq_khz" || true
  done
}
clocksource_get() { cat "$CLK/current_clocksource"; }
clocksource_fix() {
  parity
  if grep -qw "$1" "$CLK/available_clocksource"; then echo "$1" > "$CLK/current_clocksource"
  else manual "$1 is not an available clocksource (the kernel marked it unstable; see dmesg)"; fi
}
HWP_HINT="manual r440-2-13's BIOS exposes no HWP. Match it in the BIOS (same System Profile as r440-2-13), or add intel_pstate=no_hwp to GRUB_CMDLINE_LINUX_DEFAULT, run update-grub, reboot. Not added automatically."

# HT on: trials sit on physical cores 12-31 with their siblings 52-71 idle.
item rt "smt control"                 "$WANT_SMT"            smt_get                     smt_fix
# No HWP: P-states come from the cpufreq governor, not from the CPU's own logic.
item rt "hwp (needs passive P-states)" "~absent"            hwp_get                     "$HWP_HINT"
item rt "intel_pstate status"         "$WANT_PSTATE"         "pstate_get status"         "pstate_fix status"
item rt "cpufreq driver"              "$WANT_DRIVER x$NCPU"  "per_cpu cpufreq/scaling_driver"
# Turbo on: "full strength" is the 4.0 GHz turbo bin, not the 2.1 GHz base.
item rt "intel_pstate no_turbo"       "$WANT_NO_TURBO"       "pstate_get no_turbo"       no_turbo_fix
item rt "intel_pstate max_perf_pct"   "$WANT_MAX_PERF_PCT"   "pstate_get max_perf_pct"   "pstate_fix max_perf_pct"
item rt "intel_pstate min_perf_pct"   "$WANT_MIN_PERF_PCT"   "pstate_get min_perf_pct"   "pstate_fix min_perf_pct"
# performance = top P-state always; schedutil/ondemand ramp and drop with load.
item rt "scaling_governor"            "$WANT_GOVERNOR x$NCPU" "per_cpu cpufreq/scaling_governor" governor_fix
# Full hardware range: no lowered max cap left behind by a power tool.
item rt "scaling min-max (kHz)"       "$WANT_FREQ_RANGE x$NCPU" freq_range_get           freq_range_fix
# Energy/perf bias hint to the CPU; 6 = "normal".
item rt "energy_perf_bias"            "$WANT_EPB x$NCPU"     "per_cpu power/energy_perf_bias" epb_fix
# Uncore (LLC/memory fabric) clock pinned at max: steady memory latency for every trial.
item rt "uncore min-max (kHz)"        "$WANT_UNCORE x$WANT_NPKG"  uncore_get                  uncore_fix
# tsc: clock_gettime() in the fuzzer and targets stays a vDSO read, not a syscall.
item rt "clocksource"                 "$WANT_CLOCKSOURCE"    clocksource_get             clocksource_fix

# --------------------------------------------------------------------------
section "CPU idle states"
# No C6: an idle sibling or core never sleeps deep, so wakeups (fork server,
# container scheduling) cost ~2 us instead of ~92 us.
# --------------------------------------------------------------------------
idle_get() {
  local c s sig
  for c in "$CPU"/cpu[0-9]*; do
    sig=""
    for s in "$c"/cpuidle/state[0-9]*; do sig+="$(cat "$s/name"):$(cat "$s/disable") "; done
    echo "${sig% }"
  done | tally
}
idle_want_for() {   # idle_want_for <state name>: wanted disable value, or empty
  local p; for p in $WANT_IDLE; do if [[ ${p%%:*} == "$1" ]]; then echo "${p#*:}"; return 0; fi; done; return 0
}
idle_fix() {
  local c s w; parity
  for c in "$CPU"/cpu[0-9]*; do
    for s in "$c"/cpuidle/state[0-9]*; do
      w=$(idle_want_for "$(cat "$s/name")")
      if [[ -n $w ]]; then set_sysfs "$s/disable" "$w"; fi
    done
  done
}
idle_gov_get() { cat "$CPU/cpuidle/current_governor"; }
idle_gov_fix() { parity; echo "$1" > "$CPU/cpuidle/current_governor"; }

item rt "cpuidle states (name:disable)" "$WANT_IDLE x$NCPU" idle_get     idle_fix
item rt "cpuidle governor"              "$WANT_IDLE_GOV"    idle_gov_get idle_gov_fix

# --------------------------------------------------------------------------
section "Memory"
# THP madvise/madvise and KSM off are this kernel's defaults; THP=always or KSM
# scanning would add page-fault and khugepaged/ksmd CPU noise to every trial.
# --------------------------------------------------------------------------
thp_get() { sed -E 's/.*\[([^]]+)\].*/\1/' "$MM/transparent_hugepage/$1"; }
thp_fix() { parity; echo "$2" > "$MM/transparent_hugepage/$1"; }
ksm_get() { cat "$MM/ksm/run"; }
ksm_fix() { parity; echo "$1" > "$MM/ksm/run"; }
item rt "thp enabled"        "$WANT_THP_ENABLED" "thp_get enabled"       "thp_fix enabled"
item rt "thp defrag"         "$WANT_THP_DEFRAG"  "thp_get defrag"        "thp_fix defrag"
item rt "thp shmem_enabled"  "$WANT_THP_SHMEM"   "thp_get shmem_enabled" "thp_fix shmem_enabled"
item rt "ksm run"            "$WANT_KSM"         ksm_get                 ksm_fix

# --------------------------------------------------------------------------
section "Persistence of the CPU and memory settings"
# The governor persists through r440-2-13's own unit, installed here byte for byte.
# The rest comes from firmware or kernel defaults there. Where this host needed a
# live fix above, or its firmware boot defaults differ, fuzz-cpu-parity.service
# re-applies all of it at every boot (before cpu-governor.service).
# --------------------------------------------------------------------------
GOV_UNIT=/etc/systemd/system/cpu-governor.service
GOV_UNIT_TEXT='[Unit]
Description=Pin CPU governor to performance
After=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/cpupower frequency-set -g performance

[Install]
WantedBy=multi-user.target'

PARITY_HELPER=/usr/local/sbin/fuzz-cpu-parity.sh
PARITY_UNIT=/etc/systemd/system/fuzz-cpu-parity.service
PARITY_UNIT_TEXT="[Unit]
Description=Match CPU and memory settings to $CAPTURE_HOST (P-states, C-states, uncore, THP, KSM)
After=sysinit.target
Before=cpu-governor.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$PARITY_HELPER

[Install]
WantedBy=multi-user.target"
parity_helper_text() {
  local p
  cat <<EOF
#!/bin/sh
# Written by configure_fuzz_host.sh: re-applies at every boot the CPU and memory
# settings that $CAPTURE_HOST has by firmware or kernel default but this host does not.
# Idempotent: each value is written only when it differs.
w() { [ -w "\$1" ] && [ "\$(cat "\$1")" != "\$2" ] && echo "\$2" > "\$1"; return 0; }
p=/sys/devices/system/cpu
w \$p/intel_pstate/status $WANT_PSTATE
w \$p/intel_pstate/no_turbo $WANT_NO_TURBO
w \$p/intel_pstate/max_perf_pct $WANT_MAX_PERF_PCT
w \$p/intel_pstate/min_perf_pct $WANT_MIN_PERF_PCT
w \$p/smt/control $WANT_SMT
for c in \$p/cpu[0-9]*; do
  w \$c/cpufreq/scaling_max_freq ${WANT_FREQ_RANGE#*-}
  w \$c/cpufreq/scaling_min_freq ${WANT_FREQ_RANGE%-*}
  w \$c/power/energy_perf_bias $WANT_EPB
  for s in \$c/cpuidle/state[0-9]*; do
    case "\$(cat \$s/name 2>/dev/null)" in
EOF
  # shellcheck disable=SC2016  # $s belongs to the generated script
  for p in $WANT_IDLE; do printf '      %s) w $s/disable %s ;;\n' "${p%%:*}" "${p#*:}"; done
  cat <<EOF
    esac
  done
done
w \$p/cpuidle/current_governor $WANT_IDLE_GOV
modprobe -q intel_uncore_frequency 2>/dev/null || true
for u in \$p/intel_uncore_frequency/package_*; do
  w \$u/max_freq_khz ${WANT_UNCORE#*-}
  w \$u/min_freq_khz ${WANT_UNCORE%-*}
done
k=/sys/devices/system/clocksource/clocksource0
grep -qw $WANT_CLOCKSOURCE \$k/available_clocksource 2>/dev/null && w \$k/current_clocksource $WANT_CLOCKSOURCE
t=/sys/kernel/mm/transparent_hugepage
grep -qE '(^|\[)$WANT_THP_ENABLED(\]|\$)' \$t/enabled 2>/dev/null || echo $WANT_THP_ENABLED > \$t/enabled
grep -qE '(^|\[)$WANT_THP_DEFRAG(\]|\$)' \$t/defrag 2>/dev/null || echo $WANT_THP_DEFRAG > \$t/defrag
grep -qE '(^|\[)$WANT_THP_SHMEM(\]|\$)' \$t/shmem_enabled 2>/dev/null || echo $WANT_THP_SHMEM > \$t/shmem_enabled
w /sys/kernel/mm/ksm/run $WANT_KSM
# Governor fallback. cpu-governor.service (ordered after this unit) stays the
# primary mechanism and writes the same value, so the two cannot disagree.
for c in \$p/cpu[0-9]*; do w \$c/cpufreq/scaling_governor $WANT_GOVERNOR; done
exit 0
EOF
}

gov_unit_get() {
  if [[ ! -e $R$GOV_UNIT ]]; then echo absent
  elif [[ "$(cat "$R$GOV_UNIT")" == "$GOV_UNIT_TEXT" ]]; then echo "as on $CAPTURE_HOST"
  else echo "differs"; fi
}
gov_unit_fix() { write_file "$R$GOV_UNIT" 0644 "$GOV_UNIT_TEXT"; }
cpupower_get() { if [[ -x $R/usr/lib/linux-tools/$(uname -r)/cpupower ]]; then echo present; else echo missing; fi; }
CPUPOWER_HINT="manual apt-get install linux-tools-common linux-tools-$(uname -r)  (linux-tools-generic keeps it current across kernel upgrades)"

c6_default_get() {   # boot default of C6: "disabled" means firmware left it out of _CST
  local c s; for c in "$CPU"/cpu[0-9]*; do
    for s in "$c"/cpuidle/state[0-9]*; do
      if [[ $(cat "$s/name") == C6 ]]; then cat "$s/default_status"; fi
    done
  done | tally
}
parity_get() {
  local h=$R$PARITY_HELPER u=$R$PARITY_UNIT st
  st=$(unit_state_get fuzz-cpu-parity.service)
  if [[ ! -e $h && ! -e $u ]]; then echo "not installed"; return 0; fi
  if [[ -x $h && "$(cat "$h")" == "$(parity_helper_text)" && "$(cat "$u" 2>/dev/null)" == "$PARITY_UNIT_TEXT" && $st == enabled ]]; then
    echo installed
  else echo "stale or partial (unit $st)"; fi
}
parity_install() {
  write_file "$R$PARITY_HELPER" 0755 "$(parity_helper_text)"
  write_file "$R$PARITY_UNIT" 0644 "$PARITY_UNIT_TEXT"
  if [[ $(unit_state_get fuzz-cpu-parity.service) != enabled ]]; then unit_enable_fix fuzz-cpu-parity.service; fi
}
fw_boot_get() {   # will the firmware-derived settings survive a reboot?
  local bad=()
  [[ $(c6_default_get) == "disabled x$NCPU" ]] || bad+=(C6)
  [[ $(uncore_get initial_) == "$WANT_UNCORE x$WANT_NPKG" ]] || bad+=(uncore)
  [[ $(hwp_get) == absent* ]] || bad+=(HWP)
  if [[ ${#bad[@]} -eq 0 ]]; then echo "persisted (firmware, as on $CAPTURE_HOST)"
  elif [[ $(parity_get) == installed ]]; then echo "persisted (fuzz-cpu-parity.service)"
  else echo "not persisted: firmware boot default differs for ${bad[*]}"; fi
}
fw_boot_fix() { parity; parity_install; }

item file "cpu-governor.service"          "as on $CAPTURE_HOST" gov_unit_get gov_unit_fix
item file "cpu-governor.service enabled"  enabled  "unit_state_get cpu-governor.service" "unit_enable_fix cpu-governor.service"
item file "cpupower for running kernel"   present  cpupower_get "$CPUPOWER_HINT"
item rt   "cpu-governor.service active"   active   "unit_active_get cpu-governor.service" "unit_start_fix cpu-governor.service"
item rt   "firmware cpu settings at boot" "~persisted" fw_boot_get fw_boot_fix
want_parity="not installed"
# --apply --files-only installs it unconditionally, so tests exercise it.
if [[ $NEED_PARITY_UNIT == 1 || ( $MODE == apply && $FILES_ONLY == 1 ) || $(parity_get) != "not installed" ]]; then want_parity=installed; fi
item file "fuzz-cpu-parity.service"       "$want_parity" parity_get parity_install
if [[ $MODE == apply && $NEED_PARITY_UNIT == 1 && $FILES_ONLY == 0 ]]; then
  run_live systemctl daemon-reload || true
  run_live systemctl start fuzz-cpu-parity.service || log "starting fuzz-cpu-parity.service failed"
fi

# --------------------------------------------------------------------------
section "Services that would fight these settings"
# None of these is installed on r440-2-13 (systemd-oomd included). irqbalance would
# move IRQs onto trial cores, numad/ksmtuned move or merge trial memory, the others
# rewrite governors/EPB, and systemd-oomd could kill a memory-heavy trial.
# --------------------------------------------------------------------------
CONFLICT_SERVICES="irqbalance.service tuned.service power-profiles-daemon.service cpufrequtils.service
 ondemand.service cpupower.service tlp.service numad.service ksmtuned.service auto-cpufreq.service
 systemd-oomd.service systemd-oomd.socket"
conflicts_get() {
  local s e out=()
  for s in $CONFLICT_SERVICES; do
    e=$(systemctl is-enabled "$s" 2>/dev/null || true)
    case $e in enabled|enabled-runtime|generated|alias|indirect) out+=("$s:$e") ;; esac
    if systemctl is-active --quiet "$s" >/dev/null 2>&1; then out+=("$s:active"); fi
  done
  echo "${out[*]:-none}"
}
conflicts_fix() {
  local s
  for s in $CONFLICT_SERVICES; do
    if systemctl is-enabled --quiet "$s" >/dev/null 2>&1 || systemctl is-active --quiet "$s" >/dev/null 2>&1; then
      run_live systemctl disable --now "$s" || true
      log "optional: apt-get purge the package that ships $s"
      if [[ $s == irqbalance.service ]]; then
        REBOOT_REASONS+=("irqbalance stopped; the IRQ affinities it set stay until reboot")
      fi
    fi
  done
}
item rt "conflicting tuning services" none conflicts_get conflicts_fix
[[ $FILES_ONLY == 1 ]] || info "irq affinity" "default_smp_affinity=$(cat /proc/irq/default_smp_affinity) (kernel default, not managed)"

# --------------------------------------------------------------------------
section "Crash handling (core dumps, apport): --core-pattern=$CORE_MODE"
# apport (r440-2-13 today): apport.service pipes every crash to /usr/share/apport/apport
# and sets suid_dumpable=2, core_pipe_limit=10 at boot. r440-2-13 had core_pattern=core
# until its 2026-09-29 04:33 MST reboot and has run apport since.
# core: apport disabled and masked; core_pattern=core (+ suid_dumpable=0,
# core_pipe_limit=0) from the sysctl file below. Trials run with --ulimit core=0
# either way, so `core` writes no files.
# --------------------------------------------------------------------------
apport_default_get() {
  [[ -f $R/etc/default/apport ]] || { echo "not installed"; return 0; }
  local v; v=$({ grep -E '^[[:space:]]*enabled=' "$R/etc/default/apport" || true; } | tail -n1 | tr -d '[:space:]')
  echo "${v:-no enabled= line}"
}
apport_default_fix() {
  local f v=enabled=1
  [[ $CORE_MODE == apport ]] || v=enabled=0
  if [[ ! -f $R/etc/default/apport ]]; then
    [[ $CORE_MODE == core ]] || manual "apport is not installed: apt-get install apport apport-core-dump-handler"
    return 1
  fi
  f=$(real_path "$R/etc/default/apport") || { fail "/etc/default/apport links outside CFG_ROOT; not edited"; return 1; }
  backup "$f"
  if grep -qE '^[[:space:]]*enabled=' "$f"; then sed -i --follow-symlinks -E "s/^([[:space:]]*)enabled=.*/\\1$v/" "$f"; else echo "$v" >> "$f"; fi
  log "set $v in /etc/default/apport"
}
apport_unit_fix() {   # core mode only ever masks; it never unmasks a purged apport
  if [[ $CORE_MODE == core ]]; then unit_mask_fix apport.service
  else unit_enable_fix apport.service "apt-get install apport apport-core-dump-handler"; fi
}
apport_active_fix() { if [[ $1 == active ]]; then unit_start_fix apport.service; else unit_stop_fix apport.service; fi; }
proc_get() { cat "/proc/sys/${1//.//}"; }
proc_set() { printf '%s\n' "$2" > "/proc/sys/${1//.//}"; }
sysctl_fix() { NEED_SYSCTL_FILE=1; proc_set "$1" "$2"; }   # live now, and from the sysctl file at boot
absent_get() { if [[ -e $R$1 ]]; then echo installed; else echo absent; fi; }

item file "/etc/default/apport"           "$WANT_APPORT_DEFAULT" apport_default_get apport_default_fix
item file "apport.service"                "$WANT_APPORT_UNIT"    "unit_state_get apport.service" apport_unit_fix
item rt   "apport.service active"         "$WANT_APPORT_ACTIVE"  "unit_active_get apport.service" apport_active_fix
# Who receives each crash: with apport, one host Python process per target crash.
item rt   "kernel.core_pattern"           "$WANT_CORE_PATTERN"   "proc_get kernel.core_pattern"   "sysctl_fix kernel.core_pattern"
item rt   "fs.suid_dumpable"              "$WANT_SUID_DUMPABLE"  "proc_get fs.suid_dumpable"      "sysctl_fix fs.suid_dumpable"
item rt   "kernel.core_pipe_limit"        "$WANT_CORE_PIPE_LIMIT" "proc_get kernel.core_pipe_limit" "sysctl_fix kernel.core_pipe_limit"
# A second crash handler would take over core_pattern.
item file "systemd-coredump"              absent "absent_get /usr/lib/systemd/systemd-coredump" "manual apt-get purge systemd-coredump"
item file "whoopsie"                      absent "absent_get /usr/bin/whoopsie" "manual apt-get purge whoopsie"

# --------------------------------------------------------------------------
section "Scheduler and other sysctls (stock values on r440-2-13)"
# Nothing on r440-2-13 sets these: they are kernel or Ubuntu defaults. A twin whose
# live values or sysctl files differ gets them back from one file that
# systemd-sysctl reads last (zz-*: byte order puts it after 99-* and local.conf).
# --------------------------------------------------------------------------
GUARD_SYSCTLS=(
  kernel.randomize_va_space=2       # ASLR on; afl-system-config sets 0, changing target behaviour
  kernel.perf_event_paranoid=4      # Ubuntu default; profiling perf runs as root in --privileged containers
  kernel.kptr_restrict=1            # Ubuntu default; affects kernel symbols in perf profiles
  kernel.yama.ptrace_scope=1        # Ubuntu default
  kernel.nmi_watchdog=1             # NMI watchdog holds one PMU counter per CPU (perf has one fewer)
  kernel.watchdog=1                 # lockup detectors on
  kernel.core_uses_pid=0            # stock core file naming
  kernel.sched_autogroup_enabled=1  # per-session task groups: how builds and fuzzers share CPU
  kernel.sched_rt_period_us=1000000 # RT throttling window
  kernel.sched_rt_runtime_us=950000 # RT tasks capped at 95% of each window
  kernel.sched_schedstats=0         # scheduler statistics off (on adds cost to every switch)
  kernel.numa_balancing=1           # automatic NUMA page migration; trials span both sockets
  kernel.timer_migration=1          # timers may move off idle CPUs
  vm.zone_reclaim_mode=0            # allocate on the remote node rather than reclaim locally
  vm.swappiness=60                  # stock; the host has a swap file
  vm.overcommit_memory=0            # heuristic overcommit; mode 2 breaks ASan's shadow mappings
  vm.max_map_count=1048576          # Ubuntu 24.04 default; ASan targets map many regions
  kernel.pid_max=4194304            # systemd default; fork-server fuzzing cycles pids fast
)
SYSCTL_FILE=/etc/sysctl.d/zz-fuzz-host-parity.conf
SYSCTL_BASE=${SYSCTL_FILE##*/}
checked_sysctls() {
  printf '%s\n' "${GUARD_SYSCTLS[@]}" "kernel.core_pattern=$WANT_CORE_PATTERN" \
    "fs.suid_dumpable=$WANT_SUID_DUMPABLE" "kernel.core_pipe_limit=$WANT_CORE_PIPE_LIMIT"
}
sysctl_file_text() {
  local kv
  echo "# Written by configure_fuzz_host.sh: $CAPTURE_HOST's values (captured $CAPTURE_DATE, --core-pattern=$CORE_MODE)."
  echo "# Named zz-* so systemd-sysctl reads it after every other sysctl.d file."
  while IFS= read -r kv; do echo "${kv%%=*} = ${kv#*=}"; done < <(checked_sysctls)
}
sysctl_file_get() {
  if [[ ! -e $R$SYSCTL_FILE ]]; then echo "not installed"
  elif [[ "$(cat "$R$SYSCTL_FILE")" == "$(sysctl_file_text)" ]]; then echo installed
  else echo stale; fi
}
sysctl_file_fix() { write_file "$R$SYSCTL_FILE" 0644 "$(sysctl_file_text)"; }
# The files systemd-sysctl reads, as "<basename><TAB><path>". A basename in
# /etc/sysctl.d hides the same name in /run, /usr/local/lib and /usr/lib.
# /etc/sysctl.conf sorts as "~" (after the zz file) whether or not Ubuntu's
# 99-sysctl.conf link points at it: `sysctl -p` and `sysctl --system` re-read it
# last, so its conflicting lines are commented out rather than overridden.
sysctl_sources() {
  local d f b conf=$R/etc/sysctl.conf
  declare -A seen=()
  for d in "$R/etc/sysctl.d" "$R/run/sysctl.d" "$R/usr/local/lib/sysctl.d" "$R/usr/lib/sysctl.d"; do
    for f in "$d"/*.conf; do
      b=${f##*/}
      [[ -z ${seen[$b]:-} ]] || continue
      seen[$b]=1
      [[ -f $f ]] || continue                      # masked (-> /dev/null) or dangling
      if [[ -f $conf && $(readlink -f "$f") == "$(readlink -f "$conf")" ]]; then continue; fi
      printf '%s\t%s\n' "$b" "$f"
    done
  done
  if [[ -f $conf ]]; then printf '~\t%s\n' "$conf"; fi
}
sysctl_conflicts() {   # "<basename><TAB><path><TAB><key>" for every line setting a checked key differently
  local b f kv key want line
  while IFS=$'\t' read -r b f; do
    [[ $f != "$R$SYSCTL_FILE" ]] || continue
    while IFS= read -r kv; do
      key=${kv%%=*}; want=$(tr -d '[:space:]' <<<"${kv#*=}")
      while IFS= read -r line; do
        if [[ $(tr -d '[:space:]' <<<"${line#*=}") != "$want" ]]; then printf '%s\t%s\t%s\n' "$b" "$f" "$key"; fi
      done < <(grep -E "^[[:space:]]*-?${key//./[./]}[[:space:]]*=" "$f" 2>/dev/null || true)
    done < <(checked_sysctls)
  done < <(sysctl_sources)
}
sysctl_conflicts_get() {
  local b f key over=() open=() cur
  cur=$(sysctl_file_get)
  while IFS=$'\t' read -r b f key; do
    if [[ $cur == installed && $b < $SYSCTL_BASE ]]; then over+=("${f#"$R"}:$key"); else open+=("${f#"$R"}:$key"); fi
  done < <(sysctl_conflicts)
  if [[ ${#open[@]} -gt 0 ]]; then echo "${open[*]}"
  elif [[ ${#over[@]} -gt 0 ]]; then echo "none (overridden by $SYSCTL_BASE: ${over[*]})"
  else echo none; fi
}
sysctl_conflicts_fix() {
  local b f key
  NEED_SYSCTL_FILE=1; sysctl_file_fix
  while IFS=$'\t' read -r b f key; do   # lines read after the zz file cannot be overridden by it
    [[ $b > $SYSCTL_BASE ]] || continue
    if [[ $f == "$R/etc/"* ]]; then comment_out "$f" "-?${key//./[./]}[[:space:]]*="
    else manual "${f#"$R"} sets $key and is read after $SYSCTL_BASE"; fi
  done < <(sysctl_conflicts)
}

for kv in "${GUARD_SYSCTLS[@]}"; do
  item rt "${kv%%=*}" "${kv#*=}" "proc_get ${kv%%=*}" "sysctl_fix ${kv%%=*}"
done
# A sysctl file with another value is a DIFF even when the live value matches:
# it takes effect at the next boot.
item file "sysctl files setting other values" "~none" sysctl_conflicts_get sysctl_conflicts_fix
want_sysctl_file="not installed"
if [[ $NEED_SYSCTL_FILE == 1 || $CORE_MODE == core || -n $(sysctl_conflicts) || -e $R$SYSCTL_FILE \
      || ( $MODE == apply && $FILES_ONLY == 1 ) ]]; then want_sysctl_file=installed; fi
item file "${SYSCTL_FILE#/etc/}" "$want_sysctl_file" sysctl_file_get sysctl_file_fix

# --------------------------------------------------------------------------
section "systemd, boot hooks and limits"
# r440-2-13 has none of these. Each could pin processes to CPUs, change limits,
# or re-tune the CPU at boot behind this script's back.
# --------------------------------------------------------------------------
SD_KEYS='CPUAffinity|NUMAPolicy|NUMAMask|DefaultLimit[A-Z]+|DefaultTasksMax|DefaultCPUAccounting'
sd_conf_files() { existing "$R/etc/systemd/system.conf" "$R/etc/systemd/user.conf" "$R"/etc/systemd/system.conf.d/*.conf "$R"/etc/systemd/user.conf.d/*.conf; }
sd_conf_get() { mapfile -t fs < <(sd_conf_files); grep_files "^[[:space:]]*($SD_KEYS)=" "${fs[@]}"; }
sd_conf_fix() {
  local f
  while read -r f; do
    if grep -qE "^[[:space:]]*($SD_KEYS)=" "$f"; then comment_out "$f" "($SD_KEYS)="; fi
  done < <(sd_conf_files)
  REBOOT_REASONS+=("systemd manager CPU/limit defaults change at next boot")
}
SLICE_KEYS='AllowedCPUs|StartupAllowedCPUs|CPUAffinity|CPUQuota|CPUWeight|StartupCPUWeight|AllowedMemoryNodes'
slice_files() {
  find "$R/etc/systemd/system" -maxdepth 2 -type f \( -path '*.slice.d/*.conf' -o -path '*.scope.d/*.conf' -o -name '*.slice' \) 2>/dev/null | sort
}
slice_get() { mapfile -t fs < <(slice_files); grep_files "^[[:space:]]*($SLICE_KEYS)=" "${fs[@]}"; }
slice_fix() {
  local f
  while read -r f; do
    if grep -qE "^[[:space:]]*($SLICE_KEYS)=" "$f"; then comment_out "$f" "($SLICE_KEYS)="; fi
  done < <(slice_files)
  run_live systemctl daemon-reload || true
  REBOOT_REASONS+=("slice CPU limits were removed; running slices keep them until reboot")
}
control_get() {   # `systemctl set-property` keeps its settings here
  local out
  out=$(find "$R/etc/systemd/system.control" "$R/run/systemd/system.control" -type f 2>/dev/null | sed "s|^$R||" | sort | paste -sd ' ' - || true)
  echo "${out:-none}"
}
UNIT_RE='scaling_governor|cpupower|cpufreq|cpuidle|intel_pstate|no_turbo|energy_perf|smt/control|sysctl|/proc/sys|core_pattern|afl-|transparent_hugepage|/proc/irq'
foreign_units_get() {
  local out
  out=$(find "$R/etc/systemd/system" -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' \) \
          ! -name cpu-governor.service ! -name fuzz-cpu-parity.service -print0 2>/dev/null \
        | xargs -0 -r grep -l -i -E "$UNIT_RE" 2>/dev/null | sed "s|^$R||" | paste -sd ' ' - || true)
  echo "${out:-none}"
}
rc_local_get() {
  local f=$R/etc/rc.local n
  [[ -f $f ]] || { echo "no active commands"; return 0; }
  n=$(grep -cvE '^[[:space:]]*(#|$|exit 0)' "$f" || true)
  if [[ $n == 0 ]]; then echo "no active commands"; else echo "$n active lines"; fi
}
tmpfiles_get() { mapfile -t fs < <(existing "$R"/etc/tmpfiles.d/*.conf "$R"/run/tmpfiles.d/*.conf); grep_files '^[[:space:]]*w[-+!=~^]*[[:space:]]+/(sys|proc)/' "${fs[@]}"; }
CRON_RE='@reboot|sysctl|/proc/sys|/sys/|cpupower|cpufreq|scaling_governor|no_turbo|intel_pstate|cpuidle|smt/control|core_pattern|transparent_hugepage|afl-system-config|afl-persistent-config'
cron_files() { existing "$R/etc/crontab" "$R"/etc/cron.d/* "$R"/etc/cron.hourly/* "$R"/etc/cron.daily/* "$R"/etc/cron.weekly/* "$R"/etc/cron.monthly/* "$R"/etc/cron.yearly/*; }
cron_get() { mapfile -t fs < <(cron_files); grep_files "^[^#]*($CRON_RE)" "${fs[@]}"; }
UDEV_RE='cpufreq|cpuidle|governor|scaling_|energy_perf|/cpu[0-9*]|SUBSYSTEM=="cpu"|power/control'
udev_get() { mapfile -t fs < <(existing "$R"/etc/udev/rules.d/*.rules); grep_files "$UDEV_RE" "${fs[@]}"; }
udev_lib_get() {   # /usr/lib rules no package owns; without a dpkg db, only rules touching cpu/power
  local rules=("$R"/usr/lib/udev/rules.d/*.rules) lists=("$R"/var/lib/dpkg/info/*.list) f owned out=()
  [[ ${#rules[@]} -gt 0 ]] || { echo none; return 0; }
  if [[ ${#lists[@]} -eq 0 ]]; then grep_files "$UDEV_RE" "${rules[@]}"; return 0; fi
  owned=$(grep -hxF -f <(for f in "${rules[@]}"; do f=${f#"$R"}; echo "$f"; echo "${f#/usr}"; done) "${lists[@]}" 2>/dev/null || true)
  for f in "${rules[@]}"; do
    f=${f#"$R"}
    grep -qxF -e "$f" -e "${f#/usr}" <<<"$owned" || out+=("$f")
  done
  echo "${out[*]:-none}"
}
sysfs_conf_get() { mapfile -t fs < <(existing "$R/etc/sysfs.conf" "$R"/etc/sysfs.d/*.conf); grep_files '^[[:space:]]*[^#[:space:]]' "${fs[@]}"; }
limits_get() { mapfile -t fs < <(existing "$R/etc/security/limits.conf" "$R"/etc/security/limits.d/*.conf); grep_files '^[[:space:]]*[^#[:space:]]' "${fs[@]}"; }

# Processes systemd starts (dockerd included) inherit CPUAffinity/limits from here.
item file "system.conf/user.conf CPU, limits" none sd_conf_get    sd_conf_fix
# AllowedCPUs on system.slice would squeeze every container onto fewer cores.
item file "slice/scope CPU drop-ins"          none slice_get      slice_fix
item file "systemd system.control"            none control_get    "manual review: systemctl revert <unit> drops set-property settings"
item file "custom units touching cpu/sysctl"  none foreign_units_get "manual review and disable them"
item file "/etc/rc.local"         "no active commands" rc_local_get "manual review /etc/rc.local"
item file "tmpfiles.d writes to /sys, /proc"  none tmpfiles_get   "manual review those tmpfiles.d lines"
item file "cron jobs touching cpu/sysfs/sysctl" none cron_get     "manual review those cron entries"
item file "udev rules (/etc) touching cpu"    none udev_get       "manual review those rules"
item file "udev rules (/usr/lib) not packaged" none udev_lib_get  "manual review those rules"
item file "sysfs.conf / sysfs.d"              none sysfs_conf_get "manual review sysfsutils settings"
# Login limits only: trial containers take their limits from docker, not PAM.
item fwarn "limits.conf / limits.d"           none limits_get

# --------------------------------------------------------------------------
section "Docker"
# r440-2-13 runs the packaged docker.service with no daemon.json and no drop-ins;
# trials set their own --cpuset-cpus, --memory and --ulimit per container.
# --------------------------------------------------------------------------
DOCKER_KEYS='default-ulimits cpu-rt-period cpu-rt-runtime exec-opts cgroup-parent default-cgroupns-mode oom-score-adjust default-shm-size'
DAEMON_JSON_PY='
import json, os, sys
path, keys, mode = sys.argv[1], sys.argv[2].split(), sys.argv[3]
try:
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
except Exception as exc:
    print("<invalid JSON: %s>" % exc)
    sys.exit(3)
found = [k for k in keys if k in data]
if mode == "get":
    print(" ".join(found) or "none")
    sys.exit(0)
for k in found:
    del data[k]
st = os.stat(path)
tmp = path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
os.chmod(tmp, st.st_mode & 0o7777)
if (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()):
    os.chown(tmp, st.st_uid, st.st_gid)
os.replace(tmp, path)
'
daemon_json_get() {
  local f=$R/etc/docker/daemon.json
  [[ -f $f ]] || { echo none; return 0; }
  command -v python3 >/dev/null 2>&1 || { echo "<cannot parse: no python3>"; return 0; }
  python3 -I -c "$DAEMON_JSON_PY" "$f" "$DOCKER_KEYS" get || true
}
daemon_json_fix() {
  local f
  f=$(real_path "$R/etc/docker/daemon.json") || { fail "/etc/docker/daemon.json links outside CFG_ROOT; not edited"; return 1; }
  command -v python3 >/dev/null 2>&1 || { fail "no python3: remove $2 from /etc/docker/daemon.json by hand"; return 1; }
  if ! python3 -I -c "$DAEMON_JSON_PY" "$f" "$DOCKER_KEYS" get >/dev/null; then
    fail "/etc/docker/daemon.json is not valid JSON; left unchanged, fix it by hand"; return 1
  fi
  backup "$f"
  if python3 -I -c "$DAEMON_JSON_PY" "$f" "$DOCKER_KEYS" fix >/dev/null; then
    log "removed $2 from /etc/docker/daemon.json"; NEED_DOCKER_RESTART=1
  else
    fail "rewriting /etc/docker/daemon.json failed; the backup is next to it"
  fi
}
DROPIN_KEYS='Limit[A-Z]+|CPU[A-Za-z]*|AllowedCPUs|Nice|IOScheduling[A-Za-z]*|TasksMax|Slice'
dropin_files() { existing "$R"/etc/systemd/system/docker.service.d/*.conf "$R"/etc/systemd/system/containerd.service.d/*.conf; }
dropin_get() { mapfile -t fs < <(dropin_files); grep_files "^[[:space:]]*($DROPIN_KEYS)=" "${fs[@]}"; }
dropin_fix() {
  local f
  while read -r f; do
    if grep -qE "^[[:space:]]*($DROPIN_KEYS)=" "$f"; then comment_out "$f" "($DROPIN_KEYS)="; fi
  done < <(dropin_files)
  run_live systemctl daemon-reload || true
  NEED_DOCKER_RESTART=1
}
exec_override_get() {
  mapfile -t fs < <(existing "$R/etc/systemd/system/docker.service" "$R"/etc/systemd/system/docker.service.d/*.conf)
  grep_files '^[[:space:]]*ExecStart=' "${fs[@]}"
}
DOCKERD_FLAGS_RE='--default-ulimit|--exec-opt|--cgroup-parent|--default-cgroupns-mode|--cpu-rt-|--default-shm-size|--oom-score-adjust'
dockerd_flags_files_get() {
  mapfile -t fs < <(existing "$R/etc/systemd/system/docker.service" "$R"/etc/systemd/system/docker.service.d/*.conf)
  grep_files "^[[:space:]]*ExecStart=.*($DOCKERD_FLAGS_RE)" "${fs[@]}"
}
dockerd_flags_live_get() {
  local out; out=$(dockerd_exec_get | grep -oE -e "($DOCKERD_FLAGS_RE)[^ ]*( [^-][^ ]*)?" | paste -sd ' ' - || true)
  echo "${out:-none}"
}
docker_fmt() { docker info --format "$1"; }
docker_containerd_get() { docker version --format '{{range .Server.Components}}{{if eq .Name "containerd"}}{{.Version}}{{end}}{{end}}'; }
dockerd_exec_get() { systemctl show docker.service -p ExecStart --value | sed -n 's/.*argv\[\]=\([^;]*[^; ]\) *;.*/\1/p' | head -n1; }

# daemon-wide ulimits / RT budget / cgroup parent would apply to every trial container.
item file  "daemon.json CPU/limit keys"       none daemon_json_get daemon_json_fix
item file  "docker/containerd unit drop-ins"  none dropin_get      dropin_fix
item fwarn "docker.service ExecStart override" none exec_override_get
# Same rule as daemon.json: these flags change every trial container's limits.
DOCKERD_FLAGS_HINT="manual remove those dockerd flags from the ExecStart override (daemon.json has none on r440-2-13 either)"
item file  "dockerd CPU/limit flags (unit files)" none dockerd_flags_files_get "$DOCKERD_FLAGS_HINT"
item rt    "dockerd CPU/limit flags (running)"    none dockerd_flags_live_get  "$DOCKERD_FLAGS_HINT"
item hw    "docker version"                   "$WANT_DOCKER_VERSION"     "docker_fmt {{.ServerVersion}}"
item hw    "containerd version"               "$WANT_CONTAINERD_VERSION" docker_containerd_get
item hw    "docker storage driver"            "$WANT_DOCKER_DRIVER"      "docker_fmt {{.Driver}}"
item hw    "docker default runtime"           "$WANT_DOCKER_RUNTIME"     "docker_fmt {{.DefaultRuntime}}"
item hw    "docker cgroup driver/version"     systemd/cgroup-v2          "docker_fmt {{.CgroupDriver}}/cgroup-v{{.CgroupVersion}}"
item hw    "dockerd command line"             "$WANT_DOCKERD_EXEC"       dockerd_exec_get
if [[ $NEED_DOCKER_RESTART == 1 ]]; then
  if [[ $RESTART_DOCKER == 1 ]]; then
    run_live systemctl restart docker.service || log "docker restart failed"
  else
    log "docker settings changed: restart docker to use them (kills running containers):"
    log "  systemctl daemon-reload && systemctl restart docker   (or rerun with --restart-docker)"
  fi
fi

# --------------------------------------------------------------------------
section "Root-only reads (not captured on $CAPTURE_HOST; shown to compare two hosts)"
# --------------------------------------------------------------------------
if [[ $FILES_ONLY == 1 ]]; then
  say SKIP "root-only reads" "(live state; --files-only)"
elif [[ $EUID -ne 0 ]]; then
  say SKIP "root-only reads" "sched debugfs, /dev/cpu_dma_latency holders, root crontab: run as root"
else
  d=/sys/kernel/debug/sched
  if [[ -d $d ]]; then
    v=""
    for k in base_slice_ns migration_cost_ns nr_migrate tunable_scaling preempt; do
      if [[ -r $d/$k ]]; then v+="$k=$(tr '\n' ' ' < "$d/$k" | sed 's/ *$//') "; fi
    done
    info "sched debugfs" "${v:-<none readable>}"
  else
    info "sched debugfs" "not mounted"
  fi
  holders=$(find /proc/[0-9]*/fd -lname /dev/cpu_dma_latency 2>/dev/null | cut -d/ -f3 | sort -u \
            | while read -r p; do printf '%s(%s) ' "$(cat "/proc/$p/comm" 2>/dev/null)" "$p"; done || true)
  info "/dev/cpu_dma_latency holders" "${holders:-none}"
  crontabs=(/var/spool/cron/crontabs/*)
  cron=none
  if [[ ${#crontabs[@]} -gt 0 ]]; then cron=$(grep_files "^[^#]*($CRON_RE)" "${crontabs[@]}"); fi
  info "user crontabs touching cpu/sysctl" "$cron"
fi
if [[ $FILES_ONLY == 0 ]]; then
  mapfile -t gfs < <(grub_files)
  grub_default=$( { grep -h -E '^[[:space:]]*GRUB_DEFAULT=' "${gfs[@]}" /dev/null 2>/dev/null || true; } | tail -n1 | sed -E 's/^[^=]*=//; s/["'"'"']//g')
  case ${grub_default:-0} in
    0) gd="GRUB_DEFAULT=0: the newest kernel boots next" ;;
    saved) gd="GRUB_DEFAULT=saved: the last booted entry boots next" ;;
    *) gd="GRUB_DEFAULT=$grub_default" ;;
  esac
  info "installed kernels" "$(cd /boot && printf '%s ' vmlinuz-* | sed 's/vmlinuz-//g')($gd)"
fi

# --------------------------------------------------------------------------
echo
if [[ ${#REBOOT_REASONS[@]} -gt 0 ]]; then
  echo "################################################################"
  echo "##  REBOOT REQUIRED (not done by this script):"
  for r in "${REBOOT_REASONS[@]}"; do echo "##    - $r"; done
  echo "################################################################"
fi
if [[ $MODE == apply && $NFIXED -gt 0 ]]; then
  echo "Changes were made: re-run --check after the next reboot to confirm they persist."
fi
printf 'summary: %d OK, %d DIFF, %d FIXED, %d FAILED, %d WARN\n' "$NOK" "$NDIFF" "$NFIXED" "$NFAILED" "$NWARN"
if [[ $NDIFF -gt 0 || $NFAILED -gt 0 ]]; then exit 1; fi
exit 0
