# Phase3 Kubernetes Fuzzing Report

- Generated: `2026-05-28 21:56:27 UTC`
- Data source: `ssh nfs:/shared/bena/phase3-kube`
- Kubernetes context: `davit@gwc.sefcom.asu.edu`, namespace `davit`
- Parsed artifact archives: `760` zip files (`760` present when checked)
- Per-run compact data: `report_kube_records.json.gz` and `report_kube_records.csv`

## Important Notes

- These results are from the persistent NFS zip archives, not from `kubectl logs`. That means recovered findings remain available even after pods finish.
- `outcome=finding` is a successful wrapper result: libFuzzer/sanitizer found something, artifacts were saved, and the pod usually exits `0`.
- `outcome=clean` means the fuzzer ran to its configured time limit without a finding.
- `outcome=infra_error` means the fuzzer exited nonzero without a recognizable libFuzzer/sanitizer finding; these still need manual investigation.
- The full corpus is not archived. The report uses `corpus_file_count`, `corpus_du_bytes`, and `corpus_du_human` from each archive metadata file.
- Some `libfuzzer.log` files expand to multiple GB inside the zip, mostly from verbose GPAC/Selinux output. Logs above 200 MiB were not fully inflated; those rows still include metadata, corpus sizes, crash file names, and timeout classification when available, but detailed exec/s/coverage may be missing.

## Current Cluster Status

| Job | Succeeded | Failed | Active | Completions |
|---|---:|---:|---:|---:|
| `phase3-gpac-baseline-100` | 100 | 0 | 0 | 100 |
| `phase3-gpac-optimized-100` | 100 | 0 | 0 | 100 |
| `phase3-librawspeed-baseline-100` | 100 | 0 | 0 | 100 |
| `phase3-librawspeed-optimized-100` | 100 | 0 | 0 | 100 |
| `phase3-selinux-baseline-100` | 100 | 0 | 0 | 100 |
| `phase3-selinux-optimized-100` | 59 | 1 | 10 | 100 |
| `phase3-unrar-baseline-100` | 85 | 15 | 0 | 100 |
| `phase3-unrar-optimized-100` | 88 | 12 | 0 | 100 |

Pod phases at collection: `Failed`=28, `Running`=10, `Succeeded`=732

## Overall Artifact Outcomes

![Outcome counts](report_kube_figures/outcomes_by_job.png)

| Project | Variant | Artifacts | Clean | Findings | Infra errors | Missing/not done | Pod exit 0 | Nonzero pod exit | Crash files | Logs skipped | Corpus archived |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| selinux | baseline | 100 | 3 | 97 | 0 | 0 | 100 | 0 | 97 | 26 | 0 |
| selinux | optimized | 60 | 27 | 32 | 1 | 40 | 59 | 1 | 38 | 40 | 0 |
| gpac | baseline | 100 | 1 | 99 | 0 | 0 | 100 | 0 | 118 | 41 | 0 |
| gpac | optimized | 100 | 0 | 100 | 0 | 0 | 100 | 0 | 136 | 3 | 0 |
| librawspeed | baseline | 100 | 0 | 100 | 0 | 0 | 100 | 0 | 100 | 0 | 0 |
| librawspeed | optimized | 100 | 0 | 100 | 0 | 0 | 100 | 0 | 100 | 0 | 0 |
| unrar | baseline | 100 | 0 | 85 | 15 | 0 | 85 | 15 | 85 | 0 | 0 |
| unrar | optimized | 100 | 0 | 88 | 12 | 0 | 88 | 12 | 88 | 0 | 0 |

## Baseline vs Optimized Summary

Mean/median cells are formatted as `mean / median (n=...)`. Exec/s and coverage only include logs that were parsed, so check `logs skipped`.

| Project | Artifacts B/O | Findings B/O | Clean B/O | Infra B/O | Time to finding B/O | Exec/s B/O | Coverage B/O | Features B/O | Corpus files B/O | Corpus bytes B/O | Logs skipped B/O |
|---|---:|---:|---:|---:|---|---|---|---|---|---|---:|
| selinux | 100/60 | 97/32 | 3/27 | 0/1 | 1h 25m 02s / 1h 16m 14s (n=97) / 1h 14m 51s / 24m 18s (n=32) | 645 / 574 (n=74) / 2,616 / 2,730 (n=20) | 659 / 680 (n=74) / 575 / 540 (n=20) | 2,146 / 2,290 (n=74) / 1,855 / 1,690 (n=20) | 497 / 498 (n=100) / 695 / 716 (n=60) | 153.0 KiB / 160.8 KiB (n=100) / 233.8 KiB / 264.7 KiB (n=60) | 26/40 |
| gpac | 100/100 | 99/100 | 1/0 | 0/0 | 33m 15s / 24m 50s (n=99) / 48m 12s / 27m 17s (n=100) | 739 / 510 (n=59) / 652 / 185 (n=97) | 863 / 851 (n=59) / 925 / 916 (n=97) | 2,179 / 2,214 (n=59) / 2,245 / 2,204 (n=97) | 390 / 384 (n=100) / 402 / 384 (n=100) | 58.6 KiB / 55.8 KiB (n=100) / 60.8 KiB / 57.0 KiB (n=100) | 41/3 |
| librawspeed | 100/100 | 100/100 | 0/0 | 0/0 | 2s / 1s (n=100) / 2s / 0s (n=100) | 392 / 0 (n=100) / 485 / 0 (n=100) | 307 / 308 (n=100) / 307 / 308 (n=100) | 91 / 95 (n=100) / 91 / 95 (n=100) | 7 / 6 (n=100) / 7 / 6 (n=100) | 12.9 KiB / 12.4 KiB (n=100) / 12.9 KiB / 12.4 KiB (n=100) | 0/0 |
| unrar | 100/100 | 85/88 | 0/0 | 15/12 | 23m 02s / 21m 30s (n=85) / 20m 40s / 20m 00s (n=88) | 155 / 144 (n=85) / 160 / 152 (n=88) | 622 / 669 (n=85) / 625 / 644 (n=88) | 1,194 / 1,197 (n=85) / 1,220 / 1,178 (n=88) | 111 / 102 (n=100) / 122 / 108 (n=100) | 94.7 KiB / 61.3 KiB (n=100) / 104.0 KiB / 67.1 KiB (n=100) | 0/0 |

![Mean exec/s](report_kube_figures/exec_s_mean.png)

![Median corpus size](report_kube_figures/corpus_median_kib.png)

![Log parse coverage](report_kube_figures/log_parse_coverage.png)

## Metrics By Job

| Project | Variant | Outcome | Count | Elapsed | Exec/s | Coverage | Features | Peak RSS MB | Executed units | New units | Corpus files | Corpus bytes |
|---|---|---|---:|---|---|---|---|---|---|---|---|---|
| selinux | baseline | finding | 97 | 1h 25m 02s / 1h 16m 14s (n=97) | 654 / 577 (n=73) | 662 / 681 (n=73) | 2,158 / 2,299 (n=73) | 57 / 57 (n=73) | 1,981,852 / 1,785,644 (n=73) | 2,075 / 2,200 (n=73) | 494 / 497 (n=97) | 151.1 KiB / 159.3 KiB (n=97) |
| selinux | baseline | clean | 3 | 6h 00m 02s / 6h 00m 01s (n=3) | 19 / 19 (n=1) | 475 / 475 (n=1) | 1,268 / 1,268 (n=1) | 54 / 54 (n=1) | 412,866 / 412,866 (n=1) | 864 / 864 (n=1) | 570 / 705 (n=3) | 216.6 KiB / 283.4 KiB (n=3) |
| selinux | optimized | finding | 32 | 1h 14m 51s / 24m 18s (n=32) | 2,749 / 2,742 (n=19) | 569 / 523 (n=19) | 1,831 / 1,646 (n=19) | 57 / 56 (n=19) | 1,335,958 / 1,081,265 (n=19) | 1,487 / 1,320 (n=19) | 526 / 489 (n=32) | 157.9 KiB / 133.8 KiB (n=32) |
| selinux | optimized | clean | 27 | 6h 00m 01s / 6h 00m 01s (n=27) | 78 / 78 (n=1) | 687 / 687 (n=1) | 2,308 / 2,308 (n=1) | 59 / 59 (n=1) | 1,704,426 / 1,704,426 (n=1) | 1,941 / 1,941 (n=1) | 885 / 868 (n=27) | 317.0 KiB / 311.3 KiB (n=27) |
| selinux | optimized | infra_error | 1 | 3h 35m 26s / 3h 35m 26s (n=1) | n/a | n/a | n/a | n/a | n/a | n/a | 985 / 985 (n=1) | 413.4 KiB / 413.4 KiB (n=1) |
| gpac | baseline | finding | 99 | 33m 15s / 24m 50s (n=99) | 739 / 510 (n=59) | 863 / 851 (n=59) | 2,179 / 2,214 (n=59) | 4,915 / 8,279 (n=59) | 253,402 / 225,657 (n=59) | 1,003 / 987 (n=59) | 391 / 384 (n=99) | 58.8 KiB / 55.8 KiB (n=99) |
| gpac | baseline | clean | 1 | 6h 00m 54s / 6h 00m 54s (n=1) | n/a | n/a | n/a | n/a | n/a | n/a | 282 / 282 (n=1) | 34.9 KiB / 34.9 KiB (n=1) |
| gpac | optimized | finding | 100 | 48m 12s / 27m 17s (n=100) | 652 / 185 (n=97) | 925 / 916 (n=97) | 2,245 / 2,204 (n=97) | 4,913 / 4,681 (n=97) | 291,367 / 250,868 (n=97) | 1,129 / 994 (n=97) | 402 / 384 (n=100) | 60.8 KiB / 57.0 KiB (n=100) |
| librawspeed | baseline | finding | 100 | 2s / 1s (n=100) | 392 / 0 (n=100) | 307 / 308 (n=100) | 91 / 95 (n=100) | 44 / 43 (n=100) | 3,057 / 2,030 (n=100) | 6 / 5 (n=100) | 7 / 6 (n=100) | 12.9 KiB / 12.4 KiB (n=100) |
| librawspeed | optimized | finding | 100 | 2s / 0s (n=100) | 485 / 0 (n=100) | 307 / 308 (n=100) | 91 / 95 (n=100) | 44 / 43 (n=100) | 3,057 / 2,030 (n=100) | 6 / 5 (n=100) | 7 / 6 (n=100) | 12.9 KiB / 12.4 KiB (n=100) |
| unrar | baseline | finding | 85 | 23m 02s / 21m 30s (n=85) | 155 / 144 (n=85) | 622 / 669 (n=85) | 1,194 / 1,197 (n=85) | 95 / 95 (n=85) | 207,438 / 200,060 (n=85) | 1,340 / 1,344 (n=85) | 130 / 107 (n=85) | 110.7 KiB / 69.7 KiB (n=85) |
| unrar | baseline | infra_error | 15 | 0s / 0s (n=15) | n/a | n/a | n/a | n/a | n/a | n/a | 1 / 1 (n=15) | 4.0 KiB / 4.0 KiB (n=15) |
| unrar | optimized | finding | 88 | 20m 40s / 20m 00s (n=88) | 160 / 152 (n=88) | 625 / 644 (n=88) | 1,220 / 1,178 (n=88) | 105 / 95 (n=88) | 193,955 / 185,362 (n=88) | 1,326 / 1,302 (n=88) | 138 / 116 (n=88) | 117.6 KiB / 75.1 KiB (n=88) |
| unrar | optimized | infra_error | 12 | 0s / 0s (n=12) | n/a | n/a | n/a | n/a | n/a | n/a | 1 / 1 (n=12) | 4.0 KiB / 4.0 KiB (n=12) |

## Unique Findings

Signatures are grouped by sanitizer, normalized summary, and `DEDUP_TOKEN`. Rows labeled `signature unavailable` are findings whose logs were skipped or did not contain a parsed signature.

| Project | Variant | Count | Time to finding | Exec/s | Cov/ft | First trial | Example crash file | Sanitizer | Summary | Dedup token |
|---|---|---:|---|---|---|---:|---|---|---|---|
| selinux | baseline | 73 | 53m 58s / 44m 35s (n=73) | 654 / 577 (n=73) | 662 / 681 (n=73) / 2,158 / 2,299 (n=73) | 0 | `crashes/crash-7085a8ee0872e652c70f4bc37950b6c6c8908905` | AddressSanitizer | AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0xb14a7) | strchr--cil_fill_ipaddr |
| selinux | baseline | 24 | 2h 59m 32s / 2h 54m 14s (n=24) | n/a | n/a / n/a | 6 | `crashes/crash-64e4b73a1da89e2f0c50010a2ff182741724e0fa` | signature unavailable | signature unavailable |  |
| selinux | optimized | 18 | 12m 59s / 8m 06s (n=18) | 2,698 / 2,730 (n=18) | 567 / 520 (n=18) / 1,796 / 1,598 (n=18) | 0 | `crashes/crash-4fa57408563ac4be617885dfbafe5a8e09a41061` | AddressSanitizer | AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0xb14a7) | strchr--cil_fill_ipaddr |
| selinux | optimized | 13 | 2h 45m 06s / 2h 30m 03s (n=13) | n/a | n/a / n/a | 5 | `crashes/crash-74dbc703db24c001d4a36afb8e85b4b443d7f157` | signature unavailable | signature unavailable |  |
| selinux | optimized | 1 | 15m 06s / 15m 06s (n=1) | 3,672 / 3,672 (n=1) | 601 / 601 (n=1) / 2,452 / 2,452 (n=1) | 3 | `crashes/crash-d34bcbc96cd4ed6b76d7aafc391fcef9ebc430c4` | AddressSanitizer | AddressSanitizer: heap-use-after-free /src/selinux/libsepol/src/../cil/src/cil_tree.c:185:12 in cil_tree_chil... | __interceptor_malloc--cil_malloc--cil_tree_node_init |
| gpac | baseline | 39 | 46m 30s / 30m 03s (n=39) | n/a | n/a / n/a | 0 | `crashes/timeout-49736daa4db10d60c3fb1cae40a8cc233550372c` | libFuzzer | libFuzzer: timeout |  |
| gpac | baseline | 30 | 11m 43s / 6m 49s (n=30) | 858 / 622 (n=30) | 768 / 776 (n=30) / 1,925 / 1,955 (n=30) | 2 | `crashes/oom-d2a35e0dae538d6c6752f2ca749ec66c3c0be6f0` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--ssix_box_read |
| gpac | baseline | 13 | 34m 14s / 5m 56s (n=13) | 920 / 808 (n=13) | 974 / 967 (n=13) / 2,487 / 2,602 (n=13) | 4 | `crashes/crash-4e3aaa41e7781fd3f65c5d2150f71ba92ab7d484` | AddressSanitizer | AddressSanitizer: SEGV /src/gpac/src/utils/list.c:642:14 in gf_list_count | gf_list_count--iloc_entry_del--iloc_box_del |
| gpac | baseline | 13 | 13m 40s / 15m 10s (n=13) | 355 / 330 (n=13) | 934 / 986 (n=13) / 2,354 / 2,479 (n=13) | 1 | `crashes/crash-15aa8db9908d9e30ead078efed7e14445b80a592` | AddressSanitizer | AddressSanitizer: heap-buffer-overflow /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:466:5 in ... | malloc--gf_malloc--abst_box_read |
| gpac | baseline | 1 | 4m 02s / 4m 02s (n=1) | 1,127 / 1,127 (n=1) | 861 / 861 (n=1) / 2,297 / 2,297 (n=1) | 30 | `crashes/crash-c10146814c4297cfec9c4bd71e719c78de08dc9d` | AddressSanitizer | AddressSanitizer: SEGV /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_atomic_clang.h:80... | atomic_compare_exchange_strong<__sanitizer::atomic_uint8_t>--AtomicallySetQuarantineFlagI... |
| gpac | baseline | 1 | 6h 00m 17s / 6h 00m 17s (n=1) | 19 / 19 (n=1) | 980 / 980 (n=1) / 2,385 / 2,385 (n=1) | 18 | `crashes/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709` | AddressSanitizer | AddressSanitizer: leak(s) | malloc--gf_malloc--afra_box_read |
| gpac | baseline | 1 | 1h 17m 08s / 1h 17m 08s (n=1) | 149 / 149 (n=1) | 1,256 / 1,256 (n=1) / 3,228 / 3,228 (n=1) | 86 | `crashes/oom-c17585cc8c988df2ac0da4b7bb27dd100ea71b21` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--afrt_box_read |
| gpac | baseline | 1 | 1h 03m 44s / 1h 03m 44s (n=1) | n/a | n/a / n/a | 46 | `crashes/oom-875e972859e53a098dc1e2245f4bf316dee19900` | signature unavailable | signature unavailable |  |
| gpac | optimized | 30 | 39m 41s / 13m 29s (n=30) | 716 / 290 (n=30) | 881 / 838 (n=30) / 2,162 / 2,154 (n=30) | 4 | `crashes/oom-d56662680b188bc48be05f1293c2c425148bfb04` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--ssix_box_read |
| gpac | optimized | 23 | 48m 22s / 30m 04s (n=23) | 100 / 95 (n=23) | 868 / 842 (n=23) / 2,061 / 2,170 (n=23) | 7 | `crashes/timeout-2720228f256b1d9fc6461c41dd973bffcd92e2a4` | libFuzzer | libFuzzer: timeout | __sanitizer_print_stack_trace--fuzzer::PrintStackTrace()--fuzzer::Fuzzer::AlarmCallback() |
| gpac | optimized | 16 | 18m 14s / 1m 54s (n=16) | 1,756 / 2,074 (n=16) | 935 / 890 (n=16) / 2,319 / 2,110 (n=16) | 1 | `crashes/crash-f28ae0fedf3fe664733a46186482da94381a6b95` | AddressSanitizer | AddressSanitizer: SEGV /src/gpac/src/utils/list.c:642:14 in gf_list_count | gf_list_count--iloc_entry_del--iloc_box_del |
| gpac | optimized | 11 | 10m 59s / 11m 21s (n=11) | 590 / 482 (n=11) | 1,059 / 986 (n=11) / 2,586 / 2,479 (n=11) | 0 | `crashes/crash-dbf06774a19db7c383482194dafe31700768d59c` | AddressSanitizer | AddressSanitizer: heap-buffer-overflow /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:466:5 in ... | malloc--gf_malloc--abst_box_read |
| gpac | optimized | 5 | 26m 41s / 25m 03s (n=5) | 208 / 170 (n=5) | 1,004 / 993 (n=5) / 2,337 / 2,402 (n=5) | 27 | `crashes/oom-83cea465ce10d4c94b196bef786da1fc78ea1d42` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--stsh_box_read |
| gpac | optimized | 4 | 1h 02m 40s / 40m 36s (n=4) | 621 / 230 (n=4) | 1,022 / 1,064 (n=4) / 2,464 / 2,495 (n=4) | 34 | `crashes/crash-5036137e49a4683a10f79c7d76be86f9bf168141` | AddressSanitizer | AddressSanitizer: SEGV /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_atomic_clang.h:80... | atomic_compare_exchange_strong<__sanitizer::atomic_uint8_t>--AtomicallySetQuarantineFlagI... |
| gpac | optimized | 3 | 36m 44s / 40m 04s (n=3) | n/a | n/a / n/a | 6 | `crashes/timeout-3e550d33e1c2fc89e983bde30b37f43f81a725c5` | libFuzzer | libFuzzer: timeout |  |
| gpac | optimized | 2 | 6h 15m 22s / 6h 15m 22s (n=2) | 12 / 12 (n=2) | 954 / 954 (n=2) / 2,298 / 2,298 (n=2) | 47 | `crashes/slow-unit-cf32ed5fc3efe942ff06fd9a020105d6c7f75a37` | AddressSanitizer | AddressSanitizer: leak(s) | malloc--gf_malloc--afrt_box_read |
| gpac | optimized | 2 | 27m 18s / 27m 18s (n=2) | 120 / 120 (n=2) | 904 / 904 (n=2) / 1,990 / 1,990 (n=2) | 36 | `crashes/oom-b79f716d142b02e12ae65d7278d3f192c4798884` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--saio_box_read |
| gpac | optimized | 1 | 6h 18m 07s / 6h 18m 07s (n=1) | 10 / 10 (n=1) | 851 / 851 (n=1) / 1,911 / 1,911 (n=1) | 53 | `crashes/slow-unit-5c114b4a90172c6c15328f4fb074583f8459c834` | AddressSanitizer | AddressSanitizer: leak(s) | malloc--gf_malloc--afra_box_read |
| gpac | optimized | 1 | 6h 00m 16s / 6h 00m 16s (n=1) | 48 / 48 (n=1) | 1,396 / 1,396 (n=1) / 3,764 / 3,764 (n=1) | 55 | `crashes/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709` | AddressSanitizer | AddressSanitizer: leak(s) | malloc--gf_malloc--xtra_box_read |
| gpac | optimized | 1 | 1h 04m 13s / 1h 04m 13s (n=1) | 154 / 154 (n=1) | 960 / 960 (n=1) / 2,650 / 2,650 (n=1) | 14 | `crashes/slow-unit-52aba69af8568c8987b1ba1d82a8f73644b1f0ac` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--afrt_box_read |
| gpac | optimized | 1 | 1m 54s / 1m 54s (n=1) | 890 / 890 (n=1) | 646 / 646 (n=1) / 1,520 / 1,520 (n=1) | 78 | `crashes/oom-815930a20a1af3e945e494b39cf86cd3d011dea7` | libFuzzer | libFuzzer: out-of-memory | malloc--gf_malloc--fecr_box_read |
| librawspeed | baseline | 67 | 2s / 1s (n=67) | 583 / 0 (n=67) | 300 / 285 (n=67) / 83 / 66 (n=67) | 0 | `crashes/crash-1940258e20b4d8f3ce921d670b303f0496340809` | AddressSanitizer | AddressSanitizer: ILL /src/librawspeed/src/librawspeed/io/Endianness.h:98:3 in unsigned int rawspeed::getByte... | unsigned int rawspeed::getByteSwapped<unsigned int>(void const*, bool)--unsigned int raws... |
| librawspeed | baseline | 32 | 1s / 1s (n=32) | 5 / 0 (n=32) | 320 / 314 (n=32) / 108 / 100 (n=32) | 4 | `crashes/crash-70ca9e64d3d8d316e024a0c6b777d49d96d59b51` | AddressSanitizer | AddressSanitizer: ILL /src/librawspeed/src/librawspeed/tiff/CiffEntry.cpp:69:3 in rawspeed::CiffEntry::getEle... | rawspeed::CiffEntry::getElementShift() const--rawspeed::CiffEntry::CiffEntry(rawspeed::By... |
| librawspeed | baseline | 1 | 0s / 0s (n=1) | 0 / 0 (n=1) | 345 / 345 (n=1) / 141 / 141 (n=1) | 34 | `crashes/crash-d3f097e33d00da5cbbc95970743b0bd3f045b3de` | AddressSanitizer | AddressSanitizer: ILL /src/librawspeed/src/librawspeed/tiff/TiffEntry.cpp:54:26 in rawspeed::TiffEntry::TiffE... | rawspeed::TiffEntry::TiffEntry(rawspeed::TiffIFD*, rawspeed::ByteStream*)--std::__1::uniq... |
| librawspeed | optimized | 67 | 3s / 1s (n=67) | 457 / 0 (n=67) | 300 / 285 (n=67) / 83 / 66 (n=67) | 0 | `crashes/crash-1940258e20b4d8f3ce921d670b303f0496340809` | AddressSanitizer | AddressSanitizer: ILL /src/librawspeed/src/librawspeed/io/Endianness.h:98:3 in unsigned int rawspeed::getByte... | unsigned int rawspeed::getByteSwapped<unsigned int>(void const*, bool)--unsigned int raws... |
| librawspeed | optimized | 32 | 0s / 0s (n=32) | 558 / 0 (n=32) | 320 / 314 (n=32) / 108 / 100 (n=32) | 4 | `crashes/crash-70ca9e64d3d8d316e024a0c6b777d49d96d59b51` | AddressSanitizer | AddressSanitizer: ILL /src/librawspeed/src/librawspeed/tiff/CiffEntry.cpp:69:3 in rawspeed::CiffEntry::getEle... | rawspeed::CiffEntry::getElementShift() const--rawspeed::CiffEntry::CiffEntry(rawspeed::By... |
| librawspeed | optimized | 1 | 0s / 0s (n=1) | 0 / 0 (n=1) | 345 / 345 (n=1) / 141 / 141 (n=1) | 34 | `crashes/crash-d3f097e33d00da5cbbc95970743b0bd3f045b3de` | AddressSanitizer | AddressSanitizer: ILL /src/librawspeed/src/librawspeed/tiff/TiffEntry.cpp:54:26 in rawspeed::TiffEntry::TiffE... | rawspeed::TiffEntry::TiffEntry(rawspeed::TiffIFD*, rawspeed::ByteStream*)--std::__1::uniq... |
| unrar | baseline | 21 | 24m 02s / 23m 16s (n=21) | 154 / 143 (n=21) | 634 / 623 (n=21) / 1,174 / 1,100 (n=21) | 5 | `crashes/crash-81e25d16e1d51af850a787a9116d4592e5924618` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/arcread.cpp:1337:3 in Archive::ConvertFileHeader(FileH... | CmdExtract::ExtractArchive() |
| unrar | baseline | 16 | 24m 46s / 23m 36s (n=16) | 153 / 138 (n=16) | 584 / 518 (n=16) / 1,097 / 932 (n=16) | 1 | `crashes/crash-3dfa4e5210e82510480ad886ad27a2000b403909` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/llvm/projects/libcxxabi/src/cxa_personality.cpp:946:22 in __... | __gxx_personality_v0--_Unwind_RaiseException--__cxa_throw |
| unrar | baseline | 16 | 24m 09s / 22m 28s (n=16) | 144 / 138 (n=16) | 618 / 686 (n=16) / 1,233 / 1,292 (n=16) | 8 | `crashes/crash-fcefca70d2522f51cb0d25737219e3b387627f20` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/arcread.cpp:1284:3 in Archive::ConvertAttributes() | CmdExtract::ExtractArchive() |
| unrar | baseline | 10 | 20m 11s / 18m 48s (n=10) | 177 / 151 (n=10) | 658 / 679 (n=10) / 1,302 / 1,298 (n=10) | 2 | `crashes/crash-0a725055ab15f06f9fc87ad913fb8feea99adaaf` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/unicode.cpp:171:9 in CharToWideMap(char const*, wchar_... | __interceptor_realloc--Array<unsigned char>::Add(unsigned long)--Archive::GetComment(Arra... |
| unrar | baseline | 8 | 23m 44s / 21m 48s (n=8) | 175 / 176 (n=8) | 672 / 693 (n=8) / 1,436 / 1,390 (n=8) | 9 | `crashes/crash-62f06fab9c250b51ba64e16b3325c744d3007a37` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/./arccmt.cpp:117:20 in Archive::GetComment(Array<wchar... | __interceptor_realloc--Array<wchar_t>::Add(unsigned long)--Archive::GetComment(Array<wcha... |
| unrar | baseline | 6 | 17m 46s / 16m 40s (n=6) | 170 / 158 (n=6) | 496 / 493 (n=6) / 836 / 802 (n=6) | 6 | `crashes/crash-6b631373b2ba4cd90e13ab3000333891be53e152` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/rdwrfn.cpp:98:13 in ComprDataIO::UnpRead(unsigned char... | CmdExtract::ExtractArchive() |
| unrar | baseline | 4 | 23m 38s / 22m 19s (n=4) | 137 / 138 (n=4) | 687 / 687 (n=4) / 1,337 / 1,284 (n=4) | 18 | `crashes/crash-18c0dd77403b0e3c6fb44daf43939be91c75f60b` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/llvm/projects/libcxxabi/src/cxa_personality.cpp:495:27 in ge... | get_thrown_object_ptr--__cxxabiv1::scan_eh_tab(__cxxabiv1::(anonymous namespace)::scan_re... |
| unrar | baseline | 2 | 20m 08s / 20m 08s (n=2) | 118 / 118 (n=2) | 693 / 693 (n=2) / 1,279 / 1,279 (n=2) | 31 | `crashes/crash-aedddb50525546cae367bc59b9a7f4aa4a6cbd7a` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/arcread.cpp:1337:3 in Archive::ConvertFileHeader(FileH... | Archive::ReadHeader15() |
| unrar | baseline | 1 | 10m 49s / 10m 49s (n=1) | 133 / 133 (n=1) | 679 / 679 (n=1) / 1,365 / 1,365 (n=1) | 14 | `crashes/crash-ab9fbcc34d4b824db7c87ba2cc0c8e4f215f0986` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/cmddata.cpp:1197:7 in CommandData::IsProcessFile(FileH... | CmdExtract::ExtractArchive() |
| unrar | baseline | 1 | 26m 07s / 26m 07s (n=1) | 113 / 113 (n=1) | 541 / 541 (n=1) / 793 / 793 (n=1) | 16 | `crashes/crash-47a1f59cb7e318f307cbb2e7ca4996af69a670dd` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/unicode.cpp:87:7 in CharToWide(char const*, wchar_t*, ... | __interceptor_realloc--Array<unsigned char>::Add(unsigned long)--Archive::GetComment(Arra... |
| unrar | optimized | 21 | 22m 40s / 20m 34s (n=21) | 144 / 137 (n=21) | 626 / 577 (n=21) / 1,150 / 1,007 (n=21) | 1 | `crashes/crash-7db9ce7a204e8a8f530f1e393a5f57d1e6006fe2` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/arcread.cpp:1337:3 in Archive::ConvertFileHeader(FileH... | CmdExtract::ExtractArchive() |
| unrar | optimized | 17 | 22m 29s / 23m 40s (n=17) | 160 / 152 (n=17) | 640 / 565 (n=17) / 1,309 / 1,175 (n=17) | 0 | `crashes/crash-292b2df4035705234c4aeaa0f80537cc06243c26` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/llvm/projects/libcxxabi/src/cxa_personality.cpp:946:22 in __... | __gxx_personality_v0--_Unwind_RaiseException--__cxa_throw |
| unrar | optimized | 12 | 16m 42s / 17m 55s (n=12) | 161 / 156 (n=12) | 682 / 700 (n=12) / 1,453 / 1,592 (n=12) | 3 | `crashes/crash-ec1269592526440453483fa606e90aef3750fee2` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/./arccmt.cpp:117:20 in Archive::GetComment(Array<wchar... | __interceptor_realloc--Array<wchar_t>::Add(unsigned long)--Archive::GetComment(Array<wcha... |
| unrar | optimized | 11 | 17m 34s / 16m 52s (n=11) | 171 / 173 (n=11) | 622 / 686 (n=11) / 1,265 / 1,379 (n=11) | 15 | `crashes/crash-4e6b0fa0c21e6a1421187c8da95c984e879dfc2e` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/arcread.cpp:1284:3 in Archive::ConvertAttributes() | CmdExtract::ExtractArchive() |
| unrar | optimized | 9 | 19m 06s / 20m 00s (n=9) | 164 / 153 (n=9) | 640 / 690 (n=9) / 1,257 / 1,236 (n=9) | 9 | `crashes/crash-8835ef1410fc1a26ee0ac448628ad109f0f33a17` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/unicode.cpp:171:9 in CharToWideMap(char const*, wchar_... | __interceptor_realloc--Array<unsigned char>::Add(unsigned long)--Archive::GetComment(Arra... |
| unrar | optimized | 6 | 20m 53s / 22m 26s (n=6) | 194 / 180 (n=6) | 576 / 588 (n=6) / 1,020 / 934 (n=6) | 5 | `crashes/crash-26e607f9eeae31b6a208670dfefe93aac7c074bd` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/llvm/projects/libcxxabi/src/cxa_personality.cpp:495:27 in ge... | get_thrown_object_ptr--__cxxabiv1::scan_eh_tab(__cxxabiv1::(anonymous namespace)::scan_re... |
| unrar | optimized | 5 | 18m 14s / 19m 29s (n=5) | 144 / 134 (n=5) | 624 / 677 (n=5) / 1,129 / 1,285 (n=5) | 22 | `crashes/crash-7395ef1c5a5e9f1ffb8c5db89993a9f7f4b72935` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/unicode.cpp:87:7 in CharToWide(char const*, wchar_t*, ... | __interceptor_realloc--Array<unsigned char>::Add(unsigned long)--Archive::GetComment(Arra... |
| unrar | optimized | 4 | 18m 16s / 17m 18s (n=4) | 167 / 167 (n=4) | 427 / 389 (n=4) / 650 / 536 (n=4) | 12 | `crashes/crash-c3fecf728004804c9b8a4ba55b22f694c30f2888` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/rdwrfn.cpp:98:13 in ComprDataIO::UnpRead(unsigned char... | CmdExtract::ExtractArchive() |
| unrar | optimized | 2 | 28m 01s / 28m 01s (n=2) | 164 / 164 (n=2) | 651 / 651 (n=2) / 1,307 / 1,307 (n=2) | 49 | `crashes/crash-27b3813bffe856ab5c2a5436544984e65cc3b74c` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/cmddata.cpp:1197:7 in CommandData::IsProcessFile(FileH... | CmdExtract::ExtractArchive() |
| unrar | optimized | 1 | 49m 14s / 49m 14s (n=1) | 130 / 130 (n=1) | 631 / 631 (n=1) / 1,271 / 1,271 (n=1) | 64 | `crashes/crash-51651263df20c03787f0d15dec5bbd16fb285bbf` | MemorySanitizer | MemorySanitizer: use-of-uninitialized-value /src/unrar/arcread.cpp:1337:3 in Archive::ConvertFileHeader(FileH... | Archive::ReadHeader15() |

## Infra Errors

| Project | Variant | Count | Exit codes | Trials | Notes |
|---|---|---:|---|---|---|
| selinux | optimized | 1 | 139: 1 | `42` | 1 without crash files; some large logs skipped |
| unrar | baseline | 15 | 139: 15 | `0,4,23,26,29,40,42,47,54,62,78,80,82,83,95` | 15 empty logs; 15 without crash files |
| unrar | optimized | 12 | 139: 12 | `16,23,29,37,41,52,57,66,69,86,89,98` | 12 empty logs; 12 without crash files |

## Corpus Size Takeaways

| Project | Variant | Mean files | Median files | Mean bytes | Median bytes | Max bytes |
|---|---|---:|---:|---:|---:|---:|
| selinux | baseline | 497 | 498 | 153.0 KiB | 160.8 KiB | 338.0 KiB |
| selinux | optimized | 695 | 716 | 233.8 KiB | 264.7 KiB | 510.2 KiB |
| gpac | baseline | 390 | 384 | 58.6 KiB | 55.8 KiB | 137.7 KiB |
| gpac | optimized | 402 | 384 | 60.8 KiB | 57.0 KiB | 207.2 KiB |
| librawspeed | baseline | 7 | 6 | 12.9 KiB | 12.4 KiB | 28.4 KiB |
| librawspeed | optimized | 7 | 6 | 12.9 KiB | 12.4 KiB | 28.4 KiB |
| unrar | baseline | 111 | 102 | 94.7 KiB | 61.3 KiB | 683.5 KiB |
| unrar | optimized | 122 | 108 | 104.0 KiB | 67.1 KiB | 564.7 KiB |

No archive in this snapshot contains a `corpus/` directory; all `corpus_archived` values are `0`.

## Log Size / Parse Coverage

| Project | Variant | Logs | Parsed logs | Skipped logs | Mean uncompressed log | Median uncompressed log | Max uncompressed log |
|---|---|---:|---:|---:|---:|---:|---:|
| selinux | baseline | 100 | 74 | 26 | 138.9 MiB | 104.0 MiB | 585.8 MiB |
| selinux | optimized | 60 | 20 | 40 | 1.3 GiB | 1.4 GiB | 3.5 GiB |
| gpac | baseline | 100 | 59 | 41 | 2.8 GiB | 86.2 MiB | 27.7 GiB |
| gpac | optimized | 100 | 97 | 3 | 199.7 MiB | 556.8 KiB | 7.3 GiB |
| librawspeed | baseline | 100 | 100 | 0 | 5.0 KiB | 5.0 KiB | 7.0 KiB |
| librawspeed | optimized | 100 | 100 | 0 | 5.0 KiB | 5.0 KiB | 7.1 KiB |
| unrar | baseline | 100 | 100 | 0 | 146.7 KiB | 167.2 KiB | 243.2 KiB |
| unrar | optimized | 100 | 100 | 0 | 150.6 KiB | 163.3 KiB | 251.5 KiB |

## Interpretation

- The main previous recovery problem is improved in this run: findings are saved to NFS and generally have `pod_exit_code=0`, so Kubernetes `Completed` no longer means only clean runs.
- GPAC no longer shows Kubernetes `OOMKilled` in the parsed artifact outcomes; out-of-memory cases appear as libFuzzer findings when libFuzzer reported them.
- Unrar still has immediate `exit 139` infra errors with empty logs and no crash files. Those are not recoverable from the current artifacts and should be debugged separately.
- Selinux optimized was still incomplete at collection time: 60 artifacts were present, while the cluster showed 59 succeeded, 1 failed, and 10 active pods, with the remaining indexes not started yet.
- The verbose libFuzzer flags produced very large logs, especially for GPAC and Selinux. For future large runs, consider disabling `-print_funcs=1` or lowering verbosity if full detailed log parsing matters more than maximum per-run text output.

