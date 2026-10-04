# Baseline Corpus Replay Speedups

Data source: the one-pod baseline corpus archives from `nfs:/shared/bena/phase3-kube`.

Method:
- Extracted only `corpus/` and `metadata.env` from each baseline archive.
- Replayed each baseline-generated corpus through both the baseline and optimized `dbenashv/benchmarkphase3-*:{codex-4}` images.
- Ran 10 repeats per project/variant inside Docker, using the same corpus files for both variants.
- Used fixed-input replay with `-runs=1`, `-detect_leaks=0`, `-rss_limit_mb=8192`, `-malloc_limit_mb=8192`, and `-print_final_stats=1`.
- Raw data: `/tmp/phase3-corpus-replay/results/replay_results.csv`
- Summary CSV: `/tmp/phase3-corpus-replay/results/replay_summary.csv`

| Project | Baseline corpus | Baseline time mean / median | Optimized time mean / median | Mean speedup | Median speedup | Median time reduction | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| selinux | 440 files, 66,277 B | 0.431s / 0.420s | 0.163s / 0.158s | 2.64x | 2.66x | 62.39% | All 20 replays exited 0. |
| gpac | 323 files, 15,895 B | 0.126s / 0.128s | 0.124s / 0.123s | 1.01x | 1.04x | 4.25% | All 20 replays exited 0; difference is small. |
| librawspeed | 6 files, 746 B | 0.041s / 0.039s | 0.042s / 0.039s | 0.97x | 0.98x | -2.00% | Optimized was slightly slower on this tiny corpus; process overhead dominates. |
| unrar | 88 files, 40,320 B | 0.373s / 0.365s | 0.343s / 0.338s | 1.09x | 1.08x | 7.46% | Clean repeats only: baseline 6/10, optimized 9/10. Signal 139 failures make this less reliable. |

## Interpretation

SELinux shows the clear replay speedup: about `2.66x` by median wall time on the baseline-generated corpus.

GPAC is effectively flat for this fixed-input corpus, with only a small `1.04x` median speedup.

Librawspeed does not show a speedup in this replay test. The corpus has only 6 files and completes in about 40 ms, so fixed process startup and libFuzzer initialization are a large part of the measurement.

Unrar appears faster on successful replays, but the comparison is unstable because some runs exited with signal 139 before finishing the corpus. Treat the `1.08x` median clean-run speedup as directional, not a reliable final number.
