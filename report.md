# codex-2 Corrected Crash Report

This note summarizes the current `codex-2` results from raw trial artifacts, not just the generated phase-4 report.

## Scope

- Source report checked: [results/codex-2/report/report.md](/home/sefcom/asu/project/test/benchmark/results/codex-2/report/report.md)
- Raw artifacts checked:
  - [results/codex-2/ffmpeg-CVE-2019-17542](/home/sefcom/asu/project/test/benchmark/results/codex-2/ffmpeg-CVE-2019-17542)
  - [results/codex-2/libidn2-CVE-2019-18224](/home/sefcom/asu/project/test/benchmark/results/codex-2/libidn2-CVE-2019-18224)
  - [results/codex-2/gpac-CVE-2021-31255](/home/sefcom/asu/project/test/benchmark/results/codex-2/gpac-CVE-2021-31255)

## Validity Rules Used Here

- FFmpeg `crash-da39a3ee...` zero-byte artifacts at about `48h` were excluded.
  - Those trials end in LeakSanitizer shutdown output, not the target CFHD bug.
  - The repeated `da39a3ee...` hash is the SHA-1 of an empty file.
- GPAC `oom-*` and `timeout-*` artifacts were excluded from time-to-crash and input-size summaries.
- Input-size summaries below use the first valid crash artifact per trial, because that matches time-to-crash.

## Overall Exec/s

- Average of per-project average exec/s: `774.5` baseline -> `1069.3` optimized (`1.38x`)
- Mean per-project avg-exec/s speedup: `1.19x`

| Project | Baseline avg exec/s | Optimized avg exec/s | Avg exec/s speedup | Baseline median exec/s | Optimized median exec/s |
|---|---:|---:|---:|---:|---:|
| ffmpeg | 429.5 | 327.5 | 0.76x | 319.8 | 284.0 |
| libidn2 | 1466.0 | 2373.0 | 1.62x | 1474.9 | 2244.9 |
| gpac | 428.0 | 507.5 | 1.19x | 274.1 | 228.5 |

Note: GPAC looks better on average than on median because a few faster trials skew the mean upward.

## Valid Time To Crash

| Project | Baseline valid crashes | Optimized valid crashes | Baseline median TTC | Optimized median TTC | TTC speedup |
|---|---:|---:|---:|---:|---:|
| ffmpeg | 4/10 | 4/10 | 38.37h | 26.27h | 1.46x |
| libidn2 | 10/10 | 10/10 | 1.74h | 1.41h | 1.23x |
| gpac | 3/10 | 1/10 | 11.56m | 6.87m | 1.68x |

Important caveat for GPAC: the optimized side has only one valid crash after filtering out OOM and timeout artifacts, so that `1.68x` figure is not stable.

## Input Sizes

### ffmpeg (CVE-2019-17542)

- Valid baseline crash input sizes: `258B` to `959B`, median `407.5B`
- Valid optimized crash input sizes: `147B` to `326B`, median `263.5B`
- Valid unique crash inputs: `4` baseline, `4` optimized
- Total unique first artifacts on disk: `5` baseline, `5` optimized
- The repeated extra artifact is the invalid zero-byte `crash-da39a3ee...` leak-at-shutdown placeholder

### libidn2 (CVE-2019-18224)

- Valid baseline crash input sizes: `44B` to `268B`, median `106B`
- Valid optimized crash input sizes: `52B` to `260B`, median `90B`
- Valid unique crash inputs: `10` baseline, `10` optimized
- No repeated same-input issue showed up here

### gpac (CVE-2021-31255)

- Valid baseline crash input sizes: `55B` to `658B`, median `202B`
- Valid optimized crash input sizes: only one valid crash, `26B`
- Valid unique crash inputs: `3` baseline, `1` optimized
- Most recorded GPAC artifacts are not target-bug hits:
  - baseline first artifacts: `2` OOM, `5` timeout, `3` crash
  - optimized first artifacts: `9` OOM, `1` crash

## What The “Same Input” Pattern Actually Means

- FFmpeg: yes, the repeated end-of-run artifact is the same input, but it is not a valid target crash. It is a zero-byte LeakSanitizer shutdown artifact and should not drive bug-finding conclusions.
- libidn2: no, the crashes are not all the same input. All first valid crash hashes are unique in both variants.
- GPAC: no same-input issue either. The bigger problem is that most recorded events are OOM or timeout artifacts, not valid target crashes.

## Bottom Line

- The current generated `codex-2` report overstates FFmpeg time-to-crash by letting shutdown leak artifacts sit at the 48-hour boundary.
- After filtering invalid events:
  - FFmpeg improves on valid time-to-crash but regresses on exec/s
  - libidn2 improves on both exec/s and time-to-crash
  - GPAC remains hard to interpret because valid crash counts are low and most first artifacts are OOM or timeout
