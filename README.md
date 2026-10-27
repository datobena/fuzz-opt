# fuzz-opt

Does an LLM agent rewriting a fuzz target's source for *throughput* find more
bugs? Each experiment runs one project as 10 baseline + 10 optimized AFL++
trials, where every optimized trial gets its own optimizer, its own source tree
and its own binary, hot-swapped in whenever a fold passes the replay gate.

```
./run_online_pertrial.sh libxml2          # 24h, 10+10 trials, 10 optimizers
python3 bootstrap_server.py --check       # preflight: skill, credentials, cores
python3 -m pytest                         # must be run from this directory
```

## Layout

Everything at the root is either the pipeline itself or live state the pipeline
writes. Everything else is sorted by what it is *for*.

| | |
|---|---|
| `run_benchmark.py`, `config.py` | entry point and every tunable knob |
| `phase1_select_cves.py` … `phase4_analysis.py` | the four pipeline phases; `phase3_online.py` drives the per-trial optimizers |
| `mutation_capture.py`, `mutation_dump_*.c` | the AFL custom-mutator shim that harvests each trial's own mutations |
| `manifest.json`, `arvo_baseline_denylist.json` | **live state** — the active run set, and targets whose baseline failed |
| `skills/` | the optimizer skill the sandboxed agent runs (`SKILL.md` + helper scripts); `config.PHASE2_SKILL_DIR` points here |
| `lib/`, `sandbox/` | shared modules; `sandbox/` is the broker + egress jail the optimizer agent runs behind |
| `prework/` | per-target build recipes (`targets/` for ARVO, `fuzzbench/` for FuzzBench) |
| `k8s/` | the Indexed-Job backend for `PHASE3_BACKEND=k8s` |
| `tests/` | the suite; run `pytest` from the root, not from here |
| `analysis/` | coverage growth, crash dedup/cross-check, CPU cost, plots, per-campaign reports |
| `tools/` | operational one-offs: target scaffolding, ARVO candidate screening, preflight, coverage replay drivers |
| `tools/drivers/` | the shell driver for each historical batch, kept as a record of how it was launched |
| `data/` | inputs and analysis outputs: `arvo/` candidates, `manifests/` past run sets, `crosschecks/`, `dedup/`, `bug_reports/`, `preflight_reports/`, `covtime*/` curves |
| `docs/` | setup guide, the write-up for each completed batch, and `research_notes/` |
| `plots/`, `coverage_growth/` | generated figures and the per-trial CSVs behind them |

`results/` is a symlink to bulk local storage and is never committed.

## Two things that will bite you

**Run from the root.** Scripts under `analysis/` and `tools/` add the root to
`sys.path` themselves, but several of them — and several tests — still resolve
`prework/targets/...` and `sandbox/agent_tools` against the *current directory*.

**`edges_found` is not comparable across arms.** The two arms run different
binaries and therefore different instrumentation, so an edge-count ratio
between them means nothing until both corpora are replayed on one common
binary. `analysis/coverage_growth.py` says the same thing at more length.

## Plot historical libFuzzer runs

The coverage/throughput plotter also accepts older static A/B runs with
`fuzzer.log`, `metadata.json`, and retained `corpus/` files:

```sh
python3 analysis/plot_coverage_growth.py --engine libfuzzer \
  --experiment-id static-final-24h --target libxml2-arvo-1972 \
  --results-dir /path/to/benchmark/results --jobs 4 \
  --covdir /path/to/plot-data --outdir /path/to/plots
```

This replays each trial's retained inputs in discovery order on the same
baseline binary, using Docker's `gcr.io/oss-fuzz-base/base-runner` image
(`--runner-image` overrides it). Discovery times use preserved corpus mtimes
relative to the trial's recorded start. Replay CSVs and provenance are cached;
repeating the command reuses matching results. Incomplete replays fail instead
of producing a partial curve. Source experiment files remain read-only.

The throughput panel shows libFuzzer's cumulative average, with elapsed times
estimated from execution counts and integer `exec/s` reports. Both panels use
mean and 95% confidence intervals across the available trials. PNG and PDF
outputs are named by experiment and target. This mode does not charge optimizer
CPU time: these historical trials ran fixed binaries.
