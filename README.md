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

## Source edit boundary

Optimizer rounds enforce a host-owned edit policy after trusted corpus/profile
preparation and before the agent starts. The policy permits content changes to
existing C/C++ source and header files only. It excludes the resolved harness,
fuzz-support directories and fuzz-named files, files defining fuzz entrypoints,
conventional `config.h`/`config.hh`/`config.hpp`/`config.hxx` configuration headers,
and targets of protected symlink aliases. New files, deleted/renamed paths,
permission changes, hardlinks, symlink/type replacements, and modifications or
timestamp changes to protected files reject the current build. Pre-existing symlinks
must remain unchanged; baseline hardlinks fail closed.

For support code with unconventional names, add project-relative patterns to
`config.SOURCE_SCOPE_EXCLUDE_GLOBS`, for example
`{"project": ("src/shared_driver.c", "test_support/*")}`. These exclusions are
host configuration, never agent input. A source extension alone cannot identify
arbitrarily named shared harness helpers; project owners must identify those.
Configuration headers with unconventional names also require explicit exclusions.
An exclusion beneath a directory symlink conservatively protects its target
subtree, including further aliases. An unresolved harness fails closed.

Every sandbox broker build compiles a validated private snapshot instead of the
live writable agent tree. The authoritative rebuild runs after agent/broker
removal is confirmed and the tree is checked again. Its generated build files
are discarded while preserving the validated source edits. The host policy and
backup never appear in agent mounts. A rejected build reports the offending
paths and expected protected-file timestamps/modes so the agent can restore
those files, keep valid library source edits, and retry within the same round.
Every request and the final candidate are checked afresh; a past violation does
not permanently reject a corrected candidate.

`source_scope_violation.json` describes an actively invalid candidate. Successful
fresh validation archives that report as `source_scope_violation.resolved-*.json`
and clears the active rejection. `source_scope_history.jsonl` retains rejection
and resolution events independently of acceptance. If the agent exits with an
invalid tree, the host rejects the final candidate and restores the complete
pre-agent tree, including ignored/untracked paths. Online provenance records
`rejected-source-scope`; it is not optimization convergence evidence.

If a previous container may still write, restoration is deferred. A sibling
`.source-scope-recovery-<project>.json` marker retains the private backup and
prevents staging, profiling or establishing a fresh baseline. The online orphan
cleanup restores it only after all recorded writers are gone and ownership is
recovered. For manual recovery, stop **all** old agent/build containers first,
then call `lib.source_scope.recover_pending(source_dir, writers_stopped=True)`.
Never remove the marker just to continue a run.

This enforces edit scope, not behavioral equivalence: permitted source edits
still need the existing crash and replay checks. The unconfined debug optimizer
can access host state and therefore does not provide the sandbox's security
boundary; use the default sandbox for enforcement against an untrusted agent.

Online optimization collects up to 30,000 mutation inputs by default
(`PHASE2_MUTATION_CAP`). A seeded shuffle splits each snapshot into a 75% tuning
prefix and a 25% held-out suffix. Profiling, agent replay, and smoke tests use
only tuning inputs; the final host replay compares both binaries on held-out
inputs. A fixed snapshot keeps the same partition across later rounds. If time
or unit limits shrink tuning to x% of its partition, final replay uses x% of the
held-out partition too, rounded to whole inputs with at least one per partition.
Crash filtering drops inputs in place without moving them between partitions;
an empty surviving partition skips the round. `corpus/split_manifest.json`
records the seed, original partitions, sampling fraction, and surviving input
membership. It and the held-out corpus stay outside the optimizer mounts.
`ONLINE_GATE_FULL_SET=1` expands only the host crash check, never final replay
timing. Online rounds without a usable snapshot skip instead of falling back to
single-corpus tuning and acceptance. Standalone phase 2 retains its existing
single-corpus workflow.
