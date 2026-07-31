# AFL++ Migration + Sandboxed Optimizer — Design

**Date:** 2026-07-30
**Status:** Approved (pending spec review)

## Context

The benchmark measures whether LLM-driven source-level "fold" optimizations make a fuzz
target find its bug faster. Two problems with the current design motivate this work.

**1. libFuzzer stops at the first crash.** Every phase-3 trial dies at the very event
being measured, so a trial yields one data point and nothing after it. Migrating to
AFL++ lets a trial keep fuzzing past a crash, producing richer comparisons: bug-count
over time, uncensored coverage curves, and multiple distinct crashes per trial.

**2. The optimizer agent can see where the bug is.** The agent runs today as
`claude -p --dangerously-skip-permissions` (or `codex exec
--dangerously-bypass-approvals-and-sandbox`) with **no confinement at all** — full
filesystem, full network, full docker, and `_agent_child_env` (`phase2_setup.py:1829`)
copies the entire orchestrator `os.environ`. That invalidates the central claim the
benchmark wants to make: *that optimization does not remove bugs*. If the agent knows
where the bug is, it can preserve it deliberately, and the result means nothing.

## Leak inventory (verified, 2026-07-30)

Recorded here because it is the justification for the sandbox and the checklist the
leak-audit test must cover.

**Tier 1 — the answer is handed over directly**

1. `<experiment_dir>/poc/repro.log` contains the full ASAN trace. libxml2's names the
   bug outright: `xmlSnprintfElementContent /src/libxml2/valid.c:1279`.
2. `<experiment_dir>/poc/poc_input` — the crashing input.
3. The ARVO image bakes `/tmp/poc` and `/bin/arvo`; `docker run n132/arvo:1972-vul arvo`
   reproduces and prints the trace. The agent has docker because the wrapper build/smoke
   commands *are* docker commands.

**Tier 2 — identifiers that make it lookup-able**

4. `manifest.json` / `setup_metadata.json`: `cve`, `local_id`, `image`, `crash_type`.
5. `FUZZ_SOURCE_FOLDS_*` env vars embed the image name and host paths such as
   `results/<exp>/libxml2-arvo-1972/…` — the ARVO id and CVE are in the path strings.
6. Network → ARVO-Meta on GitHub is keyed by that id and gives the fix commit.

**Tier 3 — indirect**

7. `.git` is present in the extracted source, with the upstream remote and the exact
   vulnerable commit.
8. `build_corpus.py`'s crash-filter removes corpus units that crash the baseline — each
   removed unit *is* a PoC, and the filter log identifies them.
9. Corpus-grow fuzzes the vulnerable baseline, so the bug can simply be found during
   phase 2 and print a trace into the agent's own tool output.
10. Host leftovers: prior `results/*/report/report.md`, `~/.claude/projects/*` transcripts.
11. Any sanitizer trace from a smoke or validate run.

**12. The bug-preservation gate is itself an oracle.** If the agent ever learns "that
fold removed the bug", it can binary-search folds to localize the bug — a stronger leak
than the PoC. The gate must run after the agent session, orchestrator-side, with the
result never fed back.

## Decisions (confirmed with user)

- **Dataset: ARVO, but the ARVO image is not used for building.** Source is extracted
  from it; the build happens in a modernized per-target image. This also removes leak
  vectors 1–3 at the root.
- **Engine: AFL++ v5.02c** (latest release, 2026-06-29), built from source and pinned
  identically across every target.
- **Non-reproducing bugs: drop the target.** If the PoC no longer crashes the newly
  built baseline, the target is excluded rather than patched around.
- **Confinement: container + build broker.** Not CLI permission rules — a real boundary,
  uniform across the claude and codex backends.
- **Failure feedback: compiler errors yes, sanitizer traces no.**
- **Source-tree hygiene:** neutral mount root, `.git` removed, env rebuilt from an
  allowlist. Project-identity stripping was considered and **rejected** as futile — the
  source code identifies the project regardless.
- **Dependency modernization: hand-written Dockerfile per target**, treated as a curated,
  reviewable artifact.
- **First milestone: one target end-to-end** (libxml2/arvo-1972 — its ARVO image is
  already Ubuntu 20.04 / clang 15, so it is most likely to survive modernization).
- **Registry: local only.** `PHASE3_BACKEND=local` until the pipeline is proven.

## Component 1 — Prework

Runs once per target, producing a pinned image that every later phase uses.

```
prework/
  aflpp.pin                      # AFL++ v5.02c commit sha
  targets/libxml2-arvo-1972/
    Dockerfile                   # hand-written, curated
    build.sh                     # from the ARVO image's /src/build.sh
    meta.json                    # arvo id, fuzz_target, expected crash_type (orchestrator-only)
  build_target_image.py
```

`build_target_image.py`:

1. Pull the ARVO image; extract `/src/<project>`, `/src/build.sh`, the harness source,
   and `.options`/dict files. Extract the PoC to a **broker-only** path.
2. Build the hand-written Dockerfile: `FROM gcr.io/oss-fuzz-base/base-builder@sha256:<pin>`,
   modernized deps, then **AFL++ v5.02c built from source over `/src/aflplusplus`** — the
   exact directory stock `compile_afl` copies `libAFLDriver.a` and the `afl-*` binaries
   from, so the standard OSS-Fuzz build path picks up v5.02c unmodified.
3. Build with `FUZZING_ENGINE=afl SANITIZER=address`.
4. **Verify the PoC still crashes the new binary.** Drop the target if not.
5. Tag `bench-aflpp/<project>-<arvoid>`.

The historical `projects/<p>/Dockerfile` (via the existing `checkout_oss_fuzz_at_commit`,
`phase2_setup.py:218`) is a *reference* for writing the curated one — its `git clone` and
`COPY` lines are dropped since ARVO supplies the source.

## Component 2 — Sandbox

```
sandbox/
  Dockerfile.agent    # agent CLI + local tools; no docker client
  broker.py           # host-side, unix socket
  agent_tools/        # fold-build, fold-smoke, fold-replay-time  (mounted ro)
  scrub.py            # keeps compiler diagnostics, drops sanitizer traces
```

**Agent container** mounts exactly `/work/src` (rw, `.git` stripped), `/work/profile`
(ro), `/work/bin` (ro), and `/run/broker.sock`. No docker socket, no host filesystem, no
results dir, no benchmark repo. Env is rebuilt from an allowlist of the variables the
skill actually reads, with values rewritten to `/work/...` paths.

Network is **not** `--network none` — an LLM CLI must reach its model API. Egress is
allowlisted to that endpoint only, via a proxy the container is pointed at.

**Broker** accepts typed requests and returns typed results:

| request | returns |
|---|---|
| `build` | `{ok, scrubbed_log}` |
| `smoke` | `{ok, scrubbed_log}` |
| `replay_time` | `{seconds, repeats}` |

It performs all docker work against the modernized image using the agent's current
`/work/src`, and logs everything **unscrubbed** orchestrator-side for audit.

`scrub.py` **fails closed**: if it cannot confidently parse a log, it returns pass/fail
only rather than risk passing a trace through.

## Component 3 — Engine migration

**Phase 2 primitives.** Corpus grow becomes `afl-fuzz -V <secs> -i seeds -o out`,
harvesting `out/default/queue`. Deterministic replay timing becomes `afl-showmap -i <dir>`.
Mutation capture becomes an `AFL_CUSTOM_MUTATOR_LIBRARY` `.so` implementing
`afl_custom_post_process` — a runtime hook, which **removes the current link-time
libFuzzer shim** (`mutation_dump_mutator.c`) and its build.sh injection entirely. All of
these run broker-side; the agent never executes the target.

**Phase 3.** `run_all_trials_slot` (`phase3_runner.py:701`) is engine-agnostic and stays.
Replaced: `_launch_container` (line 254) runs `afl-fuzz … -V <duration> -s <seed> -m none
-t 5000+ -- /out/<target>` with a writable output dir; `monitor_trial` (line 372) reads
crashes from `afl_out/default/crashes/id:…,time:<ms>,…`, taking **TTB straight from the
filename**; `parse_fuzzer_stats` (line 538) reads `fuzzer_stats` and `plot_data`.

**New requirement AFL++ creates:** because trials no longer stop, each yields many
crashes and only some are the target bug. Triage replays each artifact and matches the
manifest `crash_type` — `crash_classify.verify_crash_reproduces` already does this.

**Phase 4.** TTB semantics unchanged. Coverage-over-time comes from `plot_data`,
retiring `run_covtime.py`'s ZIP-mtime reconstruction; bug-count-over-time is added.

## Round data flow

1. Broker: corpus grow → crash filter → mutation capture → one profile → hotspot list
   written to `/work/profile`.
2. Agent container launches; edits `/work/src`; calls `fold-build` / `fold-replay-time`.
3. Agent exits.
4. **Orchestrator, outside the sandbox:** rebuild, PoC gate, replay-speedup gate →
   accept or revert.

The agent is never told the PoC result (leak vector 12). `_make_retry_prompt`
(`phase2_setup.py:1768`) currently feeds back the last 200 lines of build log and must
route through the same scrubber.

## Error handling

- Broker request timeout → error result to the agent, incident logged orchestrator-side.
- Agent container dies → treated as no-fold; source reverted to the round's baseline.
- Scrubber uncertainty → fail closed to pass/fail.
- PoC gate failure → revert to baseline, record `bug_removed`, never surfaced to the agent.

## Verification

- **Unit:** `scrub.py` (traces removed, compiler diagnostics preserved), broker protocol,
  AFL crash-filename TTB parsing, `fuzzer_stats`/`plot_data` parsing.
- **Leak audit (key deliverable):** launch an agent container with an adversarial probe
  prompt that attempts every vector in the inventory above — env, `/proc`, network egress,
  docker socket, walking up from `/work` — and assert nothing identifying escapes. This
  test is what makes the "optimization does not remove bugs" claim defensible.
- **Prework:** PoC reproduces on the newly built AFL++/ASAN baseline.
- **End-to-end:** libxml2/arvo-1972 through prework → sandboxed phase 2 → phase 3 → report.

Run top-level test files explicitly; bare `pytest` breaks on cloned trees under `results/`.

## Open risks

- **Toolchain attrition.** Unknown how many ARVO targets survive a modern clang with the
  bug intact. Measured, not predicted — first signal comes from the libxml2 milestone.
- **Hand-written Dockerfiles do not scale.** Deliberate: expanding the pool is manual.
- **Leak vector 9 is not fully closable.** Corpus-grow fuzzes the vulnerable baseline, so
  the bug can be found during phase 2. Moving grow broker-side keeps it out of the agent's
  view, which is sufficient — but it is a mitigation, not an elimination.

## Out of scope

Kubernetes backend, Magma (considered and set aside), online optimization
(`phase3_online.py`) — ported only after the static pipeline works.
