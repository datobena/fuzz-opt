# Running the online optimization on another server

## What travels in git, and what does not

**In the repo:** all pipeline code, the four target definitions (hand-written
Dockerfile + curated build.sh + meta.json), the selinux PoC, and the pins
(`prework/base.pin`, `prework/aflpp.pin`).

**Not in the repo, rebuilt on arrival:** the four prework images (~3.5 GB each),
the agent image, and the egress proxy image. `bootstrap_server.py` builds them.

**Not in the repo, and must not be:** `.sandbox-creds/` (live OAuth tokens) and
`results/`.

**Not needed at all:** an `oss-fuzz` checkout. Only `phase2_setup`'s legacy
OSV/ARVO-reproducer paths touch `config.OSS_FUZZ_DIR`; the sandboxed AFL path
does not.

## Bring-up

```bash
git clone <repo> && cd benchmark
git checkout feat/aflpp-sandboxed-optimizer

claude                      # log in once; a Max plan is fine, no API key needed
python3 bootstrap_server.py --check     # what is missing
python3 bootstrap_server.py             # build it (slow: pulls multi-GB ARVO images)
```

Expect roughly 1-2 hours, dominated by pulling ARVO images and compiling AFL++
into each target image. `--check` afterwards should show all four targets `ok`.

A target reporting FAIL is **excluded, not patched around** — the benchmark only
measures bugs that demonstrably exist in the binary under test. All four
reproduce on the reference machine, so a failure here means the new machine
differs in a way worth understanding before trusting any result from it.

## Sizing for a bigger box

`config.py` defaults assume 40 cores. Set these for the new machine:

```bash
export TOTAL_CORES=<n>
export ONLINE_TRIAL_CORES=<lo>-<hi>       # cores pinned to fuzzing trials
export ONLINE_OPTIMIZER_CORES=<lo>-<hi>   # DISJOINT pool for optimizer docker work
export NUM_TRIALS=<per arm>
```

Keep the two ranges **disjoint**. They exist so optimization cannot steal cycles
from the trials it is being measured against — overlapping them biases the very
comparison the run produces.

## Egress

The agent network is `--internal`: no route out. The proxy is the only path and
forwards only to the model-API hosts, logging every ALLOW/DENY. That log is the
evidence the optimizer never reached the CVE database or ARVO metadata — keep it
with the results.

Nothing to configure; `sandbox/session.py` creates the network and starts the
proxy. Verify after the first round:

```bash
docker logs bench-egress-proxy | grep DENY | head
```

## Before committing days of compute

No full phase-2 -> 3 -> 4 cycle has been run end to end. Do one short
single-target run first:

```bash
NUM_TRIALS=2 ONLINE_SWAP_INTERVAL_SECS=600 \
  python3 run_benchmark.py --phase online --project libxml2 --duration 1800
```

Then check: `setup_metadata.json` carries a `poc_verdict`, crashes appear under
`afl_out/default/crashes/` with `time:` in their names, and the proxy log shows
allows only.
