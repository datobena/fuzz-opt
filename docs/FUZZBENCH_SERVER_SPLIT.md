# FuzzBench campaigns split across two servers

The remaining FuzzBench parity campaigns are mruby (the last bug benchmark) and all
23 coverage benchmarks. They are split 12 / 12. Every campaign takes 24 h, so the
count is the workload. Each list also gets 5 of the 10 targets I estimate are
expensive to build (bloaty, sqlite3, openssl, systemd, openthread / PROJ, harfbuzz,
freetype2, curl, mbedtls). That estimate comes from what each project compiles; it
has not been measured.

| List | Server | Manifest |
|---|---|---|
| 1 | r440-2-13 (this one) | `data/manifests/manifest_fuzzbench_list1.json` |
| 2 | the other server | `data/manifests/manifest_fuzzbench_list2.json` |

**List 1:** mruby (bug), bloaty, sqlite3, openssl, systemd, openthread, jsoncpp, zlib,
libxml2, re2, libpng, vorbis.

**List 2:** PROJ, harfbuzz, freetype2, curl, mbedtls, libjpeg-turbo.main, libxslt,
woff2, Little-CMS, libpcap, openh264, stb.

Each list holds every project name once. That matters because bloaty, libxml2,
harfbuzz and mbedtls have both a bug entry and a coverage entry in
`manifest_fuzzbench.json`, and `--project` matches on the name alone. Always launch
with your list's manifest, never the full one.

## Before the first campaign on a server

```
git pull
tools/configure_fuzz_host.sh --check          # CPU governor, core_pattern, etc.; fix any FAIL
python3 tools/add_account_token.py --list     # every account you will switch to must be listed
claude -p --model claude-opus-5 "reply ok" < /dev/null   # the active account has quota left
```

A target's image (the `image` field in the manifest) is built once:

```
python3 -m prework.fuzzbench_image --dir <fuzzbench_dir>   # e.g. --dir proj4_proj_crs_to_crs_fuzzer
```

## Running a campaign

Run **one campaign at a time**. A campaign uses cores 2–39: the trials, the
optimizers and their builds. Two campaigns at once would share cores and spoil both
measurements. Go down your list in order.

Smoke-test each target once before its 24 h run. This step exists because harfbuzz's
first build broke only on the second rebuild:

```
export BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_fuzzbench_list2.json   # list1 on r440-2-13
DURATION=7200 INTERVAL=300 OPT_TIMEOUT=2700 EXP_PREFIX=smoke-cov ./run_online_pertrial.sh <project>
```

The smoke run passes if:
- the log reaches `=== Benchmark Complete ===`;
- at least one optimizer round logs `outcome=`;
- there is no `Traceback`, `ccache off`, `prebuild error` or `weekly limit` line.

Then launch the real campaign:

```
export BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_fuzzbench_list2.json
EXP_PREFIX=online-24h-cov ./run_online_pertrial.sh <project>      # mruby: EXP_PREFIX=online-24h-r2
```

When the launcher exits and the log ends with `=== Benchmark Complete ===`, check
these before starting the next campaign:

- `grep -c "weekly limit" .<exp>.log` is 0. If it isn't, optimizer rounds failed
  silently from that point on, even though state.json may say the run succeeded.
- Every trial's `afl_out/default/fuzzer_stats` is non-empty and its `run_time` is
  close to 86400. Optimized trials run a little short because of the restarts at
  each hot swap.
- `journalctl --list-boots` shows no reboot during the run. The host crashed once,
  on 2026-10-22, and left a half-finished run behind.

Don't delete a finished campaign's results. Report each experiment id, and any
problems, back to r440-2-13.
