# Task 4 report: upstream ccache equivalence tool

Files: tools/upstream_ccache_equivalence.py, tests/test_upstream_ccache_equivalence.py

## Scenarios (single `compile`, via prework_build.rebuild_with_prework_image)
P0 (no cache, one core), P0prime (no cache, multi-core), C0 (cold cache, multi), W0 (warm cache copy, one core),
PC/WC (fold_ helper in a compiled .c/.cc + calls; plain then warm), PH/WH (static __inline__ helper in a header
with >=2 includers + one caller; plain then warm). Uncached builds get CCACHE_DISABLE=1 from the production path.
Trees are copied to work/trees/<label>/source_tree/src/<project> with the original's set-aside `vcs` dir
symlinked beside, so vcs_dir_for() restores .git as in production. No audit build exists upstream, so fold
candidates come from a source scan (probe.rank_sources, add_c_fold, header_candidates); a candidate counts only if
the helper symbol is in some /out ELF (fallback for headers, as in the fb tool). --max-candidates default 3.

## Verdict function
`decide_verdict(pairs, stats, noise=None, p0_vs_p0prime=None) -> {"verdict","pass","problems","masked"}`
- `pairs`: name -> `compare_outs(x_out, y_out, noise)`; needed: P0_vs_C0, P0_vs_W0, PC_vs_WC, PH_vs_WH.
- compare_outs hashes every ELF file directly in /out (sets must match, non-empty; fuzz target must be present,
  checked in Runner.compare); differing files go through upstream_masked_compare with per-harness models from
  `learn_noise(P0_out, P0prime_out)`. Loaded-code diffs are never masked.
- fail if: missing/differing pair; C0/W0/WC/WH stats not `used`; W0/WC/WH with zero hits; P0 vs P0' non-deterministic
  and not maskable or harness sets differ.

## Missing statslog
`statslog_for(cache_dir)` checks `<cache>/statslog` exists, else returns `parse_stats(None)` (used False), so the
verdict fails with "ccache not used" rather than crashing. Stale statslog is removed from each warm cache copy.

## Tests
`python3 -m pytest tests/test_upstream_ccache_equivalence.py -v` -> 6 passed (pass-all-identical, unused-cache fail,
warm-without-hits fail, noise-masked strings, loaded-code fail, missing pair / harness set).

## CLI (Task 7)
python3 tools/upstream_ccache_equivalence.py --project <p> --src <root>/source_tree/src/<p> --work <scratch>/eq/<p> --cpuset 40-58 --one-core 59 [--parallel] [--fuzz-target T] [--timeout S] [--max-candidates N]
Writes <work>/report.json + report.txt; exit 0 on pass / pass_noise_masked.

## Concerns
- Docker orchestration is untested (Task 7). Not exercised: cpuset_lock with multi-cpu strings in rebuild path,
  ownership restore of cache dir (done via restore_ownership after each cached build).
- Fold candidates are not verified as compiled (no audit log); wrong picks cost a build each (bounded by max-candidates).
- Hit requirement for WC/WH is hits>0 (not a rate threshold).
- manifest entry: first address-sanitizer entry for the project.
