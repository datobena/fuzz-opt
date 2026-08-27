# Online source-fold optimization — bug-finding analysis (4 targets, 24 h, 9+9 trials)

Companion to [`RESULTS_online24h_coverage.md`](RESULTS_online24h_coverage.md).

**Headline: bug-finding does not follow coverage.** Coverage favoured the optimized arm on all
four targets; deduplicated bug counts favour it on only one.

---

## 1. Why raw crash counts are meaningless here

AFL de-duplicates crashes against an **in-memory bitmap that is not restored on resume**, and it
archives `crashes/` to `crashes.<ts>` on every relaunch. The online arm resumes after *every hot
swap*; the baseline never restarts. So a bug found in round 1 is re-saved as "new" in rounds
2, 3, … purely because the fuzzer was restarted.

The effect is enormous — selinux's online arm produced **57× more artifacts than bugs**:

| Target | Arm | Raw artifacts | Reproduced | Unique inputs | **Distinct bugs** |
|---|---|---:|---:|---:|---:|
| selinux | baseline | 14 | 13 | 13 | **1** |
| selinux | optimized | 170 | 132 | 127 | **3** |
| libavc | baseline | 94 | 23 | 23 | **2** |
| libavc | optimized | 40 | 3 | 3 | **1** |
| wolfssl | baseline | 4 | 4 | 4 | **1** |
| wolfssl | optimized | 20 | 17 | 17 | **2** |
| libxml2 | both | 0 | — | — | **0** |

Any comparison of raw counts across arms is measuring the number of restarts, not the target.

### Bug identity

A crash is identified by its **sanitizer report**, not by the input:

```
(error kind, top N non-runtime frames)
```

* Sanitizer interceptors (`__asan_*`, `malloc`, `free`, …) are stripped — identical for every
  overflow, so they carry no information.
* Kinds are **normalised**: a fold that shifts allocation layout can make ASan trip
  `use-after-poison` where the baseline reports `heap-use-after-free` at the same frame. That is
  one bug reported by two checks, not two bugs. (`container-overflow` → `heap-buffer-overflow`
  likewise.)
* Both **1-frame and 3-frame** identities are computed, because neither is universally right:
  1 frame can merge distinct bugs crashing in the same function, 3 frames can split one bug reached
  by two call paths. **They agreed on every target here**, so the counts are unambiguous.

## 2. Deduplicated results

Trials (out of 9) that found each bug, and time to first discovery.

### selinux (CVE-2021-36085)

| Bug | Baseline | Optimized |
|---|---|---|
| `heap-use-after-free: cil_tree_children_destroy` | 2/9 @ 2.2 h | **7/9** @ 5.7 h |
| `heap-buffer-overflow: cil_post_fc_fill_data` | — | **9/9** @ 3.6 h |
| `heap-buffer-overflow: cil_classorder_to_policydb` | — | **1/9** @ 21.5 h |
| **TARGET bug** `heap-use-after-free: __cil_verify_classperms` | 0/9 | 0/9 |

**The one clear win.** 3 distinct bugs vs 1, including two the baseline never found in any trial.
Note the baseline found the *shared* bug **sooner** (2.2 h vs 5.7 h) — the online arm finds it more
**reliably** (7/9 vs 2/9), not faster.

### libavc (arvo-16505)

| Bug | Baseline | Optimized |
|---|---|---|
| `heap-buffer-overflow: ih264d_compute_bs_non_mbaff_thread` (TARGET) | 1/9 @ 3.5 h | 1/9 @ 17.4 h |
| `heap-use-after-free: ih264_inter_pred_luma_vert_qpel_ssse3` | 1/9 @ 15.4 h | — |

**Baseline ahead**: 2 bugs vs 1, and it hit the target bug at 3.5 h where the online arm needed
17.4 h. Evidence is thin — see limitation 1 below.

### wolfssl (arvo-26567)

| Bug | Baseline | Optimized |
|---|---|---|
| `heap-buffer-overflow: RsaPad_PSS` | **4/9** @ 0.1 h | 2/9 @ 0.1 h |
| `stack-buffer-overflow: fp_div` | — | 3/9 @ 17.8 h — **INTRODUCED, not a find** |

**Baseline ahead**: discounting `fp_div`, both arms found one real bug and the baseline found it in
4/9 trials vs 2/9.

### Summary across targets

| Target | Verdict |
|---|---|
| selinux | optimized **wins** (3 bugs vs 1; 7/9 vs 2/9 on the shared bug) |
| libavc | baseline ahead (2 vs 1) |
| wolfssl | baseline ahead (4/9 vs 2/9 on the only genuine bug) |
| libxml2 | no crashes in either arm |

## 3. Did the optimizer add or remove bugs?

Every artifact was replayed on **both** arms' binaries (`cross_check_bugs.py`, 342 artifacts,
3 attempts per side):

```
optimized artifact -> baseline binary,  no crash  =>  INTRODUCED by a fold
baseline  artifact -> optimized binary, no crash  =>  REMOVED (masked) by a fold
```

Two guards, both of which would otherwise fabricate findings:

* **Flaky crashes.** Every artifact is first replayed against *its own* arm's binary. Artifacts
  that will not reproduce there are excluded, not counted — libavc's threaded decoder produces many
  such, and they would all have read as "removed".
* **Signature shifts.** Kinds are normalised as above, so a layout-induced
  `use-after-poison` ↔ `heap-use-after-free` does not register as one introduction plus one removal.

The optimized side is compared against the binary that was **live at each crash's timestamp**; the
baseline side against the **last binary trials actually executed** (`iter_06` selinux/wolfssl,
`iter_03` libavc) — *not* the last binary built, since selinux's `iter_08` came from a round that
finished after the trials ended and was never executed.

### Results

| Target | Artifacts | Non-reproducible | Present in both arms | **Introduced** | **Removed** |
|---|---:|---:|---:|---:|---:|
| selinux | 184 | 39 | 145 | **0** | **0** |
| libavc | 134 | 108 | 26 | **0** | **0** |
| wolfssl | 24 | 3 | 18 | **3** | **0** |

**Nothing was removed on any target.** Every reproducible baseline crash still crashes the folded
binary the trials actually ran. This is stronger than what the pipeline enforces: the PoC gate only
checks that the *target* bug survives; this confirms it for every incidentally-found bug too.

**Three introductions, all wolfssl, all one defect** — `stack-buffer-overflow: fp_div`, from the
iter_05 fold, which round 7 later removed. Already excluded from wolfssl's tallies above.

## 4. Limitations

1. **libavc's crashes are mostly irreproducible.** 71/94 baseline and 37/40 optimized artifacts
   fail to crash even the binary that produced them, across 3 attempts — scheduler-dependent races
   in a threaded decoder. Its 1/9-vs-1/9 target-bug row rests on single artifacts and is thin
   evidence, not a real tie. libavc's **coverage** result (no effect) is the sounder statement.
2. **Neither arm rediscovered selinux's target CVE** in 24 h, though the PoC reproduces it every
   round. For that target the story is discovery *breadth*, not time-to-target.
3. **The PoC gate cannot catch added bugs** — it is deliberately non-enforcing and measures only
   whether the original bug survives. `fp_div` was found by this cross-check, not by the gate.
4. Inserted-helper instrumentation (see coverage report §5.1) dilutes AFL's feedback in the
   optimized arm, which biases these results **against** it.

## 5. Reproducing

```bash
python3 repair_online_crash_times.py  --experiment-id <id> --apply   # rebuild records from artifacts
python3 verify_crash_signatures.py    --experiment-id <id> --apply   # classify vs live binary
python3 cross_check_bugs.py --experiment-id <id> --jobs 34 --json-out crosscheck_<id>.json
python3 dedup_crashes.py    --experiment-id <id> --jobs 34 --json-out dedup_<id>.json
```

Artifacts: `crosscheck_online-24h-*.json`, `dedup_online-24h-*.json`.
