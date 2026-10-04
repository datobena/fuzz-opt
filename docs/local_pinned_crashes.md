# local-pinned — crashes found per trial

Per-trial crashes from the CPU-pinned local run (selinux + libavc; baseline / aggr8h / mut8h; 10 trials × 8h). A trial counts as crashing if it wrote a real `crash-<sha>` artifact before the 8h cutoff (matches the detection counts). The signature is the ASan `SUMMARY:` line from its `fuzz.log`; a crash artifact with **no** ASan report is a bare deadly-signal (SIGSEGV) crash — for libavc these are non-deterministic decoder-thread crashes and are labeled `deadly-signal (no report)`.

**Different trials find different bugs.** selinux hits ≥4 distinct crashes; only 5/30 selinux trials find the actual target CVE (heap-use-after-free in `cil_tree_children_destroy`).

## Distinct bugs found (across all 60 trials)

| bug (ASan type @ function) | file | # trials | found by |
|---|---|---:|---|
| **[selinux] SEGV** @ `cil_gen_defaultrange` | `cil_build_ast.c` | 12 | aggr8h/02, aggr8h/03, aggr8h/05, aggr8h/07, baseline/01, baseline/02, baseline/05, mut8h/01, mut8h/02, mut8h/04, mut8h/06, mut8h/07 |
| **[selinux] SEGV** @ `__cil_resolve_name_with_parents` | `cil_resolve_ast.c:4171:42` | 6 | aggr8h/08, aggr8h/09, baseline/00, baseline/03, baseline/09, mut8h/03 |
| **[selinux] heap-use-after-free** @ `cil_tree_children_destroy` ⟵ **target CVE** | `cil_tree.c:185:12` | 5 | aggr8h/01, baseline/04, baseline/06, baseline/08, mut8h/00 |
| **[libavc] deadly-signal** @ `(no ASan report — likely non-deterministic thread crash)` | `?` | 3 | aggr8h/00, baseline/06, mut8h/08 |
| **[libavc] heap-buffer-overflow** @ `ih264d_compute_bs_non_mbaff_thread` ⟵ **target bug** | `ih264d_thread_compute_bs.c:291:39` | 2 | aggr8h/01, aggr8h/07 |
| **[selinux] heap-buffer-overflow** @ `cil_post_fc_fill_data` | `cil_post.c:166:9` | 2 | baseline/07, mut8h/09 |

## selinux — per trial (target: Heap-use-after-free (CVE-2021-36085))

| trial | baseline | aggr8h | mut8h |
|---|---|---|---|
| 00 | SEGV @ `__cil_resolve_name_with_parents`<br>0.73h | — | heap-use-after-free @ `cil_tree_children_destroy`<br>4.34h |
| 01 | SEGV @ `cil_gen_defaultrange`<br>2.45h | heap-use-after-free @ `cil_tree_children_destroy`<br>4.51h | SEGV @ `cil_gen_defaultrange`<br>0.89h |
| 02 | SEGV @ `cil_gen_defaultrange`<br>0.77h | SEGV @ `cil_gen_defaultrange`<br>0.97h | SEGV @ `cil_gen_defaultrange`<br>0.38h |
| 03 | SEGV @ `__cil_resolve_name_with_parents`<br>0.11h | SEGV @ `cil_gen_defaultrange`<br>0.05h | SEGV @ `__cil_resolve_name_with_parents`<br>3.82h |
| 04 | heap-use-after-free @ `cil_tree_children_destroy`<br>3.55h | — | SEGV @ `cil_gen_defaultrange`<br>0.80h |
| 05 | SEGV @ `cil_gen_defaultrange`<br>3.30h | SEGV @ `cil_gen_defaultrange`<br>4.53h | — |
| 06 | heap-use-after-free @ `cil_tree_children_destroy`<br>2.81h | — | SEGV @ `cil_gen_defaultrange`<br>0.62h |
| 07 | heap-buffer-overflow @ `cil_post_fc_fill_data`<br>2.54h | SEGV @ `cil_gen_defaultrange`<br>7.97h | SEGV @ `cil_gen_defaultrange`<br>1.75h |
| 08 | heap-use-after-free @ `cil_tree_children_destroy`<br>3.28h | SEGV @ `__cil_resolve_name_with_parents`<br>0.12h | — |
| 09 | SEGV @ `__cil_resolve_name_with_parents`<br>1.43h | SEGV @ `__cil_resolve_name_with_parents`<br>0.63h | heap-buffer-overflow @ `cil_post_fc_fill_data`<br>6.52h |

## libavc — per trial (target: Heap-buffer-overflow (arvo-16505))

| trial | baseline | aggr8h | mut8h |
|---|---|---|---|
| 00 | — | deadly-signal @ `(no ASan report — likely non-deterministic thread crash)`<br>6.75h | — |
| 01 | — | heap-buffer-overflow @ `ih264d_compute_bs_non_mbaff_thread`<br>0.71h | — |
| 02 | — | — | — |
| 03 | — | — | — |
| 04 | — | — | — |
| 05 | — | — | — |
| 06 | deadly-signal @ `(no ASan report — likely non-deterministic thread crash)`<br>7.27h | — | — |
| 07 | — | heap-buffer-overflow @ `ih264d_compute_bs_non_mbaff_thread`<br>5.03h | — |
| 08 | — | — | deadly-signal @ `(no ASan report — likely non-deterministic thread crash)`<br>7.93h |
| 09 | — | — | — |

## Reconciliation with detection counts

Crash trials per (target,variant) — now matches the signature-agnostic detection counts:

- **selinux:** baseline 10/10, aggr8h 7/10, mut8h 8/10
- **libavc:** baseline 1/10, aggr8h 3/10, mut8h 1/10

- libavc crashes without an ASan `SUMMARY` (aggr8h/00, baseline/06, mut8h/08) are bare SIGSEGV crashes in a decoder worker thread — non-deterministic and mostly non-reproducible, consistent with the gold-standard reproduction result.

- Raw artifacts: `local_pinned/<target>/<variant>/trial_NN/crashes/`.
