#!/usr/bin/env python3
"""Assemble the comprehensive new-kube-1 report from canonical sources +
the crash-validity findings, and write results/new-kube-1/new-kube-1_full_report.md.
"""
import glob, json, statistics, zipfile
from pathlib import Path

BASE = Path("/home/sefcom/asu/project/test/benchmark/results/new-kube-1")
TTB_DATA = "/tmp/nk1_ttb_data"
res = {e["key"]: e for e in json.load(open(BASE / "report" / "results.json"))}

ORDER = ["selinux-CVE-2021-36085", "assimp-arvo-24463", "libxml2-arvo-1972",
         "wolfssl-arvo-26567", "libavc-arvo-16505", "PcapPlusPlus-arvo-22232"]
PROJ = {"selinux-CVE-2021-36085": "selinux", "assimp-arvo-24463": "assimp",
        "libxml2-arvo-1972": "libxml2", "wolfssl-arvo-26567": "wolfssl",
        "libavc-arvo-16505": "libavc", "PcapPlusPlus-arvo-22232": "PcapPlusPlus"}

# Qualitative facts gathered from artifacts + crash-replay validity audit.
META = {
 "selinux-CVE-2021-36085": dict(
   ft="secilc-fuzzer", short="selinux", arvo="CVE-2021-36085",
   arvo_type="Heap-use-after-free READ",
   arvo_bug="heap-use-after-free in `__cil_verify_classperms` (CIL classperms resolve)",
   p2corpus="13,548 — downloaded 13,843 → crash-filtered (−364) → +1 h baseline grow (+69). Injected from poff-selinux-2.",
   p3seed="11 (bundled `secilc-fuzzer_seed_corpus.zip`)",
   fold="injected from poff-selinux-2 (reused, not re-optimized)",
   found="SEGV (NULL-deref) in `cil_fill_ipaddr` (all 20 trials) + SEGV `cil_gen_defaultrange` + heap-overflow `cil_post_fc_fill_data→qsort`; one baseline UAF in `cil_tree_children_destroy` (still not the CVE)",
   match="❌ NO — the CVE-2021-36085 UAF was never hit (0/20)", det="deterministic"),
 "assimp-arvo-24463": dict(
   ft="assimp_fuzzer", short="assimp", arvo="ARVO-24463",
   arvo_type="Heap-buffer-overflow READ 1",
   arvo_bug="heap-buffer-overflow in `OpenDDLParser::parseIdentifier` (OpenGEX/OpenDDL parser)",
   p2corpus="404 — 400-input sample of the crash-filtered download (~8,096) + 4 from a 20-min baseline grow",
   p3seed="0 — COLD START (assimp ships no `_seed_corpus.zip`)",
   fold="`IOStreamBuffer.h` (lazy, file-sized cache instead of eager 16 MB fill) + drop per-message `flush()` in `StdOStreamLogStream.h`",
   found="heap-overflow in **irrXML** `CXMLReaderImpl::parseOpeningXMLElement` (9/10 distinct) + one `std::string` stack-overflow",
   match="❌ NO — different/shallower bug (irrXML, not OpenDDL)", det="deterministic"),
 "libxml2-arvo-1972": dict(
   ft="libxml2_xml_read_memory_fuzzer", short="libxml2", arvo="ARVO-1972",
   arvo_type="Stack-buffer-overflow WRITE",
   arvo_bug="stack-buffer-overflow WRITE (xml read path)",
   p2corpus="1,631 — download was ~empty (1 file) → 1 h baseline grow (+1,630)",
   p3seed="0 — COLD START (no bundled `_seed_corpus.zip`)",
   fold="`error.c` (strip error-formatting overhead) + `uri.c` (URI parse tweak)",
   found="no crash (0/10 both variants in 48 h)",
   match="— not found (no crash in 48 h)", det="n/a"),
 "wolfssl-arvo-26567": dict(
   ft="fuzzer-wolfssl-rsa", short="wolfssl", arvo="ARVO-26567",
   arvo_type="Heap-buffer-overflow WRITE",
   arvo_bug="heap-buffer-overflow WRITE (RSA path)",
   p2corpus="3,514 — downloaded 3,382 + 20-min baseline grow (+132)",
   p3seed="1,380 (bundled `fuzzer-wolfssl-rsa_seed_corpus.zip`)",
   fold="`tfm.c` (+47, big-int fast path) + `random.c` (+14)",
   found="no crash (0/10 both variants in 48 h)",
   match="— not found (no crash in 48 h)", det="n/a"),
 "libavc-arvo-16505": dict(
   ft="avc_dec_fuzzer", short="libavc", arvo="ARVO-16505",
   arvo_type="Heap-buffer-overflow READ 8",
   arvo_bug="heap-buffer-overflow in H.264 deblocking `ih264d_compute_bs_non_mbaff_thread`",
   p2corpus="486 — from the REAL 17,767-unit download: subset to ≤64KB → crash/slow-filter (4,886 clean) → 20-min fork-mode grow → coverage-merge → stride-sampled to 486 (full-corpus filter timed out on a pathological slow tail of tiny units declaring 10240×10240 frames)",
   p3seed="0 — COLD START (no bundled `_seed_corpus.zip`)",
   fold="`ih264_platform_macros.h` (+10, x86 platform macro/prefetch)",
   found="MULTITHREADED decoder → mostly **non-reproducible** (9/10 recorded crashes don't replay; live crash_times = 19 crash / 81 unknown). 1 reproduced = the real ARVO `ih264d` deblocking overflow",
   match="⚠️ PARTIAL — crashes mostly flaky/non-deterministic; 1 genuine ARVO hit", det="NON-DETERMINISTIC (threaded)"),
 "PcapPlusPlus-arvo-22232": dict(
   ft="FuzzTarget", short="PcapPlusPlus", arvo="ARVO-22232",
   arvo_type="Heap-buffer-overflow READ 1",
   arvo_bug="heap-buffer-overflow in `IPv6Layer::parseExtensions`",
   p2corpus="13 — download was ~empty (1 file) → 1 h baseline grow (+12)",
   p3seed="430 (bundled `FuzzTarget_seed_corpus.zip`)",
   fold="`SSLHandshake.{h,cpp}` + `GtpLayer.cpp` + `PPPoELayer.cpp`",
   found="heap-overflow in `NullLoopbackLayer::getFamily` (dominant) + `DnsResource::getDataLength`",
   match="❌ NO — different/shallower bugs (NullLoopback/DNS, not IPv6Layer)", det="deterministic (opt 9/10 — 1 index ImagePull-failed)"),
}


def fmt(s):
    if s is None: return "—"
    if s < 90: return f"{s:.1f}s"
    if s < 5400: return f"{s/60:.1f}m"
    return f"{s/3600:.2f}h"


def crashed_ttb():
    """Crashed-only TTB (mean/median) per (project, variant) from trial zips."""
    agg = {}
    for zp in glob.glob(f"{TTB_DATA}/**/trials/trial-*.zip", recursive=True):
        parts = Path(zp).parts; ti = parts.index("trials")
        p, v = parts[ti-3], parts[ti-2]
        try: zf = zipfile.ZipFile(zp)
        except Exception: continue
        cr = []
        for n in zf.namelist():
            if n.endswith("crash_times.json"):
                try: cr = json.loads(zf.read(n))
                except Exception: cr = []
        # Exclude the spurious end-of-run artifact at the 48h censor boundary
        # (libxml2 writes a crash-prefixed artifact at exit that isn't a real bug;
        # phase-4 found_bug and the crash-replay audit both say 0 crashes).
        ts = [c["timestamp_s"] for c in cr
              if c.get("crash_type") == "crash" and c["timestamp_s"] < 172800]
        agg.setdefault((p, v), []).append(min(ts) if ts else None)
    return agg


def stat(vals, f):
    v = [x for x in vals if x is not None]
    return f(v) if v else None


agg = crashed_ttb()
lines = []
W = lines.append

W("# new-kube-1 — Full Benchmark Report\n")
W("Does an LLM source-fold optimization (faster fuzz harness) find the known ARVO/CVE bug **faster** over a 48 h libFuzzer campaign vs. the unmodified baseline?\n")
W("- **Experiment:** `new-kube-1` · 6 targets · 10 trials/variant · **48 h/trial** · libFuzzer + AddressSanitizer · Kubernetes (10 parallel/variant)")
W("- **selinux** reuses the prior poff-selinux-2 optimization (not re-optimized); the other 5 are n132/arvo DockerHub images optimized fresh in phase 2.")
W("- **Corpus policy:** phase-2 profiling+replay on the *optimization corpus* (download as-is, or a 1 h baseline grow if the download was empty); phase-3 fuzzing seeded from each project's *bundled initial* `_seed_corpus.zip` (empty = cold start).")
W("- c-blosc2 and open62541 (2 of the original 7) produced no accepted fold in phase 2 and are excluded.\n")

W("## 1. Headline speedups\n")
W("| target | replay (opt-corpus) | live exec/s | TTB median speedup | TTB mean speedup | p-value | A12 | found ARVO bug? |")
W("|---|--:|--:|--:|--:|--:|--:|---|")
for k in ORDER:
    e = res[k]; m = META[k]; pr = PROJ[k]
    b = agg.get((pr, "baseline"), []); o = agg.get((pr, "optimized"), [])
    mb_med, mo_med = stat(b, statistics.median), stat(o, statistics.median)
    mb_mn, mo_mn = stat(b, statistics.mean), stat(o, statistics.mean)
    med_sp = f"{mb_med/mo_med:.2f}×" if (mb_med and mo_med) else "—"
    mn_sp = f"{mb_mn/mo_mn:.2f}×" if (mb_mn and mo_mn) else "—"
    rep = f"{e['replay_speedup']:.2f}×" if e.get("replay_speedup") else "—"
    ex = f"{e['exec_s_speedup']:.2f}×" if e.get("exec_s_speedup") else "—"
    verdict = m["match"].split(" ")[0]
    W(f"| **{m['short']}** ({m['arvo']}) | {rep} | {ex} | {med_sp} | {mn_sp} | {e['p_value']:.4f} | {e['a12']:.2f} | {verdict} |")
W("\n*Replay = same fixed corpus replayed on both binaries (pure exec speed). Live exec/s = median executions/s during the 48 h run. TTB speedup = baseline/optimized over trials that crashed. p-value (one-sided Mann-Whitney) and A12 (Vargha-Delaney) from phase-4 with 48 h censoring. \"found ARVO bug?\" — see §4.*\n")

W("## 2. Time-to-bug (crashed trials only)\n")
W("| target | baseline crashed/n | base mean | base median | optimized crashed/n | opt mean | opt median |")
W("|---|--:|--:|--:|--:|--:|--:|")
for k in ORDER:
    pr = PROJ[k]; m = META[k]
    b = agg.get((pr, "baseline"), []); o = agg.get((pr, "optimized"), [])
    bc = [x for x in b if x is not None]; oc = [x for x in o if x is not None]
    W(f"| **{m['short']}** | {len(bc)}/{len(b)} | {fmt(stat(b,statistics.mean))} | {fmt(stat(b,statistics.median))} "
      f"| {len(oc)}/{len(o)} | {fmt(stat(o,statistics.mean))} | {fmt(stat(o,statistics.median))} |")
W("\n*libxml2 & wolfssl: 0 crashes in 48 h (censored). libavc crashes are largely non-reproducible (threaded decoder) — treat its TTB as unreliable.*\n")

W("## 3. Replay & live throughput detail\n")
W("| target | replay base→opt (s) | replay corpus (files) | replay speedup | live base exec/s | live opt exec/s | exec/s speedup |")
W("|---|--:|--:|--:|--:|--:|--:|")
for k in ORDER:
    e = res[k]; m = META[k]
    rb, ro = e.get("replay_baseline_time_s"), e.get("replay_optimized_time_s")
    W(f"| **{m['short']}** | {rb:.2f}→{ro:.2f} | {e.get('replay_corpus_file_count')} | {e['replay_speedup']:.2f}× "
      f"| {e['baseline_exec_s_median']:.0f} | {e['optimized_exec_s_median']:.0f} | "
      f"{(str(round(e['exec_s_speedup'],2))+'×') if e.get('exec_s_speedup') else 'N/A'} |")
W("")

W("## 4. Crash validity — was it the ARVO-reported bug?\n")
W("| target | ARVO-reported bug | what phase-3 actually crashed on | correct bug? |")
W("|---|---|---|---|")
for k in ORDER:
    m = META[k]
    W(f"| **{m['short']}** | {m['arvo_bug']} ({m['arvo_type']}) | {m['found']} | {m['match']} |")
W("\n**libFuzzer exits at the first crash**, so from these seeds a shallower, unrelated bug wins the race and the targeted ARVO/CVE is never reached. The optimized binaries *do* still reproduce the real ARVO/CVE on each PoC (phase-2 verification = baseline+optimized true). So: replay/exec-speed numbers are valid; TTB ratios are valid *same-bug* comparisons; but the bug measured is **not** the ARVO/CVE (except libavc, partially).\n")

W("## 5. Corpora & optimization per target\n")
W("| target | fuzz target | phase-2 (profile+replay) corpus | phase-3 initial seed | fold |")
W("|---|---|---|---|---|")
for k in ORDER:
    m = META[k]
    W(f"| **{m['short']}** | `{m['ft']}` | {m['p2corpus']} | {m['p3seed']} | {m['fold']} |")
W("")
W("**Corpus origin (phase-2):** 4/6 had their **own real OSS-Fuzz download** — selinux (13,843), assimp (12,222→8,114), libavc (17,767), wolfssl (3,389→3,382). **2/6 had no usable download (GCS empty, 1-file fallback) and were 1h-generated from scratch** — **libxml2** (→1,631) and **PcapPlusPlus** (→13). selinux additionally ran a 1h grow on its real corpus; assimp/libavc/wolfssl ran 20-min grows on theirs. (Most corpora were grown to some degree — this predates the later \"don't grow a non-empty seed\" policy clarification.)")
W("")

W("## 6. Key findings\n")
W("1. **Execution speed improved on most targets** (replay and/or live exec/s): assimp 9.12× replay / 1.74× live, libxml2 1.26× / **3.06× live**, wolfssl 1.11× / 1.45×, selinux 1.45× / 1.35×, PcapPlusPlus 1.05×, libavc ~1.0× / 0.86×.")
W("2. **selinux is the only statistically-significant TTB win** (3.87× median, p=0.009, A12=0.82 large) — but on a shallow `cil_fill_ipaddr` SEGV, **not** CVE-2021-36085.")
W("3. **assimp**: 1.6–1.8× TTB on the shallow irrXML bug (medium effect, p≈0.09).")
W("4. **libxml2 & wolfssl**: faster execution but **no bug found** in 48 h from the curated seeds.")
W("5. **No target measured time-to-the-ARVO-bug** via first-crash TTB: 3 found different shallower bugs, libavc is non-deterministic (1 genuine ARVO hit), 2 found nothing.")
W("6. **PcapPlusPlus optimized = 9/10 trials** (one pod index hit a transient ImagePull failure; `backoffLimitPerIndex=0` → that index failed).\n")

W("## 7. To measure true time-to-the-ARVO-bug (follow-up)\n")
W("- Run phase-3 crash-tolerant (`-fork=1 -ignore_crashes`) so trials continue past shallow bugs.")
W("- Count a trial \"solved\" only when a crash's `DEDUP_TOKEN` matches the target (e.g. `__cil_verify_classperms` for selinux, OpenDDL `parseIdentifier` for assimp).")
W("- For libavc, force single-thread deterministic decode so crashes reproduce.")
W("- Optionally seed closer to the target path / harden the harness against the shallow bugs.\n")

W("## 8. Artifacts\n")
W("- `report/report.md`, `report/results.json`, `report/table.tex` (phase-4 output)")
W("- `report/<key>/{time_to_bug_boxplot,survival_curve,exec_per_sec}.png` (per-target plots)")
W("- `<key>/{baseline,optimized}/trial_*/` (raw trials + `crashes/`), `<key>/setup_metadata.json` (replay), `<key>/optimized/source_diff/optimization.diff` (the fold)")

out = BASE / "new-kube-1_full_report.md"
out.write_text("\n".join(lines) + "\n")
print(f"WROTE {out}  ({len(lines)} lines)")
