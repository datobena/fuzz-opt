# 7 New Working ARVO Projects — Collection Report

**Date:** 2026-06-03
**Goal:** find **7 ARVO projects we hadn't tried**, each verified to *work* =
**builds from source + reproduces its planted bug**.
**Result:** ✅ **7 collected and verified** (10 distinct projects actually passed; 7 kept,
3 surplus). Artifacts: `new_arvo_projects.json`, `arvo_image_screen_results.json`,
`arvo_meta_candidates.json`.

---

## 1. Why these come from ARVO prebuilt images (not the usual pipeline)

The benchmark's reproduce path (`lib/arvo.py:fetch_arvo_issue` → `arvo_reproducer.fetch_issue`)
rebuilds from source keyed by an OSS-Fuzz **IssueTracker id** (`https://issues.oss-fuzz.com/issues/{id}`).
That id pool lives only in `cves.txt` and is **exhausted** — all **42** distinct projects tried
(`find_arvo_candidates.py` sources solely from `cves.txt`).

Verified during planning:

| Source | Keyed by | Works with `fetch_issue`? |
|---|---|---|
| `cves.txt` (42xxxxxx) | OSS-Fuzz **IssueTracker** id | ✅ resolves (libidn2, selinux) — but exhausted |
| **ARVO-Meta** (4,993 issues, ids 289–68524) | old **Monorail** id | ❌ `10012`/`25402` → content-less shell |
| local `oss-fuzz-vulns` (3,835) | old **Monorail** id (bugs.chromium) | ❌ |

`bugs.chromium.org` no longer server-redirects old→new, so there's no easy id bridge. **But**
`n132/arvo` on Docker Hub publishes **23,900 prebuilt reproduce images** (`<id>-vul` / `<id>-fix`)
keyed by exactly the Monorail ids ARVO-Meta provides. So we source new projects from ARVO-Meta
metadata and **verify them via the prebuilt images** — sidestepping the id problem entirely.

> **Scope / follow-up (important):** these 7 are verified via **ARVO images**, *not* the
> benchmark's IssueTracker source-rebuild path. To actually run them through a full kube
> experiment, phase 2 needs a small **"ARVO-image source" mode** (pull `<id>-vul`, extract `/src`,
> run the optimizer, rebuild with `arvo compile`). That is **not done here** — this task only
> collects + verifies. It is feasible: the `apply-fuzz-source-folds` skill already supports
> "extracted historical trees that validate through external build and smoke commands."

---

## 2. Method

**The `arvo` image contract** (locked by a probe on `25402-vul`/muparser):
- **reproduce/smoke:** `docker run --rm n132/arvo:<id>-vul arvo` → runs `/out/<target> /tmp/poc`;
  on the bug, exits ≠0 with `ERROR/SUMMARY: AddressSanitizer: <type>`.
- **build:** `docker run --rm n132/arvo:<id>-vul arvo compile` → rebuilds the target from `/src`
  (exit 0). Image bakes `SANITIZER=address`, `FUZZING_ENGINE=libfuzzer`.

**Filter funnel** (`fetch_arvo_meta_candidates.py`):

| Stage | Count |
|---|---:|
| ARVO-Meta records parsed | 4,993 |
| → `fuzzer == libfuzzer` (vs afl 900, honggfuzz 361) | 3,732 |
| → `sanitizer == asan` (vs msan 1118, ubsan 429) | 3,446 |
| → drop leak/timeout/OOM crash types | — |
| → **project NOT in the 42 already-touched** | **1,436 bugs / 194 distinct new projects** |
| Ranked candidates written (≤3 fallback bugs/project; giants deferred) | 443 |

**Screening** (`screen_arvo_images.py`, 4 projects in parallel, per-candidate timeouts, `docker rmi`
after each): pull → reproduce → (if reproduced) `arvo compile` → discover `fuzz_target` → keep iff
both pass; one per distinct project; stop at 7. Resumable via `arvo_image_screen_results.json`.

**Screened: 12 verdicts → 10 working, 2 build_failed** (both were PcapPlusPlus's first two bugs;
its third compiled). Every *distinct project* screened ended up working — no dead projects.

---

## 3. The 7 new working projects

| # | Project | ARVO id | Image | Fuzz target | Crash (observed = reproduced) |
|---|---|---|---|---|---|
| 1 | **libxml2** | 1972 | `n132/arvo:1972-vul` | `libxml2_xml_read_memory_fuzzer` | stack-buffer-overflow |
| 2 | **c-blosc2** | 24837 | `n132/arvo:24837-vul` | `decompress_fuzzer` | heap-buffer-overflow |
| 3 | **wolfssl** | 26567 | `n132/arvo:26567-vul` | `fuzzer-wolfssl-rsa` | heap-buffer-overflow |
| 4 | **libavc** | 16505 | `n132/arvo:16505-vul` | `avc_dec_fuzzer` | heap-buffer-overflow |
| 5 | **assimp** | 24463 | `n132/arvo:24463-vul` | `assimp_fuzzer` | heap-buffer-overflow |
| 6 | **PcapPlusPlus** | 22232 | `n132/arvo:22232-vul` | `FuzzTarget` | heap-buffer-overflow |
| 7 | **open62541** | 3609 | `n132/arvo:3609-vul` | `fuzz_binary_message` | negative-size-param |

For every kept project, the **observed ASAN crash matched the ARVO-Meta crash type** → the
reproduction is genuine, not an unrelated crash.

**Spot-check (re-pulled fresh, re-ran `arvo`):**
- `libxml2/1972` → exit 1, `AddressSanitizer: stack-buffer-overflow` ✅
- `open62541/3609` → exit 1, `AddressSanitizer: negative-size-param` ✅

**Surplus working projects** (verified but beyond the target of 7, available as extras):
`radare2` (10222), `libredwg` (31419), `graphicsmagick` (8280).

**Failures:** `PcapPlusPlus/22102` and `/22105` — reproduced but `arvo compile` failed; the
project's third bug (`22232`) compiled cleanly, so PcapPlusPlus is still counted as working.

---

## 4. Reproduce

```bash
cd /home/sefcom/asu/project/test/benchmark

# 1. acquire ARVO-Meta metadata (sparse, ~metadata only)
git clone --filter=blob:none --no-checkout --depth 1 \
    https://github.com/n132/ARVO-Meta .cache/ARVO-Meta
git -C .cache/ARVO-Meta sparse-checkout set archive_data/meta
git -C .cache/ARVO-Meta checkout

# 2. build the ranked candidate pool (new projects only)
python3 fetch_arvo_meta_candidates.py        # -> arvo_meta_candidates.json

# 3. screen images until 7 distinct new projects build + reproduce
python3 screen_arvo_images.py --target 7      # -> new_arvo_projects.json (+ results)

# verify any one:
docker run --rm n132/arvo:1972-vul arvo       # libxml2 -> ASAN stack-buffer-overflow
```

## 5. Artifacts
- `new_arvo_projects.json` — the 7 kept projects (project, ARVO id, image, fuzz_target, crash).
- `arvo_image_screen_results.json` — all 12 screening verdicts (resumable skip-cache).
- `arvo_meta_candidates.json` — 443 ranked candidates / 194 new projects (re-screen for more).
- `fetch_arvo_meta_candidates.py`, `screen_arvo_images.py` — the tooling.
