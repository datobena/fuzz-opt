"""ccache for FuzzBench-parity rebuilds of the optimized arm: host-side helpers.

The container side is prework/fb_build.sh (step 3b); the rules are in the
fuzzbench-parity-ccache skill. In short:

  * BOTH halves of an optimized-arm rebuild (main and cmplog) are cached; main and
    cmplog objects never share an entry (build kind + AFL_LLVM_CMPLOG are in the
    key). The baseline arm and the reference baseline are never cached;
  * a target gets a cache only after tools/fb_ccache_equivalence.py passed for it
    (pass: byte-identical; pass_noise_masked: equal up to P0-vs-P0' noise) and its
    fuzzbench_dir was added to VERIFIED_LIST (`<dir>` or `<dir> pass_noise_masked`);
  * inside the container ccache is /opt/fb_ccache/ccache, never on PATH, and runs
    below afl-cc (AFL_CC/AFL_CXX), with a per-object dictionary sidecar under
    <cache>/fb_dict/<kind> (fb_build.sh);
  * one cache per optimized trial (agent-edited code builds into it), seeded by
    copying a target-level template filled by one extra pristine build at campaign
    setup (plus, for a pass_noise_masked target, one more uncached build to learn
    the build's own noise). The template is never mounted into an agent build.

Everything here is pure Python (no docker) so it can be unit-tested.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

PREWORK_DIR = Path(__file__).resolve().parent
VERIFIED_LIST = PREWORK_DIR / "fuzzbench_ccache_verified.txt"
CONTAINER_VERIFIED_LIST = "/fold/ccache_verified.txt"
CONTAINER_CACHE_DIR = "/ccache"
# ccache inside fb-aflpp images: unpacked here, never on PATH (fuzzbench_image.py).
CONTAINER_CCACHE_BIN = "/opt/fb_ccache/ccache"
# Per-object dictionary sidecar inside a cache dir (fb_build.sh CCWRAP_PY).
DICT_STORE_DIRNAME = "fb_dict"
STATS_MARK = "FB_CCACHE_STATS "
# Host-only env key that carries a trial's cache dir from phase3_online to the
# broker (phase2_setup._invoke_agent_sandboxed). Not on the agent env allowlist.
BROKER_ENV_KEY = "PHASE2_FB_CCACHE_DIR"
TEMPLATE_DIRNAME = "ccache_template"
TRIAL_DIRNAME = "ccache"


# --------------------------------------------------------------- verified list

# Verified-list line: `<fuzzbench_dir> [<marker>]`. No marker = MODE_PASS.
MODE_PASS = "pass"
MODE_NOISE = "pass_noise_masked"
MODES = (MODE_PASS, MODE_NOISE)


def read_verified_modes(path: str | os.PathLike | None = None) -> dict[str, str]:
    """{fuzzbench_dir: "pass" | "pass_noise_masked"} from the verified list.

    '#' starts a comment; blank lines are ignored. A line is `<dir>` (verified as
    pass) or `<dir> pass` or `<dir> pass_noise_masked` (equal only after masking
    the build's own noise: the campaign template check then learns that noise
    with one extra uncached build, and the campaign verifier runs with --noise).
    A line with any other marker is ignored, here and in fb_build.sh."""
    p = Path(path) if path else VERIFIED_LIST
    try:
        text = p.read_text()
    except FileNotFoundError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        f = line.split("#", 1)[0].split()
        if len(f) == 1:
            out[f[0]] = MODE_PASS
        elif len(f) == 2 and f[1] in MODES:
            out[f[0]] = f[1]
        elif f:
            logger.warning("ccache verified list: ignoring malformed line %r", line)
    return out


def read_verified(path: str | os.PathLike | None = None) -> set[str]:
    """fuzzbench_dirs on the verified list (any valid marker)."""
    return set(read_verified_modes(path))


def ccache_globally_enabled() -> bool:
    """Kill switch: FB_CCACHE=0 in the environment, or config.FB_CCACHE = False."""
    if os.environ.get("FB_CCACHE", "").strip() == "0":
        return False
    try:
        import config  # noqa: WPS433 -- optional at import time
        return bool(getattr(config, "FB_CCACHE", True))
    except Exception:  # noqa: BLE001
        return True


def target_uses_ccache(entry: dict, *, verified_path=None) -> bool:
    """True when this manifest entry's optimized-arm rebuilds may use a cache."""
    return target_ccache_mode(entry, verified_path=verified_path) is not None


def target_ccache_mode(entry: dict, *, verified_path=None) -> str | None:
    """MODE_PASS / MODE_NOISE for a FuzzBench entry whose optimized-arm rebuilds
    may use a cache, else None (not FuzzBench, kill switch, not listed)."""
    if entry.get("kind") != "fuzzbench" or not entry.get("fuzzbench_dir"):
        return None
    if not ccache_globally_enabled():
        return None
    return read_verified_modes(verified_path).get(entry["fuzzbench_dir"])


# --------------------------------------------------------------- build logs

def _finish_stats(rec: dict | None) -> dict | None:
    if rec is not None and rec.get("enabled"):
        hits = int(rec.get("hits_direct", 0)) + int(rec.get("hits_preprocessed", 0))
        misses = int(rec.get("misses", 0))
        rec["hits"] = hits
        rec["hit_rate"] = round(hits / (hits + misses), 4) if hits + misses else None
    return rec


def parse_stats(log: str | None, build: str | None = None) -> dict | None:
    """ccache stats from the FB_CCACHE_STATS records fb_build.sh prints, one per
    build ("build": "main" | "cmplog"; a record without one is a round-2 cmplog
    record). The last record of each build counts.

    ``build`` given: that build's record (None if absent). Otherwise a combined
    record: ``enabled`` if any build used the cache, hit/miss counters summed over
    the builds that did, and ``builds`` = {kind: record}. None when the log has
    no record (an old fb_build.sh, or a build that died early)."""
    if not log:
        return None
    recs: dict[str, dict] = {}
    for line in log.splitlines():
        i = line.find(STATS_MARK)
        if i < 0:
            continue
        try:
            rec = json.loads(line[i + len(STATS_MARK):])
        except ValueError:
            continue
        if isinstance(rec, dict):
            recs[rec.get("build") or "cmplog"] = rec
    for r in recs.values():
        _finish_stats(r)
    if build is not None:
        return recs.get(build)
    if not recs:
        return None
    on = [r for r in recs.values() if r.get("enabled")]
    comb: dict = {"enabled": bool(on), "builds": recs}
    if on:
        for k in ("hits_direct", "hits_preprocessed", "misses", "compiler_check_failed"):
            comb[k] = sum(int(r.get(k, 0)) for r in on)
        comb["version"] = on[0].get("version")
        # Both halves of a FuzzBench build used the cache (a log with only one
        # record -- an old fb_build.sh, or a build that died early -- does not).
        comb["all_builds_enabled"] = all((recs.get(k) or {}).get("enabled")
                                         for k in ("main", "cmplog"))
        _finish_stats(comb)
    else:
        comb["reason"] = next((r.get("reason") for r in recs.values()
                               if r.get("reason")), None)
    return comb


def slim_stats(st: dict | None) -> dict | None:
    """parse_stats() result without ccache's raw counter tables (for provenance)."""
    if not st:
        return st
    out = {k: v for k, v in st.items() if k not in ("counters", "builds")}
    if st.get("builds"):
        out["builds"] = {b: {k: v for k, v in r.items() if k != "counters"}
                         for b, r in st["builds"].items()}
    return out


def parse_build_timings(log: str | None) -> dict[str, float]:
    """{'/out': secs, '/out/cmplog': secs} from FB_BUILD_TIMING lines."""
    out: dict[str, float] = {}
    for m in re.finditer(r"FB_BUILD_TIMING out=(\S+) secs=([0-9.]+)", log or ""):
        out[m.group(1)] = float(m.group(2))
    return out


# --------------------------------------------------------------- /out compare

def sha256_file(path: str | os.PathLike) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def dict_entries(path: str | os.PathLike) -> set[str] | None:
    """Unique entries of an AFL++ dictionary file (None if it does not exist).

    afl-cc appends to /out/afl++.dict from parallel compiles, so the line ORDER
    varies run to run; AFL++ dedups -x entries on load, so the set is what counts.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    return {ln.strip().decode("latin-1") for ln in data.splitlines() if ln.strip()}


def out_fingerprint(out_dir: str | os.PathLike, fuzz_target: str) -> dict:
    """What the equivalence checks compare: main + cmplog binary + dict entry set."""
    d = Path(out_dir)
    entries = dict_entries(d / "afl++.dict")
    return {
        "main": sha256_file(d / fuzz_target),
        "cmplog": sha256_file(d / "cmplog" / fuzz_target),
        "dict_set": (hashlib.sha256("\n".join(sorted(entries)).encode("latin-1"))
                     .hexdigest() if entries is not None else None),
        "dict_entries": len(entries) if entries is not None else None,
    }


def compare_outs(a: str | os.PathLike, b: str | os.PathLike, fuzz_target: str) -> dict:
    """Compare two /out dirs. ``identical`` only if every part exists and matches."""
    fa, fb = out_fingerprint(a, fuzz_target), out_fingerprint(b, fuzz_target)
    parts = {}
    for k in ("main", "cmplog", "dict_set"):
        parts[k] = fa[k] is not None and fa[k] == fb[k]
    res = {"identical": all(parts.values()), "parts": parts, "a": fa, "b": fb}
    if not parts["dict_set"]:
        ea, eb = dict_entries(Path(a) / "afl++.dict"), dict_entries(Path(b) / "afl++.dict")
        if ea is not None and eb is not None:
            res["dict_only_in_a"] = sorted(ea - eb)[:20]
            res["dict_only_in_b"] = sorted(eb - ea)[:20]
    return res


# --------------------------------------------------------------- cache dirs

def template_dir(online_dir: str | os.PathLike) -> str:
    return str(Path(online_dir) / TEMPLATE_DIRNAME)


def trial_cache_dir(trial_online_dir: str | os.PathLike) -> str:
    return str(Path(trial_online_dir) / TRIAL_DIRNAME)


def seed_cache(template: str | os.PathLike, dest: str | os.PathLike) -> str:
    """Fresh copy of the template cache at ``dest`` (replacing whatever was there).

    Each optimized trial gets its own writable copy: its builds compile
    agent-edited code, so a shared writable cache could carry one trial's objects
    into another's build. The copy drops ccache's lock/tmp files and stats are
    zeroed per build by fb_build.sh, so nothing else needs rewriting.
    """
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(template, dest, symlinks=False,
                    ignore=shutil.ignore_patterns("tmp", "*.lock", "*.tmp.*"))
    return str(dest)


# --------------------------------------------------------------- noise masking
#
# Some builds are not reproducible even without a cache: php embeds `uname -a` (the
# random container hostname) and __DATE__/__TIME__, openthread __DATE__ __TIME__,
# curl's OpenSSL a build date whose buildinf.h MD5 lands in DWARF5 .debug_line. For
# those, the equivalence test learns "noise regions" from two plain builds P0/P0'
# of the same tree and accepts a cached-vs-plain difference only inside them:
#
#   * every differing byte range of P0 vs P0' is widened to its enclosing
#     NUL-terminated printable string (kind "string"), or else to 16-byte aligned
#     blocks (kind "block"); a block is noise only inside a NON-ALLOC ELF section
#     (debug info). A block in a loaded section (code, data) is kind "code" and is
#     never maskable: a build race (woff2: two parallel compiles write one
#     dictionary.o) changes code and must fail;
#   * each region is remembered with its length and up to CTX bytes of context on
#     each side that P0 and P0' agree on, so it can be found again in a different
#     layout (a fold moves offsets);
#   * a pair (plain X, cached Y) of equal size is "masked-equal" when every differing
#     range, widened the same way, lies inside a remembered region found in X at a
#     place where its context matches (or at its own offset when X is P0 itself).

CTX = 32
MIN_CTX = 8
SHF_ALLOC = 0x2
_PRINTABLE = frozenset(list(range(0x20, 0x7F)) + [0x09])


def elf_sections(data: bytes) -> list[tuple[str, int, int, int]]:
    """[(name, file offset, size, sh_flags)] of a little-endian ELF64 (else [])."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return []
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if not shoff or shentsize < 64 or shoff + shnum * shentsize > len(data):
        return []
    hdrs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        name, typ, flags = struct.unpack_from("<IIQ", data, o)
        off, size = struct.unpack_from("<QQ", data, o + 24)
        hdrs.append((name, typ, flags, off, size))
    stroff = hdrs[shstrndx][3] if shstrndx < len(hdrs) else 0
    out = []
    for name, typ, flags, off, size in hdrs:
        if typ == 8 or not size:          # SHT_NOBITS / empty
            continue
        end = data.find(b"\0", stroff + name)
        out.append((data[stroff + name:end].decode("latin-1"), off, size, flags))
    return out


def diff_ranges(a: bytes, b: bytes, limit: int = 200000) -> list[tuple[int, int]]:
    """Maximal [start, end) byte ranges where equal-length a and b differ."""
    if len(a) != len(b):
        raise ValueError("diff_ranges needs equal sizes")
    out: list[tuple[int, int]] = []
    ma, mb = memoryview(a), memoryview(b)

    def walk(lo, hi):
        if ma[lo:hi] == mb[lo:hi] or len(out) > limit:
            return
        if hi - lo <= 256:
            for k in range(lo, hi):
                if a[k] != b[k]:
                    if out and out[-1][1] == k:
                        out[-1] = (out[-1][0], k + 1)
                    else:
                        out.append((k, k + 1))
            return
        mid = (lo + hi) // 2
        walk(lo, mid)
        walk(mid, hi)

    step = 1 << 16
    for off in range(0, len(a), step):
        walk(off, min(len(a), off + step))
    return out


def _string_bounds(data: bytes, s: int, e: int) -> tuple[int, int] | None:
    """[start, end) of the NUL-terminated printable string containing [s, e)."""
    if any(data[k] not in _PRINTABLE for k in range(s, e)):
        return None
    i, j = s, e
    while i > 0 and data[i - 1] in _PRINTABLE:
        i -= 1
    while j < len(data) and data[j] in _PRINTABLE:
        j += 1
    if j >= len(data) or data[j] != 0 or j - i < 4:
        return None
    return i, j


def _section_of(sections, s: int, e: int):
    for name, off, size, flags in sections:
        if off <= s and e <= off + size:
            return name, flags
    return None, None


def widen_regions(x: bytes, y: bytes, ranges, sections) -> list[dict]:
    """Differing ranges -> merged noise-candidate regions (see the block comment)."""
    regs = []
    for s, e in ranges:
        sx, sy = _string_bounds(x, s, e), _string_bounds(y, s, e)
        if sx and sy:
            regs.append({"kind": "string", "start": min(sx[0], sy[0]),
                         "end": max(sx[1], sy[1])})
            continue
        ws, we = s & ~15, (e + 15) & ~15
        sec, flags = _section_of(sections, ws, min(we, len(x)))
        kind = "block" if sec is not None and not (flags & SHF_ALLOC) else "code"
        regs.append({"kind": kind, "start": ws, "end": min(we, len(x)), "section": sec})
    regs.sort(key=lambda r: (r["start"], r["end"]))
    merged: list[dict] = []
    for r in regs:
        if merged and r["start"] <= merged[-1]["end"]:
            m = merged[-1]
            m["end"] = max(m["end"], r["end"])
            if r["kind"] != m["kind"]:
                m["kind"] = "code" if "code" in (r["kind"], m["kind"]) else "block"
        else:
            merged.append(dict(r))
    return merged


def _context(p0: bytes, p1: bytes, s: int, e: int) -> tuple[bytes, bytes]:
    pre_a, pre_b = p0[max(0, s - CTX):s], p1[max(0, s - CTX):s]
    k = 0
    while k < len(pre_a) and pre_a[-1 - k] == pre_b[-1 - k]:
        k += 1
    post_a, post_b = p0[e:e + CTX], p1[e:e + CTX]
    j = 0
    while j < len(post_a) and post_a[j] == post_b[j]:
        j += 1
    return (pre_a[len(pre_a) - k:], post_a[:j])


def _describe(data: bytes, r: dict) -> str:
    if r["kind"] == "string":
        return data[r["start"]:r["end"]].decode("latin-1")[:120]
    return f"{r['end'] - r['start']} bytes in {r.get('section')} @0x{r['start']:x}"


def noise_model(p0_path, p1_path) -> dict:
    """Noise regions of one output file from two plain builds P0 and P0'."""
    try:
        p0, p1 = Path(p0_path).read_bytes(), Path(p1_path).read_bytes()
    except OSError as e:
        return {"ok": False, "why": f"unreadable: {e}", "regions": []}
    m = {"sha_p0": hashlib.sha256(p0).hexdigest(), "regions": [], "ok": True}
    if p0 == p1:
        return {**m, "deterministic": True}
    m["deterministic"] = False
    if len(p0) != len(p1):
        return {**m, "ok": False, "why": "P0 and P0' differ in size"}
    regs = widen_regions(p0, p1, diff_ranges(p0, p1), elf_sections(p0))
    bad = [r for r in regs if r["kind"] == "code"]
    raw = diff_ranges(p0, p1)
    for r in regs:
        if r["kind"] == "block":
            # Context around the raw differing bytes (the "core"), not the aligned
            # block: block alignment moves with the layout, the bytes around do not.
            inside = [(a, b) for a, b in raw if a < r["end"] and b > r["start"]]
            r["core"] = (inside[0][0], inside[-1][1]) if inside else (r["start"], r["end"])
            r["pre"], r["post"] = _context(p0, p1, *r["core"])
        else:
            r["pre"], r["post"] = _context(p0, p1, r["start"], r["end"])
        r["skeleton"] = _skeleton(p0[r["start"]:r["end"]])
        r["text"] = _describe(p0, r)
    m["regions"] = regs
    if bad:
        m["ok"] = False
        m["why"] = (f"{len(bad)} differing range(s) in loaded code/data that are not "
                    f"strings (e.g. {bad[0].get('section')} @0x{bad[0]['start']:x}): "
                    "not maskable")
    return m


def _skeleton(b: bytes) -> bytes:
    """Letters and digits -> 'a': a hostname or a timestamp keeps its shape."""
    return bytes(0x61 if (0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A)
                 else c for c in b)


def _ctx_match(x: bytes, ts: int, te: int, pre: bytes, post: bytes) -> int:
    k = 0
    while k < len(pre) and ts - 1 - k >= 0 and x[ts - 1 - k] == pre[-1 - k]:
        k += 1
    j = 0
    while j < len(post) and te + j < len(x) and x[te + j] == post[j]:
        j += 1
    return k + j


def _region_found(x: bytes, r: dict, model: dict, x_is_p0: bool,
                  raw: list[tuple[int, int]]) -> dict | None:
    """A remembered noise region of the same kind that covers pair region r in x.

    x is P0 itself: by offset. Otherwise by context (>= MIN_CTX matching bytes, up to
    2*MIN_CTX when that much is known): a string must be the whole enclosing string,
    with the same length and letter/digit shape; a block's raw differing bytes must
    lie within 15 bytes (the 16-byte widening) of the remembered differing bytes."""
    for t in model["regions"]:
        if t["kind"] != r["kind"]:
            continue
        if x_is_p0 and t["start"] <= r["start"] and r["end"] <= t["end"]:
            return t
        avail = len(t["pre"]) + len(t["post"])
        if avail < MIN_CTX:
            continue
        need = max(MIN_CTX, min(2 * MIN_CTX, avail))
        if t["kind"] == "string":
            ts, te = r["start"], r["end"]
            if te - ts == t["end"] - t["start"] and _skeleton(x[ts:te]) == t["skeleton"] \
                    and _ctx_match(x, ts, te, t["pre"], t["post"]) >= need:
                return t
            continue
        cl = t["core"][1] - t["core"][0]
        inside = [(a, b) for a, b in raw if a < r["end"] and b > r["start"]]
        if not inside:
            continue
        rs, re_ = inside[0][0], inside[-1][1]
        for ts in range(max(0, re_ - cl - 15), rs + 16):
            te = ts + cl
            if ts - 15 <= rs and re_ <= te + 15 and \
                    _ctx_match(x, ts, te, t["pre"], t["post"]) >= need:
                return t
    return None


def masked_compare(x_path, y_path, model: dict | None) -> dict:
    """Plain X vs cached Y for one file: identical | masked | differs."""
    try:
        x, y = Path(x_path).read_bytes(), Path(y_path).read_bytes()
    except OSError as e:
        return {"status": "differs", "why": f"unreadable: {e}"}
    if x == y:
        return {"status": "identical"}
    if len(x) != len(y):
        return {"status": "differs", "why": f"size {len(x)} vs {len(y)}"}
    if not model or not model.get("ok") or model.get("deterministic"):
        why = ("P0 == P0' (no noise to mask)" if model and model.get("deterministic")
               else (model or {}).get("why", "no noise model"))
        return {"status": "differs", "why": why}
    x_is_p0 = hashlib.sha256(x).hexdigest() == model["sha_p0"]
    raw = diff_ranges(x, y)
    regs = widen_regions(x, y, raw, elf_sections(x))
    masked, unmasked = [], []
    for r in regs:
        if r["kind"] != "code" and _region_found(x, r, model, x_is_p0, raw):
            masked.append(_describe(x, r))
        else:
            unmasked.append(_describe(x, r) + f" [{r['kind']}]")
    if unmasked:
        return {"status": "differs", "why": "differences outside noise regions",
                "unmasked": unmasked[:20], "masked": masked[:20]}
    return {"status": "masked", "masked": masked[:50]}


def noise_models(p0_out, p1_out, fuzz_target: str) -> dict:
    """{"main": model, "cmplog": model} from two plain (uncached) /out dirs of the
    same tree. Shared by the equivalence test (P0 / P0'), the campaign template
    check (baseline / extra uncached build) and the campaign verifier."""
    return {part: noise_model(Path(p0_out) / rel, Path(p1_out) / rel)
            for part, rel in (("main", fuzz_target), ("cmplog", f"cmplog/{fuzz_target}"))}


def compare_with_noise(plain_out, plain2_out, cached_out, fuzz_target: str) -> dict:
    """Cached /out vs plain /out, accepting differences only inside the noise that
    two plain builds (plain_out, plain2_out) of the same tree show.

    ``status``: identical | masked | differs (compare_outs_masked); ``ok`` is True
    for identical or masked. Also returns the P0-vs-P0' comparison and a summary
    of the noise models. Dict sets must be equal (plain vs plain too)."""
    models = noise_models(plain_out, plain2_out, fuzz_target)
    pp = compare_outs(plain_out, plain2_out, fuzz_target)
    res = compare_outs_masked(plain_out, cached_out, fuzz_target, models)
    problems = []
    if not pp["parts"]["dict_set"]:
        problems.append("the two plain builds have different dictionary sets")
    for part, m in models.items():
        if not m.get("deterministic") and not m.get("ok"):
            problems.append(f"plain builds differ in {part} and that is not "
                            f"maskable: {m.get('why')}")
    res["plain_vs_plain"] = {"identical": pp["identical"], "parts": pp["parts"]}
    res["noise"] = {part: {"deterministic": m.get("deterministic"), "ok": m.get("ok"),
                           "why": m.get("why"),
                           "regions": [r.get("text") for r in m.get("regions", [])][:20]}
                    for part, m in models.items()}
    res["noise_problems"] = problems
    res["ok"] = res["status"] in ("identical", "masked") and not (
        problems and res["status"] != "identical")
    return res


def cmplog_hook_sites(path: str | os.PathLike) -> int | None:
    """Call sites of __cmplog_* hooks in a binary (objdump -d), None on error.

    A cmplog binary has many; a main binary must have none. The runtime itself
    defines the hook functions in both, so `nm` cannot tell them apart."""
    import subprocess
    try:
        p = subprocess.Popen(["objdump", "-d", "--no-show-raw-insn", str(path)],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    n = 0
    pat = re.compile(rb"\bcall\w*\s+[0-9a-f]+ <__cmplog_\w+")
    for line in p.stdout:
        if pat.search(line):
            n += 1
    return n if p.wait() == 0 else None


def compare_outs_masked(a, b, fuzz_target: str, models: dict) -> dict:
    """compare_outs plus noise masking for the two binaries. ``models`` maps
    "main"/"cmplog" -> noise_model(P0 file, P0' file)."""
    res = compare_outs(a, b, fuzz_target)
    if res["identical"]:
        res["status"] = "identical"
        return res
    detail = {}
    status = "masked"
    for part, rel in (("main", fuzz_target), ("cmplog", f"cmplog/{fuzz_target}")):
        if res["parts"][part]:
            detail[part] = {"status": "identical"}
            continue
        detail[part] = masked_compare(Path(a) / rel, Path(b) / rel, models.get(part))
        if detail[part]["status"] != "masked":
            status = "differs"
    if not res["parts"]["dict_set"]:
        status = "differs"
    res["status"] = status
    res["masked_detail"] = detail
    return res
