#!/usr/bin/env python3
"""Ranked hotspot table of TARGET-SOURCE functions, built from perf call chains.

``replay_fuzzer_profile.py`` dumps every sample's call chain with ``perf script``
inside the profiler container (where ``/out`` and a matching perf exist, so
symbols resolve), plus each sample's own IP in a second ``perf script -G`` pass,
and then calls :func:`build_hotspot_table` on the host. The result is
``hotspots.txt`` (for the optimizer agent) and ``hotspots.json``
(machine-readable). The perf reports (children/flat/callgraph/dso) are untouched:
this is an ADDITIONAL view of the same, full profile.

Every frame is put in one class:

  target      a DSO of the build under test (the fuzz target binary, or a shared
              library the build put under /out) whose function source maps into
              the project's editable tree, minus the harness and shared
              fuzz-support code
  sanitizer   sanitizer / coverage runtime in those DSOs: ``__asan*``,
              ``__sanitizer*``, ``__interceptor_*`` ..., compiler-rt and AFL's
              coverage runtime
  thirdparty  any other code in those DSOs: std-library templates (libc++ /
              libstdc++ headers), statically linked third-party libraries, code
              without debug info
  libc        libc and every other shared library outside /out, including the
              build image's own libraries the profiler supplies under
              /opt/target-libs (target_libs.py; e.g. glib)
  kernel      kernel and kernel modules
  other       everything else: afl-showmap, the AFL / libFuzzer driver, the
              harness, shells

Two per-function metrics, both with NO percent cut-off:

  caused     walk each chain from the leaf toward the root and credit the sample
             to the NEAREST target-source frame. The credit is split by what the
             leaf was: own code, sanitizer/coverage, third-party, allocator, libc,
             kernel, other. A cheap function that triggers expensive sanitizer or
             allocator work gets that work; a wrapper does NOT get the work done
             by other target functions below it. Walking from the leaf also keeps
             the metric valid when LBR truncates the root end of a chain.
  inclusive  the sample counts once for every target-source function anywhere in
             its chain (recursion counts once).

``allocator`` is a sub-bucket: a sample whose frames between the leaf and the
credited function include an allocator entry point (malloc/free/calloc/realloc,
operator new/delete) or ASan allocator internals.

The leaf is the sample's own IP. Under ``--call-graph lbr`` the first callchain
entry is the most recently CALLED function, which for a sample taken on a call
instruction is a callee that has not run yet; the IP pass corrects that.

Percentages are of the total sample PERIOD, like ``perf report``; raw sample
counts are reported beside them. Function -> source file:line comes from each
DSO's debug info: each UNIQUE function start address is resolved once with
addr2line (or llvm-addr2line), never once per sample. Inlined functions are
reported under the non-inlined function that contains them.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import time
from pathlib import Path

HOTSPOTS_TXT = "hotspots.txt"
HOTSPOTS_JSON = "hotspots.json"
TXT_MIN_ROWS = 200
SCHEMA_VERSION = 2
CONTAINER_OUT = "/out"

CLS_TARGET = "target"
CLS_SANITIZER = "sanitizer"
CLS_THIRDPARTY = "thirdparty"
CLS_LIBC = "libc"
CLS_KERNEL = "kernel"
CLS_OTHER = "other"
BUCKETS = ("own", "sanitizer", "thirdparty", "allocator", "libc", "kernel", "other")
OUTSIDE_BUCKETS = ("sanitizer", "thirdparty", "allocator", "libc", "kernel", "other")

# The agent may edit only these (SKILL.md, verify_source_only_changes.py).
EDITABLE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})

# Names that are sanitizer or coverage runtime wherever their source says they
# come from. The C++-namespaced spellings (__asan::Allocator::Allocate,
# __sanitizer::StackDepotBase<...>::Put) are where most of the self time sits.
_SANITIZER_PREFIXES = (
    "__asan", "__sanitizer", "__ubsan", "__lsan", "__msan", "__tsan", "__hwasan",
    "__dfsan", "__interceptor_", "___interceptor_", "__interception",
    "__sancov", "__afl_", "__cmplog_",
    # Compiler-generated per-module ctors/dtors the instrumentation passes emit
    # into every TU (asan.module_ctor, sancov.module_ctor_trace_pc_guard, ...).
    # Their debug info points at the project file they were emitted into, but
    # no source edit can touch them.
    "asan.", "sancov.", "msan.", "tsan.", "hwasan.", "ubsan.", "dfsan.", "lsan.",
    "memprof.", "nsan.", "rtsan.",
)
# Generator inputs the debug info can point at through #line directives.
_GENERATOR_SUFFIXES = frozenset({".l", ".ll", ".lex", ".y", ".yy", ".ypp", ".re",
                                 ".rl", ".gperf", ".lemon", ".peg"})
# Source paths of the sanitizer / coverage runtime compiled into the target.
_RUNTIME_PATH_MARKERS = ("/compiler-rt/", "compiler-rt/lib/", "afl-compiler-rt",
                         "llvm_mode/", "/instrumentation/afl-")
# Allocator entry points, after stripping an interceptor prefix.
_ALLOC_NAMES = frozenset({
    "malloc", "free", "calloc", "realloc", "reallocarray", "posix_memalign",
    "memalign", "aligned_alloc", "valloc", "pvalloc", "cfree", "malloc_usable_size",
    "__libc_malloc", "__libc_free", "__libc_calloc", "__libc_realloc",
    "__libc_memalign", "_int_malloc", "_int_free", "_int_realloc",
})
_ALLOC_PREFIXES = (
    "operator new", "operator delete", "_Znw", "_Zna", "_Zdl", "_Zda",
    "__asan::Allocator::", "__asan::QuarantineCallback", "__asan::asan_malloc",
    "__asan::asan_calloc", "__asan::asan_realloc", "__asan::asan_reallocarray",
    "__asan::asan_free", "__asan::asan_delete", "__asan::asan_memalign",
    "__asan::asan_posix_memalign", "__asan::asan_aligned_alloc",
    "__asan::asan_valloc", "__asan::asan_pvalloc",
    "__asan::asan_malloc_usable_size", "__sanitizer::Quarantine",
    "__sanitizer::CombinedAllocator", "__sanitizer::SizeClassAllocator",
    "__sanitizer::LargeMmapAllocator", "__sanitizer::InternalAlloc",
    "__sanitizer::InternalFree", "__sanitizer::InternalRealloc",
    "__sanitizer::DlSymAllocator", "__lsan::Allocate", "__lsan::Deallocate",
    "__lsan::Reallocate",
)
# A path component (or file stem) naming fuzz-only code: fuzz/, fuzzer/,
# fuzzing/, oss-fuzz/, fuzz-common.c, fuzzer-sapi.c ... but not "fuzzy".
_FUZZ_COMPONENT_RE = re.compile(
    r"(^|[-_.])(oss-?)?fuzz(ing|ers?|tests?|_?targets?)?($|[-_.])", re.I)
# The AFL / libFuzzer drivers that call LLVMFuzzerTestOneInput (class "other").
_DRIVER_MARKERS = ("aflpp_driver", "aflpp_qemu_driver", "/libfuzzer/",
                   "/compiler-rt/lib/fuzzer/", "FuzzerMain",
                   "StandaloneFuzzTargetMain", "/honggfuzz/")
_HARNESS_SYMBOLS = ("LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize",
                    "LLVMFuzzerCustomMutator", "LLVMFuzzerCustomCrossOver")
_KERNEL_IP = 0xFFFF800000000000
_USER_BRACKET_DSOS = frozenset({"[vdso]", "[vsyscall]", "[vdso32]", "[vdsox32]"})
_SKIP_TREE_DIRS = frozenset({".git", ".hg", ".svn"})
# Source-root mismatch: this many unmapped target-DSO files whose names DO exist
# in the editable tree, with not one function mapped, is a wrong root, not a
# target without project code.
MISMATCH_MIN_FILES = 5

_HEADER_RE = re.compile(r"^(.*?)\s+(\d+)\s+(\d+)\s*(.*)$")


class HotspotError(RuntimeError):
    """The hotspot table could not be built. Always loud: it is the agent's
    primary ranking input, so the caller treats it as a failed profile."""


# ---------------------------------------------------------------------------
# Minimal ELF64 reader (no pyelftools on the hosts): type, PT_LOADs, symbols.
# ---------------------------------------------------------------------------
class ElfInfo:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.e_type = None          # 2 = ET_EXEC, 3 = ET_DYN (PIE or shared lib)
        self.loads: list[tuple[int, int, int]] = []   # (p_offset, p_vaddr, p_filesz)
        try:
            with open(self.path, "rb") as f:
                self._data = f.read()
        except OSError as e:
            raise HotspotError(f"cannot read {self.path}: {e}") from e
        d = self._data
        if len(d) < 64 or d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise HotspotError(f"{self.path} is not a little-endian ELF64 file")
        try:
            (self.e_type,) = struct.unpack_from("<H", d, 16)
            e_phoff, e_shoff = struct.unpack_from("<QQ", d, 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(
                "<HHHH", d, 54)
            for i in range(e_phnum):
                p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(
                    "<IIQQQQ", d, e_phoff + i * e_phentsize)
                if p_type == 1:
                    self.loads.append((p_offset, p_vaddr, p_filesz))
            self._sections = []
            for i in range(e_shnum):
                (_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info,
                 _align, sh_entsize) = struct.unpack_from(
                    "<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)
                self._sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
        except struct.error as e:
            raise HotspotError(f"{self.path}: truncated ELF ({e})") from e

    @property
    def is_pie(self) -> bool:
        return self.e_type == 3

    def file_offset_to_vaddr(self, off: int) -> int | None:
        for p_offset, p_vaddr, p_filesz in self.loads:
            if p_offset <= off < p_offset + p_filesz:
                return off - p_offset + p_vaddr
        return None

    def symbol_addresses(self, names) -> dict[str, int]:
        """st_value of each named FUNC symbol in .symtab (else .dynsym)."""
        want = {n.encode(): n for n in names}
        out: dict[str, int] = {}
        d = self._data
        for sh_type in (2, 11):                    # SHT_SYMTAB, then SHT_DYNSYM
            for (t, off, size, link, entsize) in self._sections:
                if t != sh_type or not entsize:
                    continue
                str_off = self._sections[link][1]
                for i in range(size // entsize):
                    st_name, st_info, _other, _shndx, st_value, _sz = struct.unpack_from(
                        "<IBBHQQ", d, off + i * entsize)
                    if (st_info & 0xF) != 2 or not st_value:      # STT_FUNC
                        continue
                    end = d.find(b"\0", str_off + st_name)
                    name = d[str_off + st_name:end]
                    if name in want and want[name] not in out:
                        out[want[name]] = st_value
            if out:
                break
        return out


# ---------------------------------------------------------------------------
# perf script parsing
# ---------------------------------------------------------------------------
def parse_frame_line(line: str):
    """``<ip> <sym>+0x<off> (<dso>+0x<dsoff>)`` -> (ip, sym, symoff, dso, dsoff).

    symoff / dsoff are None when perf printed none (``[unknown]`` symbols). The
    DSO is the LAST parenthesised group, so C++ signatures inside the symbol
    are left alone.
    """
    s = line.strip()
    sp = s.find(" ")
    if sp <= 0:
        return None
    try:
        ip = int(s[:sp], 16)
    except ValueError:
        return None
    rest = s[sp + 1:].strip()
    dso, dsoff = "", None
    lp = rest.rfind(" (") if rest.endswith(")") else -1
    if lp >= 0:
        dso_part, sym_part = rest[lp + 2:-1], rest[:lp]
        k = dso_part.rfind("+0x")
        if k >= 0:
            dso = dso_part[:k]
            try:
                dsoff = int(dso_part[k + 3:], 16)
            except ValueError:
                dso, dsoff = dso_part, None
        else:
            dso = dso_part
    else:
        sym_part = rest
    sym, symoff = sym_part.strip(), None
    k = sym.rfind("+0x")
    if k > 0:
        try:
            symoff = int(sym[k + 3:], 16)
            sym = sym[:k]
        except ValueError:
            symoff = None
    return ip, sym or "[unknown]", symoff, dso, dsoff


def iter_samples(lines):
    """Yield (period, [frame lines leaf-first]) per perf-script sample."""
    period = None
    frames: list[str] = []
    for line in lines:
        if not line.strip():
            if period is not None:
                yield period, frames
            period, frames = None, []
            continue
        if line[0] in " \t":
            if period is not None:
                frames.append(line)
            continue
        if period is not None:
            yield period, frames
        m = _HEADER_RE.match(line.rstrip("\n"))
        if not m:
            period, frames = None, []
            continue
        period = int(m.group(3))
        frames = []
        if m.group(4).strip():          # no call chain: the ip is inline
            frames.append(m.group(4))
    if period is not None:
        yield period, frames


def iter_ip_samples(lines):
    """Yield (period, ip frame text) per line of ``perf script -G`` output."""
    for line in lines:
        if not line.strip():
            continue
        m = _HEADER_RE.match(line.rstrip("\n"))
        if not m:
            raise HotspotError(f"unparseable sample-IP line: {line[:200]!r}")
        yield int(m.group(3)), m.group(4)


def _is_alloc_name(name: str) -> bool:
    base = name
    for p in ("___interceptor_", "__interceptor_"):
        if base.startswith(p):
            base = base[len(p):]
            break
    paren = base.find("(")
    if paren > 0:
        base = base[:paren]
    if base in _ALLOC_NAMES:
        return True
    return name.startswith(_ALLOC_PREFIXES)


def is_build_dso(dso: str, fuzz_target: str) -> bool:
    """A DSO of the build under test: the fuzz target binary, or a shared
    library the build put under /out (a project's own lib*.so, loaded by
    rpath). afl-showmap and the other AFL tools under /out are not."""
    if not dso.startswith(CONTAINER_OUT + "/"):
        return False
    base = os.path.basename(dso)
    return base == fuzz_target or ".so" in base


class _Frames:
    """Interns frames into function ids. Build-DSO frames are keyed by (DSO,
    function START address), so one function is one id however many distinct
    instruction addresses were sampled in it."""

    def __init__(self, fuzz_target: str, elf_for):
        self.fuzz_target = fuzz_target
        self.elf_for = elf_for            # dso path -> ElfInfo | None
        self.by_line: dict[str, int] = {}
        self.by_key: dict[tuple, int] = {}
        # per fid: [kind, dso, name, start_vaddr]; kind in {"T","K","D"}
        self.info: list[list] = []

    def _fid(self, key, kind, dso, name, start):
        fid = self.by_key.get(key)
        if fid is None:
            fid = len(self.info)
            self.by_key[key] = fid
            self.info.append([kind, dso, name, start])
        return fid

    def fid_for_line(self, line: str) -> int | None:
        fid = self.by_line.get(line)
        if fid is not None:
            return fid
        parsed = parse_frame_line(line)
        if parsed is None:
            return None
        ip, sym, symoff, dso, dsoff = parsed
        if ip >= _KERNEL_IP or dso.startswith("[kernel") or (
                dso.startswith("[") and dso not in _USER_BRACKET_DSOS
                and dso != "[unknown]"):
            fid = self._fid(("K",), "K", "[kernel]", "[kernel]", None)
        elif is_build_dso(dso, self.fuzz_target):
            start = None
            elf = self.elf_for(dso)
            if symoff is not None and sym != "[unknown]" and elf is not None:
                if elf.is_pie:
                    v = elf.file_offset_to_vaddr(dsoff) if dsoff is not None else None
                    start = v - symoff if v is not None else None
                else:
                    start = ip - symoff
            if start is None:
                fid = self._fid(("T?", dso, sym), "T", dso, sym, None)
            else:
                fid = self._fid(("T", dso, start), "T", dso, sym, start)
        else:
            fid = self._fid(("D", dso, sym), "D", dso, sym, None)
        self.by_line[line] = fid
        return fid


def _chain(flines, frames: _Frames) -> list[int]:
    out: list[int] = []
    last = -1
    for fl in flines:
        fid = frames.fid_for_line(fl)
        if fid is None or fid == last:
            continue
        out.append(fid)
        last = fid
    return out


def read_chains(lines, frames: _Frames, ip_lines=None, stats: dict | None = None):
    """{chain (tuple of fids, leaf first, consecutive repeats collapsed):
    [samples, period]}, plus totals. Collapsing A,A,A->A changes neither the
    nearest-target walk nor the once-per-sample inclusive count.

    ``ip_lines`` (``perf script -G`` output of the same perf.data, same sample
    order) supplies each sample's own IP. When the chain's first entry is not
    the IP's function: if the IP's function is the next entry, the first one is
    a callee the LBR recorded as called but that has not executed yet (the
    sample was taken on the call instruction) and is dropped; otherwise the IP's
    function is put in front as the leaf.
    """
    stats = stats if stats is not None else {}
    chains: dict[tuple, list] = {}
    n = 0
    total_period = 0
    fixed_n = fixed_p = 0
    ip_iter = iter_ip_samples(ip_lines) if ip_lines is not None else None
    for period, flines in iter_samples(lines):
        n += 1
        total_period += period
        out = _chain(flines, frames)
        if ip_iter is not None:
            try:
                ip_period, ip_frame = next(ip_iter)
            except StopIteration:
                raise HotspotError(
                    f"sample-IP dump ended after {n - 1} samples; the call-chain "
                    "dump has more (truncated perf script output)") from None
            if ip_period != period:
                raise HotspotError(
                    f"sample {n}: call-chain and sample-IP dumps disagree (period "
                    f"{period} vs {ip_period}); they are not the same sample stream")
            ipfid = frames.fid_for_line(ip_frame) if ip_frame.strip() else None
            if ipfid is not None and (not out or out[0] != ipfid):
                if len(out) > 1 and out[1] == ipfid:
                    out = out[1:]
                else:
                    out.insert(0, ipfid)
                fixed_n += 1
                fixed_p += period
        key = tuple(out)
        acc = chains.get(key)
        if acc is None:
            chains[key] = [1, period]
        else:
            acc[0] += 1
            acc[1] += period
    if ip_iter is not None:
        extra = sum(1 for _ in ip_iter)
        if extra:
            raise HotspotError(
                f"sample-IP dump has {extra} more samples than the call-chain dump "
                f"({n}); truncated perf script output")
        stats["ip_leaf_fixed_samples"] = fixed_n
        stats["ip_leaf_fixed_pct"] = (round(100.0 * fixed_p / total_period, 2)
                                      if total_period else 0.0)
    return chains, n, total_period


# ---------------------------------------------------------------------------
# Source resolution and classification
# ---------------------------------------------------------------------------
def find_symbolizer() -> list[str] | None:
    """GNU addr2line, or llvm-addr2line (same CLI; also as llvm-addr2line-NN)."""
    for name in ("addr2line", "llvm-addr2line"):
        p = shutil.which(name)
        if p:
            return [p]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        try:
            for f in sorted(os.listdir(d), reverse=True):
                if re.fullmatch(r"llvm-addr2line-\d+", f):
                    return [os.path.join(d, f)]
        except OSError:
            continue
    return None


def resolve_sources(binary: str, addrs, *, timeout: int = 600) -> dict[int, tuple]:
    """{addr: (function, file or None, line or None)}, one addr2line call for all.

    ``-i`` lists the inline chain innermost first; the LAST entry is the
    non-inlined function that contains the address, which is the row we want.
    """
    addrs = sorted(set(a for a in addrs if a is not None))
    if not addrs:
        return {}
    tool = find_symbolizer()
    if tool is None:
        raise HotspotError("no addr2line / llvm-addr2line on PATH; cannot map "
                           "functions to source files")
    try:
        r = subprocess.run(
            tool + ["-a", "-f", "-i", "-C", "-e", str(binary)],
            input="".join(f"0x{a:x}\n" for a in addrs),
            capture_output=True, text=True, errors="replace", timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise HotspotError(f"{tool[0]} failed on {binary}: {e}") from e
    if r.returncode != 0:
        raise HotspotError(f"{tool[0]} exited {r.returncode} on {binary}: "
                           f"{(r.stderr or '')[-300:]}")
    out: dict[int, tuple] = {}
    cur = None
    pairs: list[tuple[str, str]] = []
    lines = r.stdout.splitlines()
    addr_re = re.compile(r"^0x[0-9a-fA-F]+$")

    def flush():
        if cur is None:
            return
        if not pairs:
            out[cur] = ("??", None, None)
            return
        func, loc = pairs[-1]
        out[cur] = (func,) + _split_loc(loc)

    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if addr_re.match(ln):
            flush()
            cur = int(ln, 16)
            pairs = []
            i += 1
            continue
        func = ln
        loc = lines[i + 1].strip() if i + 1 < len(lines) else "??:0"
        pairs.append((func, loc))
        i += 2
    flush()
    return out


def symbolizer_selftest(binary: str | None = None) -> tuple[bool, str]:
    """Can the symbolizer actually resolve? With a fuzz target binary: map its
    LLVMFuzzerTestOneInput to a source file. Without one: run it at all."""
    tool = find_symbolizer()
    if tool is None:
        return False, "no addr2line / llvm-addr2line (or llvm-addr2line-NN) on PATH"
    if binary:
        try:
            addr = ElfInfo(binary).symbol_addresses(_HARNESS_SYMBOLS[:1])
            got = resolve_sources(binary, addr.values())
        except HotspotError as e:
            return False, f"{tool[0]}: {e}"
        f = next((v[1] for v in got.values() if v[1]), None)
        if not f:
            return False, (f"{tool[0]} could not map LLVMFuzzerTestOneInput of "
                           f"{binary} to a source file")
        return True, f"{tool[0]} resolves {os.path.basename(binary)} -> {f}"
    try:
        r = subprocess.run(tool + ["-a", "-f", "-e", tool[0], "0x0"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"{tool[0]} does not run: {e}"
    if r.returncode != 0 or "0x0" not in r.stdout:
        return False, f"{tool[0]} exited {r.returncode}: {(r.stderr or '')[-200:]}"
    return True, f"{tool[0]} runs (no fuzz target binary found to test resolution)"


def _split_loc(loc: str):
    """'/src/x/a.c:12 (discriminator 3)' -> ('/src/x/a.c', 12); '??:0' -> (None, None)."""
    loc = loc.split(" (discriminator", 1)[0].strip()
    path, _, line = loc.rpartition(":")
    if not path or path.startswith("??"):
        return None, None
    try:
        return os.path.normpath(path), int(line)
    except ValueError:
        return os.path.normpath(path), None


def _has_fuzz_component(rel: str) -> bool:
    parts = rel.split("/")
    stems = parts[:-1] + [os.path.splitext(parts[-1])[0]]
    return any(_FUZZ_COMPONENT_RE.search(p) for p in stems if p)


def _under(path: str, root: str) -> bool:
    p, r = path.lower(), root.lower().rstrip("/")
    return p.startswith(r + "/")


def infer_source_root(harness_file: str | None) -> str | None:
    """/src/<project> from a harness path such as /src/<project>/fuzz/target.c."""
    if not harness_file:
        return None
    parts = Path(harness_file).parts
    if len(parts) >= 4 and parts[0] == "/" and parts[1] == "src":
        return "/src/" + parts[2]
    return None


class SourceMap:
    """Maps a debug-info path to the agent's editable tree.

    1. prefix: under the in-image source root (``/src/<tree basename>``) -> the
       path below it, whether or not the file exists in the tree (a file
       generated at build time, such as an amalgamation, still maps);
    2. suffix: the path ends in ``/<tree basename>/<rel>`` for a file ``rel``
       that exists in the tree -- the build compiled a COPY of the tree under
       another prefix (e.g. a copy checked out inside a separate fuzzers repo).
       The longest such suffix wins.
    """

    def __init__(self, source_root: str | None, tree: str | Path | None = None):
        self.source_root = os.path.normpath(source_root) if source_root else None
        self.tree = Path(tree) if tree else None
        self.files: set[str] = set()
        self.names: set[str] = set()
        if self.tree is not None:
            if not self.tree.is_dir():
                raise HotspotError(f"editable source tree {self.tree} does not exist")
            for dirpath, dirnames, filenames in os.walk(self.tree):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_TREE_DIRS]
                rel_dir = os.path.relpath(dirpath, self.tree)
                for fn in filenames:
                    rel = fn if rel_dir == "." else f"{rel_dir}/{fn}"
                    self.files.add(rel)
                    self.names.add(fn)
        self.basename = (self.tree.name if self.tree is not None
                         else (os.path.basename(self.source_root)
                               if self.source_root else None))

    def map(self, path: str | None) -> str | None:
        """Tree-relative path for ``path``, or None when it is not project code."""
        if not path:
            return None
        if self.source_root and _under(path, self.source_root):
            return path[len(self.source_root):].lstrip("/")
        if not self.files:
            return None
        if not os.path.isabs(path):
            return path if path in self.files else None
        comps = path.split("/")
        for i, c in enumerate(comps[:-1]):
            if c == self.basename:
                rel = "/".join(comps[i + 1:])
                if rel in self.files:
                    return rel
        return None

    def editable(self, rel: str) -> tuple[bool | None, str | None]:
        """(editable, note): is ``rel`` a file the agent may edit?"""
        if self.tree is None:
            return None, "editable tree unknown"
        if rel not in self.files:
            return False, ("generated at build time: not in the editable tree; find "
                           "the function's real source in the tree")
        suffix = os.path.splitext(rel)[1].lower()
        if suffix in _GENERATOR_SUFFIXES:
            return False, (f"generator input ({suffix}): the build turns it into C, so "
                           "the code cannot be edited here; only .c/.cc/.cpp/.cxx/.h/"
                           ".hh/.hpp/.hxx files may be edited")
        if suffix not in EDITABLE_SUFFIXES:
            return False, (f"a {suffix or 'suffix-less'} file, not one of the editable "
                           "types (.c/.cc/.cpp/.cxx/.h/.hh/.hpp/.hxx); fold in the C/C++ "
                           "code that includes or calls it")
        return True, None


class Classifier:
    def __init__(self, smap: SourceMap, harness_files=()):
        self.smap = smap
        self.harness_files = {os.path.normpath(h) for h in harness_files if h}
        self.harness_basenames = {os.path.basename(h) for h in self.harness_files}

    @property
    def source_root(self):
        return self.smap.source_root

    def classify_target_frame(self, name: str, path: str | None) -> tuple[str, str | None]:
        """(class, tree-relative path or None) of a build-DSO frame."""
        if name.startswith(_SANITIZER_PREFIXES):
            return CLS_SANITIZER, None
        if name.startswith("fuzzer::"):
            return CLS_OTHER, None          # libFuzzer's own engine
        if not path:
            return CLS_THIRDPARTY, None     # no debug info: not project source
        if path in self.harness_files:
            return CLS_OTHER, None
        if any(m in path for m in _DRIVER_MARKERS):
            return CLS_OTHER, None
        if any(m in path for m in _RUNTIME_PATH_MARKERS):
            return CLS_SANITIZER, None
        rel = self.smap.map(path)
        if rel is not None:
            if _has_fuzz_component(rel):
                return CLS_OTHER, None      # shared fuzz-support code
            return CLS_TARGET, rel
        if os.path.basename(path) in self.harness_basenames and \
                _has_fuzz_component(path):
            return CLS_OTHER, None          # harness outside the project dir
        return CLS_THIRDPARTY, None         # std headers, third-party code

    @staticmethod
    def classify_dso_frame(dso: str) -> str:
        base = os.path.basename(dso)
        if dso in _USER_BRACKET_DSOS or ".so" in base:
            return CLS_LIBC
        return CLS_OTHER


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------
def attribute(chains: dict, fid_class: list[str], fid_alloc: list[bool]):
    """Caused + inclusive per target-source fid, and the outside-target totals.

    Returns (per_fid, outside) where per_fid[fid] = {"samples", "period",
    "<bucket>_period" ..., "incl_samples", "incl_period"} and outside =
    {"samples", "period", "<bucket>_period" ...}.
    """
    per: dict[int, dict] = {}
    outside = {"samples": 0, "period": 0}
    for b in OUTSIDE_BUCKETS:
        outside[b + "_period"] = 0
        outside[b + "_samples"] = 0

    def row(fid):
        r = per.get(fid)
        if r is None:
            r = {"samples": 0, "period": 0, "incl_samples": 0, "incl_period": 0}
            for b in BUCKETS:
                r[b + "_period"] = 0
                r[b + "_samples"] = 0
            per[fid] = r
        return r

    for chain, (cnt, period) in chains.items():
        nearest = -1
        alloc = False
        for i, fid in enumerate(chain):
            if fid_class[fid] == CLS_TARGET:
                nearest = i
                break
            if fid_alloc[fid]:
                alloc = True
        leaf_cls = fid_class[chain[0]] if chain else CLS_OTHER
        if nearest < 0:
            b = "allocator" if alloc else (leaf_cls if leaf_cls != CLS_TARGET
                                           else CLS_OTHER)
            outside["samples"] += cnt
            outside["period"] += period
            outside[b + "_period"] += period
            outside[b + "_samples"] += cnt
        else:
            r = row(chain[nearest])
            if nearest == 0:
                b = "own"
            elif alloc:
                b = "allocator"
            else:
                b = leaf_cls
            r["samples"] += cnt
            r["period"] += period
            r[b + "_period"] += period
            r[b + "_samples"] += cnt
        seen = set()
        for fid in chain:
            if fid_class[fid] == CLS_TARGET and fid not in seen:
                seen.add(fid)
                r = row(fid)
                r["incl_samples"] += cnt
                r["incl_period"] += period
    return per, outside


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _open_text(path: Path):
    return (gzip.open if path.suffix == ".gz" else open)(path, "rt", errors="replace")


def build_hotspot_table(*, perf_script: str | Path, binary: str | Path,
                        fuzz_target: str, out_dir: str | Path,
                        source_root: str | None = None,
                        harness_paths=(), timings: dict | None = None,
                        ip_script: str | Path | None = None,
                        source_tree: str | Path | None = None,
                        host_out_dir: str | Path | None = None,
                        expected_samples: int | None = None) -> dict:
    """Build hotspots.json + hotspots.txt in ``out_dir``; return the JSON dict.

    ``perf_script``: ``perf script -F comm,pid,period,ip,sym,symoff,dso,dsoff``
    output (plain or .gz); ``ip_script``: the same with ``-G`` (one line per
    sample, its own IP). ``binary``: host path of the profiled target (the file
    mounted at /out/<fuzz_target>); ``host_out_dir`` (default: its directory) is
    the host dir mounted at /out, where shared libraries of the build are found.
    ``source_tree``: host path of the agent's editable tree; without it only the
    ``source_root`` prefix maps and the ``editable`` flag is unknown.
    ``expected_samples``: perf report's sample count, cross-checked against the
    dump. Raises HotspotError.
    """
    t0 = time.monotonic()
    timings = timings if timings is not None else {}
    perf_script = Path(perf_script)
    if not perf_script.is_file() or perf_script.stat().st_size == 0:
        raise HotspotError(f"perf script output missing or empty: {perf_script}")
    if ip_script is not None:
        ip_script = Path(ip_script)
        if not ip_script.is_file() or ip_script.stat().st_size == 0:
            raise HotspotError(f"sample-IP dump missing or empty: {ip_script}")
    binary = Path(binary)
    host_out = Path(host_out_dir) if host_out_dir else binary.parent
    main_dso = f"{CONTAINER_OUT}/{fuzz_target}"
    elves: dict[str, ElfInfo | None] = {main_dso: ElfInfo(binary)}
    missing_dsos: set[str] = set()

    def host_path(dso: str) -> Path:
        return binary if dso == main_dso else host_out / os.path.relpath(dso, CONTAINER_OUT)

    def elf_for(dso: str):
        if dso not in elves:
            try:
                elves[dso] = ElfInfo(host_path(dso))
            except HotspotError:
                elves[dso] = None
                missing_dsos.add(dso)
        return elves[dso]

    frames = _Frames(fuzz_target, elf_for)
    try:
        with _open_text(perf_script) as f:
            if ip_script is not None:
                with _open_text(ip_script) as g:
                    chains, n_samples, total_period = read_chains(f, frames, g, timings)
            else:
                chains, n_samples, total_period = read_chains(f, frames, None, timings)
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        raise HotspotError(f"cannot read the perf script dump: {e}") from e
    timings["parse_s"] = round(time.monotonic() - t0, 2)
    if n_samples == 0:
        raise HotspotError(f"no samples in {perf_script}")
    if expected_samples is not None and n_samples != expected_samples:
        raise HotspotError(
            f"perf script printed {n_samples} samples but perf report counts "
            f"{expected_samples}: the dump is truncated or incomplete")

    # Resolve each unique build-DSO function once (plus the harness entry points).
    t1 = time.monotonic()
    harness_addrs = elves[main_dso].symbol_addresses(_HARNESS_SYMBOLS)
    want: dict[str, set] = {}
    for kind, dso, name, start in frames.info:
        if kind == "T" and start is not None and not name.startswith(_SANITIZER_PREFIXES):
            want.setdefault(dso, set()).add(start)
    want.setdefault(main_dso, set()).update(harness_addrs.values())
    src: dict[tuple, tuple] = {}
    for dso, addrs in want.items():
        if elves.get(dso) is None:
            continue
        for a, v in resolve_sources(str(host_path(dso)), addrs).items():
            src[(dso, a)] = v
    timings["symbolize_s"] = round(time.monotonic() - t1, 2)
    timings["functions_resolved"] = sum(len(v) for v in want.values())
    timings["build_dsos"] = sorted(d for d in elves if elves[d] is not None)
    if missing_dsos:
        timings["build_dsos_missing_on_host"] = sorted(missing_dsos)

    harness_files = set()
    for a in harness_addrs.values():
        f = src.get((main_dso, a), (None, None, None))[1]
        if f:
            harness_files.add(f)
    for h in harness_paths or ():
        if h:
            harness_files.add(os.path.normpath(str(h)))
    if not source_root:
        source_root = next((infer_source_root(h) for h in sorted(harness_files)
                            if infer_source_root(h)), None)
    smap = SourceMap(source_root, source_tree)
    clf = Classifier(smap, harness_files)

    fid_class: list[str] = []
    fid_alloc: list[bool] = []
    fid_src: list[tuple] = []
    fid_rel: list[str | None] = []
    unmapped_named: set[str] = set()
    for kind, dso, name, start in frames.info:
        rel = None
        if kind == "K":
            cls, s = CLS_KERNEL, (name, None, None)
        elif kind == "T":
            s = src.get((dso, start), (name, None, None)) if start is not None \
                else (name, None, None)
            cls, rel = clf.classify_target_frame(name, s[1])
            if (cls == CLS_THIRDPARTY and s[1] and smap.names
                    and os.path.basename(s[1]) in smap.names):
                unmapped_named.add(s[1])
        else:
            cls, s = Classifier.classify_dso_frame(dso), (name, None, None)
        fid_class.append(cls)
        fid_alloc.append(cls not in (CLS_TARGET, CLS_KERNEL) and _is_alloc_name(name))
        fid_src.append(s)
        fid_rel.append(rel)

    if CLS_TARGET not in fid_class and len(unmapped_named) >= MISMATCH_MIN_FILES:
        ex = sorted(unmapped_named)[:3]
        raise HotspotError(
            f"source-root mismatch: no function of the build maps to the editable "
            f"tree ({smap.tree or '?'}; in-image root {smap.source_root}), yet "
            f"{len(unmapped_named)} of its source files have names that exist in "
            f"that tree, e.g. {ex}. The build compiled the project from somewhere "
            "the profiler does not know; pass the right --source-root.")

    # Samples with ANY frame in the build's own binary or libraries: zero means
    # perf never saw the target run at all (vs. merely little project code).
    build_dso_samples = sum(cnt for chain, (cnt, _p) in chains.items()
                            if any(frames.info[f][0] == "T" for f in chain))

    t2 = time.monotonic()
    per, outside = attribute(chains, fid_class, fid_alloc)
    timings["attribute_s"] = round(time.monotonic() - t2, 2)
    timings["unique_chains"] = len(chains)

    attributed_samples = sum(r["samples"] for r in per.values())
    attributed_period = sum(r["period"] for r in per.values())

    def pct(p, denom=total_period):
        return round(100.0 * p / denom, 4) if denom else 0.0

    rows = []
    for fid, r in per.items():
        if r["samples"] == 0 and r["incl_samples"] == 0:
            continue
        kind, dso, name, start = frames.info[fid]
        func, path, line = fid_src[fid]
        rel = fid_rel[fid]
        editable, note = smap.editable(rel) if rel is not None else (None, None)
        row = {
            "function": name,
            "debug_name": func if func and func != "??" else None,
            "file": path,
            "rel_path": rel,
            "line": line,
            "editable": editable,
            "edit_note": note,
            "dso": dso,
            "addr": f"0x{start:x}" if start is not None else None,
            "samples": r["samples"],
            "period": r["period"],
            "caused_pct": pct(r["period"]),
            "caused_pct_of_target": pct(r["period"], attributed_period),
            "self_pct": pct(r["own_period"]),
            "inclusive_pct": pct(r["incl_period"]),
            "inclusive_samples": r["incl_samples"],
            "self_samples": r["own_samples"],
        }
        for b in BUCKETS[1:]:
            row[f"{b}_pct"] = pct(r[f"{b}_period"])
            row[f"{b}_samples"] = r[f"{b}_samples"]
        rows.append(row)
    rows.sort(key=lambda x: (-x["period"], -x["inclusive_samples"], x["function"]))
    for i, x in enumerate(rows, 1):
        x["rank"] = i

    attributed_by = {}
    for b in BUCKETS:
        p = sum(r[b + "_period"] for r in per.values())
        s = sum(r[b + "_samples"] for r in per.values())
        attributed_by[b] = {"pct": pct(p), "samples": s, "period": p}
    outside_by = {b: {"pct": pct(outside[b + "_period"]),
                      "samples": outside[b + "_samples"],
                      "period": outside[b + "_period"]} for b in OUTSIDE_BUCKETS}

    result = {
        "schema_version": SCHEMA_VERSION,
        "fuzz_target": fuzz_target,
        # In-container paths only, never host ones: this file is read by the
        # sandboxed agent, and host paths carry the experiment dir (<project>-<cve>).
        "binary": main_dso,
        "build_dsos": timings["build_dsos"],
        "source_root": smap.source_root,
        "editable_tree_known": smap.tree is not None,
        "harness_files": sorted(harness_files),
        "weight": "period (perf report convention); raw sample counts alongside",
        "totals": {
            "samples": n_samples,
            "period": total_period,
            "build_dso_samples": build_dso_samples,
            "target_attributed": {"samples": attributed_samples,
                                  "period": attributed_period,
                                  "pct": pct(attributed_period),
                                  "by_class": attributed_by},
            "outside_target": {"samples": outside["samples"],
                               "period": outside["period"],
                               "pct": pct(outside["period"]),
                               "by_class": outside_by},
        },
        "target_source_functions": len(rows),
        "timings": timings,
        "functions": rows,
    }
    if attributed_samples + outside["samples"] != n_samples or \
            attributed_period + outside["period"] != total_period:
        raise HotspotError(
            f"attribution does not add up: {attributed_samples} + "
            f"{outside['samples']} != {n_samples} samples")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timings["total_s"] = round(time.monotonic() - t0, 2)
    (out_dir / HOTSPOTS_JSON).write_text(json.dumps(result, indent=1))
    (out_dir / HOTSPOTS_TXT).write_text(render_text(result))
    return result


def render_text(result: dict, max_rows: int = TXT_MIN_ROWS) -> str:
    t = result["totals"]
    ta, ot = t["target_attributed"], t["outside_target"]
    ab, ob = ta["by_class"], ot["by_class"]
    L = []
    L.append("# hotspots.txt -- target-source functions ranked by CAUSED cost "
             "(the primary ranking input)")
    L.append(f"# fuzz target: {result['fuzz_target']}   source root: "
             f"{result['source_root'] or '(unknown)'}   build DSOs: "
             + ", ".join(result.get("build_dsos") or [result["binary"]]))
    if result["harness_files"]:
        L.append("# excluded as harness: " + ", ".join(result["harness_files"])
                 + "  (plus files under fuzz-named dirs such as fuzz/, fuzzer/)")
    L.append(f"# total samples: {t['samples']}   (percentages are of total "
             "sample period, as in perf report; no percent cut-off)")
    L.append(f"# target-attributed: {ta['pct']:6.2f}%  ({ta['samples']} samples)  "
             f"own {ab['own']['pct']:.2f} | sanitizer/coverage "
             f"{ab['sanitizer']['pct']:.2f} | third-party {ab['thirdparty']['pct']:.2f}"
             f" | allocator {ab['allocator']['pct']:.2f} | libc {ab['libc']['pct']:.2f}"
             f" | kernel {ab['kernel']['pct']:.2f} | other {ab['other']['pct']:.2f}")
    L.append(f"# outside target:    {ot['pct']:6.2f}%  ({ot['samples']} samples)  "
             f"sanitizer/coverage {ob['sanitizer']['pct']:.2f} | third-party "
             f"{ob['thirdparty']['pct']:.2f} | allocator {ob['allocator']['pct']:.2f} | "
             f"libc {ob['libc']['pct']:.2f} | kernel {ob['kernel']['pct']:.2f} | other "
             f"(afl-showmap, driver, harness, shell) {ob['other']['pct']:.2f}")
    L.append("#")
    L.append("# caused  = samples credited to this function: walk each call chain from "
             "the sample's IP toward the root and stop at")
    L.append("#           the FIRST target-source frame. It includes the sanitizer, "
             "third-party, allocator, libc and kernel work")
    L.append("#           this function triggers directly, but NOT work done by other "
             "target functions it calls (those have rows).")
    L.append("# caused% = of all samples; of-tgt% = of target-attributed samples. "
             "self + san/cov + 3rdp + alloc + libc + kern + other = caused.")
    L.append("# self    = this function's own code. san/cov = sanitizer or AFL "
             "coverage runtime (__asan*, __sanitizer*, interceptors, fake stack).")
    L.append("# 3rdp    = std-library templates (std::map, std::vector ...) and "
             "third-party code compiled into the binary, called directly.")
    L.append("# alloc   = under malloc/free/realloc/new/delete or ASan allocator "
             "internals. incl% = this function anywhere on the chain (once).")
    L.append("# ed      = y: the row's file is in your editable tree and of an editable "
             "type; n: it is generated at build time (an")
    L.append("#           amalgamation), a generator input (.l/.y) or a non-editable type "
             "(.inc) -- see hotspots.json edit_note; ?: unknown.")
    L.append("# Inlined functions are reported under the non-inlined function that "
             "contains them. file:line is tree-relative when it maps.")
    L.append("#")
    hdr = (f"{'rank':>4} {'caused%':>8} {'of-tgt%':>8} {'self%':>7} {'san/cov%':>8} "
           f"{'3rdp%':>6} {'alloc%':>7} {'libc%':>6} {'kern%':>6} {'other%':>6} "
           f"{'incl%':>7} {'samples':>8} ed  function  [file:line]")
    L.append(hdr)
    rows = result["functions"]
    for x in rows[:max_rows]:
        f = x.get("rel_path") or x["file"] or "?"
        loc = f"{f}:{x['line']}" if x["line"] else f
        if x.get("dso") and x["dso"] != result["binary"]:
            loc += f" in {os.path.basename(x['dso'])}"
        ed = {True: "y", False: "n"}.get(x.get("editable"), "?")
        L.append(
            f"{x['rank']:>4} {x['caused_pct']:8.2f} {x['caused_pct_of_target']:8.2f} "
            f"{x['self_pct']:7.2f} {x['sanitizer_pct']:8.2f} {x['thirdparty_pct']:6.2f} "
            f"{x['allocator_pct']:7.2f} {x['libc_pct']:6.2f} {x['kernel_pct']:6.2f} "
            f"{x['other_pct']:6.2f} {x['inclusive_pct']:7.2f} {x['samples']:8d} "
            f"{ed:<3} {x['function']}  [{loc}]")
    if len(rows) > max_rows:
        L.append(f"# ... {len(rows) - max_rows} more target-source functions in "
                 f"{HOTSPOTS_JSON}")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--perf-script", required=True)
    ap.add_argument("--ip-script", default=None)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--fuzz-target", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--source-root", default=None)
    ap.add_argument("--source-tree", default=None)
    ap.add_argument("--host-out-dir", default=None)
    ap.add_argument("--harness", action="append", default=[])
    ap.add_argument("--expected-samples", type=int, default=None)
    a = ap.parse_args()
    res = build_hotspot_table(perf_script=a.perf_script, binary=a.binary,
                              fuzz_target=a.fuzz_target, out_dir=a.out_dir,
                              source_root=a.source_root, harness_paths=a.harness,
                              ip_script=a.ip_script, source_tree=a.source_tree,
                              host_out_dir=a.host_out_dir,
                              expected_samples=a.expected_samples)
    print(json.dumps({"totals": res["totals"], "timings": res["timings"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
