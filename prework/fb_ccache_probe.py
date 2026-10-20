"""Synthetic fold edits for the ccache equivalence test (tools/fb_ccache_equivalence.py).

Section 5 of the fuzzbench-parity-ccache skill builds three trees: pristine, one with
a new ``fold_`` helper added to a compiled .c/.cc file and called from an existing
function, and one with a ``static inline`` ``fold_`` helper added to a header that
several compiled files include. This module picks those files from a build's
FB_AUDIT_CC_LOG and makes the edits. Text processing plus `nm` on built binaries; no
docker.

Rules the edits follow (round-2 fixes):
  * the helpers are `__attribute__((noinline, used))`, so their symbol shows up in a
    binary exactly when their object is linked: a fold variant only counts when the
    helper symbol is in the MAIN fuzz binary (php's opcache.so, openssl apps/,
    unlinked systemd files and the harness itself do not count);
  * every inserted line is <= MAX_COLS columns (curl's checksrc rejects longer ones);
  * a call goes right after the body's '{' even when the body is on the same line
    (C++ one-liners like `Reader::Reader() : f_(x) {}`);
  * file-scope function definitions may be indented (FreeType's FT_*_DEF style).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

C_HELPER = "fold_fbcc_probe_c"
H_HELPER = "fold_fbcc_probe_h"
MAX_COLS = 79
HARNESS_MARK = "LLVMFuzzerTestOneInput"
# Harness code is never a fold-in-.c candidate (the fold must land in library code):
# any file DEFINING a *FuzzerTestOneInput function (openssl's fuzz/x509.c defines
# FuzzerTestOneInput, called by fuzz/driver.c), any file mentioning
# LLVMFuzzerTestOneInput, and any file under a fuzz/, fuzzing/, fuzzer(s)/ dir
# (tests/fuzz/ included) of the project tree.
_HARNESS_DEF = re.compile(r"\b\w*FuzzerTestOneInput\s*\([^;{}]*\)\s*\{")
_HARNESS_DIR = re.compile(r"(^|/)(fuzz|fuzzing|fuzzer|fuzzers)/", re.IGNORECASE)
SOURCE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++")
HEADER_EXTS = (".h", ".hh", ".hpp", ".hxx")
# Paths that are usually compiled but not linked into the fuzz target. Tried last.
_UNLIKELY = re.compile(r"(^|/)(tests?|examples?|demos?|bench\w*|samples?|tools?|"
                       r"contrib|doc|docs|minigzip|example)(/|\.|$)", re.IGNORECASE)
_KEYWORDS = {"if", "for", "while", "switch", "else", "do", "typedef", "return", "case",
             "namespace", "extern", "class", "sizeof", "static_assert", "using",
             "template", "struct", "union", "enum"}
# Allowed as the first word only when followed by a return type (`struct x *f(`).
_TYPE_INTRO = {"struct", "union", "enum"}


# --------------------------------------------------------------- audit log

def load_audit(path: str | os.PathLike) -> list[dict]:
    recs = []
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    recs.append(json.loads(line))
                except ValueError:
                    continue
    return recs


def compiled_sources(recs: list[dict], *, src_root: str, build: str = "main") -> list[str]:
    """Container paths of project sources compiled with -c in ``build``, in compile
    order, deduplicated, restricted to files under ``src_root`` (/src/<name>)."""
    root = src_root.rstrip("/") + "/"
    seen: dict[str, None] = {}
    for r in recs:
        if r.get("build") != build:
            continue
        argv = list(r.get("argv") or [])[1:]
        if "-c" not in argv:
            continue
        cwd = r.get("cwd") or "/"
        skip_next = False
        for a in argv:
            if skip_next:
                skip_next = False
                continue
            if a in ("-o", "-MF", "-MT", "-MQ", "-include", "-I", "-isystem", "-x"):
                skip_next = True
                continue
            if a.startswith("-") or not a.lower().endswith(SOURCE_EXTS):
                continue
            p = os.path.normpath(a if a.startswith("/") else os.path.join(cwd, a))
            if p.startswith(root):
                seen.setdefault(p, None)
    return list(seen)


def rank_sources(paths: list[str]) -> list[str]:
    """Likely-linked files first (stable within each group)."""
    return ([p for p in paths if not _UNLIKELY.search(p)]
            + [p for p in paths if _UNLIKELY.search(p)])


# --------------------------------------------------------------- C scanning

def _strip_code(text: str) -> str:
    """Replace comments and string/char literals with spaces (newlines kept), so
    brace counting and pattern matching see only code. Preprocessor lines are kept
    (they are recognised by a leading '#')."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] not in (c, "\n"):
                j += 2 if text[j] == "\\" else 1
            j = min(j, n)
            closed = j < n and text[j] == c
            out.append(c + re.sub(r"[^\n]", " ", text[i + 1:j]) + (c if closed else ""))
            i = j + 1 if closed else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _is_transparent_block(prefix: str) -> bool:
    p = prefix.strip()
    # String contents are blanked by _strip_code, so `extern "C"` reads `extern " "`.
    return bool(re.search(r'(\bextern\s+"[^"\n]*"|\bnamespace(\s+[A-Za-z_][\w:]*)?)\s*$', p))


def function_defs(text: str) -> list[tuple[int, int, str]]:
    """(0-based line, column, name) of each '{' that opens a file-scope function body.

    Heuristic, conservative: every enclosing block must be extern "C" / namespace,
    and the code since the previous ; { } must look like a signature (contain '(',
    end in ')' optionally followed by const/noexcept/override, no '=' before the
    first '(', no constexpr/consteval). Indentation is allowed (FreeType indents
    file-scope code). Misses are fine (the caller tries another file); false
    positives are caught by the build.
    """
    code = _strip_code(text)
    lines = code.split("\n")
    stack: list[bool] = []          # True = transparent (extern "C" / namespace)
    pending = ""                    # code since the last ; { } at this level
    result = []
    in_directive = False
    for ln, line in enumerate(lines):
        if in_directive or line.lstrip().startswith("#"):
            in_directive = line.rstrip().endswith("\\")
            continue
        for col, ch in enumerate(line):
            if ch == "{":
                if all(stack):
                    name = _function_name(pending)
                    if name is None and line[:col].strip() == "":
                        name = _knr_name(lines, ln)
                    if name:
                        result.append((ln, col, name))
                stack.append(_is_transparent_block(pending))
                pending = ""
            elif ch == "}":
                if stack:
                    stack.pop()
                pending = ""
            elif ch == ";":
                pending = ""
            else:
                pending += ch
        pending += "\n"
    return result


def function_body_lines(text: str) -> list[int]:
    """0-based lines of the '{' of file-scope function bodies (see function_defs)."""
    return [ln for ln, _col, _name in function_defs(text)]


_SIG_TAIL = re.compile(r"\)\s*(const\s*)?(noexcept\s*)?(override\s*)?(final\s*)?$")


def _function_name(pending: str) -> str | None:
    sig = re.sub(r"\s+", " ", pending).strip()
    if not sig or "(" not in sig or "=" in sig.split("(", 1)[0]:
        return None
    if re.search(r"\b(constexpr|consteval)\b", sig):
        return None
    m = _SIG_TAIL.search(sig)
    if not m or not _sig_head_ok(sig):
        return None
    # The parameter list is the LAST top-level (...) group (FreeType puts the return
    # type in a macro: `FT_EXPORT_DEF( FT_Error ) FT_Init_FreeType( ... )`).
    close = m.start()
    depth, i = 0, close
    while i >= 0:
        if sig[i] == ")":
            depth += 1
        elif sig[i] == "(":
            depth -= 1
            if depth == 0:
                break
        i -= 1
    if i <= 0:
        return None
    nm = re.search(r"([A-Za-z_]\w*)\s*$", sig[:i])
    if not nm or nm.group(1) in _KEYWORDS:
        return None
    return nm.group(1)


def _sig_head_ok(sig_one: str) -> bool:
    head = sig_one.split("(", 1)[0].split()
    if len(head) < 1 or head[-1] in _KEYWORDS:
        return False
    if head[0] in _KEYWORDS and not (head[0] in _TYPE_INTRO and len(head) >= 3):
        return False
    return True


def _knr_name(lines: list[str], brace_line: int) -> str | None:
    """K&R definition: `int f(a, b)` / `int a;` lines / `{` alone (old zlib)."""
    k = brace_line - 1
    decls = 0
    while k >= 0 and brace_line - k <= 24 and (
            not lines[k].strip()
            or (lines[k].rstrip().endswith(";") and not lines[k].lstrip().startswith("#"))):
        decls += bool(lines[k].strip())
        k -= 1
    if k < 0 or decls == 0 or not lines[k].rstrip().endswith(")"):
        return None
    j = k
    while j >= 0 and k - j < 6 and not re.match(r"[A-Za-z_]", lines[j]):
        j -= 1
    if j < 0 or not re.match(r"[A-Za-z_]", lines[j]):
        return None
    sig_one = re.sub(r"\s+", " ", " ".join(lines[j:k + 1])).strip()
    if "(" not in sig_one or "=" in sig_one.split("(", 1)[0] or sig_one.endswith(";"):
        return None
    if not _sig_head_ok(sig_one):
        return None
    return _function_name(sig_one)


def defined_function_names(text: str) -> list[str]:
    return sorted({name for _l, _c, name in function_defs(text)})


def insert_call(text: str, call_expr: str, *, var: str,
                max_sites: int = 8) -> tuple[str, list[int]] | None:
    """Insert `__attribute__((unused)) volatile int <var> = <call_expr>;` as the
    first statement of up to ``max_sites`` file-scope function bodies (some may sit
    in #if'd-out code, so one site alone often has no effect on the binary). The
    statement goes on its own line right after the '{', splitting a one-line body.
    Returns (new_text, 1-based lines of the inserted statements)."""
    defs = function_defs(text)[:max_sites]
    if not defs:
        return None
    lines = text.split("\n")
    stmt = f"__attribute__((unused)) volatile int {var} = {call_expr};"
    inserted: list[int] = []
    for ln, col, _name in reversed(defs):
        line = lines[ln]
        ind = re.match(r"[ \t]*", line).group(0).replace("\t", "    ")
        decl = (ind + "  ")[:max(2, MAX_COLS - len(stmt))] + stmt
        if len(decl) > MAX_COLS:
            return None
        head, tail = line[:col + 1].rstrip(), line[col + 1:]
        new = [head, decl] + ([ind + tail.strip()] if tail.strip() else [])
        lines[ln:ln + 1] = new
        inserted = [x + len(new) - 1 for x in inserted]
        inserted.insert(0, ln + 2)
    return "\n".join(lines), inserted


def _helper_lines(name: str, body: str, *, inline: bool) -> list[str]:
    spec = "static __inline__" if inline else "static"
    return [f"{spec} __attribute__((noinline, used)) int",
            f"{name}(int x)",
            "{",
            f"  return {body};",
            "}"]


def is_harness(path: str, text: str | None) -> bool:
    """Fuzz-harness code (see _HARNESS_DEF / _HARNESS_DIR). ``path`` is a container
    path /src/<project>/... or a path relative to the project root."""
    rel = re.sub(r"^/src/[^/]+/", "", path)
    if _HARNESS_DIR.search(rel):
        return True
    return bool(text) and (HARNESS_MARK in text or bool(_HARNESS_DEF.search(text)))


def add_c_fold(text: str) -> tuple[str, dict] | None:
    """New fold_ helper at the top of a .c/.cc file, called from its file-scope
    functions. The helper only uses `int`, so it needs no include."""
    if C_HELPER in text or is_harness("", text):
        return None
    called = insert_call(text, f"{C_HELPER}(7)", var="fbcc_c_v")
    if called is None:
        return None
    body, sites = called
    helper = _helper_lines(C_HELPER, "x * 3 + 1", inline=False)
    return ("\n".join(helper) + "\n" + body,
            {"helper": C_HELPER, "call_lines": [x + len(helper) for x in sites]})


def add_h_call(text: str) -> tuple[str, dict] | None:
    """Call the header helper from the functions of a file that includes it."""
    called = insert_call(text, f"{H_HELPER}(11)", var="fbcc_h_v")
    if called is None:
        return None
    return called[0], {"helper": H_HELPER, "call_lines": called[1]}


# --------------------------------------------------------------- headers

def guard_insert_line(text: str) -> int | None:
    """0-based line AFTER which a file-scope helper can go inside the include guard:
    after `#pragma once`, after `#define G` when it is the first code line after
    `#ifndef G`, else right after `#ifndef G` when `#define G` comes later in the
    file (lcms2_internal.h defines its guard macro at the very end)."""
    code = _strip_code(text).split("\n")
    nonblank = [i for i, l in enumerate(code) if l.strip()]
    if not nonblank:
        return None
    first = nonblank[0]
    if re.match(r"\s*#\s*pragma\s+once\b", code[first]):
        return first
    m = (re.match(r"\s*#\s*ifndef\s+(\w+)", code[first])
         or re.match(r"\s*#\s*if\s+!\s*defined\s*\(?\s*(\w+)", code[first]))
    if not m:
        return None
    define = re.compile(rf"\s*#\s*define\s+{re.escape(m.group(1))}\b")
    later = [i for i in nonblank if i > first]
    if later and define.match(code[later[0]]):
        return later[0]
    if any(define.match(code[i]) for i in later):
        return first
    return None


def add_header_fold(text: str) -> str | None:
    """`static __inline__` fold_ helper inside the header's include guard.
    __inline__ (not `inline`) so a -std=c89 build accepts it too."""
    if H_HELPER in text:
        return None
    at = guard_insert_line(text)
    if at is None:
        return None
    lines = text.split("\n")
    lines[at + 1:at + 1] = _helper_lines(H_HELPER, "x * 5 + 3", inline=True)
    return "\n".join(lines)


# --------------------------------------------------------------- linkage

_SYM_SUFFIX = re.compile(r"\.(llvm|cold|part|constprop|isra|lto_priv)\.?\d*.*$")


def binary_symbols(path: str | os.PathLike) -> set[str]:
    """Function-name tokens defined in a binary: plain C names, and every
    <len><identifier> component of mangled C++ names (both forms are added)."""
    r = subprocess.run(["nm", "--defined-only", str(path)], capture_output=True,
                       text=True, errors="replace")
    out: set[str] = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym = _SYM_SUFFIX.sub("", parts[2])
        out.add(sym)
        if sym.startswith("_Z"):
            for m in re.finditer(r"(\d+)", sym):
                n = int(m.group(1))
                tok = sym[m.end():m.end() + n]
                if len(tok) == n and re.fullmatch(r"[A-Za-z_]\w*", tok):
                    out.add(tok)
    return out


def helper_in_binary(path: str | os.PathLike, helper: str) -> bool:
    r = subprocess.run(["nm", str(path)], capture_output=True, text=True,
                       errors="replace")
    return helper in r.stdout


def link_line_sources(recs: list[dict], *, target: str, src_root: str,
                      build: str = "main") -> set[str]:
    """Container paths of sources whose object is on the command that links
    ``target`` (objects linked through an archive are not seen here)."""
    obj_src: dict[str, str] = {}
    linked: set[str] = set()
    for r in recs:
        if r.get("build") != build:
            continue
        argv = list(r.get("argv") or [])[1:]
        cwd = r.get("cwd") or "/"
        absp = lambda x: os.path.normpath(x if x.startswith("/") else os.path.join(cwd, x))  # noqa: E731
        out = None
        for i, x in enumerate(argv):
            if x == "-o" and i + 1 < len(argv):
                out = argv[i + 1]
        if "-c" in argv:
            srcs = [x for x in argv if not x.startswith("-")
                    and x.lower().endswith(SOURCE_EXTS)]
            if out and len(srcs) == 1:
                obj_src[absp(out)] = absp(srcs[0])
        elif out and os.path.basename(out) == target:
            linked |= {absp(x) for x in argv if x.endswith((".o", ".lo"))}
            linked |= {absp(x) for x in argv if not x.startswith("-")
                       and x.lower().endswith(SOURCE_EXTS)}
    root = src_root.rstrip("/") + "/"
    res = {obj_src.get(o, o) for o in linked}
    return {x for x in res if x.startswith(root) and x.lower().endswith(SOURCE_EXTS)}


def rank_candidates(paths: list[str], *, texts: dict[str, str], symbols: set[str],
                    linked: set[str] = frozenset()) -> list[tuple[str, int]]:
    """Fold-in-.c candidates, most likely to reach the fuzz target first: harness
    files (is_harness: *FuzzerTestOneInput definitions, fuzz/ dirs) dropped; then
    files on the target's link line, then by how many of the file's function names are defined in the
    main binary (archive members show up here), then the _UNLIKELY demotion."""
    out = []
    for p in paths:
        t = texts.get(p)
        if t is None or is_harness(p, t):
            continue
        names = defined_function_names(t)
        score = sum(1 for n in names if n in symbols)
        out.append((p, score))
    order = {p: i for i, p in enumerate(paths)}
    out.sort(key=lambda ps: (-(ps[0] in linked), -ps[1], bool(_UNLIKELY.search(ps[0])),
                             order[ps[0]]))
    return out


def header_candidates(tree: Path, compiled_host: list[Path]) -> list[tuple[Path, list[Path]]]:
    """Project headers ranked by how many compiled sources #include them directly.

    Returns [(header, [including sources])] with at least two includers, most
    included first. Matching is by basename against `#include "..."` lines, so
    headers sharing a basename are not distinguished (the build still decides).
    """
    by_name: dict[str, list[Path]] = {}
    for h in tree.rglob("*"):
        if h.suffix.lower() in HEADER_EXTS and h.is_file() and ".git" not in h.parts \
                and not _HARNESS_DIR.search(str(h.relative_to(tree))):
            by_name.setdefault(h.name, []).append(h)
    inc_re = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
    counts: dict[Path, list[Path]] = {}
    for src in compiled_host:
        try:
            text = src.read_text(errors="replace")
        except OSError:
            continue
        for inc in set(inc_re.findall(text)):
            base = os.path.basename(inc)
            hs = by_name.get(base, [])
            if len(hs) == 1:
                counts.setdefault(hs[0], []).append(src)
    ranked = sorted(((h, s) for h, s in counts.items() if len(s) >= 2),
                    key=lambda hs: (-len(hs[1]), str(hs[0])))
    return ranked
