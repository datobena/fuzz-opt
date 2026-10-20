#!/bin/bash
# FuzzBench-parity build of one benchmark with the `aflplusplus` fuzzer.
#
# Runs inside an fb-aflpp/<fuzzbench_dir> image (prework/fuzzbench_image.py), mounted
# at /fold/fb_build.sh. It is FuzzBench's docker/benchmark-builder/fuzzer_build, i.e.
#   cd <benchmark WORKDIR>; PYTHONPATH=$SRC python3 -c "from fuzzers import utils;
#   utils.initialize_env(); from fuzzers.aflplusplus import fuzzer; fuzzer.build()"
# moved from `docker build` time to `docker run` time so every rebuild can supply a
# modified source tree. Deviations, all required by the experiment's mechanics:
#   * /out is a reused bind mount: it is emptied first (FuzzBench's
#     os.mkdir(/out/cmplog) raises otherwise), then re-seeded with the image's own
#     /out snapshot (/fb_image_out) so files a benchmark Dockerfile wrote into $OUT at
#     image-build time are present exactly as in FuzzBench's builder image.
#   * optional copy-in of the modified tree from /fold/src (read-only) over
#     $SRC/$FB_SRC_NAME. Nothing is ever bind-mounted under /src: FuzzBench's
#     restore_directory($SRC) rmtree's /src and would wipe a host mount.
#   * optimizer-inserted fold_* helpers are excluded from instrumentation (below).
#   * the build-step wall time is logged, and /afl/afl-showmap is copied into /out
#     (replay gate / profiler / coverage tooling need it; afl-fuzz ignores it).
#   * ccache for BOTH builds (main and cmplog, step 3b), only when the caller mounts
#     a cache at /ccache AND the target is on prework/fuzzbench_ccache_verified.txt
#     (mounted at /fold/ccache_verified.txt). Only optimized-arm rebuilds mount one;
#     the baseline arm and the reference baseline never do. Without the mount nothing
#     below changes the build. ccache (/opt/fb_ccache/ccache) is never on PATH, and
#     it runs BELOW afl-cc (AFL_CC/AFL_CXX), so CC, CXX, CFLAGS, CXXFLAGS and PATH
#     are those of the uncached build; a per-object dictionary sidecar keeps
#     afl++.dict complete. Main and cmplog objects never share a cache entry (the
#     build kind and AFL_LLVM_CMPLOG are in the key).
#   * FB_AUDIT_CC_LOG=<file under /out> (debug only, never in production): log every
#     compiler invocation of both builds as one JSON line, then run the real compiler.
set -euo pipefail
: "${SRC:?}" "${OUT:?}" "${FUZZER:?}" "${FB_WORKDIR:?image lacks FB_WORKDIR}"

# 1. Fresh /out, then the image's build-time /out contents.
find "$OUT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
if [ -d /fb_image_out ]; then cp -a /fb_image_out/. "$OUT"/; fi

# fold_<name> identifiers in a tree (see step 3).
fold_idents() {
  grep -rhoIE \
    --include='*.c' --include='*.cc' --include='*.cpp' --include='*.cxx' \
    --include='*.c++' --include='*.h' --include='*.hh' --include='*.hpp' \
    --include='*.hxx' --include='*.inc' --include='*.inl' --include='*.ipp' \
    --include='*.def' --include='*.y' --include='*.l' --include='*.rl' \
    --exclude-dir=.git '\bfold_[A-Za-z0-9_]+' "$1" 2>/dev/null | sort -u || true
}

# 2. Copy in the modified source tree.
fold_names=""
if [ -d /fold/src ]; then
  name="${FB_SRC_NAME:?FB_SRC_NAME is required when /fold/src is mounted}"
  case "$name" in */*|.|..) echo "fb_build: bad FB_SRC_NAME '$name'" >&2; exit 2;; esac
  dest="$SRC/$name"
  if [ ! -d "$dest" ]; then
    # Refuse rather than build the pristine copy while the edits sit elsewhere.
    echo "fb_build: $dest does not exist in the image; refusing to guess" >&2
    exit 2
  fi
  # Only names the modified tree ADDS are excluded: the pristine benchmark (and
  # the rest of $SRC, e.g. /src/aflplusplus's GCC plugin) already has real
  # fold_* functions -- libpcap fold_op/fold_edge, php fold_case -- whose
  # instrumentation must stay exactly FuzzBench's.
  fold_names="$(comm -13 <(fold_idents "$dest") <(fold_idents /fold/src))"
  cd /
  rm -rf "$dest"
  cp -a --no-preserve=ownership /fold/src "$dest"
fi
cd "$FB_WORKDIR"

# 3. fold_* exclusion lists, only for fold_ identifiers the copied-in tree adds over
#    the image's pristine source (a baseline build, or one with no new folds, is
#    then byte-for-byte FuzzBench's).
#    Both lists are generated from those exact names, never static `fold_*` globs.
#    * AFL_LLVM_DENYLIST (PCGUARD coverage in type:coverage; the cmplog and
#      dict2file passes in both types). AFL++ 56d5aa31 matches fnmatch("*" + entry)
#      -- a SUFFIX/substring match -- and silently skips any entry longer than the
#      function name. So: C entry `fold_x`, and C++ entry `<len>fold_x*`, the
#      length-prefixed mangled name component (`_ZL9fold_hashi` -> `9fold_hash*`).
#      Never `[0-9]fold_x*`: its 5-char bracket counts toward the length check, so
#      short mangled names (_Z7fold_abi) were never matched and stayed instrumented.
#    * clang -fsanitize-coverage-ignorelist (type:bug, LLVMNATIVE: clang's own
#      trace-pc-guard ignores AFL_LLVM_DENYLIST). clang 15 anchors each pattern as
#      ^(...)$ with * -> .*: C entry `fold_x`, C++ entry `_Z*<len>fold_x*`, which
#      covers free (_Z), internal-linkage (_ZL), nested (_ZN) and local/lambda (_ZZ)
#      forms. Appended to CFLAGS/CXXFLAGS after utils.initialize_env().
write_fold_lists() {  # <denylist> <ignorelist>; names from $fold_names
  { echo "# generated by fb_build.sh (AFL_LLVM_DENYLIST)"
    for n in $fold_names; do echo "fun:$n"; echo "fun:${#n}$n*"; done
  } > "$1"
  { echo "# generated by fb_build.sh (-fsanitize-coverage-ignorelist)"
    for n in $fold_names; do echo "fun:$n"; echo "fun:_Z*${#n}$n*"; done
  } > "$2"
}
export FB_FOLD_DENYLIST="" FB_FOLD_IGNORELIST=""
if [ -n "$fold_names" ]; then
  FB_FOLD_DENYLIST=/tmp/fb_fold_denylist.txt
  FB_FOLD_IGNORELIST=/tmp/fb_fold_ignorelist.txt
  write_fold_lists "$FB_FOLD_DENYLIST" "$FB_FOLD_IGNORELIST"
  echo "fb_build: excluding $(echo "$fold_names" | wc -l) fold_* identifier(s) from instrumentation"
fi

# 3b. ccache decision for both builds (fuzz-opt deviation; see the
#     fuzzbench-parity-ccache skill). Why each guard exists:
#     * no /ccache mount -> off: the baseline arm, the reference baseline and every
#       other caller build exactly as before.
#     * not on the verified list -> off: a target gets ccache only after the
#       equivalence test (tools/fb_ccache_equivalence.py) showed cached == uncached.
#       A list line is `<fuzzbench_dir> [pass|pass_noise_masked]`; the marker only
#       matters on the host (campaign template check), a line with any other marker
#       does not count. FB_CCACHE_FORCE=1 skips this one check and is set ONLY by
#       that tool.
#     * ccache not at /opt/fb_ccache/ccache -> off (an old image).
#     * fold-name hazard -> off: ccache does not hash the fold exclusion lists (their
#       content changes every round; hashing them would make every file miss). That
#       is safe only while each list entry can match nothing but the identifier it
#       names. AFL++ matches `fun:N` as a SUFFIX (`unfold_hash` matches fold_hash)
#       and `fun:<len>N*` / clang's `_Z*<len>N*` as a substring of the mangled name,
#       so an UNCHANGED file defining such a longer identifier would compile
#       differently under this tree's lists than its cached object did. If such an
#       identifier exists anywhere the compiler can read, this build runs uncached --
#       unless every file holding it also holds the fold name it matches. Such a
#       file always compiles under a list that has that name (the list comes from
#       the tree, and the name is in the file), so its cached objects agree. This
#       is php's `typedef struct _fold_x {...} fold_x;`: without the exemption one
#       agent typedef turned off the cache for a whole round of single-core builds.
FB_CCACHE_ON=0
FB_CCACHE_WHY=""
ccache_verified() {
  [ -f /fold/ccache_verified.txt ] &&
    awk -v t="$1" '{ sub(/#.*/, ""); sub(/\r$/, "") }
      NF >= 1 && $1 == t && (NF == 1 || (NF == 2 && ($2 == "pass" || $2 == "pass_noise_masked"))) { f = 1 }
      END { exit !f }' /fold/ccache_verified.txt
}
# Prints "<identifier> <fold name>" for every identifier that is not itself an added
# fold name but that one of this tree's list entries would also match, and that
# appears in at least one file without that fold name (see the guard above).
ccache_fold_hazards() {
  [ -n "$fold_names" ] || return 0
  local alt d t x f safe
  local dirs=("$SRC")
  alt="$(printf '%s\n' $fold_names | paste -sd'|')"
  for d in /usr/include /usr/local/include; do [ -d "$d" ] && dirs+=("$d"); done
  { grep -rhoIE --exclude-dir=.git "[A-Za-z0-9_]*($alt)[A-Za-z0-9_]*" "${dirs[@]}" \
      2>/dev/null || true; } | LC_ALL=C sort -u |
  awk -v names="$fold_names" '
    BEGIN { n = split(names, N, "\n"); for (i = 1; i <= n; i++) D[N[i]] = 1 }
    ($0 in D) { next }
    { t = $0; lt = length(t)
      for (i = 1; i <= n; i++) {
        x = N[i]; lx = length(x)
        if (lt <= lx) continue
        if (substr(t, lt - lx + 1) == x || index(lt t, lx x) > 0) print t, x
      } }' |
  while read -r t x; do
    safe=1
    while IFS= read -r f; do
      grep -qw -- "$x" "$f" || { safe=0; break; }
    done < <(grep -rlwI --exclude-dir=.git -- "$t" "${dirs[@]}" 2>/dev/null || true)
    [ "$safe" = 1 ] || echo "$t $x"
  done | awk '!seen[$1]++'
}
FB_CCACHE_BIN=/opt/fb_ccache/ccache   # never on PATH (prework/fuzzbench_image.py)
if [ ! -d /ccache ]; then
  FB_CCACHE_WHY=no-mount
elif [ ! -x "$FB_CCACHE_BIN" ]; then
  FB_CCACHE_WHY=no-ccache-in-image
  echo "fb_build: /ccache is mounted but this image has no $FB_CCACHE_BIN; builds run uncached" >&2
elif [ "${FB_CCACHE_FORCE:-}" != 1 ] && ! ccache_verified "${BENCHMARK:?}"; then
  FB_CCACHE_WHY=not-verified
  echo "fb_build: $BENCHMARK is not on the ccache verified list; builds run uncached"
else
  hazards="$(ccache_fold_hazards)"
  if [ -n "$hazards" ]; then
    FB_CCACHE_WHY=fold-name-hazard
    echo "fb_build: ccache off for this build; added fold names also match:" >&2
    echo "$hazards" | head -20 | sed 's/^/  /' >&2
  else
    FB_CCACHE_ON=1
    mkdir -p /tmp/fb_ccache/dict
    : > /tmp/fb_ccache/ccache.conf   # CCACHE_CONFIGPATH: ignore any /ccache/ccache.conf
    # Part of the key ccache cannot see by itself (its own key already has the
    # preprocessed source / include contents, the full clang command line that
    # afl-cc built, and the compiler name): this script (wrapper + key logic), the
    # AFL++ driver and every pass plugin. The hook (step 4) adds the real clang's
    # path, sha256 and --version and hashes it all ONCE per build into a digest the
    # wrapper hands ccache as CCACHE_COMPILERCHECK=string:<...>; per compile the
    # wrapper adds the build kind and every AFL_* / clang-relevant variable of the
    # clang process (afl-cc sets some itself) -- no per-call compiler-check process.
    { echo "fb_build ccache key v3"
      sha256sum /fold/fb_build.sh /afl/afl-cc /afl/*.so
    } > /tmp/fb_ccache/toolchain.txt
    # The wrapper always hands clang the fold lists (empty ones when this tree adds
    # no fold), so a cached compile's key is the same with and without folds and
    # unchanged files keep hitting the cache across rounds.
    if [ -z "$fold_names" ]; then
      write_fold_lists /tmp/fb_fold_denylist.txt /tmp/fb_fold_ignorelist.txt
    fi
  fi
fi
export FB_CCACHE_ON FB_CCACHE_WHY

# 3c. Audit logger (debug only): validated here, installed per build in step 4.
if [ -n "${FB_AUDIT_CC_LOG:-}" ]; then
  case "$FB_AUDIT_CC_LOG" in
    "$OUT"/*) ;;
    *) echo "fb_build: FB_AUDIT_CC_LOG must be a file under $OUT" >&2; exit 2;;
  esac
  mkdir -p "$(dirname "$FB_AUDIT_CC_LOG")"
  : > "$FB_AUDIT_CC_LOG"
  echo "fb_build: AUDIT MODE, compiler invocations logged to $FB_AUDIT_CC_LOG"
fi

# 4. FuzzBench's fuzzer_build, plus the fold exclusion, per-build timing, and the
#    optional ccache / audit wrappers. With no /ccache mount and no
#    FB_AUDIT_CC_LOG, build_benchmark runs exactly as FuzzBench calls it. The hook
#    is passed with -c, as fuzzer_build does, so sys.path[0] stays the WORKDIR.
#    The main build runs inside FuzzBench's restore_directory($SRC) and
#    restore_directory($WORK); nothing the cache needs lives there (wrappers, temp
#    dict files and key files are under /tmp/fb_ccache, the cache is /ccache).
FB_HOOK="$(cat <<'PY'
import hashlib, importlib, json, os, re, subprocess, sys, time
from fuzzers import utils
utils.initialize_env()
# fb_build.sh plumbing, removed so neither build's environment carries it.
ccache_on = os.environ.pop('FB_CCACHE_ON', '0') == '1'
ccache_why = os.environ.pop('FB_CCACHE_WHY', '')
audit_log = os.environ.pop('FB_AUDIT_CC_LOG', '')
os.environ.pop('FB_CCACHE_FORCE', None)
is_bug = utils.get_config_value('type') == 'bug'
deny = os.environ.get('FB_FOLD_DENYLIST')
if deny:
    os.environ['AFL_LLVM_DENYLIST'] = deny
    if utils.get_config_value('type') == 'bug':
        flag = '-fsanitize-coverage-ignorelist=' + os.environ['FB_FOLD_IGNORELIST']
        utils.append_flags('CFLAGS', [flag])
        utils.append_flags('CXXFLAGS', [flag])
    print('fold exclusion: AFL_LLVM_DENYLIST =', deny)
    print('CFLAGS =', os.environ['CFLAGS'])


def _write_exec(path, text):
    with open(path, 'w') as f:
        f.write(text)
    os.chmod(path, 0o755)


CCACHE_BIN = '/opt/fb_ccache/ccache'
DENY_FILE = '/tmp/fb_fold_denylist.txt'
IGNORE_FLAG = '-fsanitize-coverage-ignorelist=/tmp/fb_fold_ignorelist.txt'
# CCACHE_COMPILERCHECK is set per compile by the wrapper (string:<key digest>).
CCACHE_CONF = dict(CCACHE_DIR='/ccache', CCACHE_MAXSIZE='10G', CCACHE_UMASK='002',
                   CCACHE_CONFIGPATH='/tmp/fb_ccache/ccache.conf', CCACHE_HASHDIR='1')

# The compiler afl-cc execs, AFL_CC / AFL_CXX (afl-cc.c add_real_argv0). ccache sits
# BELOW afl-cc, so CC, CXX, CFLAGS, CXXFLAGS, PATH and the compiler argv[0] the build
# calls are exactly those of the uncached build (OpenSSL embeds "compiler: $CC
# $CFLAGS" in libcrypto). Python, so it can keep afl-cc's dict2file output. One
# wrapper per build kind (/tmp/fb_ccache/afl/<main|cmplog>/clang[++]).
#
# Only a plain `-c` compile of ONE input into ONE determinable object goes through
# ccache. Everything else (links, -E, -S, response files, several inputs, output to
# stdout) execs the real clang with the same argv, as afl-cc would have.
#
# Key: ccache hashes the preprocessed source / includes, the clang argv and the
# compiler name; CCACHE_COMPILERCHECK=string:<digest> adds, computed here without
# starting any process: TOOLCHAIN (sha256 of fb_build.sh, afl-cc, every /afl/*.so,
# the real clang's path, sha256 and --version; hashed once per build by the hook),
# the build KIND (main / cmplog: their objects never share an entry, on top of
# AFL_LLVM_CMPLOG being in the env part), the real compiler path, every AFL_*
# variable of the clang process except the per-call AFL_LLVM_DICT2FILE (the build's
# own dictionary path stands in for it), and the clang-relevant env (CCC_*, CPATH,
# ...). Startup cost is kept minimal: os / sys / hashlib only, posix_spawn.
#
# Dictionary sidecar: afl-cc's dict2file pass appends a file's constants to
# AFL_LLVM_DICT2FILE (/out/afl++.dict) while compiling; a cache hit skips the compile
# and those entries would be lost. So each cached compile writes to its own temp
# file; after a compile that produced the object, its lines are stored under
# /ccache/fb_dict/<kind>/<aa>/<sha256 of the object> (the store travels with the
# template -> per-trial cache copies); a call that wrote nothing replays the stored
# lines for that object. The result goes to the real dictionary with one O_APPEND
# write.
CCWRAP_PY = r"""
import os, sys
from hashlib import sha256 as _sha256
ARG_OPTS = {'-o', '-I', '-D', '-U', '-include', '-imacros', '-isystem', '-iquote',
            '-idirafter', '-iprefix', '-iwithprefix', '-iwithprefixbefore',
            '-isysroot', '--sysroot', '-MF', '-MT', '-MQ', '-MJ', '-x', '-Xclang',
            '-mllvm', '-Xlinker', '-Xassembler', '-Xpreprocessor', '-target',
            '-arch', '-L', '-l', '-u', '-z', '-T', '-e', '-B', '-F', '-iframework',
            '-ivfsoverlay', '--param', '-include-pch', '-imultilib', '-isystem-after',
            '-resource-dir', '-gcc-toolchain', '-serialize-diagnostics',
            '-dependency-file', '-dependency-dot', '-working-directory', '-Xanalyzer',
            '-Xopenmp-target', '-aux-triple'}
NO_CACHE = {'-E', '-S', '-M', '-MM', '-fsyntax-only', '-emit-llvm', '-flto',
            '-###', '-v', '--version', '-print-search-dirs'}
LIST_FLAGS = ('-fsanitize-coverage-allowlist=', '-fsanitize-coverage-ignorelist=',
              '-fsanitize-coverage-blocklist=', '-fsanitize-coverage-whitelist=',
              '-fsanitize-coverage-blacklist=', '-fsanitize-blacklist=',
              '-fsanitize-ignorelist=', '-fsanitize-system-ignorelist=',
              '-fprofile-list=')
LIST_ENVS = ('AFL_LLVM_ALLOWLIST', 'AFL_LLVM_DENYLIST', 'AFL_LLVM_WHITELIST',
             'AFL_LLVM_BLOCKLIST', 'AFL_LLVM_INSTRUMENT_FILE')
# clang-relevant variables outside AFL_* (round 2's compiler check covered these).
KEY_ENVS = {'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
            'LIBRARY_PATH', 'COMPILER_PATH', 'GCC_EXEC_PREFIX', 'SOURCE_DATE_EPOCH'}


def job(args):
    # (input, object) for a single-input `-c` compile, else None.
    if '-c' not in args:
        return None
    ins, out, skip = [], None, False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in NO_CACHE or a.startswith('@') or a.startswith('-flto='):
            return None
        if a == '-o':
            if i + 1 >= len(args):
                return None
            out = args[i + 1]
            skip = True
        elif a in ARG_OPTS:
            skip = True
        elif a.startswith('-o') and len(a) > 2:
            out = a[2:]
        elif a == '-' or not a.startswith('-'):
            ins.append(a)
    if len(ins) != 1 or ins[0] == '-' or not os.path.isfile(ins[0]):
        return None
    if out is None:
        out = os.path.splitext(os.path.basename(ins[0]))[0] + '.o'
    if out == '-' or out.startswith('/dev/'):
        return None
    return ins[0], out


def key_string(env, real_dict):
    # CCACHE_COMPILERCHECK value: everything round 2's per-call compiler check
    # printed, hashed in-process.
    h = _sha256()
    h.update(('fbcc v3\0%s\0kind=%s\0compiler=%s -> %s\0'
              % (TOOLCHAIN, KIND, REAL, REAL_RESOLVED)).encode())
    for k in sorted(env):
        if (k.startswith('AFL_') and k != 'AFL_LLVM_DICT2FILE') or \
                k.startswith('CCC_') or k in KEY_ENVS:
            h.update(('%s=%s\0' % (k, env[k])).encode('utf-8', 'surrogateescape'))
    h.update(('AFL_LLVM_DICT2FILE(build)=%s' % (
        '<unset>' if real_dict is None else real_dict)).encode('utf-8', 'surrogateescape'))
    return 'string:' + h.hexdigest()


def sha256(path):
    with open(path, 'rb') as f:
        return _sha256(f.read()).hexdigest()


def main():
    args = sys.argv[1:]
    j = job(args)
    if j is None:
        os.execv(REAL, [REAL] + args)
    out = j[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('CCACHE_')}
    env.update(CCACHE_CONF)
    # Same fold lists with and without folds (stable key, see step 3b). The lists
    # only name identifiers this tree adds; the fold-name guard in step 3b proved no
    # other identifier matches them, so their CONTENT cannot change an object whose
    # source is unchanged, and it is not hashed. Any OTHER list file (a project's
    # own allow/ignore list) is hashed by content (CCACHE_EXTRAFILES).
    env.setdefault('AFL_LLVM_DENYLIST', DENY_FILE)
    if IS_BUG:
        args = [a for a in args if a != IGNORE_FLAG] + [IGNORE_FLAG]
    extra = []
    for a in args:
        for f in LIST_FLAGS:
            if a.startswith(f):
                extra.append(a[len(f):])
    extra += [env[k] for k in LIST_ENVS if env.get(k)]
    extra = sorted({os.path.abspath(x) for x in extra if x} - FOLD_LISTS)
    for x in extra:
        if ':' in x or not os.path.isfile(x):
            os.execv(REAL, [REAL] + sys.argv[1:])     # cannot hash it: uncached
    if extra:
        env['CCACHE_EXTRAFILES'] = ':'.join(extra)
    real_dict = env.get('AFL_LLVM_DICT2FILE')
    env['CCACHE_COMPILERCHECK'] = key_string(env, real_dict)
    if not real_dict:
        os.execve(CCACHE, [CCACHE, REAL] + args, env)
    # Per-call dictionary file: unique among live processes; a stale one left by a
    # dead process with the same pid is truncated.
    tmp = '%s/d.%d' % (DICT_TMP, os.getpid())
    os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
    env['AFL_LLVM_DICT2FILE'] = tmp
    try:
        pid = os.posix_spawn(CCACHE, [CCACHE, REAL] + args, env)
        rc = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
        with open(tmp, 'rb') as f:
            data = f.read()
    finally:
        os.unlink(tmp)
    if rc == 0 and os.path.isfile(out):
        h = sha256(out)
        d = os.path.join(STORE, h[:2])
        p = os.path.join(d, h)
        if data:
            os.makedirs(d, exist_ok=True)
            t = '%s.tmp.%d' % (p, os.getpid())
            with open(t, 'wb') as f:
                f.write(data)
            os.replace(t, p)
        elif os.path.isfile(p):
            with open(p, 'rb') as f:
                data = f.read()
    if data:
        fd = os.open(real_dict, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    sys.exit(rc if rc >= 0 else 128 - rc)


main()
"""


def _real_compilers(env):
    """The clang / clang++ afl-cc would exec with AFL_CC/AFL_CXX unset (its
    LLVM_BINDIR), read from afl-cc's own AFL_DEBUG trace."""
    out = []
    for drv, lang in (('/afl/afl-clang-fast', 'c'), ('/afl/afl-clang-fast++', 'c++')):
        e = {k: v for k, v in env.items() if k not in ('AFL_CC', 'AFL_CXX', 'AFL_QUIET')}
        e['AFL_DEBUG'] = '1'
        r = subprocess.run([drv, '-E', '-x', lang, '/dev/null', '-o', '/dev/null'],
                           env=e, capture_output=True, text=True, errors='replace')
        # stdout: one line per command, " '<argv0>' '<arg>' ...": afl-cc's own argv,
        # then the compiler it execs.
        txt = re.sub(r'\x1b\[[0-9;]*m', '', r.stdout)
        cands = [c for c in re.findall(r"^ '(/[^']+)' ", txt, re.MULTILINE) if c != drv]
        if not cands or not os.access(cands[0], os.X_OK):
            return None
        out.append(cands[0])
    return out


_TOOLCHAIN = {}


def _toolchain_digest(real):
    """sha256 of toolchain.txt (step 3b) + the real compilers' paths, sha256 and
    --version. Computed once per (real compilers) and shared by both builds."""
    key = tuple(real)
    if key not in _TOOLCHAIN:
        with open('/tmp/fb_ccache/toolchain.txt') as f:
            text = f.read()
        for c in real:
            text += '%s %s\n' % (c, os.path.realpath(c))
        text += subprocess.run(['sha256sum'] + sorted({os.path.realpath(c) for c in real}),
                               capture_output=True, text=True, check=True).stdout
        text += subprocess.run([real[0], '--version'], capture_output=True, text=True,
                               check=True).stdout
        with open('/tmp/fb_ccache/toolchain.full.txt', 'w') as f:
            f.write(text)
        _TOOLCHAIN[key] = hashlib.sha256(text.encode()).hexdigest()
    return _TOOLCHAIN[key]


def _ccache_env(env, kind):
    """build env -> ccache below afl-cc: only AFL_CC / AFL_CXX are added.
    Returns a reason string when ccache cannot be used for this build."""
    if env.get('AFL_CC') or env.get('AFL_CXX'):
        return 'build-sets-AFL_CC'
    real = _real_compilers(env)
    if not real:
        return 'cannot-find-afl-cc-clang'
    digest = _toolchain_digest(real)
    d = '/tmp/fb_ccache/afl/' + kind
    os.makedirs(d, exist_ok=True)
    consts = ('REAL = %r\nREAL_RESOLVED = %r\nCCACHE = %r\nSTORE = %r\nDICT_TMP = %r\n'
              'DENY_FILE = %r\nIGNORE_FLAG = %r\nIS_BUG = %r\nFOLD_LISTS = {%r, %r}\n'
              'CCACHE_CONF = %r\nKIND = %r\nTOOLCHAIN = %r\n')
    for var, c in (('AFL_CC', real[0]), ('AFL_CXX', real[1])):
        w = os.path.join(d, os.path.basename(c))
        _write_exec(w, '#!%s -IS\n' % sys.executable + consts % (
            c, os.path.realpath(c), CCACHE_BIN, '/ccache/fb_dict/' + kind,
            '/tmp/fb_ccache/dict', DENY_FILE, IGNORE_FLAG, is_bug, DENY_FILE,
            '/tmp/fb_fold_ignorelist.txt', CCACHE_CONF, kind, digest) + CCWRAP_PY)
        env[var] = w
    return ''


AUDIT_PY = r'''import fcntl, json, os, sys
kind, real, log = sys.argv[1:4]
keep = {k: v for k, v in os.environ.items()
        if k.startswith("AFL_") or k in ("CFLAGS", "CXXFLAGS", "CC", "CXX")}
rec = {"build": kind, "compiler": real, "argv": [real] + sys.argv[4:],
       "cwd": os.getcwd(), "env": keep}
with open(log, "a") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    f.write(json.dumps(rec, sort_keys=True) + "\n")
'''


def _audit_env(env, kind, real_cc, real_cxx):
    """Pass-through wrappers that log one JSON line per compiler call, then exec
    the next compiler (the real one, or the ccache wrapper in a cached cmplog)."""
    d = '/tmp/fb_audit/' + kind
    os.makedirs(d, exist_ok=True)
    _write_exec('/tmp/fb_audit/log.py', AUDIT_PY)
    for var, real in (('CC', real_cc), ('CXX', real_cxx)):
        wrapper = os.path.join(d, os.path.basename(real))
        _write_exec(wrapper,
                    '#!/bin/sh\n%s -I -S /tmp/fb_audit/log.py %s %s %s "$@" '
                    '2>/dev/null || true\nexec %s "$@"\n'
                    % (sys.executable, kind, real, audit_log, env[var]))
        env[var] = wrapper


def _ccache_stats(kind):
    env = dict(os.environ, **CCACHE_CONF)
    r = subprocess.run([CCACHE_BIN, '-s'], env=env, capture_output=True, text=True)
    print(r.stdout, end='')
    st = {}
    for line in r.stdout.splitlines():
        m = re.match(r'^(\S.*?)\s{2,}(\d+)\s*$', line)
        if m:
            st[m.group(1).strip()] = int(m.group(2))
    ver = subprocess.run([CCACHE_BIN, '--version'], capture_output=True, text=True)
    return {'enabled': True, 'build': kind,
            'version': (ver.stdout.splitlines() or [''])[0],
            'hits_direct': st.get('cache hit (direct)', 0),
            'hits_preprocessed': st.get('cache hit (preprocessed)', 0),
            'misses': st.get('cache miss', 0),
            'compiler_check_failed': st.get('compiler check failed', 0),
            'counters': st}


_real_build = utils.build_benchmark


def _timed_build(env=None):
    # FuzzBench calls this twice: the main build (env=None, inside
    # restore_directory) and the cmplog build (env with AFL_LLVM_CMPLOG=1).
    kind = 'cmplog' if (env or os.environ).get('AFL_LLVM_CMPLOG') == '1' else 'main'
    use_cc = ccache_on
    why = ccache_why
    if use_cc or audit_log:
        env = dict(env if env is not None else os.environ)
        real_cc, real_cxx = env['CC'], env['CXX']
        if use_cc:
            why = _ccache_env(env, kind)
            use_cc = not why
            if use_cc:
                subprocess.run([CCACHE_BIN, '-z'], env=dict(os.environ, **CCACHE_CONF),
                               check=True, stdout=subprocess.DEVNULL)
            else:
                print('fb_build: %s build runs uncached: %s' % (kind, why), flush=True)
        if audit_log:
            _audit_env(env, kind, real_cc, real_cxx)
    t0 = time.time()
    _real_build(env=env)
    out = (env or os.environ).get('OUT')
    print('FB_BUILD_TIMING out=%s secs=%.1f' % (out, time.time() - t0), flush=True)
    st = _ccache_stats(kind) if use_cc else {'enabled': False, 'build': kind,
                                             'reason': why}
    print('FB_CCACHE_STATS ' + json.dumps(st, sort_keys=True), flush=True)


utils.build_benchmark = _timed_build
fuzzer = importlib.import_module('fuzzers.%s.fuzzer' % os.environ['FUZZER'])
fuzzer.build()
PY
)"
PYTHONPATH="$SRC" python3 -u -c "$FB_HOOK"

# 5. afl-showmap for the replay gate / profiler / coverage tooling.
cp /afl/afl-showmap "$OUT/"
