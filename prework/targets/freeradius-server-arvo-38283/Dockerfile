# syntax=docker/dockerfile:1
# Modernized build environment for freeradius-server / ARVO 38283.
#
# The ARVO image predates AFL++ v5.02c's LLVM floor, so only the vulnerable
# SOURCE is carried over; the toolchain comes from the pinned base + AFL++ pin.
ARG BASE
FROM ${BASE}

# Build tools. Deliberately no -dev libraries: linking against a library the
# ARVO build did not use would silently change the target under test.
RUN apt-get update && apt-get install -y --no-install-recommends \
        make cmake autoconf automake libtool pkg-config python3 python3-setuptools wget zip unzip bison flex gawk gettext texinfo nasm yasm ninja-build bsdmainutils file subversion \
    && rm -rf /var/lib/apt/lists/*

# freeradius genuinely requires libtalloc to configure ("FreeRADIUS requires
# libtalloc"), and its OSS-Fuzz project Dockerfile installs it too. This is
# restoring parity with the build ARVO used, not adding a library the
# original build lacked.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libtalloc-dev libssl-dev libpcap-dev libkqueue-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin the LLVM that AFL++ is built against rather than inheriting base-builder's
# clang. base-builder carries a clang trunk build that AFL++ v5.02c does not
# compile against; its makefile treats that as NON-FATAL, so the result would be
# an afl-cc with no compiler mode -- it "builds" and then silently produces an
# UNINSTRUMENTED target.
ARG LLVM_VERSION=18
RUN apt-get update && apt-get install -y --no-install-recommends \
        "clang-${LLVM_VERSION}" "llvm-${LLVM_VERSION}-dev" \
        "libclang-${LLVM_VERSION}-dev" "lld-${LLVM_VERSION}" \
        "libc++-${LLVM_VERSION}-dev" "libc++abi-${LLVM_VERSION}-dev" \
        "libclang-rt-${LLVM_VERSION}-dev" \
    && rm -rf /var/lib/apt/lists/*

# Replace the base image's bundled AFL++ with the pinned release. compile_afl
# copies libAFLDriver.a and the afl-* binaries out of $SRC/aflplusplus, so
# building the pin in place makes the stock OSS-Fuzz build path use it.
# `source-only` also builds the GCC plugin and Rust bindings, whose failures the
# makefile ignores -- hence asserting on artifacts, not on make's exit code.
ARG AFLPP_REF
RUN rm -rf "$SRC/aflplusplus" && \
    git clone --depth 1 --branch "${AFLPP_REF}" \
        https://github.com/AFLplusplus/AFLplusplus "$SRC/aflplusplus" && \
    cd "$SRC/aflplusplus" && \
    unset CFLAGS CXXFLAGS && \
    LLVM_CONFIG="llvm-config-${LLVM_VERSION}" make -j"$(nproc)" source-only; \
    test -f libAFLDriver.a && \
    test -x afl-fuzz && \
    test -x afl-showmap && \
    test -x afl-clang-fast

# Prove instrumentation is live, built WITH -fsanitize=address (the configuration
# `compile` actually uses). `test -x afl-clang-fast` is not enough: afl-cc exists
# even when every compiler mode failed, and a plain build passes even when the
# compiler-rt sanitizer runtimes are missing.
RUN printf 'int main(void){return 0;}\n' > /tmp/instrtest.c && \
    "$SRC/aflplusplus/afl-clang-fast" -fsanitize=address \
        -o /tmp/instrtest /tmp/instrtest.c && \
    nm /tmp/instrtest | grep -q __afl_area_ptr && \
    echo "AFL++ instrumentation verified (with ASAN)" && \
    rm -f /tmp/instrtest /tmp/instrtest.c

# ARVO's /src IS the OSS-Fuzz $SRC layout; stage_source has already pruned the
# bundled engine trees so they cannot shadow the AFL++ pin.
COPY src/ $SRC/

# --- TOOLCHAIN FIX (pipeline-specific, not upstream) ---
# freeradius's top-level Makefile builds two GNU make PLUGINS and `load`s them into
# make itself (Makefile:117,127). Built with the project's CC they carry AFL
# instrumentation, so make's dlopen fails with `undefined symbol: __afl_area_ptr`
# and the build stops before compiling anything.
#
# The Makefile already has a branch for building those targets explicitly
# (ifeq findstring libfreeradius-make,$(MAKECMDGOALS)), so pre-build them with
# AFL_NOOPT=1 -- afl-cc then behaves as a plain compiler. The plugins end up
# uninstrumented and loadable, while the fuzz target itself is still built with full
# instrumentation by the main make that follows. Instrumenting a build-time make
# plugin buys nothing: it never executes target code.
RUN sed -i 's|^make -i -j\$(nproc)$|AFL_NOOPT=1 make -i libfreeradius-make-dlopen.a libfreeradius-make-version.a \|\| true\nmake -i -j$(nproc)|' "$SRC/build.sh" \
    && grep -q AFL_NOOPT "$SRC/build.sh"

# build.sh does `git apply $SRC/patch.diff` to add the OSS-Fuzz harness, but the
# source ARVO ships already has it applied, so the second application fails
# ("patch does not apply") and the build stops before producing fuzzer_tacacs.
# Apply only when it would actually apply. A genuine patch failure is still caught
# downstream -- _build_afl_baseline verifies /out/<fuzz_target> exists and that the
# PoC still reproduces, so this cannot silently ship an unpatched target.
# clang-18 defaults to DWARF-5; the binutils ld in this image cannot parse it and
# fails every link with "DWARF error: invalid or unhandled FORM value: 0x25". The
# build runs `make -i`, so those failures are IGNORED and the build exits 0 having
# produced no fuzzer_tacacs at all -- which is why this surfaced as a missing binary
# rather than a build error. Pin the debug format to DWARF-4.
#
# The -DAFL_fuzzer_build token exists purely to satisfy src/bin/all.mk:31,
#   ifneq "$(findstring fuzzer,${CFLAGS})" ""
# which generates the fuzzer_<proto> targets ONLY when CFLAGS contains the literal
# substring 'fuzzer'. libFuzzer builds satisfy that incidentally via
# -fsanitize=fuzzer-no-link; an AFL build has no such token, so the whole fuzzer
# block is skipped and no fuzzer_tacacs target is ever defined -- which is why this
# presented as a missing binary rather than a compile failure. The gate's intent
# ('built with fuzzing flags') IS satisfied here; only its libFuzzer-specific
# detection is not. The define is otherwise unused by the source.
#
# With the targets finally generated, they still failed to LINK for two reasons:
#   * boiler.mk links with $(LDFLAGS), not $(CFLAGS), so -fsanitize=address never
#     reached the link line -- every fuzzer died on `undefined reference to
#     __asan_init`.
#   * fuzzer.c defines LLVMFuzzerTestOneInput but NO main(); libFuzzer builds get
#     one from -fsanitize=fuzzer, an AFL build needs $LIB_FUZZING_ENGINE
#     (/usr/lib/libFuzzingEngine.a). fuzzer.mk sets TGT_LDLIBS := $(LIBS), so
#     exporting LIBS is what reaches it.
# Adding a static archive to the GLOBAL LIBS is safe: archive members are pulled
# lazily, so the driver's main() is only extracted by targets that lack one.
RUN printf '%s\n' \
      'export CFLAGS="$CFLAGS -gdwarf-4 -DAFL_fuzzer_build=1"' \
      'export CXXFLAGS="$CXXFLAGS -gdwarf-4 -DAFL_fuzzer_build=1"' \
      'export LDFLAGS="${LDFLAGS:-} -fsanitize=address"' \
      'export LIBS="${LIBS:-} $LIB_FUZZING_ENGINE"' \
    | cat - "$SRC/build.sh" > /tmp/b && mv /tmp/b "$SRC/build.sh" && chmod +x "$SRC/build.sh"

RUN sed -i 's|^git apply --ignore-whitespace \$SRC/patch.diff$|if git apply --check --ignore-whitespace $SRC/patch.diff 2>/dev/null; then git apply --ignore-whitespace $SRC/patch.diff; else echo "patch.diff already applied; skipping"; fi|' "$SRC/build.sh" \
    && grep -q "already applied" "$SRC/build.sh"


# OSS-Fuzz runs build.sh from the PROJECT directory, not $SRC.
WORKDIR $SRC/freeradius-server
