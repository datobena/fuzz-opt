# syntax=docker/dockerfile:1
# Modernized build environment for libredwg / ARVO 31419.
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
# autogen.sh runs `git submodule update --init --recursive` under `set -e`, which aborts
# once the pipeline strips the shipped .git (done for leak and build reasons -- see
# phase3_online step 1a). jsmn/jsmn.h is already vendored in the extracted tree, so the
# fetch has nothing to do; an EMPTY repo lets the command succeed while leaking no
# history. The earlier `git fetch --tags` block runs before autogen.sh sets -e.
# safe.directory is also needed: the build container runs as root while the source
# tree is bind-mounted from a uid-1000 host dir, so git refuses it as 'dubious
# ownership'. Scoped to this throwaway build container.
RUN printf '%s\n' \
      'git config --global --add safe.directory "*" 2>/dev/null || true' \
      'if [ -d libredwg ] && [ ! -d libredwg/.git ]; then git -C libredwg init -q; fi' \
    | cat - "$SRC/build.sh" > /tmp/b && mv /tmp/b "$SRC/build.sh" && chmod +x "$SRC/build.sh"

RUN sed -i 's|^make$|make -i|' "$SRC/build.sh" && grep -q "^make -i" "$SRC/build.sh"
# The fuzz target is linked separately at the end of build.sh from
# src/.libs/libredwg.a; the plain `make` also builds example programs
# (dwg2svg2) that fail to link against the AFL-instrumented static lib.
# -i keeps going so the library and the harness still get built. A missing
# /out/llvmfuzz is still caught downstream -- the build is not assumed to
# have worked just because make exited 0.


# libredwg's build.sh starts with `cd libredwg`, so it must run FROM $SRC --
# not from the project directory like most OSS-Fuzz targets. Setting the
# usual WORKDIR $SRC/libredwg makes that cd fail with
# "cd: libredwg: No such file or directory".
WORKDIR $SRC
