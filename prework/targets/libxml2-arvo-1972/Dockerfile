# syntax=docker/dockerfile:1
# Modernized build environment for libxml2 / ARVO 1972.
#
# Deps mirror oss-fuzz/projects/libxml2/Dockerfile, minus its `git clone` (ARVO
# supplies the vulnerable source) and minus its automake pin (the modern base
# already ships a newer automake than the historical image did).
ARG BASE
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool pkg-config zlib1g-dev liblzma-dev python3 \
    && rm -rf /var/lib/apt/lists/*

# Pin the LLVM that AFL++ is built against, rather than inheriting whatever
# clang base-builder ships this month. Two reasons:
#   1. Correctness. base-builder currently carries a clang 22 trunk build, and
#      AFL++ v5.02c does not compile against LLVM 22 headers -- afl-llvm-common.o
#      fails on changed StringLiteral signatures. AFL++'s makefile treats that as
#      NON-FATAL, so the result is an afl-cc with no compiler mode: it "builds"
#      and then silently produces an UNINSTRUMENTED target.
#   2. Reproducibility. base-builder's clang moves without warning; pinning here
#      means the compiler is part of the experiment's pinned configuration.
# AFL++ documents LLVM 14 as the floor and 18 as recommended.
ARG LLVM_VERSION=18
RUN apt-get update && apt-get install -y --no-install-recommends \
        "clang-${LLVM_VERSION}" "llvm-${LLVM_VERSION}-dev" \
        "libclang-${LLVM_VERSION}-dev" "lld-${LLVM_VERSION}" \
        "libc++-${LLVM_VERSION}-dev" "libc++abi-${LLVM_VERSION}-dev" \
    && rm -rf /var/lib/apt/lists/*

# Replace the base image's bundled AFL++ with the pinned release. compile_afl
# copies libAFLDriver.a and the afl-* binaries out of $SRC/aflplusplus, so
# building the pin in place makes the stock OSS-Fuzz build path use it with no
# further patching.
#
# The asserts matter: AFL++'s GNUmakefile builds llvm_mode with a leading `-`,
# so a pass that fails to compile against a very new LLVM is NON-FATAL and would
# otherwise leave us silently without afl-clang-fast -- i.e. an uninstrumented
# target that still "builds".
# `source-only` also builds the GCC plugin and Rust bindings, neither of which we
# use; their failures are ignored by the makefile, hence asserting on artifacts
# rather than on make's exit code.
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

# Prove instrumentation is actually live. `test -x afl-clang-fast` is NOT enough:
# afl-cc exists even when every compiler mode failed to build, and then compiles
# happily while emitting no coverage at all. __afl_area_ptr is the coverage
# bitmap pointer, so its presence in a trivial binary is the real signal.
RUN printf 'int main(void){return 0;}\n' > /tmp/instrtest.c && \
    "$SRC/aflplusplus/afl-clang-fast" -o /tmp/instrtest /tmp/instrtest.c && \
    nm /tmp/instrtest | grep -q __afl_area_ptr && \
    echo "AFL++ instrumentation verified" && \
    rm -f /tmp/instrtest /tmp/instrtest.c

# ARVO's /src IS the OSS-Fuzz $SRC layout (project dir, harness sources,
# .options/dict, build.sh), so it lands back at $SRC verbatim. stage_source()
# has already pruned ARVO's bundled engine trees so they cannot shadow the
# AFL++ pin built above.
COPY src/ $SRC/
WORKDIR $SRC
