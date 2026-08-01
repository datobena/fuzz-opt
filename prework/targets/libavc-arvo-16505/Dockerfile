# syntax=docker/dockerfile:1
# Modernized build environment for libavc / ARVO 16505.
#
# The ARVO image is Ubuntu 16.04 with clang 9 and classic AFL 2.52b -- far below
# AFL++ v5.02c's LLVM 14 floor, which is why the build moves to a modern base and
# only the vulnerable SOURCE is carried over.
ARG BASE
FROM ${BASE}

# Deps mirror oss-fuzz/projects/libavc/Dockerfile (wget, cmake), minus its
# git clone since ARVO supplies the source.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget cmake \
    && rm -rf /var/lib/apt/lists/*

# Pin the LLVM that AFL++ is built against rather than inheriting whatever clang
# base-builder ships. base-builder currently carries a clang 22 trunk build, and
# AFL++ v5.02c does not compile against LLVM 22 headers -- afl-llvm-common.o
# fails on changed StringLiteral signatures. AFL++'s makefile treats that as
# NON-FATAL, so the result is an afl-cc with no compiler mode: it "builds" and
# then silently produces an UNINSTRUMENTED target.
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
# compiler-rt sanitizer runtimes are missing -- which surfaces only later as
# configure's opaque "C compiler cannot create executables".
RUN printf 'int main(void){return 0;}\n' > /tmp/instrtest.c && \
    "$SRC/aflplusplus/afl-clang-fast" -fsanitize=address \
        -o /tmp/instrtest /tmp/instrtest.c && \
    nm /tmp/instrtest | grep -q __afl_area_ptr && \
    echo "AFL++ instrumentation verified (with ASAN)" && \
    rm -f /tmp/instrtest /tmp/instrtest.c

# ARVO's /src IS the OSS-Fuzz $SRC layout; stage_source has already pruned the
# bundled engine trees so they cannot shadow the AFL++ pin.
COPY src/ $SRC/

# OSS-Fuzz runs build.sh from the PROJECT directory, not $SRC.
WORKDIR $SRC/libavc
