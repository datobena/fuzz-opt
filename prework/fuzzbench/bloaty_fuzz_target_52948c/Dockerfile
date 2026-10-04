# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

ARG BASE
FROM ${BASE}

# ---- pinned toolchain (grafted from prework/targets/*) ----------------------
# FuzzBench pins base-builder to an older digest and inherits whatever AFL++ that
# image ships. Replace it with the benchmark's OWN pinned source built against
# our base + AFL++ v5.02c, so this answers "does it build on the newest AFL++".
# LLVM_VERSION is NOT set in base-builder -- the prework targets declare it as an
# ARG, and without it the package names expand to "clang-" and apt exits 100.
ARG LLVM_VERSION=18
RUN apt-get update && apt-get install -y --no-install-recommends \
        make cmake autoconf automake libtool pkg-config python3 wget zip unzip \
        bison flex gawk gettext texinfo nasm yasm ninja-build file \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends \
        "clang-${LLVM_VERSION}" "llvm-${LLVM_VERSION}-dev" \
        "libclang-${LLVM_VERSION}-dev" "lld-${LLVM_VERSION}" \
        "libc++-${LLVM_VERSION}-dev" "libc++abi-${LLVM_VERSION}-dev" \
        "libclang-rt-${LLVM_VERSION}-dev" \
    && rm -rf /var/lib/apt/lists/*
RUN rm -rf "$SRC/aflplusplus" && \
    git clone --depth 1 --branch "v5.02c" \
        https://github.com/AFLplusplus/AFLplusplus "$SRC/aflplusplus" && \
    cd "$SRC/aflplusplus" && \
    unset CFLAGS CXXFLAGS && \
    LLVM_CONFIG="llvm-config-${LLVM_VERSION}" make -j"$(nproc)" source-only; \
    test -f libAFLDriver.a && test -x afl-fuzz && test -x afl-showmap && \
    test -x afl-clang-fast

RUN apt-get update && \
    apt-get install -y \
        cmake \
        ninja-build \
        g++ \
        libz-dev

RUN git clone \
    https://github.com/google/bloaty.git
RUN git -C bloaty checkout 52948c107c8f81045e7f9223ec02706b19cfa882

WORKDIR bloaty
COPY build.sh $SRC/
