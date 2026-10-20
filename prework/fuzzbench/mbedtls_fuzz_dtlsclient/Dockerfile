# Copyright 2018 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd
RUN apt-get update && apt-get install -y make cmake
RUN apt-get update && apt-get install -y \
    python-all-dev \
    python3-all-dev \
    python3-pip  && \
    ln -s /usr/local/bin/pip3 /usr/local/bin/pip

RUN git clone --recursive -b development https://github.com/Mbed-TLS/mbedtls.git mbedtls

RUN git clone --depth 1 https://github.com/google/boringssl.git boringssl
RUN git clone --recursive https://github.com/openssl/openssl.git openssl
# fuzz-opt deviation: pin boringssl to cbccae538c6f03cdf7b9fa263fd1c37724d7a769 (2023-01-26) and openssl to
# 6e3b1c81736b1829584e3f40c2d00040fe1aa881 (2023-01-26), nearest to benchmark commit_date -- upstream clones HEAD.
# build.sh cp's their fuzz corpora under `bash -e`, so a layout change at HEAD breaks it.
# openssl: -f because HEAD's fuzz/corpora submodule sits where the pinned tree has
# tracked files (same `checkout -f` checkout_commit.py uses). --checkout: gost-engine
# is `update = rebase` in .gitmodules, which needs a git identity; a plain checkout
# of the recorded gitlink is what the upstream --recursive clone gives.
RUN git -C boringssl fetch --depth 1 origin cbccae538c6f03cdf7b9fa263fd1c37724d7a769 && \
    git -C boringssl checkout FETCH_HEAD && \
    git -C openssl checkout -f 6e3b1c81736b1829584e3f40c2d00040fe1aa881 && \
    git -C openssl submodule update --init --recursive --checkout --force
WORKDIR mbedtls
COPY build.sh $SRC/
