# Copyright 2020 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:8b4a73d83374b298a0a771eeec9a1d44ceff3416a678b7d7946303389d022aca
RUN apt-get update && apt-get install -y \
    make \
    autoconf \
    automake \
    libtool \
    cmake \
    patchelf \
    libbz2-dev \
    zlib1g-dev \
    libjson-c-dev \
    build-essential \
    python \
    wget

RUN git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/rnpgp/rnp.git rnp
WORKDIR $SRC
# fuzz-opt deviations: A2 fetch Botan at image build time (compile runs with --network none);
# A1 Botan 3.4.0 -> 3.13.0 (3.4.0 lacks modules rnp HEAD's ci/botan3-pqc-modules requests; 3.13.0 is rnp's own fuzzing CI pin).
RUN wget -q -O $SRC/Botan-3.13.0.tar.xz https://botan.randombit.net/releases/Botan-3.13.0.tar.xz && \
    echo "12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620  $SRC/Botan-3.13.0.tar.xz" | sha256sum -c -
WORKDIR $SRC
COPY build.sh $SRC/
