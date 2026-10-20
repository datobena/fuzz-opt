# Copyright 2017 Google Inc.
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

RUN apt-get update && \
    apt-get install -y \
        cmake \
        ninja-build \
        g++ \
        libz-dev

RUN git clone \
    https://github.com/google/bloaty.git
# fuzz-opt deviation: populate bloaty's git submodules (third_party/*) at the
# benchmark commit's gitlinks. FuzzBench gets them from bloaty's CMakeLists.txt
# (`git submodule update --init --recursive` at configure time, needs .git), but our
# pipeline extracts /src/bloaty with .git stripped and rebuilds that tree, where the
# CMake step silently no-ops and the build fails ("third_party/capstone does not
# contain CMakeLists.txt"). The checkout of the benchmark commit (same commit
# checkout_commit.py checks out later) must come first so the gitlinks match it.
RUN git -C bloaty checkout 52948c107c8f81045e7f9223ec02706b19cfa882 && \
    git -C bloaty submodule update --init --recursive

WORKDIR bloaty
COPY build.sh $SRC/
