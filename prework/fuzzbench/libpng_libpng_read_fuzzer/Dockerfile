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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd

RUN apt-get update && \
    apt-get install -y \
    make \
    autoconf \
    automake \
    libtool \
    zlib1g-dev

RUN git clone \
        --depth 1 \
        --branch v1.2.13 \
        https://github.com/madler/zlib.git

RUN git clone \
        https://github.com/glennrp/libpng.git
# fuzz-opt deviation: check out the benchmark commit before the next line.
# libpng HEAD (default branch libpng18) no longer has contrib/oss-fuzz/build.sh,
# so upstream's `cp` fails at docker-build time, before checkout_commit.py runs.
RUN git -C libpng checkout cd0ea2a7f53b603d3d9b5b891c779c430047b39a
RUN cp libpng/contrib/oss-fuzz/build.sh $SRC

WORKDIR libpng

# fuzz-opt deviation: pin google/fuzzing to 128a82660ffe414036ded9a6e561a9532945280d
# (2022-10-26, nearest to benchmark commit_date) -- upstream clones HEAD (master).
RUN wget --no-check-certificate -qO $OUT/libpng_read_fuzzer.dict \
    https://raw.githubusercontent.com/google/fuzzing/128a82660ffe414036ded9a6e561a9532945280d/dictionaries/png.dict

ADD seeds /opt/seeds
COPY * $SRC/
