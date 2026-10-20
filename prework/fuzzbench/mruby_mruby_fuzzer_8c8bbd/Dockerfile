# Copyright 2019 Google Inc.
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
RUN apt-get update && apt-get install -y build-essential ruby bison ninja-build \
    cmake zlib1g-dev libbz2-dev liblzma-dev
RUN git clone \
        https://github.com/mruby/mruby
RUN git clone --depth 1 https://github.com/bshastry/mruby_seeds.git mruby_seeds
# fuzz-opt deviation: pin mruby_seeds to 5a618aba8e4493eceff7a430cba7c848e6cbabfd
# (2019-05-04, nearest to benchmark commit_date; still HEAD) -- upstream clones HEAD.
# build.sh zips the whole dir incl. .git/*, so only touch git when HEAD has moved
# (today it has not, and the seed zip stays byte-identical to FuzzBench's).
RUN if [ "$(git -C mruby_seeds rev-parse HEAD)" != 5a618aba8e4493eceff7a430cba7c848e6cbabfd ]; then \
      git -C mruby_seeds fetch --depth 1 origin 5a618aba8e4493eceff7a430cba7c848e6cbabfd && \
      git -C mruby_seeds checkout FETCH_HEAD; \
    fi
WORKDIR mruby
COPY build.sh *.c *.options *.dict $SRC/
