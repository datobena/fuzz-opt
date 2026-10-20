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
    autoconf \
    automake \
    make \
    wget

RUN git clone https://github.com/google/re2.git

# fuzz-opt deviation: pin google/fuzzing to 25c648f09052f752cd3a2fc1f0131855896bb7d1
# (2023-01-19, nearest to benchmark commit_date) -- upstream clones HEAD (master).
RUN wget -qO $OUT/fuzzer.dict \
    https://raw.githubusercontent.com/google/fuzzing/25c648f09052f752cd3a2fc1f0131855896bb7d1/dictionaries/regexp.dict
COPY build.sh target.cc $SRC/
