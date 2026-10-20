# Copyright 2016 Google Inc.
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

# Curl will be checked out to the commit hash specified in benchmark.yaml.
RUN git clone https://github.com/curl/curl-fuzzer /src/curl_fuzzer
RUN git -C /src/curl_fuzzer checkout dd486c1e5910e722e43c451d4de928ac80f5967d
RUN git clone --depth 1 https://github.com/curl/curl.git /src/curl

# Use curl-fuzzer's scripts to get latest dependencies.
RUN $SRC/curl_fuzzer/scripts/ossfuzzdeps.sh
# fuzz-opt deviation: pin zlib to 1.2.13 (released 2022-10-13, the zlib.net release
# at benchmark commit_date) -- upstream's build fetches https://zlib.net/zlib.tar.gz
# (latest release) via curl_fuzzer/scripts/download_zlib.sh. handle_x.sh skips the
# download when /src/zlib exists; this reproduces download_zlib.sh's layout.
RUN wget -qO /tmp/zlib.tar.gz https://zlib.net/fossils/zlib-1.2.13.tar.gz && \
    echo "b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30  /tmp/zlib.tar.gz" | sha256sum -c && \
    tar -xf /tmp/zlib.tar.gz --directory /tmp && \
    mv /tmp/zlib-1.2.13 /src/zlib && rm /tmp/zlib.tar.gz

WORKDIR $SRC/curl_fuzzer
COPY build.sh $SRC/
