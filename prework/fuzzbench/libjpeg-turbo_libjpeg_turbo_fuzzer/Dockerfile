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
    apt-get install -y make yasm cmake

# fuzz-opt deviation: pin libjpeg-turbo/fuzz to 8e323685149d06c7316e037e2f0d6215318a5512
# (2023-02-02, its first commit, nearest to benchmark commit_date; branches.txt =
# main, 2.1.x, 2.0.x) -- upstream clones HEAD, which decides which branches get cloned.
# Each branch clone is then pinned: main and 2.1.x to the benchmark commit 3b19db4e
# (2.1.x tip at commit_date; main is the target build and checkout_commit.py pins only
# whichever libjpeg-turbo.* dir it visits first), 2.0.x to b0a40a66 (its tip at
# commit_date) -- upstream clones each branch at HEAD.
RUN git clone https://github.com/libjpeg-turbo/fuzz && \
    git -C fuzz checkout 8e323685149d06c7316e037e2f0d6215318a5512 && \
    cat fuzz/branches.txt | while read branch; do \
      git clone https://github.com/libjpeg-turbo/libjpeg-turbo \
          -b $branch libjpeg-turbo.$branch; \
    done
RUN git -C libjpeg-turbo.main checkout 3b19db4e6e7493a748369974819b4c5fa84c7614 && \
    git -C libjpeg-turbo.2.1.x checkout 3b19db4e6e7493a748369974819b4c5fa84c7614 && \
    git -C libjpeg-turbo.2.0.x checkout b0a40a665978503f0e2b87cf70a1c5d68d14f801

RUN git clone https://github.com/libjpeg-turbo/seed-corpora && \
    git -C seed-corpora checkout 7c9ea5ffaac76ef618657978c9fdfa845d310b93
RUN cd seed-corpora && \
    zip -r ../decompress_fuzzer_seed_corpus.zip \
        afl-testcases/jpeg* \
        bugs/decompress* \
        $SRC/libjpeg-turbo/testimages/*.jpg
RUN cd seed-corpora && \
    zip -r ../compress_fuzzer_seed_corpus.zip \
        afl-testcases/bmp \
        afl-testcases/gif* \
        bugs/compress* \
        $SRC/libjpeg-turbo/testimages/*.bmp \
        $SRC/libjpeg-turbo/testimages/*.ppm
RUN rm -rf seed-corpora

COPY build.sh $SRC/
