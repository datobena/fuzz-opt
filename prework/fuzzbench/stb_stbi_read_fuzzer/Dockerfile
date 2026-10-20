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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd

RUN apt-get update && \
    apt-get install -y \
        wget tar

# This project does not have any release/tag.
RUN git clone \
        https://github.com/nothings/stb.git

RUN mkdir $SRC/stbi # CIFuzz workaround

RUN wget -O \
    $SRC/stbi/gif.tar.gz https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/imagetestsuite/imagetestsuite-gif-1.00.tar.gz
RUN wget -O \
    $SRC/stbi/jpg.tar.gz https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/imagetestsuite/imagetestsuite-jpg-1.00.tar.gz
RUN wget -O \
    $SRC/stbi/bmp.zip http://entropymine.com/jason/bmpsuite/releases/bmpsuite-2.6.zip
# fuzz-opt deviation: pin tga_test_files to 606ced9f266727f248be4a45b86aa0963334b853
# (2020-03-21, nearest to benchmark commit_date) -- upstream clones HEAD (master.zip).
RUN wget -O \
    $SRC/stbi/tga.zip https://github.com/richgel999/tga_test_files/archive/606ced9f266727f248be4a45b86aa0963334b853.zip

# fuzz-opt deviation: pin mirrorer/afl to 2fb5a3482ec27b593c57258baae7089ebdc89043
# (2017-11-05, nearest to benchmark commit_date; archived repo) -- upstream clones HEAD (master).
RUN wget -O \
    $SRC/stbi/gif.dict https://raw.githubusercontent.com/mirrorer/afl/2fb5a3482ec27b593c57258baae7089ebdc89043/dictionaries/gif.dict

# Maintain compatibility with master branch until a new release
RUN cp \
    $SRC/stbi/gif.tar.gz \
    $SRC/stbi/jpg.tar.gz \
    $SRC/stbi/bmp.zip \
    $SRC/stbi/gif.dict \
    $SRC/stb

WORKDIR stb
COPY build.sh $SRC/
