# Copyright 2021 Google LLC
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
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:1dbadefbb28c6bfd796c64d9c2115977deb8f19494533cc5a3b724c3441df23d
RUN apt-get update && apt-get install -y make pkg-config
RUN git clone --depth 1 https://github.com/tink-crypto/tink-cc

# [deviation A2] Pre-fetch the archives tink-cc's CMake (cmake/TinkWorkspace.cmake,
# cmake/TinkBoringSSL.cmake) downloads with FetchContent at configure time, at the exact
# URLs and SHA256s it declares, so `compile` can run with --network none. build.sh points
# FetchContent at these copies via FETCHCONTENT_SOURCE_DIR_<NAME>.
RUN set -eux; mkdir -p $SRC/tink_deps/_dl; cd $SRC/tink_deps/_dl; \
    fetch() { name=$1; url=$2; sha=$3; f=$(basename "$url"); \
      curl -fsSL --retry 5 -o "$f" "$url"; echo "$sha  $f" | sha256sum -c -; \
      mkdir x; (cd x && cmake -E tar xf "../$f"); \
      if [ "$(ls -A x | wc -l)" = 1 ] && [ -d "x/$(ls -A x)" ]; then mv "x/$(ls -A x)" "$SRC/tink_deps/$name"; rmdir x; else mv x "$SRC/tink_deps/$name"; fi; }; \
    fetch abseil https://github.com/abseil/abseil-cpp/releases/download/20260817.0/abseil-cpp-20260817.0.tar.gz f7e05179df39c45434cad433f5783840bb3788ef322976f9138bc6b72b3a107d; \
    fetch tink_boringssl https://github.com/google/boringssl/releases/download/0.20260929.0/boringssl-0.20260929.0.tar.gz 04da9ba0664e0a7f028e961c38d604f2cc6dac852a84ca0e51dc1fa051d4c8fe; \
    fetch protobuf https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protobuf-36.2.zip ec61440905b46d42dc58ce7b490f0469263a21f93407f741c97e9b6b09533eb6; \
    cd $SRC/tink_deps; rm -rf _dl; ls $SRC/tink_deps

RUN mkdir $SRC/tink-cc/fuzzing
COPY fuzzing_CMake $SRC/tink-cc/fuzzing/CMakeLists.txt
COPY tink_encrypt_decrypt_fuzzer.cc $SRC/tink-cc/fuzzing/tink_encrypt_decrypt_fuzzer.cc
COPY build.sh $SRC/

WORKDIR tink-cc
