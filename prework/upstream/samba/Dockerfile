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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:415ccd95bff8714ae7bd5b6989f2cbc159e9715f27284f763ddfae88b5e9997b

RUN git clone https://gitlab.com/samba-team/samba samba

# Deviation A2 (fix-policy): do_build.sh fetches the seed zips at compile time,
# but compile runs with --network none. Fetch the SAME URL here instead; the
# vendored build.sh makes do_build.sh copy this file in place of its wget.
# --no-iri: with the image's empty LANG, wget's IRI handling re-encodes the
# signed CDN redirect (%2A%27%27 -> *'') and the CDN answers 403; the URL and
# the downloaded bytes are unchanged (sha256 matches a host download).
RUN wget --no-iri -O $SRC/seeds.zip 'https://gitlab.com/samba-team/samba-fuzz-seeds/-/jobs/artifacts/master/download?job=zips'

# Upstream samba dropped ubuntu2004 in commit 313a630 (2026-04-08) and
# build_image.sh still has DIST=ubuntu2004 hard-coded. The OSS-Fuzz base-builder
# for this project is Ubuntu 24.04 (see base_os_version in project.yaml), so
# point build_image.sh at the matching ubuntu2404 generated-dist before running.
RUN sed -i 's/^DIST=ubuntu2004/DIST=ubuntu2404/' \
        samba/lib/fuzzing/oss-fuzz/build_image.sh

RUN samba/lib/fuzzing/oss-fuzz/build_image.sh

WORKDIR samba
COPY build.sh $SRC/
