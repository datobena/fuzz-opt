#!/bin/bash -eu
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

export CFLAGS="$CFLAGS -Wno-error=strict-prototypes -Wno-error=format-truncation"

if [ -f /usr/local/bin/clang-22 ]; then
  export CFLAGS="${CFLAGS} -Wno-error=uninitialized-const-pointer -Wno-error=sometimes-uninitialized"
fi
# Deviation A2 (fix-policy): compile runs with --network none, so the seed zip
# is fetched in the Dockerfile (same URL) to $SRC/seeds.zip. Replace ONLY the
# two-line `wget ... -O seeds.zip` command in do_build.sh with a copy of it;
# every other line of the glue is unchanged. Fail if the line is not found.
DO_BUILD=lib/fuzzing/oss-fuzz/do_build.sh
grep -q '^wget https://gitlab.com/samba-team/samba-fuzz-seeds/-/jobs/artifacts/master/download?job=zips \\$' "$DO_BUILD"
sed -i '/^wget https:\/\/gitlab.com\/samba-team\/samba-fuzz-seeds\/-\/jobs\/artifacts\/master\/download?job=zips \\$/{N;s/.*/cp $SRC\/seeds.zip seeds.zip/}' "$DO_BUILD"
grep -qx 'cp $SRC/seeds.zip seeds.zip' "$DO_BUILD"

# The real script is maintained in the Samba repo
exec lib/fuzzing/oss-fuzz/build_samba.sh
