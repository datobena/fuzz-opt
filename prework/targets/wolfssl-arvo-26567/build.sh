#!/bin/bash -eu
# Curated build recipe for wolfssl / ARVO 26567.
#
# The ARVO build.sh has two halves. This keeps the first and drops the second:
#
#  KEPT   the nested wolf-ssl-ssh-fuzzers build, which produces our target
#         (fuzzer-wolfssl-rsa). It runs ./configure with no hardcoded compiler
#         and sets LIBFUZZER_A_PATH="$LIB_FUZZING_ENGINE", so compile_afl's
#         afl-clang-fast and libAFLDriver.a are both picked up unmodified.
#
#  DROPPED the trailing fuzz-targets build. It runs
#              ./configure ... CC="clang"
#         which OVERRIDES afl-clang-fast and would produce an uninstrumented
#         library -- a target that fuzzes at full speed while recording no
#         coverage at all. That step builds only the pem_cert target, which this
#         benchmark does not use.
#
# Deviations are tracked in meta.json so they can be reported with results.

# clang 18 rejects wolfcrypt/blake2-int.h with a HARD error (not a suppressible
# warning): "size of array element of type 'blake2s_state' (181 bytes) isn't a
# multiple of its alignment (32 bytes)". clang 12, which the ARVO image shipped,
# accepted it.
#
# blake2 is a hash module, independent of RSA; our target is fuzzer-wolfssl-rsa.
# Dropping the two blake2 feature flags is preferred over patching
# blake2-int.h, which would mean editing the vulnerable source itself.
#
# CAVEAT worth stating: changing a library's feature set changes its binary and
# heap layout, and this bug is a heap-buffer-overflow -- detection is not
# layout-independent in principle. The PoC verification in prework/verify.py is
# what settles it empirically; if the bug stops reproducing, the target is
# dropped rather than kept with a workaround.
NEW_SRC=$SRC/wolf-ssl-ssh-fuzzers/oss-fuzz/projects/wolf-ssl-ssh/
cp -R $SRC/wolfssl/ $NEW_SRC
cp -R $SRC/wolfssh/ $NEW_SRC
cp -R $SRC/fuzzing-headers/ $NEW_SRC
sed -i 's/ --enable-blake2 --enable-blake2s//' "$NEW_SRC/build_wolfssl_fuzzers.sh"

OSS_FUZZ_BUILD=1 SRC="$NEW_SRC" $NEW_SRC/build.sh

# Fail loudly rather than let prework proceed to a PoC replay against a target
# that was never produced.
test -x "$OUT/fuzzer-wolfssl-rsa" || {
  echo "ERROR: fuzzer-wolfssl-rsa not produced by the nested build" >&2
  exit 1
}
