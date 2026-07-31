#!/bin/bash -eu
# Curated build recipe for libxml2 / ARVO 1972.
#
# Verbatim from the ARVO image's /src/build.sh except for the configure flags:
#
#   --without-python  libxml2's 2017 Python bindings do not compile against the
#                     base image's Python 3.11 headers (python/libxml.c and
#                     types.c fail with "expected '(' after 'if'" as old macros
#                     expand badly). Unreachable from the fuzz target; modern
#                     OSS-Fuzz builds libxml2 the same way.
#
#   --without-zlib    RESTORES the historical configuration rather than deviating
#   --without-lzma    from it. The ARVO image ships neither zlib.h nor lzma.h and
#                     `nm -u` on its binary shows zero inflate/lzma symbols, so
#                     the historical build had both off. The modern base image
#                     does ship zlib headers, so configure would otherwise turn
#                     compression ON and then fail to link -- the historical link
#                     line below carries no -lz/-llzma.
#
# Deviations are tracked in meta.json so they can be reported alongside results.
#
# NOTE: `-lFuzzingEngine` resolves to /usr/lib/libFuzzingEngine.a, which
# compile_afl overwrites with AFL++'s libAFLDriver.a. That is the engine swap --
# the link line itself is unchanged from the historical build.

CONFIGURE_ARGS="--without-python --without-zlib --without-lzma"

./autogen.sh $CONFIGURE_ARGS
./configure $CONFIGURE_ARGS
make -j$(nproc) clean
make -j$(nproc) all

for fuzzer in libxml2_xml_read_memory_fuzzer libxml2_xml_regexp_compile_fuzzer; do
  $CXX $CXXFLAGS -std=c++11 -Iinclude/ \
    $SRC/$fuzzer.cc -o $OUT/$fuzzer \
    -lFuzzingEngine .libs/libxml2.a
done

cp $SRC/*.dict $SRC/*.options $OUT/
