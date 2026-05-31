FROM gcr.io/oss-fuzz-base/base-runner:latest

ARG PROJECT
ARG CVE
ARG VARIANT
ARG EXPERIMENT_ID
ARG FUZZ_TARGET

LABEL org.opencontainers.image.title="phase3-${PROJECT}-${VARIANT}"
LABEL org.opencontainers.image.description="Phase3 ${VARIANT} fuzzer image for ${PROJECT} ${CVE}"
LABEL org.opencontainers.image.source-experiment="${EXPERIMENT_ID}"
LABEL org.opencontainers.image.fuzz-target="${FUZZ_TARGET}"

ENV PROJECT="${PROJECT}"
ENV CVE="${CVE}"
ENV VARIANT="${VARIANT}"
ENV EXPERIMENT_ID="${EXPERIMENT_ID}"
ENV FUZZ_TARGET="${FUZZ_TARGET}"
ENV DURATION_SECONDS="21600"
ENV BASE_SEED="1337"
ENV SEED_MULTIPLIER="1000"
ENV RSS_LIMIT_MB="8192"
ENV MALLOC_LIMIT_MB="8192"
ENV CORPUS_DIR="/corpus"
ENV CRASHES_DIR="/crashes"

COPY out/ /out/
COPY seed-corpus/ /seed-corpus/
COPY poc/ /poc/
COPY entrypoint.sh /usr/local/bin/phase3-fuzzer

RUN chmod +x /usr/local/bin/phase3-fuzzer \
    && chmod -R a+rX /out /seed-corpus /poc \
    && chmod +x "/out/${FUZZ_TARGET}"

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/phase3-fuzzer"]
