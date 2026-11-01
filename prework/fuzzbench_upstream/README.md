# Vendored FuzzBench code (verbatim)

Source: https://github.com/google/fuzzbench at commit
`3234e151d70f6093272a9b4155e68ee57faf986c` (master, used as the parity reference).

Every file here is an unmodified copy of the same path upstream (Apache-2.0, see LICENSE).
Do not edit them. The deviations we need (AFL++ checkout asserted instead of `|| true`,
digest-pinned base-image stage, no in-image `fuzzer_build` RUN, recorded WORKDIR, snapshot
of the image's `/out`) are applied as checked text substitutions by
`prework/fuzzbench_image.py`, so the diff against upstream stays visible in one place.

Copied:

- `fuzzers/utils.py`, `fuzzers/afl/*`, `fuzzers/aflplusplus/*` (the only fuzzer code
  `fuzzers.aflplusplus.fuzzer.build()` imports; it needs nothing from `common/`).
  Upstream has no `fuzzers/__init__.py`; `fuzzers` is a namespace package there too.
- `docker/benchmark-builder/{Dockerfile,checkout_commit.py,fuzzer_build}`.
- `docker/base-image/Dockerfile` and the repo-root `requirements.txt`: the recipe behind
  `gcr.io/fuzzbench/base-image`, which can no longer be pulled anonymously. `prework/fuzzbench_image.py --local-base-image` rebuilds it locally (focal pinned by digest, PyYAML at the file's pin, no google-cloud-cli) as the stage-3 `base-image` source.

The AFL++ pinned by `fuzzers/aflplusplus/builder.Dockerfile` is
`56d5aa3101945e81519a3fac8783d0d8fad82779` (reports itself as 4.21a).
