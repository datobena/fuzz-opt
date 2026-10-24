"""One afl-fuzz launch builder for every fuzzing container.

Used by phase3_runner._launch_container (trial start, relaunch, hot-swap,
early-death restart), tools/preflight_online.smoke and
lib/afl_mutation_capture. Before this module each of them spelled out its own
argv and env, and they had already drifted.

Two flavours, keyed on the manifest entry:

* ARVO (``entry.get("kind") != "fuzzbench"``): exactly the argv/env the callers
  emitted before this module existed, flag for flag and in each caller's own
  order (``arvo_order``). tests/test_fuzzbench_run.py pins that byte-for-byte.

* FuzzBench (``kind == "fuzzbench"``): FuzzBench's aflplusplus runner, i.e.
  fuzzers/afl/fuzzer.py prepare_fuzz_environment + run_afl_fuzz and
  fuzzers/aflplusplus/fuzzer.py fuzz() at FuzzBench 3234e151, plus the runner
  image ENV (fuzzers/aflplusplus/runner.Dockerfile) and WORKDIR /out:

      cwd /out
      /out/afl-fuzz -i <in> -o <out> -m none -t <T> -d
                    [-x /out/afl++.dict] [-c /out/cmplog/<t>] [-x <options dict>]
                    [-s <seed>] [-V <secs>] -- /out/<t> 2147483647

  Deviations, each needed by the experiment's mechanics and nothing else:
    -t config.AFL_TIMEOUT_FLAG (fixed "1000", not "1000+": in AFL++ 4.21a the
       '+' auto-picks down to a 5 ms timeout -- user decision);
    -s <seed> / -V <secs> (deterministic RNG, time-limited campaign);
    AFL_AUTORESUME=1 (hot-swap relaunches resume the same output tree);
    AFL_TESTCACHE_SIZE=50, not 2 (the runner's 2 MB cache lets afl-fuzz spin
       forever once two 1 MiB inputs meet -- see config.FUZZBENCH_AFL_ENV);
    afl-fuzz runs in the FuzzBench *builder* image, not the runner image (same
       Ubuntu 20.04 / glibc 2.31 and the same /out), so the runner's PATH and
       LD_LIBRARY_PATH are passed explicitly.
  ``-x``/``-c`` are added only when the file exists in the host bin dir, as
  FuzzBench does. ``-d`` is a no-op in 4.21a (deterministic stays on); it is
  kept because FuzzBench passes it.
"""
from __future__ import annotations

import configparser
import os
import shlex
from dataclasses import dataclass, field

import config

# Where the bin dir is mounted inside every fuzzing container.
OUT = "/out"


def is_fuzzbench(entry: dict | None) -> bool:
    return bool(entry) and entry.get("kind") == "fuzzbench"


# --------------------------------------------------------------------------- #
# FuzzBench /out set
# --------------------------------------------------------------------------- #
def fuzzbench_out_set(fuzz_target: str) -> list[str]:
    """Files (relative to /out) that make up one FuzzBench build's fuzzing
    input: the target, its CmpLog build and the dict2file dictionary. A hot swap
    must replace all of them together; a relaunch mixing a new target with an
    old cmplog binary would run CmpLog on code the target no longer has."""
    return [fuzz_target, os.path.join("cmplog", fuzz_target), "afl++.dict"]


def fuzzbench_options_dict(host_bin_dir: str, fuzz_target: str) -> str | None:
    """FuzzBench fuzzers/utils.py get_dictionary_path, evaluated on the host
    bin dir. Returns the dictionary's path RELATIVE to /out, or None.

    `<t>.dict` wins; otherwise the first `dict = <path>` key in any section of
    `<t>.options` (path relative to /out). Like FuzzBench, an unparsable
    options file or a dict= naming a missing file is an error, not a skip:
    FuzzBench's trial would die on it too.
    """
    target = os.path.join(host_bin_dir, fuzz_target)
    if os.path.exists(target + ".dict"):
        return fuzz_target + ".dict"
    options = target + ".options"
    if not os.path.exists(options):
        return None
    cp = configparser.ConfigParser()
    with open(options, "r", encoding="utf-8") as fh:
        try:
            cp.read_file(fh)
        except configparser.Error as e:
            raise ValueError(f"Failed to parse fuzzer options file: {options}") from e
    for section in cp.sections():
        for key, value in cp.items(section):
            if key == "dict":
                # FuzzBench: os.path.join(dirname(/out/<t>), value). An absolute
                # value under /out maps back to the same file in the host dir.
                rel = os.path.normpath(
                    os.path.relpath(value, OUT) if os.path.isabs(value) else value)
                if not os.path.exists(os.path.join(host_bin_dir, rel)):
                    raise ValueError(f"Bad dictionary path in options file: {options}")
                return rel
    return None


# --------------------------------------------------------------------------- #
# Launch description
# --------------------------------------------------------------------------- #
@dataclass
class AflLaunch:
    """afl-fuzz argv + environment + cwd for one container.

    ``afl_env`` holds the AFL_* knobs, ``sanitizer_env`` ASAN/UBSAN_OPTIONS and
    ``extra_env`` everything else (PATH, LD_LIBRARY_PATH). They are kept apart
    only so the ARVO callers can keep rendering them exactly as before.
    """
    kind: str
    argv: list[str]
    afl_env: list[tuple[str, str]]
    sanitizer_env: list[tuple[str, str]]
    extra_env: list[tuple[str, str]] = field(default_factory=list)
    workdir: str | None = None
    flags: dict = field(default_factory=dict)

    @property
    def env(self) -> list[tuple[str, str]]:
        return [*self.afl_env, *self.sanitizer_env, *self.extra_env]

    def docker_env_args(self) -> list[str]:
        out: list[str] = []
        for k, v in self.env:
            out += ["-e", f"{k}={v}"]
        return out

    def docker_workdir_args(self) -> list[str]:
        return ["-w", self.workdir] if self.workdir else []

    def shell(self) -> str:
        """The argv as a shell fragment. ARVO argv contains no shell
        metacharacters and is emitted unquoted, as the callers always did."""
        if self.kind == "fuzzbench":
            return " ".join(shlex.quote(a) for a in self.argv)
        return " ".join(self.argv)

    def record(self) -> dict:
        """What provenance stores: the full flag and env set."""
        return {
            "kind": self.kind,
            "argv": list(self.argv),
            "env": dict(self.env),
            "workdir": self.workdir,
            "flags": dict(self.flags),
        }


# Caller-specific flag orders for ARVO (each caller's pre-existing argv).
ARVO_ORDER_RUNNER = ("i", "o", "V", "s", "m", "t")
ARVO_ORDER_PREFLIGHT = ("i", "o", "V", "m", "t")
ARVO_ORDER_CAPTURE = ("V", "s", "m", "t", "i", "o")


def _arvo_afl_env(autoresume: bool) -> list[tuple[str, str]]:
    env = [("AFL_NO_AFFINITY", "1"), ("AFL_SKIP_CPUFREQ", "1"),
           ("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")]
    if autoresume:
        env.append(("AFL_AUTORESUME", "1"))
    return env


def _fuzzbench_afl_env(autoresume: bool) -> list[tuple[str, str]]:
    env = [(k, v) for k, v in config.FUZZBENCH_AFL_ENV]
    if autoresume:
        env.append(("AFL_AUTORESUME", "1"))
    return env


def _sanitizer_env() -> list[tuple[str, str]]:
    # FuzzBench's fuzz-run set (common/sanitizer.py). No LSAN_OPTIONS: afl-fuzz
    # sets it itself, as under FuzzBench.
    return [("ASAN_OPTIONS", config.FUZZ_ASAN_OPTIONS),
            ("UBSAN_OPTIONS", config.FUZZ_UBSAN_OPTIONS)]


def build_afl_launch(
    *, entry: dict | None, host_bin_dir: str | None, fuzz_target: str,
    input_dir: str, output_dir: str, duration: int | None = None,
    seed: int | None = None, autoresume: bool = True,
    arvo_order: tuple[str, ...] = ARVO_ORDER_RUNNER,
) -> AflLaunch:
    """Build the afl-fuzz launch for one container.

    ``host_bin_dir`` is the HOST directory mounted at /out; for FuzzBench it is
    inspected to decide which optional flags (-x, -c, options dict) exist.
    """
    target = f"{OUT}/{fuzz_target}"
    if not is_fuzzbench(entry):
        vals = {
            "i": ["-i", input_dir], "o": ["-o", output_dir],
            "V": ["-V", str(duration)] if duration is not None else [],
            "s": ["-s", str(seed)] if seed is not None else [],
            "m": ["-m", "none"], "t": ["-t", str(config.AFL_TIMEOUT_FLAG)],
        }
        argv = [f"{OUT}/afl-fuzz"]
        for k in arvo_order:
            argv += vals[k]
        argv += ["--", target]
        return AflLaunch(
            kind="arvo", argv=argv, afl_env=_arvo_afl_env(autoresume),
            sanitizer_env=_sanitizer_env(),
            flags={"-m": "none", "-t": config.AFL_TIMEOUT_FLAG})

    bin_dir = host_bin_dir or ""
    argv = [f"{OUT}/afl-fuzz", "-i", input_dir, "-o", output_dir,
            "-m", "none", "-t", str(config.AFL_TIMEOUT_FLAG), "-d"]
    flags: dict = {"-m": "none", "-t": config.AFL_TIMEOUT_FLAG, "-d": True}
    # aflplusplus fuzz(): -x ./afl++.dict, then -c <cmplog>, only if present.
    has_dict = bool(bin_dir) and os.path.isfile(os.path.join(bin_dir, "afl++.dict"))
    has_cmplog = bool(bin_dir) and os.path.isfile(
        os.path.join(bin_dir, "cmplog", fuzz_target))
    if has_dict:
        argv += ["-x", f"{OUT}/afl++.dict"]
    if has_cmplog:
        argv += ["-c", f"{OUT}/cmplog/{fuzz_target}"]
    # afl run_afl_fuzz(): the benchmark's own dictionary, last.
    opt_dict = fuzzbench_options_dict(bin_dir, fuzz_target) if bin_dir else None
    if opt_dict:
        argv += ["-x", f"{OUT}/{opt_dict}"]
    if seed is not None:
        argv += ["-s", str(seed)]
    if duration is not None:
        argv += ["-V", str(duration)]
    argv += ["--", target, config.FUZZBENCH_PERSISTENT_ARG]
    flags.update({
        "afl++.dict": f"{OUT}/afl++.dict" if has_dict else None,
        "cmplog": f"{OUT}/cmplog/{fuzz_target}" if has_cmplog else None,
        "options_dict": f"{OUT}/{opt_dict}" if opt_dict else None,
        "target_args": [config.FUZZBENCH_PERSISTENT_ARG],
        "benchmark_type": (entry or {}).get("type"),
        "fuzzbench_dir": (entry or {}).get("fuzzbench_dir"),
    })
    return AflLaunch(
        kind="fuzzbench", argv=argv, afl_env=_fuzzbench_afl_env(autoresume),
        sanitizer_env=_sanitizer_env(),
        extra_env=[("LD_LIBRARY_PATH", config.FUZZBENCH_LD_LIBRARY_PATH),
                   ("PATH", config.FUZZBENCH_RUN_PATH)],
        workdir=OUT, flags=flags)


def shim_compiler(entry: dict | None) -> str:
    """C compiler for the mutation-capture shim inside the fuzzing container.

    ARVO prework images carry clang-18. The FuzzBench builder image
    (base-builder@87ca1e9e) has clang-15 at /usr/local/bin/clang and no
    clang-18, so the old hardcoded `clang-18` failed there and every round
    ended with no mutations.
    """
    if is_fuzzbench(entry):
        return str(config.FUZZBENCH_SHIM_CC)
    return f"clang-{getattr(config, 'PREWORK_LLVM_VERSION', 18)}"


def fuzzbench_opt_level(entry: dict | None) -> str | None:
    """The -O level FuzzBench's utils.set_compilation_flags gives this
    benchmark type (-O1 bug, -O3 coverage). BUILD_OPT_LEVEL never applies."""
    if not is_fuzzbench(entry):
        return None
    return config.FUZZBENCH_OPT_LEVEL.get(str(entry.get("type") or "coverage"))
