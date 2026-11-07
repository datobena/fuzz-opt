"""Verdict logic of tools/upstream_ccache_equivalence.py (no docker)."""
import importlib.util
import struct
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "upstream_ccache_equivalence", REPO / "tools" / "upstream_ccache_equivalence.py")
eq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(eq)


def _elf(sections):
    names = b"\0" + b"".join(n.encode() + b"\0" for n, _f, _b in sections) + b".shstrtab\0"
    body, offs = b"", []
    for _n, _f, data in sections:
        offs.append(64 + len(body))
        body += data
    stroff = 64 + len(body)
    body += names
    shoff = 64 + len(body)
    shdrs = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    pos = 1
    for (n, f, data), o in zip(sections, offs):
        shdrs += struct.pack("<IIQQQQIIQQ", pos, 1, f, 0, o, len(data), 0, 0, 1, 0)
        pos += len(n) + 1
    shdrs += struct.pack("<IIQQQQIIQQ", pos, 3, 0, 0, stroff, len(names), 0, 0, 1, 0)
    hdr = bytearray(64)
    hdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", hdr, 0x28, shoff)
    struct.pack_into("<HHH", hdr, 0x3A, 64, len(sections) + 2, len(sections) + 1)
    return bytes(hdr) + body + shdrs


def _bin(host=b"3fa2b1c0d9e8", code=b"\x90" * 64):
    return _elf([(".text", 0x6, code),
                 (".rodata", 0x2, b"\0hello\0Linux " + host + b" 6.8\0tail\0")])


def _out(tmp_path, name, **bins):
    d = tmp_path / name
    d.mkdir()
    for n, b in bins.items():
        (d / n).write_bytes(b)
    (d / "seed_corpus.zip").write_bytes(b"PK not elf")   # non-ELF is ignored
    return d


GOOD = {"used": True, "hits": 5, "misses": 0}
COLD = {"used": True, "hits": 0, "misses": 5}
STATS = {"C0": COLD, "W0": GOOD, "WC": GOOD, "WH": GOOD}


def _pairs(tmp_path, *, cached=None, noise=None):
    """P0/C0/W0/PC/WC/PH/WH all built from `_bin()` unless `cached` overrides the
    cached builds."""
    base = _bin()
    mk = lambda n, b: _out(tmp_path, n, fuzz_a=b, fuzz_b=base)  # noqa: E731
    outs = {k: mk(k, base) for k in ("P0", "PC", "PH")}
    for k in ("C0", "W0", "WC", "WH"):
        outs[k] = mk(k, cached if cached is not None else base)
    pairs = {f"{a}_vs_{b}": eq.compare_outs(outs[a], outs[b], noise)
             for a, b in (("P0", "C0"), ("P0", "W0"), ("PC", "WC"), ("PH", "WH"))}
    return pairs


def test_verdict_pass_all_identical(tmp_path):
    p0 = _out(tmp_path, "x0", fuzz_a=_bin())
    p1 = _out(tmp_path, "x1", fuzz_a=_bin())
    noise = eq.learn_noise(p0, p1)
    d = eq.decide_verdict(_pairs(tmp_path), STATS, noise, eq.compare_outs(p0, p1))
    assert d["verdict"] == "pass" and d["pass"] and not d["problems"]


def test_verdict_fail_when_cached_build_unused(tmp_path):
    stats = {**STATS, "W0": {"used": False, "hits": 0, "misses": 0}}
    pairs = _pairs(tmp_path)   # byte-identical, so only the stats can fail it
    d = eq.decide_verdict(pairs, stats)
    assert d["verdict"] == "fail" and any("W0" in p and "not used" in p for p in d["problems"])
    # an absent statslog is unused, not a crash
    assert eq.statslog_for(tmp_path / "nocache")["used"] is False
    # a build with no stats entry at all is unused too
    d = eq.decide_verdict(pairs, {k: v for k, v in STATS.items() if k != "WH"})
    assert d["verdict"] == "fail" and any("WH" in p for p in d["problems"])


def test_verdict_fail_warm_without_hits(tmp_path):
    d = eq.decide_verdict(_pairs(tmp_path), {**STATS, "WC": COLD})
    assert d["verdict"] == "fail" and any("no cache hits" in p for p in d["problems"])


def test_verdict_noise_masked_strings_only(tmp_path):
    p0 = _out(tmp_path, "n0", fuzz_a=_bin(b"3fa2b1c0d9e8"))
    p1 = _out(tmp_path, "n1", fuzz_a=_bin(b"77aa00bb11cc"))
    noise = eq.learn_noise(p0, p1)
    assert noise["fuzz_a"]["ok"]
    pp = eq.compare_outs(p0, p1)
    assert pp["status"] == "differs"
    pairs = _pairs(tmp_path, cached=_bin(b"0123456789ab"), noise=noise)
    assert pairs["P0_vs_W0"]["status"] == "masked"
    d = eq.decide_verdict(pairs, STATS, noise, pp)
    assert d["verdict"] == "pass_noise_masked" and d["pass"] and d["masked"]


def test_verdict_fail_loaded_code_diff(tmp_path):
    p0 = _out(tmp_path, "n0", fuzz_a=_bin(b"3fa2b1c0d9e8"))
    p1 = _out(tmp_path, "n1", fuzz_a=_bin(b"77aa00bb11cc"))
    noise = eq.learn_noise(p0, p1)
    code = _bin(code=b"\x90" * 32 + b"\xcc" * 32)
    pairs = _pairs(tmp_path, cached=code, noise=noise)
    assert pairs["P0_vs_C0"]["status"] == "differs"
    d = eq.decide_verdict(pairs, STATS, noise, eq.compare_outs(p0, p1))
    assert d["verdict"] == "fail" and not d["pass"]


def test_verdict_fail_missing_pair_or_harness_set(tmp_path):
    d = eq.decide_verdict({}, STATS)
    assert d["verdict"] == "fail" and any("missing" in p for p in d["problems"])
    a = _out(tmp_path, "a", h1=_bin(), h2=_bin())
    b = _out(tmp_path, "b", h1=_bin())
    assert eq.compare_outs(a, b)["status"] == "differs"
