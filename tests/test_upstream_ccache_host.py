"""Host-side upstream ccache helpers: verified list, stats, noise model."""
import struct

from prework import upstream_ccache as uc

SAMPLE = """\
2026-11-07T10:00:00 direct_cache_hit
2026-11-07T10:00:01 cache_miss
2026-11-07T10:00:02 preprocessed_cache_hit
2026-11-07T10:00:03 direct_cache_hit
2026-11-07T10:00:04 cache_miss
2026-11-07T10:00:05 unsupported_compiler_option
"""


def test_verified_list_modes(tmp_path):
    p = tmp_path / "v.txt"
    p.write_text("# c\n\nfoo\nbar pass_noise_masked  # x\nbaz pass\nqux bogus\na b c\n")
    assert uc.read_verified_modes(p) == {"foo": "pass", "bar": "pass_noise_masked",
                                         "baz": "pass"}
    assert uc.read_verified_modes(tmp_path / "missing") == {}
    assert uc.read_verified_modes() == {}   # shipped list is header-only


def test_parse_stats_absent_means_unused(tmp_path):
    for x in ("", None, "\n", tmp_path / "nope"):
        d = uc.parse_stats(x)
        assert d["used"] is False and d["hits"] == 0 and d["misses"] == 0


def test_parse_stats_hits_and_path(tmp_path):
    d = uc.parse_stats(SAMPLE)
    assert (d["hits"], d["misses"], d["other"], d["used"]) == (3, 2, 1, True)
    f = tmp_path / "statslog"
    f.write_text(SAMPLE)
    assert uc.parse_stats(f)["hits"] == 3
    assert uc.parse_stats(str(f))["misses"] == 2
    assert "results" not in uc.slim_stats(d) and uc.slim_stats(d)["hits"] == 3
    assert uc.parse_stats("2026 unsupported_compiler_option\n")["used"] is False


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


def _w(path, data):
    path.write_bytes(data)
    return path


def _bin(host, md5, code=b"\x90" * 64):
    return _elf([(".text", 0x6, code),
                 (".rodata", 0x2, b"\0hello\0Linux " + host + b" 6.8\0tail\0"),
                 (".debug_line", 0, b"D" * 40 + md5 + b"E" * 40)])


def test_noise_masked_for_strings_and_debug(tmp_path):
    w = lambda n, b: _w(tmp_path / n, b)  # noqa: E731
    p0 = w("p0", _bin(b"3fa2b1c0d9e8", b"\x01" * 16))
    p1 = w("p1", _bin(b"77aa00bb11cc", b"\x02" * 16))
    m = uc.upstream_noise_model(p0, p1)
    assert m["ok"]
    c = w("c", _bin(b"0123456789ab", b"\x03" * 16))
    assert uc.upstream_masked_compare(p0, c, m)["status"] == "masked"


def test_noise_mask_never_masks_loaded_code(tmp_path):
    w = lambda n, b: _w(tmp_path / n, b)  # noqa: E731
    p0 = w("p0", _bin(b"3fa2b1c0d9e8", b"\x01" * 16))
    p1 = w("p1", _bin(b"77aa00bb11cc", b"\x02" * 16))
    m = uc.upstream_noise_model(p0, p1)
    code = w("code", _bin(b"3fa2b1c0d9e8", b"\x01" * 16, code=b"\x90" * 32 + b"\xcc" * 32))
    assert uc.upstream_masked_compare(p0, code, m)["status"] == "differs"
    q1 = w("q1", _bin(b"3fa2b1c0d9e8", b"\x01" * 16, code=b"\x90" * 32 + b"\xcc" * 32))
    bad = uc.upstream_noise_model(p0, q1)
    assert not bad["ok"] and "not maskable" in bad["why"]
    assert uc.upstream_masked_compare(p0, q1, bad)["status"] == "differs"
