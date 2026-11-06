from lib import target_kind as tk


def test_kinds_and_defaults():
    assert tk.kind_of({"project": "x"}) == "arvo" and tk.kind_of(None) == "arvo"
    assert tk.kind_of({"kind": "fuzzbench"}) == "fuzzbench"
    assert tk.kind_of({"kind": "upstream"}) == "upstream" and tk.is_upstream({"kind": "upstream"})
    assert tk.has_poc({"project": "x"}) and not tk.has_poc({"kind": "fuzzbench"}) and not tk.has_poc({"kind": "upstream"})
    assert tk.is_upstream_image("bench-upstream/libssh") and not tk.is_upstream_image("bench-aflpp/libxml2-arvo-1972")
    assert tk.sanitizer_of({}) == "address" and tk.sanitizer_of({"sanitizer": "memory"}) == "memory"
    assert tk.language_of({}) == "c++" and tk.language_of({"language": "c"}) == "c"
