import json
from pathlib import Path
import bootstrap_server as bs
from prework.build_image import DEFINITION_LABEL, definition_hash

def _target(tmp_path, project="PcapPlusPlus", arvo_id=22232):
    t = tmp_path / f"{project}-arvo-{arvo_id}"; t.mkdir()
    (t / "Dockerfile").write_text("FROM x\n")
    (t / "meta.json").write_text(json.dumps({"project": project, "arvo_id": arvo_id}))
    return t

def test_check_images_uses_the_lowercase_tag(tmp_path, monkeypatch):
    t = _target(tmp_path)
    monkeypatch.setattr(bs, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(bs, "_image_exists", lambda img: img == "bench-aflpp/pcapplusplus-arvo-22232")
    monkeypatch.setattr(bs, "image_definition_label", lambda img: definition_hash(t))
    rows = bs.check_images()
    names = {r[0]: r[1] for r in rows}
    assert names["bench-aflpp/pcapplusplus-arvo-22232"] == bs.OK

def test_image_state_classifies_all_four_cases(tmp_path):
    t = _target(tmp_path)
    h = definition_hash(t)
    assert bs.image_state("x", t, exists=lambda i: False, label=lambda i: None) == bs.MISSING
    assert bs.image_state("x", t, exists=lambda i: True, label=lambda i: None) == bs.UNVERIFIED
    assert bs.image_state("x", t, exists=lambda i: True, label=lambda i: "0" * 64) == bs.STALE
    assert bs.image_state("x", t, exists=lambda i: True, label=lambda i: h) == bs.OK

def test_build_rebuilds_missing_and_stale_but_not_unverified_by_default(tmp_path, monkeypatch):
    t = _target(tmp_path)
    monkeypatch.setattr(bs, "TARGETS_DIR", tmp_path)
    built = []
    monkeypatch.setattr(bs.subprocess, "run", lambda cmd, **kw: built.append(cmd) or type("R", (), {"returncode": 0})())
    for state, expect in [(bs.MISSING, 1), (bs.STALE, 1), (bs.UNVERIFIED, 0), (bs.OK, 0)]:
        built.clear()
        monkeypatch.setattr(bs, "image_state", lambda tag, td, **kw: state)
        bs.build_target_images(str(tmp_path / "work"))
        assert len(built) == expect, state

def test_rebuild_unverified_flag_rebuilds_unlabeled_images(tmp_path, monkeypatch):
    _target(tmp_path)
    monkeypatch.setattr(bs, "TARGETS_DIR", tmp_path)
    built = []
    monkeypatch.setattr(bs.subprocess, "run", lambda cmd, **kw: built.append(cmd) or type("R", (), {"returncode": 0})())
    monkeypatch.setattr(bs, "image_state", lambda tag, td, **kw: bs.UNVERIFIED)
    bs.build_target_images(str(tmp_path / "work"), rebuild_unverified=True)
    assert len(built) == 1

def test_report_prints_a_mark_for_every_state(capsys):
    assert bs.report("t", [("a", bs.STALE, ""), ("b", bs.UNVERIFIED, "")]) is False
    out = capsys.readouterr().out
    assert "STALE" in out and "unver" in out
