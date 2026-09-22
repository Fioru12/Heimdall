import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.fim import build_baseline, load_baseline, save_baseline, scan


def test_fim_baseline_and_clean_scan(tmp_path):
    d = tmp_path / "etc"
    d.mkdir()
    (d / "a.conf").write_text("alpha", encoding="utf-8")
    (d / "b.conf").write_text("beta", encoding="utf-8")
    base = build_baseline([str(d)])
    assert len(base) == 2
    bf = tmp_path / "baseline.json"
    save_baseline(base, str(bf))
    assert load_baseline(str(bf)) == base
    assert scan([str(d)], base) == []


def test_fim_detects_new_modified_deleted(tmp_path):
    d = tmp_path / "watch"
    d.mkdir()
    f1 = d / "one.txt"
    f1.write_text("v1", encoding="utf-8")
    base = build_baseline([str(d)])
    # MODIFIED
    f1.write_text("v2", encoding="utf-8")
    # NEW
    (d / "two.txt").write_text("new", encoding="utf-8")
    events = scan([str(d)], base)
    by_status = {e["path"]: e["status"] for e in events}
    assert by_status[str(f1)] == "MODIFIED"
    assert by_status[str(d / "two.txt")] == "NEW"
    # DELETED
    (d / "two.txt").unlink()
    f1.write_text("v1", encoding="utf-8")
    base2 = dict(base)
    base2[str(d / "ghost.txt")] = "0" * 64
    events = scan([str(d)], base2)
    assert any(e["status"] == "DELETED" and e["path"].endswith("ghost.txt") for e in events)


def test_fim_missing_path_fails_loudly(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        build_baseline([str(tmp_path / "nope")])
    with pytest.raises(FileNotFoundError):
        load_baseline(str(tmp_path / "missing.json"))
    with pytest.raises(ValueError):
        build_baseline([])


def test_fim_events_persisted(tmp_path):
    from storage.database import HeimdallDatabase
    db = HeimdallDatabase(db_path=str(tmp_path / "t.db"))
    n = db.save_fim_events([{"path": "/x", "status": "NEW", "detail": "d"}])
    assert n == 1
    assert db.get_fim_events()[0]["status"] == "NEW"
