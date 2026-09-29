import json

import pytest

from webcquisition.case import Case, CaseError, CaseLockedError, resolve_case_dir
from webcquisition.state import AcquisitionState as S
from webcquisition.state import InvalidTransition, check_transition
from webcquisition_common.paths import UnsafePathError, normalize_relpath, safe_join, validate_case_id


def test_create_case_structure(tmp_path):
    c = Case.create(tmp_path / "CASE-2026-001", "CASE-2026-001", operator="Mario")
    assert c.case_id == "CASE-2026-001"
    assert c.state == S.CREATED
    for sub in ("acquired", "logs", "hashes", "report", "metadata"):
        assert (c.dir / sub).is_dir()
    assert (c.dir / "README.txt").is_file()
    assert json.loads((c.dir / "metadata" / "case.json").read_text())["operator"] == "Mario"


def test_case_never_overwritten(tmp_path):
    Case.create(tmp_path / "CASE-1", "CASE-1")
    with pytest.raises(CaseError):
        Case.create(tmp_path / "CASE-1", "CASE-1")


def test_existing_empty_dir_rejected(tmp_path):
    (tmp_path / "CASE-2").mkdir()
    with pytest.raises(CaseError):
        Case.create(tmp_path / "CASE-2", "CASE-2")


def test_folder_name_must_match_case_id(tmp_path):
    with pytest.raises(CaseError):
        Case.create(tmp_path / "ALTRO", "CASE-3")


@pytest.mark.parametrize("bad", ["", "../x", "a/b", "CON", "nul", "x" * 80, "caso con spazi", "-x"])
def test_invalid_case_ids(bad):
    with pytest.raises(ValueError):
        validate_case_id(bad)


def test_lock_prevents_concurrent_use(tmp_path):
    c = Case.create(tmp_path / "CASE-4", "CASE-4")
    with c.lock():
        with pytest.raises(CaseLockedError):
            with Case(c.dir).lock():
                pass
    with c.lock():  # rilasciato
        pass


def test_not_a_case(tmp_path):
    with pytest.raises(CaseError):
        Case(tmp_path)


def test_resolve_case_dir(tmp_path):
    assert resolve_case_dir(str(tmp_path / "X"), None, None) == tmp_path / "X"
    assert resolve_case_dir(None, "CASE-5", str(tmp_path)) == tmp_path / "CASE-5"
    with pytest.raises(CaseError):
        resolve_case_dir(None, None, None)


def test_state_transitions(tmp_path):
    check_transition(S.CREATED, S.PREPARING)
    check_transition(S.PREPARING, S.FINALIZING)
    check_transition(S.VERIFYING, S.INCOMPLETE)
    for bad in ((S.CREATED, S.COMPLETED), (S.COMPLETED, S.ACQUIRING), (S.FAILED, S.PREPARING),
                (S.ACQUIRING, S.COMPLETED)):
        with pytest.raises(InvalidTransition):
            check_transition(*bad)
    c = Case.create(tmp_path / "CASE-6", "CASE-6")
    c.set_state(S.PREPARING, "test")
    assert Case(c.dir).state == S.PREPARING
    assert [h["state"] for h in Case(c.dir).data["state_history"]] == ["CREATED", "PREPARING"]


@pytest.mark.parametrize("bad", ["../a", "/etc/passwd", "C:\\x", "a/../b", "\\\\srv\\x", "a\x00b"])
def test_unsafe_paths(tmp_path, bad):
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, bad)


def test_normalize_relpath():
    assert normalize_relpath("network\\capture.pcapng") == "network/capture.pcapng"
