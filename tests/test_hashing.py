import hashlib

import pytest

from webcquisition_common.hashing import (
    build_manifest,
    find_unexpected,
    format_sha256sums,
    parse_sha256sums,
    sha256_file,
    verify_entries,
)


def _tree(tmp_path):
    (tmp_path / "network").mkdir()
    (tmp_path / "network" / "a.pcapng").write_bytes(b"abc")
    (tmp_path / "tls").mkdir()
    (tmp_path / "tls" / "sslkeylog.log").write_bytes(b"")
    (tmp_path / "README.txt").write_text("x")
    return tmp_path


def test_sha256_file(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"x" * 3_000_000)
    digest, size = sha256_file(p)
    assert digest == hashlib.sha256(b"x" * 3_000_000).hexdigest() and size == 3_000_000


def test_manifest_structure(tmp_path):
    m = build_manifest(_tree(tmp_path), exclude=["README.txt"])
    assert m["algorithm"] == "SHA-256"
    paths = [f["path"] for f in m["files"]]
    assert paths == sorted(paths) and "README.txt" not in paths
    f = next(f for f in m["files"] if f["path"] == "network/a.pcapng")
    assert f["size"] == 3 and f["sha256"] == hashlib.sha256(b"abc").hexdigest() and "mtime_utc" in f


def test_sha256sums_roundtrip(tmp_path):
    m = build_manifest(_tree(tmp_path))
    text = format_sha256sums(m["files"])
    parsed = parse_sha256sums(text)
    assert parsed["network/a.pcapng"] == hashlib.sha256(b"abc").hexdigest()
    with pytest.raises(ValueError):
        parse_sha256sums("zzz  file")


def test_verify_detects_mismatch_and_missing(tmp_path):
    root = _tree(tmp_path)
    entries = build_manifest(root)["files"]
    assert verify_entries(root, entries) == []
    (root / "network" / "a.pcapng").write_bytes(b"abd")
    (root / "README.txt").unlink()
    issues = {(p["path"], p["issue"]) for p in verify_entries(root, entries)}
    assert ("network/a.pcapng", "hash_mismatch") in issues
    assert ("README.txt", "missing") in issues


def test_find_unexpected(tmp_path):
    root = _tree(tmp_path)
    entries = build_manifest(root)["files"]
    (root / "intruso.txt").write_text("?")
    assert find_unexpected(root, entries) == ["intruso.txt"]
