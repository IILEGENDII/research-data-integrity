import json

import pytest

from research_integrity.inventory import scan
from research_integrity.manifest import (
    canonical,
    load_manifest,
    make_payload,
    parse,
    save_manifest,
    validate,
)
from research_integrity.models import InputError


def envelope(*paths):
    return {
        "payload": {
            "schema_version": 1,
            "algorithm": "sha256",
            "created_at": "2026-01-01T00:00:00Z",
            "files": [{"path": path, "size": 0, "sha256": "0" * 64} for path in paths],
        },
        "signature": None,
    }


def test_roundtrip(tmp_path):
    assert canonical({"z": "é", "a": 1}) == b'{"a":1,"z":"\\u00e9"}'
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "x").touch()
    value = {"payload": make_payload(scan(tmp_path / "data")), "signature": None}
    path = tmp_path / "baseline"
    save_manifest(path, value)
    assert load_manifest(path) == value
    with pytest.raises(InputError):
        save_manifest(path, envelope())
    assert load_manifest(path) == value


@pytest.mark.parametrize(
    "paths",
    [
        ("",),
        (".",),
        ("x/../y",),
        ("/root",),
        ("D:foo",),
        ("C:/x",),
        ("\\\\host\\x",),
        ("a\\b",),
        ("a//b",),
        ("a/",),
        ("a\x00",),
        ("con.txt",),
        ("file.",),
        ("a:b",),
        ("a", "a"),
        ("z", "a"),
        ("A/y", "a/z"),
        ("file", "file/x"),
        ("e\u0301",),
        ("x" * 256,),
        ("bad\udfff",),
    ],
)
def test_invalid_paths(paths):
    with pytest.raises(InputError):
        validate(envelope(*paths))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("size", -1),
        ("size", True),
        ("size", 0.1),
        ("size", 2**63),
        ("sha256", "ab"),
        ("sha256", "A" * 64),
        ("sha256", None),
        ("extra", 1),
    ],
)
def test_bad_entry(field, value):
    doc = envelope("a")
    doc["payload"]["files"][0][field] = value
    with pytest.raises(InputError):
        parse(json.dumps(doc).encode())


@pytest.mark.parametrize(
    "data",
    [
        b"\xff",
        b"{",
        b'{"payload":0,"payload":1}',
        b'{"v":NaN}',
        b'{"v":Infinity}',
        b"[" * 40,
        b'"' + b"a" * 25000 + b'"',
        b"{}",
    ],
)
def test_bad_json(data):
    with pytest.raises(InputError):
        parse(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("algorithm", "md5"),
        ("created_at", "2026-02-31T00:00:00Z"),
        ("files", {}),
        ("new", 1),
    ],
)
def test_bad_payload(field, value):
    doc = envelope()
    doc["payload"][field] = value
    with pytest.raises(InputError):
        validate(doc)


def test_limits():
    data = canonical(envelope("a"))
    with pytest.raises(InputError):
        parse(data, max_entries=0)
    with pytest.raises(InputError):
        parse(data, max_bytes=8)
