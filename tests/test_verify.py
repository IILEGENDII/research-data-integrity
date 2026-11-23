import json
import os
from importlib import import_module

import pytest

from research_integrity import signing
from research_integrity.cli import main
from research_integrity.models import Issue

verification = import_module("research_integrity.verify")


def test_clean_and_restored(signed_dataset, run_verify):
    root, manifest, public = signed_dataset
    original = manifest.read_bytes()
    frame = root / "frame.bin"
    stamp = frame.stat().st_mtime_ns
    os.utime(frame, ns=(stamp + 1000000000, stamp + 1000000000))
    code, doc = run_verify(*signed_dataset)
    assert code == 0 and doc["summary"]["unchanged"] == 2 and doc["summary"]["bytes_read"] == 7
    assert doc["manifest_trust"] == "verified"
    frame.write_bytes(b"4231")
    code, doc = run_verify(*signed_dataset)
    assert code == 1 and doc["result"] == "differences"
    row = next(r for r in doc["findings"] if r["status"] == "modified")
    assert (
        row["expected_sha256"] != row["observed_sha256"]
        and row["observed_size"] == row["expected_size"] == 4
    )
    frame.write_bytes(b"1234")
    assert run_verify(root, manifest, public)[0] == 0
    assert manifest.read_bytes() == original


def test_combined_differences(signed_dataset, run_verify):
    root, _, _ = signed_dataset
    (root / "checkpoint").rename(root / "later")
    with (root / "frame.bin").open("ab") as f:
        f.write(b"more")
    code, doc = run_verify(*signed_dataset)
    assert code == 1
    assert [(r["path"], r["status"]) for r in doc["findings"]] == [
        ("checkpoint", "missing"),
        ("frame.bin", "modified"),
        ("later", "added"),
    ]


def test_incomplete_precedes_changes(signed_dataset, run_verify, monkeypatch):
    root, _, _ = signed_dataset
    original = verification.scan

    def unreadable(*args, **kwargs):
        result = original(*args, **kwargs)
        result.files.pop("checkpoint")
        result.errors.append(Issue("unreadable", "checkpoint", "Cannot read entry."))
        return result

    monkeypatch.setattr(verification, "scan", unreadable)
    (root / "frame.bin").write_bytes(b"42")
    code, doc = run_verify(*signed_dataset)
    assert code == 2 and doc["summary"]["modified"] == 1 and doc["summary"]["missing"] == 0
    assert doc["errors"][0]["status"] == "unreadable"


def test_trust_before_scan(signed_dataset, run_verify, monkeypatch):
    root, manifest, public = signed_dataset
    monkeypatch.setattr(
        verification, "scan", lambda *a, **kw: pytest.fail("read data before authentication")
    )
    assert run_verify(root, manifest, None, "--allow-unsigned")[0] == 3
    doc = json.loads(manifest.read_text())
    doc["payload"]["files"][0]["size"] += 1
    manifest.write_text(json.dumps(doc))
    code, report = run_verify(root, manifest, public)
    assert code == 3 and report["summary"]["signature_invalid"] == 1
    assert report["summary"]["files_scanned"] == 0 and not report["findings"]
    doc.pop("signature")
    manifest.write_text(json.dumps(doc))
    assert run_verify(root, manifest, None, "--allow-unsigned")[0] == 2


def test_unsigned_empty(tmp_path, run_verify, capsys):
    root = tmp_path / "empty"
    root.mkdir()
    path = tmp_path / "inventory"
    assert main(["baseline", str(root), "--output", str(path), "--unsigned"]) == 0
    assert "UNAUTHENTICATED" in capsys.readouterr().err
    assert run_verify(root, path)[0] == 3
    code, doc = run_verify(root, path, None, "--allow-unsigned")
    assert code == 0 and doc["manifest_trust"] == "unauthenticated" and not doc["findings"]


def test_output_and_inspect(signed_dataset, tmp_path, capsys, monkeypatch):
    root, manifest, public = signed_dataset
    out = tmp_path / "reports" / "report.json"
    args = [
        "verify",
        str(root),
        "--manifest",
        str(manifest),
        "--public-key",
        str(public),
        "--output",
        str(out),
        "--format",
        "json",
    ]
    assert main(args) == 0 and not capsys.readouterr().out
    assert json.loads(out.read_text())["result"] == "clean"
    assert main(args) == 2 and json.loads(capsys.readouterr().out)["result"] == "incomplete"
    monkeypatch.setattr(
        verification, "scan", lambda *a, **kw: pytest.fail("inspect accessed dataset")
    )
    assert main(["inspect", str(manifest), "--public-key", str(public)]) == 0
    output = capsys.readouterr().out
    assert "VERIFIED" in output and "Files: 2 | Bytes: 7" in output


def test_outputs_and_key_inside_root(signed_dataset, run_verify, capsys):
    root, manifest, public = signed_dataset
    out = root / "unexpected"
    code, report = run_verify(root, manifest, public, "--output", str(out))
    assert code == 2 and report["summary"]["files_scanned"] == 0 and not out.exists()
    assert main(["baseline", str(root), "--unsigned", "--output", str(out)]) == 2
    assert (
        main(
            [
                "baseline",
                str(root),
                "--sign-key",
                str(root / "frame.bin"),
                "--output",
                str(root.parent / "new"),
            ]
        )
        == 2
    )
    assert not out.exists() and not (root.parent / "new").exists()


def test_failed_signing_keeps_output_absent(signed_dataset, monkeypatch):
    root, manifest, _ = signed_dataset
    out = manifest.parent / "retry"
    monkeypatch.setattr(signing, "passphrase", lambda: b"wrong")
    assert (
        main(
            [
                "baseline",
                str(root),
                "--output",
                str(out),
                "--sign-key",
                str(root.parent / "private.pem"),
            ]
        )
        == 3
    )
    assert not out.exists()


def test_noninteractive_keygen(tmp_path, monkeypatch):
    monkeypatch.setattr(signing.sys.stdin, "isatty", lambda: False)
    assert (
        main(
            [
                "keygen",
                "--private-key",
                str(tmp_path / "a"),
                "--public-key",
                str(tmp_path / "b"),
            ]
        )
        == 3
    )
    assert list(tmp_path.iterdir()) == []
