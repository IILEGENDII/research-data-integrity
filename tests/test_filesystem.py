import os

import pytest

from research_integrity import inventory, storage
from research_integrity.cli import main
from research_integrity.models import InputError
from research_integrity.paths import checked_path, dataset_root


def link_dir(link, target):
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import _winapi

        try:
            _winapi.CreateJunction(str(target), str(link))
        except PermissionError:
            pytest.skip("junction creation unavailable")


def test_link_directory_and_root(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "file").write_bytes(b"outside")
    link = data / "link"
    link_dir(link, outside)
    result = inventory.scan(data)
    assert result.errors[0].status == "unsupported" and result.bytes_read == 0
    assert inventory.scan(link).errors
    assert main(["baseline", str(data), "--unsigned", "--output", str(link / "output")]) == 2
    assert not (outside / "output").exists()


def test_observed_directory_change(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    original = inventory.Budget.list_names

    def change(budget, directory, prefix):
        names = original(budget, directory, prefix)
        (root / "late").touch()
        stamp = root.stat().st_mtime_ns + 2_000_000_000
        os.utime(root, ns=(stamp, stamp))
        return names

    monkeypatch.setattr(inventory.Budget, "list_names", change)
    assert inventory.scan(root).errors[0].status == "unstable"
    out = tmp_path / "base"
    assert main(["baseline", str(root), "--unsigned", "--output", str(out)]) == 2
    assert not out.exists()


def test_midwrite_failure(tmp_path, monkeypatch):
    def interrupted(fd):
        raise OSError

    monkeypatch.setattr(os, "fsync", interrupted)
    with pytest.raises(OSError):
        storage.write_new(tmp_path / "output", b"new")
    assert not list(tmp_path.iterdir())


def test_publication_race(tmp_path, monkeypatch):
    output = tmp_path / "report"
    method = "rename" if os.name == "nt" else "link"
    original = getattr(os, method)

    def race(source, dest):
        output.write_bytes(b"prior writer")
        return original(source, dest)

    monkeypatch.setattr(os, method, race)
    with pytest.raises(FileExistsError):
        storage.write_new(output, b"new")
    assert list(tmp_path.iterdir()) == [output] and output.read_bytes() == b"prior writer"


def test_ambiguous_directory_entries(tmp_path):
    (tmp_path / "Frame").write_bytes(b"upper")
    if (tmp_path / "frame").exists():
        pytest.skip("case-insensitive filesystem")
    (tmp_path / "frame").write_bytes(b"lower")
    inv = inventory.scan(tmp_path)
    assert not inv.files and inv.bytes_read == 0
    assert [e.status for e in inv.errors] == ["unsupported", "unsupported"]


def test_output_traversal(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    with pytest.raises(InputError):
        checked_path(root / ".." / "output")
    with pytest.raises(InputError):
        dataset_root(type(root)(root.anchor))


def test_hardlinked_control_file(signed_dataset, run_verify):
    root, manifest, public = signed_dataset
    try:
        os.link(public, root / "alias")
    except PermissionError:
        pytest.skip("hard-link creation unavailable")
    code, doc = run_verify(root, manifest, public)
    assert code == 2 and doc["summary"]["bytes_read"] == 7
    assert doc["errors"][0]["path"] == "alias"


def test_unreadable_directory_does_not_claim_missing(signed_dataset, run_verify, monkeypatch):
    root, manifest, public = signed_dataset
    original = inventory.Budget.list_names

    def denied(self, directory, prefix):
        if not prefix:
            raise PermissionError
        return original(self, directory, prefix)

    monkeypatch.setattr(inventory.Budget, "list_names", denied)
    code, doc = run_verify(root, manifest, public)
    assert code == 2 and doc["summary"]["unreadable"] == 1 and doc["summary"]["missing"] == 0
    assert not doc["findings"]
