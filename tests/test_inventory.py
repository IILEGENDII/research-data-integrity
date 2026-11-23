import hashlib
import os
from contextlib import contextmanager

import pytest

from research_integrity import hashing, inventory


def test_regular_tree(tmp_path):
    directory = tmp_path / "input tables"
    directory.mkdir()
    data = {"input tables/café.csv": b"1,2\r\n", ".hidden": b"\xff\x00", "empty": b""}
    for name, content in data.items():
        (tmp_path / name).write_bytes(content)
    result = inventory.scan(tmp_path)
    assert not result.errors
    assert list(result.files) == sorted(data)
    assert result.bytes_read == sum(map(len, data.values()))
    for name, content in data.items():
        assert result.files[name].sha256 == hashlib.sha256(content).hexdigest()
        assert (tmp_path / name).read_bytes() == content


def test_bounded_reads(tmp_path, monkeypatch):
    path = tmp_path / "frames"
    path.write_bytes(b"x" * (2 * hashing.CHUNK_SIZE + 7))
    sizes = []
    reader = hashing.regular_reader

    @contextmanager
    def traced(*args):
        with reader(*args) as stream:

            class Trace:
                def read(self, size):
                    sizes.append(size)
                    return stream.read(size)

            yield Trace()

    monkeypatch.setattr(hashing, "regular_reader", traced)
    result = inventory.scan(tmp_path)
    assert not result.errors and len(sizes) >= 4
    assert min(sizes) > 0 and max(sizes) == hashing.CHUNK_SIZE


def test_unreadable(tmp_path, monkeypatch):
    (tmp_path / "locked").touch()

    def denied(*args):
        raise PermissionError

    monkeypatch.setattr(inventory, "hash_file", denied)
    result = inventory.scan(tmp_path)
    assert not result.files
    assert result.errors[0].status == "unreadable"


def test_symlink(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    target = tmp_path / "outside"
    target.write_bytes(b"external")
    try:
        (data / "link").symlink_to(target)
    except OSError:
        pytest.skip("file symlinks unavailable")
    result = inventory.scan(data)
    assert result.bytes_read == 0 and result.errors[0].status == "unsupported"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO")
def test_fifo(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    result = inventory.scan(tmp_path)
    assert result.bytes_read == 0 and result.errors[0].status == "unsupported"


def test_budget(tmp_path):
    (tmp_path / "one").touch()
    assert inventory.scan(tmp_path, max_entries=0).errors[0].path == "."
    assert inventory.scan(tmp_path, max_path_total=1).errors[0].path == "."
