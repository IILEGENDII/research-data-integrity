import os
import tempfile
from pathlib import Path

from .hashing import regular_reader
from .models import InputError
from .paths import checked_path


def read_bounded(path: Path, limit: int) -> bytes:
    path = checked_path(path)
    info = path.lstat()
    if info.st_size > limit:
        raise InputError("Input exceeds the byte limit.")
    with regular_reader(path, info) as stream:
        data = stream.read(limit + 1)
        if len(data) != info.st_size or len(data) > limit:
            raise InputError("Input size changed while reading.")
    return data


def new_path(path: Path) -> Path:
    path = checked_path(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    raise InputError("Output already exists. Choose a new filename.")


def write_new(path: Path, data: bytes) -> None:
    path = new_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    checked_path(path.parent)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".integrity-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            os.rename(temporary, path)  # Windows rename refuses an existing destination.
        else:
            os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
