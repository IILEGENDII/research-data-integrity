import hashlib
import os
import stat
from contextlib import contextmanager

from .models import Entry, InputError, Inventory
from .paths import is_link

CHUNK_SIZE = 4 * 1024 * 1024


class Unstable(InputError):
    pass


def stamp(info):
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        # On Windows path and descriptor queries can report different ctime semantics.
        info.st_ctime_ns if os.name == "posix" else None,
    )


@contextmanager
def regular_reader(path, expected, dir_fd=None):
    if is_link(expected) or not stat.S_ISREG(expected.st_mode):
        raise InputError("Expected a regular file.")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(path, flags, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or is_link(opened)
            or stamp(opened) != stamp(expected)
        ):
            raise Unstable("File changed before reading.")
        yield stream
        try:
            current = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise Unstable("File disappeared during reading.") from exc
        if stamp(os.fstat(fd)) != stamp(opened) or stamp(current) != stamp(opened):
            raise Unstable("File changed during reading.")


def hash_file(path, relative: str, expected, inventory: Inventory, dir_fd=None) -> Entry:
    digest = hashlib.sha256()
    size = 0
    with regular_reader(path, expected, dir_fd) as stream:
        while block := stream.read(min(CHUNK_SIZE, expected.st_size - size + 1)):
            size += len(block)
            inventory.bytes_read += len(block)
            if size > expected.st_size:
                raise Unstable("File grew during reading.")
            digest.update(block)
        if size != expected.st_size:
            raise Unstable("File ended before its observed size.")
    return Entry(relative, size, digest.hexdigest())
