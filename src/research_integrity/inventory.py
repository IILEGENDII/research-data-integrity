import os
import stat
import unicodedata
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .hashing import Unstable, hash_file, stamp
from .models import InputError, Inventory, Issue
from .paths import dataset_root, is_link, validate_path

MAX_ENTRIES = 100_000
MAX_PATH_TOTAL = 8 * 1024 * 1024


class LimitReached(InputError):
    pass


@dataclass
class Budget:
    entries: int
    path_bytes: int

    def list_names(self, directory, prefix):
        names = []
        with os.scandir(directory) as children:
            for child in children:
                self.entries -= 1
                self.path_bytes -= (
                    len(os.fsencode(child.name)) + len(prefix.encode("utf-8")) + 1
                )
                if self.entries < 0 or self.path_bytes < 0:
                    raise LimitReached("Dataset exceeds the inventory entry or path budget.")
                names.append((unicodedata.normalize("NFC", child.name), child.name))
        return sorted(names)


@contextmanager
def directory_reader(path, before, parent_fd):
    fd = None
    try:
        if os.name == "posix":
            fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(fd) if fd is not None else os.lstat(path)
        if is_link(info) or not stat.S_ISDIR(info.st_mode) or stamp(info) != stamp(before):
            raise Unstable("Directory changed before enumeration.")
        yield fd
        after = os.stat(path, dir_fd=parent_fd, follow_symlinks=False)
        if stamp(after) != stamp(before) or (
            fd is not None and stamp(os.fstat(fd)) != stamp(before)
        ):
            raise Unstable("Directory changed during enumeration.")
    finally:
        if fd is not None:
            os.close(fd)


def scan(
    root: Path, *, protected=frozenset(), max_entries=MAX_ENTRIES, max_path_total=MAX_PATH_TOTAL
) -> Inventory:
    inventory = Inventory()
    budget = Budget(max_entries, max_path_total)

    def visit(path, label, before, parent_fd=None):
        with directory_reader(path, before, parent_fd) as fd:
            names = budget.list_names(fd if fd is not None else path, label)
            # Skip both spellings before opening either one, including directory subtrees.
            counts = Counter(name.casefold() for name, _ in names)
            for name, original in names:
                relative = f"{label}/{name}" if label else name
                location = original if fd is not None else Path(path) / original
                try:
                    validate_path(relative)
                    if counts[name.casefold()] > 1:
                        raise InputError("Ambiguous normalized or case-insensitive name.")
                    info = os.stat(location, dir_fd=fd, follow_symlinks=False)
                    if is_link(info) or info.st_dev != root_info.st_dev:
                        raise InputError("Link, reparse point or different filesystem.")
                    if (info.st_dev, info.st_ino) in protected:
                        raise InputError("Dataset entry aliases an input manifest or key.")
                    if stat.S_ISDIR(info.st_mode):
                        visit(location, relative, info, fd)
                    elif stat.S_ISREG(info.st_mode):
                        inventory.files[relative] = hash_file(
                            location, relative, info, inventory, fd
                        )
                    else:
                        raise InputError("Special files are unsupported.")
                except LimitReached:
                    raise
                except Unstable as exc:
                    inventory.errors.append(Issue("unstable", relative, str(exc)))
                except InputError as exc:
                    inventory.errors.append(Issue("unsupported", relative, str(exc)))
                except OSError:
                    inventory.errors.append(
                        Issue("unreadable", relative, "Cannot inspect or read entry.")
                    )

    try:
        root = dataset_root(root)
        root_info = root.lstat()
        visit(root, "", root_info)
    except Unstable as exc:
        inventory.errors.append(Issue("unstable", ".", str(exc)))
    except InputError as exc:
        inventory.errors.append(Issue("unsupported", ".", str(exc)))
    except OSError:
        inventory.errors.append(Issue("unreadable", ".", "Cannot access dataset directory."))
    inventory.files = dict(sorted(inventory.files.items()))
    inventory.errors.sort(key=lambda issue: (issue.path, issue.status, issue.message))
    return inventory
