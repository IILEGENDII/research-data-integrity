import os
import re
import stat
import unicodedata
from pathlib import Path

from .models import InputError

MAX_PATH_BYTES = 4096
MAX_DEPTH = 64
DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³])", re.IGNORECASE)


def validate_path(name: str) -> None:
    if type(name) is not str or not name or not name.isprintable():
        raise InputError("Invalid relative path or nonprinting character.")
    if unicodedata.normalize("NFC", name) != name or len(name.encode("utf-8")) > MAX_PATH_BYTES:
        raise InputError("Path exceeds limits or is not NFC-normalized.")
    parts = name.split("/")
    if len(parts) > MAX_DEPTH:
        raise InputError("Path exceeds directory depth limit.")
    for part in parts:
        if (
            not part
            or part in {".", ".."}
            or part.endswith((".", " "))
            or len(part.encode("utf-8")) > 255
            or any(c in '<>:"\\|?*' for c in part)
            or DEVICE.fullmatch(part.split(".")[0].rstrip(" "))
        ):
            raise InputError("Path contains a nonportable component.")


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def checked_path(path: Path) -> Path:
    if ".." in path.parts or (
        os.name == "nt"
        and (path.drive.startswith("\\\\") or (path.drive and not path.is_absolute()))
    ):
        raise InputError("Use an ordinary local path without parent traversal.")
    path = path.absolute()
    for part in (*reversed(path.parents), path):
        if os.name == "nt" and part.name:
            validate_path(unicodedata.normalize("NFC", part.name))
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if is_link(info):
            raise InputError("An explicit path crosses a link or reparse point.")
    return path


def dataset_root(path: Path) -> Path:
    root = checked_path(path)
    if root == Path(root.anchor) or Path.home().is_relative_to(root):
        raise InputError("Choose a dataset below the drive or home directory.")
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise InputError("Expected a dataset directory.")
    return root


def outside(path: Path, root: Path) -> Path:
    root = checked_path(root)
    if path.absolute().is_relative_to(root):
        raise InputError("Keep manifests, keys and reports outside the dataset.")
    path = checked_path(path)
    # Directory identity also catches case-insensitive aliases and short Windows names.
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return path
    for ancestor in (path, *path.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if os.path.samestat(info, root_info):
            raise InputError("Keep manifests, keys and reports outside the dataset.")
    return path
