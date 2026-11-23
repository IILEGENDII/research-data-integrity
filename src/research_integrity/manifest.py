import base64
import binascii
import json
import re
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .inventory import MAX_ENTRIES, MAX_PATH_TOTAL
from .models import InputError
from .paths import validate_path
from .storage import read_bounded, write_new

MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_STRING_BYTES = 24 * 1024 + 2
DIGEST = re.compile("[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def make_payload(inventory, created_at=None):
    if inventory.errors:
        raise InputError("Incomplete inventory cannot become a baseline.")
    return {
        "schema_version": 1,
        "algorithm": "sha256",
        "created_at": created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": [asdict(inventory.files[name]) for name in sorted(inventory.files)],
    }


def exact_keys(obj, keys):
    if not isinstance(obj, dict) or obj.keys() != set(keys):
        raise InputError("Missing or unexpected JSON properties.")


def validate(envelope: dict, *, max_entries=MAX_ENTRIES) -> None:
    exact_keys(envelope, ("payload", "signature"))
    payload = envelope["payload"]
    exact_keys(payload, ("schema_version", "algorithm", "created_at", "files"))
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["algorithm"] != "sha256"
    ):
        raise InputError("Unsupported schema or digest algorithm.")
    date = payload["created_at"]
    if not isinstance(date, str) or not TIMESTAMP.fullmatch(date):
        raise InputError("Expected a UTC timestamp with whole seconds.")
    try:
        datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise InputError("Invalid calendar timestamp.") from exc
    entries = payload["files"]
    if not isinstance(entries, list) or len(entries) > max_entries:
        raise InputError("Invalid file list or entry limit exceeded.")
    previous = ""
    prefixes = {}
    path_bytes = 0
    for entry in entries:
        exact_keys(entry, ("path", "size", "sha256"))
        name = entry["path"]
        validate_path(name)
        path_bytes += len(name.encode("utf-8"))
        if path_bytes > MAX_PATH_TOTAL or name <= previous:
            raise InputError("Paths exceed the budget, repeat, or are out of order.")
        previous = name
        # Check directory prefixes too: A/x and a/y disagree about the directory spelling.
        parent = 0
        parts = name.split("/")
        for index, part in enumerate(parts):
            key = (parent, part.casefold())
            spelling = (part, index == len(parts) - 1)
            if key not in prefixes:
                if len(prefixes) >= max_entries:
                    raise InputError("Inventory exceeds file and directory entry limit.")
                prefixes[key] = (spelling, len(prefixes) + 1)
            stored, parent = prefixes[key]
            if stored != spelling:
                raise InputError("Ambiguous path or file/directory conflict.")
        if type(entry["size"]) is not int or not 0 <= entry["size"] < 2**63:
            raise InputError("Invalid file size.")
        if type(entry["sha256"]) is not str or not DIGEST.fullmatch(entry["sha256"]):
            raise InputError("Invalid SHA-256 digest.")
    signature = envelope["signature"]
    if signature is None:
        return
    exact_keys(signature, ("algorithm", "public_key_fingerprint", "value"))
    fingerprint = signature["public_key_fingerprint"]
    if (
        signature["algorithm"] != "ed25519"
        or not isinstance(fingerprint, str)
        or not re.fullmatch("sha256:[0-9a-f]{64}", fingerprint)
    ):
        raise InputError("Unsupported signature metadata.")
    value = signature["value"]
    if type(value) is not str or len(value) != 88:
        raise InputError("Invalid signature encoding.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InputError("Invalid signature encoding.") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise InputError("Expected a canonical 64-byte Ed25519 signature.")


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InputError("Duplicate JSON property.")
        obj[key] = value
    return obj


def _integer(text):
    if len(text) > 19:
        raise InputError("Integer outside supported range.")
    return int(text)


def _invalid_number(_):
    raise InputError("Only finite integers are supported.")


def parse(data: bytes, *, max_entries=MAX_ENTRIES, max_bytes=MAX_MANIFEST_BYTES) -> dict:
    if len(data) > max_bytes:
        raise InputError("Manifest exceeds the byte limit.")
    depth = separators = 0
    start = None
    escaped = False
    for index, byte in enumerate(data):
        if start is not None:
            if index - start > MAX_STRING_BYTES:
                raise InputError("JSON string exceeds limit.")
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                start = None
        elif byte == 34:
            start = index
        elif byte in (123, 91):
            depth += 1
            if depth > 8:
                raise InputError("JSON nesting exceeds limit.")
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                raise InputError("Invalid JSON nesting.")
        elif byte in (44, 58):
            separators += 1
            if separators > 8 * max_entries + 32:
                raise InputError("JSON structure exceeds entry budget.")
    try:
        envelope = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_int=_integer,
            parse_float=_invalid_number,
            parse_constant=_invalid_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError("Invalid UTF-8 JSON manifest.") from exc
    validate(envelope, max_entries=max_entries)
    return envelope


def load_manifest(path: Path, *, max_entries=MAX_ENTRIES) -> dict:
    return parse(read_bounded(path, MAX_MANIFEST_BYTES), max_entries=max_entries)


def save_manifest(path: Path, envelope: dict, *, max_entries=MAX_ENTRIES) -> None:
    validate(envelope, max_entries=max_entries)
    data = canonical(envelope) + b"\n"
    if len(data) > MAX_MANIFEST_BYTES:
        raise InputError("Generated manifest exceeds the reader limit.")
    write_new(path, data)
