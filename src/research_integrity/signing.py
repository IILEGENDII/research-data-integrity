import base64
import getpass
import hashlib
import os
import sys
import warnings
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .inventory import MAX_ENTRIES
from .manifest import canonical, validate
from .models import InputError, TrustError
from .storage import new_path, read_bounded, write_new

KEY_LIMIT = 64 * 1024


def passphrase(*, confirm=False) -> bytes:
    if not sys.stdin.isatty():
        raise TrustError("Use an interactive terminal for the signing passphrase.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Signing passphrase: ")
            if not value or (confirm and getpass.getpass("Confirm passphrase: ") != value):
                raise TrustError("A nonempty, matching passphrase is required.")
    except (EOFError, getpass.GetPassWarning) as exc:
        raise TrustError("A private terminal prompt is required.") from exc
    return value.encode("utf-8")


def fingerprint(key: Ed25519PublicKey) -> str:
    return "sha256:" + hashlib.sha256(key.public_bytes_raw()).hexdigest()


def generate_keys(private_path: Path, public_path: Path, password: bytes) -> str:
    private_path, public_path = new_path(private_path), new_path(public_path)
    if private_path.is_relative_to(public_path) or public_path.is_relative_to(private_path):
        raise InputError("Choose distinct key files.")
    if not password:
        raise TrustError("Private keys require a nonempty passphrase.")
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    try:
        encrypted = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
    except ValueError as exc:
        raise TrustError("Passphrase cannot be used for key encryption.") from exc
    public_data = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    write_new(public_path, public_data)
    public_stat = public_path.lstat()
    try:
        write_new(private_path, encrypted)
    except BaseException:
        if os.path.samestat(public_path.lstat(), public_stat):
            public_path.unlink()
        raise
    return fingerprint(public)


def load_private(path: Path, password: bytes) -> Ed25519PrivateKey:
    data = read_bounded(path, KEY_LIMIT)
    if not data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or not password:
        raise TrustError("An encrypted PKCS#8 signing key and passphrase are required.")
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise TrustError("Cannot unlock the signing key.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TrustError("Expected an Ed25519 signing key.")
    return key


def sign(payload, key: Ed25519PrivateKey, *, max_entries=MAX_ENTRIES) -> dict:
    envelope = {"payload": payload, "signature": None}
    validate(envelope, max_entries=max_entries)
    envelope["signature"] = {
        "algorithm": "ed25519",
        "public_key_fingerprint": fingerprint(key.public_key()),
        "value": base64.b64encode(key.sign(canonical(payload))).decode("ascii"),
    }
    return envelope


def authenticate(
    envelope: dict, public_path: Path | None, allow_unsigned: bool, *, max_entries=MAX_ENTRIES
) -> str:
    validate(envelope, max_entries=max_entries)
    signature = envelope["signature"]
    if signature is None:
        if allow_unsigned and public_path is None:
            return "unauthenticated"
        raise TrustError("Unsigned manifest requires --allow-unsigned and no expected key.")
    if public_path is None:
        raise TrustError("A signed manifest requires a separately trusted public key.")
    try:
        key = serialization.load_pem_public_key(read_bounded(public_path, KEY_LIMIT))
    except (OSError, ValueError, UnsupportedAlgorithm) as exc:
        raise TrustError("Cannot load the designated public key.") from exc
    if (
        not isinstance(key, Ed25519PublicKey)
        or fingerprint(key) != signature["public_key_fingerprint"]
    ):
        raise TrustError("Manifest does not match the trusted Ed25519 key.")
    try:
        key.verify(
            base64.b64decode(signature["value"], validate=True), canonical(envelope["payload"])
        )
    except InvalidSignature as exc:
        raise TrustError("Invalid signature for this payload and public key.") from exc
    return "verified"
