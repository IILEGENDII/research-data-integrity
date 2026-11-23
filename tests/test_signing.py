import base64
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research_integrity import signing
from research_integrity.inventory import scan
from research_integrity.manifest import make_payload
from research_integrity.models import InputError, TrustError


@pytest.fixture
def signed(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "frame").write_bytes(b"synthetic")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    fp = signing.generate_keys(private, public, b"disposable")
    doc = signing.sign(make_payload(scan(root)), signing.load_private(private, b"disposable"))
    assert doc["signature"]["public_key_fingerprint"] == fp
    return doc, private, public


def test_keys(signed):
    doc, private, public = signed
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in private.read_bytes()
    if os.name == "posix":
        assert private.stat().st_mode & 0o077 == 0
    assert signing.authenticate(doc, public, False) == "verified"
    with pytest.raises(TrustError):
        signing.load_private(private, b"incorrect")
    with pytest.raises(InputError):
        signing.generate_keys(private, public, b"replacement")


@pytest.mark.parametrize(
    "field", ["size", "path", "sha256", "created_at", "signature", "fingerprint"]
)
def test_tamper(signed, field):
    doc, _, public = signed
    if field == "created_at":
        doc["payload"][field] = "2000-01-01T00:00:00Z"
    elif field == "signature":
        doc["signature"]["value"] = base64.b64encode(bytes(64)).decode()
    elif field == "fingerprint":
        doc["signature"]["public_key_fingerprint"] = "sha256:" + "0" * 64
    else:
        doc["payload"]["files"][0][field] = {"size": 0, "path": "new", "sha256": "a" * 64}[
            field
        ]
    with pytest.raises(TrustError):
        signing.authenticate(doc, public, True)


def test_downgrade(signed, tmp_path):
    doc, _, public = signed
    with pytest.raises(TrustError):
        signing.authenticate(doc, None, True)
    with pytest.raises(TrustError):
        signing.authenticate(doc, tmp_path / "lost.pem", False)
    signing.generate_keys(tmp_path / "other-private", tmp_path / "other-public", b"one use")
    with pytest.raises(TrustError):
        signing.authenticate(doc, tmp_path / "other-public", False)
    doc["signature"] = None
    for key, allow in [(None, False), (public, True), (public, False)]:
        with pytest.raises(TrustError):
            signing.authenticate(doc, key, allow)
    assert signing.authenticate(doc, None, True) == "unauthenticated"


def test_refuse_unencrypted_and_partial_pair(tmp_path, monkeypatch):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    private.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
    with pytest.raises(TrustError):
        signing.load_private(private, b"x")
    private.unlink()
    original = signing.write_new

    def fail(path, data):
        if path == private:
            raise OSError
        original(path, data)

    monkeypatch.setattr(signing, "write_new", fail)
    with pytest.raises(OSError):
        signing.generate_keys(private, public, b"x")
    assert not public.exists() and not private.exists()


@pytest.mark.parametrize("value", ["bad", "?" * 88, "A" * 88])
def test_malformed_signature(signed, value):
    doc, _, public = signed
    doc["signature"]["value"] = value
    with pytest.raises(InputError):
        signing.authenticate(doc, public, False)
