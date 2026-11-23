import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research_integrity.manifest import canonical, parse
from research_integrity.signing import authenticate, sign

VECTOR = Path(__file__).with_name("vectors") / "ed25519-v1.json"


def generate_vector():
    private = Ed25519PrivateKey.generate()
    file_data = b"synthetic\n"
    payload = {
        "schema_version": 1,
        "algorithm": "sha256",
        "created_at": "2026-01-01T00:00:00Z",
        "files": [
            {
                "path": "sample.txt",
                "size": len(file_data),
                "sha256": hashlib.sha256(file_data).hexdigest(),
            }
        ],
    }
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"envelope": sign(payload, private), "public_key_pem": public.decode("ascii")}


def test_public_vector(tmp_path):
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    envelope = parse(json.dumps(vector["envelope"]).encode())
    key = tmp_path / "public.pem"
    key.write_bytes(vector["public_key_pem"].encode("ascii"))
    assert authenticate(envelope, key, False) == "verified"
    payload = envelope["payload"]
    assert payload["files"] == [
        {"path": "sample.txt", "size": 10, "sha256": hashlib.sha256(b"synthetic\n").hexdigest()}
    ]
    public = serialization.load_pem_public_key(key.read_bytes())
    public.verify(base64.b64decode(envelope["signature"]["value"]), canonical(payload))
